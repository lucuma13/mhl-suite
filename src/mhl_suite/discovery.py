"""
Cross-dialect discovery and verification orchestrator.

The engine behind the `mhlver` CLI, in two halves that feed each other:

Discovery finds every MHL under a path and classifies it once into typed items
— ClassicManifest for a classic (v1) file, AscmhlPackage for an ASC-MHL package
(one item per package, however many generation files its ascmhl/ folder holds).
Each item lazily parses/loads its manifest exactly once and caches the result,
so the dialect sniff happens once per file and the progress weights come from
the same parse verification consumes. Dialect rule: the manifest header is
authoritative (is_ascmhl_v2 reads only the root start-tag), so a classic v1
file is never treated as ASC-MHL even inside a folder named `ascmhl`; the
folder-name check is a pure performance gate.

verify_item() then runs the right dialect verify for each item — classic via
classic_verify, ASC-MHL via ascmhl_verify, both in-process through the shared
engine. It is print-free: it returns structured ManifestResults and emits
per-manifest StatusLine render data through an injected `emit` callback, so the
CLI (mhl_suite.cli.mhlver) owns all terminal I/O and this stays a testable
library. Each item's exit code is translated to a human-readable message via
dispatch tables keyed by the harmonised _exit_codes.ExitCode values.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from lxml import etree

from mhl_suite import ascmhl_verify, classic_verify, xsd_check
from mhl_suite._exit_codes import ExitCode
from mhl_suite.ascmhl_verify import verify_ascmhl
from mhl_suite.classic_verify import verify_classic
from mhl_suite.report import ManifestResult
from mhl_suite.verify import VerifyReport, render_verify_lines

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

    from mhl_suite.ascmhl_verify import History
    from mhl_suite.classic_verify import ParsedManifest


# -----------------------------------------------------------------------------
# Discovery
# -----------------------------------------------------------------------------


def _is_newer_than_classic(version: str) -> bool:
    """
    True if a `version` attribute's major component is newer than classic MHL:
    classic manifests are 1.x, ASC-MHL is 2.0+. Comparing only the major part
    means minor differences within v1 don't matter and multi-part future
    versions like 2.1.1 are handled. An empty or unparsable value is treated as
    not-newer.
    """
    try:
        return int(version.split(".", maxsplit=1)[0]) > 1
    except ValueError:
        return False


def is_ascmhl_v2(mhl_file: "str | Path") -> bool:
    """
    True if `mhl_file`'s root element declares ASC-MHL v2 rather than classic
    MHL.

    Reads only the root start-tag (iterparse, stopping at the first element)
    and checks for the ASC-MHL v2 namespace (urn:ASC:MHL:v2.0) or a `version`
    whose major component is > 1 — so a future 2.x/3.x is recognised even
    without the namespace. Any parse/read error yields False (treat as
    not-v2); the malformedness surfaces later where the file is actually
    verified.
    """
    try:
        with open(mhl_file, "rb") as f:
            for _, root in etree.iterparse(f, events=("start",)):
                ns = etree.QName(root).namespace
                return ns == "urn:ASC:MHL:v2.0" or _is_newer_than_classic(root.get("version", ""))
    except (etree.XMLSyntaxError, OSError):
        return False
    return False


@dataclass(eq=False)
class ClassicManifest:
    """A classic (v1) MHL manifest; parses itself once, lazily."""

    path: Path
    _parsed: "ParsedManifest | None" = field(default=None, repr=False)
    _load_failed: bool = field(default=False, repr=False)

    @property
    def label(self) -> str:
        """What status lines call this item."""
        return self.path.name

    def try_parsed(self) -> "ParsedManifest | None":
        """
        The parsed manifest, cached; None when it is malformed — the verify
        pass re-parses then and reports the real error, so nothing is lost by
        swallowing it here.
        """
        if self._parsed is None and not self._load_failed:
            try:
                self._parsed = classic_verify.parse_classic_manifest(str(self.path))
            except classic_verify.MalformedManifestError:
                self._load_failed = True
        return self._parsed

    def weight(self, size_only: bool) -> int:
        """
        Progress-bar weight: the byte volume verify will hash-read, or 1 under
        size-only (which reads no media bytes, so manifests count equally).
        """
        if size_only:
            return 1
        parsed = self.try_parsed()
        return parsed.hash_bytes if parsed is not None else 0


@dataclass(eq=False)
class AscmhlPackage:
    """An ASC-MHL package (the ascmhl/ folder with its generation manifests); loads its history once, lazily."""

    root: Path  # the folder the manifests describe (parent of ascmhl/)
    manifests: list[Path]  # generation files, sorted (latest last)
    _history: "History | None" = field(default=None, repr=False)
    _load_failed: bool = field(default=False, repr=False)

    @property
    def latest(self) -> Path:
        """The latest generation manifest (used as the item's representative file)."""
        return self.manifests[-1]

    @property
    def label(self) -> str:
        return str(self.root)

    def try_history(self) -> "History | None":
        """
        The loaded history, cached; None when loading fails (broken chain,
        malformed XML, …) — the verify pass reloads then and reports the real
        error with its pinned code.
        """
        if self._history is None and not self._load_failed:
            try:
                self._history = ascmhl_verify.load_history(self.root)
            except (ascmhl_verify.HistoryError, etree.XMLSyntaxError, OSError):
                self._load_failed = True
        return self._history

    def weight(self, size_only: bool) -> int:
        """Progress-bar weight: the recorded bytes of every verifiable file, or 1 under size-only."""
        if size_only:
            return 1
        history = self.try_history()
        return ascmhl_verify.history_byte_total(history) if history is not None else 0


DiscoveredItem = ClassicManifest | AscmhlPackage


def _find_mhl_files(root: Path) -> "Iterator[Path]":
    """
    Yield every .mhl file under `root`, case-insensitively, skipping macOS
    resource forks (filenames starting with '._'). rglob's character classes
    are the only portable case-insensitive match pathlib offers.
    """
    for p in root.rglob("*.[mM][hH][lL]"):
        if not p.name.startswith("._"):
            yield p


def _routes_to_ascmhl(mhl_file: Path) -> bool:
    """Dialect decision for one file (see module docstring for the rule)."""
    return mhl_file.parent.name == ascmhl_verify.ASCMHL_FOLDER and is_ascmhl_v2(mhl_file)


def classify(mhl_file: Path) -> DiscoveredItem:
    """
    Classify a single manifest path into its typed item.

    A v2 manifest stands for its whole package: the item collects every
    sibling generation file — by the loader's own rule (the NNNN_* naming
    convention and a v2 header), so a stray classic manifest sitting inside
    the ascmhl/ folder is never mistaken for a generation.
    """
    if _routes_to_ascmhl(mhl_file):
        package_dir = mhl_file.parent.parent
        siblings = sorted(
            p
            for p in mhl_file.parent.glob("*.mhl")
            if not p.name.startswith("._") and ascmhl_verify.GENERATION_RE.match(p.stem) and is_ascmhl_v2(p)
        )
        return AscmhlPackage(root=package_dir, manifests=siblings or [mhl_file])
    return ClassicManifest(path=mhl_file)


def discover(src: Path) -> list[DiscoveredItem]:
    """
    Find and classify every manifest under `src` (or `src` itself when it is a
    file), sorted by path with ASC-MHL packages deduplicated: a package's
    generations verify as one unit, so its ascmhl/ folder contributes a single
    item however many .mhl files it holds.
    """
    if src.is_file():
        return [classify(src)]
    if not src.is_dir():
        return []

    items: dict[Path, DiscoveredItem] = {}  # key: classic file path / package root
    for f in sorted(_find_mhl_files(src)):
        if _routes_to_ascmhl(f):
            package_dir = f.parent.parent
            if package_dir not in items:
                items[package_dir] = classify(f)
        else:
            items[f] = ClassicManifest(path=f)
    return [items[key] for key in sorted(items)]


# -----------------------------------------------------------------------------
# Per-manifest status rendering data
# -----------------------------------------------------------------------------
# A verify produces one or more StatusLine values describing what to print:
# which dispatch table, the exit code, the target label, and the per-file
# output text. The orchestrator never prints — it hands these to the injected
# `emit` callback, which the CLI turns into coloured terminal output. Emitting
# per manifest as the loop yields it preserves live status streaming;
# `emit=None` discards (a library caller that only wants the ManifestResults).


@dataclass
class StatusLine:
    """
    One per-manifest status to render: a dispatch-table lookup plus the
    per-file output text. `table` maps an exit code to (message template,
    severity)."""

    table: "dict[int, tuple[str, str]]"
    code: int
    label: str
    output: str


def _emit(
    emit: "Callable[[StatusLine], None] | None",
    table: "dict[int, tuple[str, str]]",
    code: int,
    label: str,
    output: str,
) -> None:
    """Hand one per-manifest StatusLine to the sink, if a sink was provided."""
    if emit is not None:
        emit(StatusLine(table, code, label, output))


# -----------------------------------------------------------------------------
# Exit-code dispatch tables
# -----------------------------------------------------------------------------
# Wording note: the per-file detail (which files, what kind of failure) comes
# from the render module's structured `[ERROR] <category>: <path>` lines, which
# are self-explanatory standalone. The tables therefore only say "this manifest
# failed" — the lines below the status explain why. The exit code itself still
# encodes the precise failure category for tooling.

_CLASSICMHL_RESULTS: dict[int, tuple[str, str]] = {
    ExitCode.OK: ("✅ MHL verified: {target}", "success"),
    ExitCode.ERROR: (
        "🚨 Verification Error: {target} — file not found or invalid argument (not an MHL file).",
        "warning",
    ),
    ExitCode.MISSING: ("❌ Verification failed: {target}", "error"),
    ExitCode.HASH_MISMATCH: ("❌ Verification failed: {target}", "error"),
    ExitCode.SIZE_MISMATCH: ("❌ Verification failed: {target}", "error"),
    ExitCode.MALFORMED_XML: ("🚨 Malformed XML: {target} cannot be parsed.", "warning"),
    ExitCode.SCHEMA_NONCOMPLIANT: ("⚠️ Schema non-compliant: {target}", "error"),
}

# Schema-check uses the same codes but with a different success message.
_CLASSICMHL_SCHEMA_RESULTS: dict[int, tuple[str, str]] = {
    **_CLASSICMHL_RESULTS,
    ExitCode.OK: ("📝 MHL schema valid: {target}", "success"),
}

_ASCMHL_VERIFY_RESULTS: dict[int, tuple[str, str]] = {
    ExitCode.OK: ("✅ ASC-MHL verified: {target}", "success"),
    ExitCode.MISSING: ("❌ ASC-MHL verification failed: {target}", "error"),
    ExitCode.HASH_MISMATCH: ("❌ ASC-MHL verification failed: {target}", "error"),
    ExitCode.DIRECTORY_HASH_MISMATCH: ("❌ ASC-MHL verification failed: {target}", "error"),
    # SIZE_MISMATCH (13) is a suite extension (the reference tool has no size
    # check), kept distinct from HASH_MISMATCH so size failures don't look like
    # hash failures.
    ExitCode.SIZE_MISMATCH: ("❌ ASC-MHL verification failed: {target}", "error"),
    ExitCode.SINGLE_FILE_NOT_FOUND: ("❌ ASC-MHL verification failed: {target}", "error"),
    ExitCode.NEW_FILES: (
        "⚠️ ASC-MHL: new files found in {target} that are not recorded in history.",
        "error",
    ),
    ExitCode.NO_HISTORY: ("❌ ASC-MHL verification failed: {target}", "error"),
    ExitCode.MODIFIED_MANIFEST: ("❌ ASC-MHL verification failed: {target}", "error"),
    ExitCode.NO_CHAIN: ("❌ ASC-MHL verification failed: {target}", "error"),
    ExitCode.MISSING_MANIFEST: ("❌ ASC-MHL verification failed: {target}", "error"),
    ExitCode.MALFORMED_XML: ("🚨 Malformed XML: {target} cannot be parsed.", "warning"),
}

_ASCMHL_SCHEMA_RESULTS: dict[int, tuple[str, str]] = {
    ExitCode.OK: ("📝 ASC-MHL schema valid: {target}", "success"),
    ExitCode.SCHEMA_NONCOMPLIANT: (
        "⚠️ ASC-MHL schema non-compliant: {target} does not match the ASC-MHL schema.",
        "error",
    ),
    ExitCode.MALFORMED_XML: ("🚨 Malformed XML: {target} cannot be parsed.", "warning"),
}


# -----------------------------------------------------------------------------
# verify_item — per-item dispatch
# -----------------------------------------------------------------------------


def _manifest_result(item: DiscoveredItem, report: VerifyReport, table: "dict[int, tuple[str, str]]") -> ManifestResult:
    """Fold one item's VerifyReport into the report model (entries carried as-is — same type)."""
    if report.code == 0:
        mstatus = "ok"
    elif report.entries:
        mstatus = "failed"
    else:
        mstatus = "error"  # manifest-level failure: malformed / integrity gate
    template, _severity = table.get(report.code, ("Unexpected exit {code}", "warning"))
    merror = "" if mstatus != "error" else template.format(target=item.label, code=report.code)
    manifest_path = item.latest if isinstance(item, AscmhlPackage) else item.path
    return ManifestResult(
        manifest_path=manifest_path,
        manifest_status=mstatus,
        manifest_error=merror,
        file_results=report.entries,
    )


def verify_item(
    item: DiscoveredItem,
    verbose: bool,
    schema: bool,
    size_only: bool = False,
    emit: "Callable[[StatusLine], None] | None" = None,
    on_bytes: "Callable[[int], None] | None" = None,
) -> "tuple[int, ManifestResult | None]":
    """
    Verify one discovered item with the right dialect engine.

    `size_only` requests the fast size-only check; `schema` validates against
    the bundled XSDs instead of verifying. `emit`, if given, receives a
    StatusLine per manifest for the CLI to render; `on_bytes` advances a
    progress bar as each file is hashed (per chunk, possibly from worker
    threads).

    Returns (exit_code, ManifestResult | None). ManifestResult is None in
    schema mode (no per-file detail exists then).
    """
    if isinstance(item, AscmhlPackage):
        return _verify_ascmhl_item(item, verbose, schema, size_only, emit, on_bytes)
    return _verify_classic_item(item, verbose, schema, size_only, emit, on_bytes)


def _verify_classic_item(
    item: ClassicManifest,
    verbose: bool,
    schema: bool,
    size_only: bool,
    emit: "Callable[[StatusLine], None] | None",
    on_bytes: "Callable[[int], None] | None",
) -> "tuple[int, ManifestResult | None]":
    """Classic manifest: schema mode or verify via the shared engine."""
    if schema:
        code, lines = xsd_check.classic_schema_report(str(item.path))
        _emit(emit, _CLASSICMHL_SCHEMA_RESULTS, code, item.label, "\n".join(lines))
        return code, None

    report = verify_classic(str(item.path), size_only=size_only, on_progress=on_bytes, parsed=item.try_parsed())
    output = "\n".join(render_verify_lines(report, verbose))
    _emit(emit, _CLASSICMHL_RESULTS, report.code, item.label, output)
    return report.code, _manifest_result(item, report, _CLASSICMHL_RESULTS)


def _verify_ascmhl_item(
    item: AscmhlPackage,
    verbose: bool,
    schema: bool,
    size_only: bool,
    emit: "Callable[[StatusLine], None] | None",
    on_bytes: "Callable[[int], None] | None",
) -> "tuple[int, ManifestResult | None]":
    """ASC-MHL package: schema mode (latest manifest + chain) or verify via the shared engine."""
    if schema:
        # Both halves of the package are always checked; the worst exit code
        # (preferring the manifest's) is returned so the caller has one signal.
        mhl_code, mhl_lines = xsd_check.ascmhl_schema_report(item.latest)
        _emit(emit, _ASCMHL_SCHEMA_RESULTS, mhl_code, str(item.latest), "\n".join(mhl_lines))

        chain_file = item.latest.parent / "ascmhl_chain.xml"
        chain_code, chain_lines = xsd_check.ascmhl_schema_report(chain_file, directory_file=True)
        _emit(emit, _ASCMHL_SCHEMA_RESULTS, chain_code, str(chain_file), "\n".join(chain_lines))
        return (mhl_code if mhl_code != 0 else chain_code), None

    report = verify_ascmhl(item.root, size_only=size_only, on_progress=on_bytes, history=item.try_history())
    output = "\n".join(render_verify_lines(report, verbose))
    _emit(emit, _ASCMHL_VERIFY_RESULTS, report.code, item.label, output)
    return report.code, _manifest_result(item, report, _ASCMHL_VERIFY_RESULTS)
