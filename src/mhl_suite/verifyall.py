# =============================================================================
# mhl_suite.verifyall — cross-dialect "verify a whole tree" orchestrator
# =============================================================================
# Copyright (c) 2026 Luis Gómez Gutiérrez. Licensed MIT.
#
# The engine behind the `mhlver` CLI: walk a path, find every MHL manifest,
# verify each via the right backend, and aggregate the results. It is print-free
# — instead of writing to the terminal it returns structured ManifestResults and
# emits per-manifest StatusLine render data through an injected `emit` callback,
# so the CLI (mhl_suite.cli.mhlver) owns all terminal I/O and this stays a
# testable library.
#
# Detection rule: a manifest inside an `ascmhl/` folder is an ASC-MHL package
# (AscMHLBackend, via mhl_suite.ascmhl); otherwise it is classic MHL
# (ClassicMHLBackend, via mhl_suite.classicmhl). Both verify in-process. Each
# backend's exit code is translated to a human-readable message via dispatch
# tables (see _CLASSICMHL_RESULTS, _ASCMHL_VERIFY_RESULTS).
# =============================================================================

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from lxml import etree

from mhl_suite.ascmhl import verify as ascmhl_verify
from mhl_suite.ascmhl.sizecheck import verify_ascmhl_sizes
from mhl_suite.classicmhl.verify import render_verify_lines, schema_report, verify_manifest
from mhl_suite.shared.report import FileResult, ManifestResult

# -----------------------------------------------------------------------------
# Per-manifest status rendering data
# -----------------------------------------------------------------------------
# A verify produces one or more StatusLine values describing what to print: which
# dispatch table, the exit code, the target label, and the per-file output text.
# The orchestrator never prints — it hands these to the injected `emit` callback,
# which the CLI turns into coloured terminal output (see cli.mhlver._report_via_table).
# Emitting per manifest as the loop yields it preserves live status streaming;
# `emit=None` discards (a library caller that only wants the ManifestResults).


@dataclass
class StatusLine:
    """One per-manifest status to render: a dispatch-table lookup plus the
    per-file output text. `table` maps an exit code to (message template, severity)."""

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


# --- ASC-MHL output rendering -------------------------------------------------
#
# Both dialects are verified in-process now: classic via mhl_suite.classicmhl.verify
# and ASC-MHL via mhl_suite.ascmhl.verify, each returning structured outcomes — so
# there is no backend stdout to parse. _render_ascmhl_lines reproduces the
# per-file terminal text from an AscVerifyReport (the ASC-MHL counterpart to
# classicmhl.render_verify_lines): failure lines always, OK lines only when
# verbose, matching the old `ascmhl-debug verify [-v]` output mhlver used to relay.


def _render_ascmhl_lines(report: "ascmhl_verify.AscVerifyReport", verbose: bool) -> list[str]:
    """Render an AscVerifyReport to the per-file lines shown on the terminal."""
    out: list[str] = []
    if verbose:
        out.extend(e.line for e in report.entries if e.status == "ok")
    out.extend(e.line for e in report.entries if e.status in ("missing", "mismatch", "new"))
    return out


# -----------------------------------------------------------------------------
# Exit-code dispatch tables
# -----------------------------------------------------------------------------
# Both backends return structured exit codes. Rather than long if/elif chains,
# we map exit_code -> (template, severity) and dispatch through a small helper.
# severity is "success" / "warning" / "error" and selects the logger.
#
# Templates use {target} which we .format() with the manifest's name or its
# package directory depending on the action.

# --- simple-mhl (classic MHL) verify exit codes ------------------------------
# These are the codes simple_mhl.py returns. Exit 70 was added in v1.0.2 to
# distinguish "missing AND mismatch" from either failure alone.
#
# Wording note: the per-file detail (which files, what kind of failure)
# comes from simple-mhl itself, which prints structured `ERROR: <category>:
# <path>` lines that are self-explanatory standalone. mhlver therefore only
# needs to say "this manifest failed" — the lines below explain why. The
# exit code itself still encodes the precise failure category for tooling.
_CLASSICMHL_RESULTS: dict[int, tuple[str, str]] = {
    0: ("✅ MHL verified: {target}", "success"),
    1: (
        "🚨 Verification Error: {target} — file not found or invalid argument (not an MHL file).",
        "warning",
    ),
    10: ("⚠️ Schema non-compliant: {target}", "error"),
    20: ("🚨 Malformed XML: {target} cannot be parsed.", "warning"),
    30: ("❌ Verification failed: {target}", "error"),
    40: ("❌ Verification failed: {target}", "error"),
    70: ("❌ Verification failed: {target}", "error"),
    127: (
        "🚨 System error: 'simple-mhl' command not found. Ensure it is in your PATH.",
        "warning",
    ),
}

# Schema-check uses the same codes but with a different success message,
# plus exit 60 which is unique to schema-check (XSD not found on disk).
_CLASSICMHL_SCHEMA_RESULTS: dict[int, tuple[str, str]] = {
    **_CLASSICMHL_RESULTS,
    0: ("📝 MHL schema valid: {target}", "success"),
    60: (
        "🚨 Schema check unavailable: simple-mhl could not locate its bundled XSD file.",
        "warning",
    ),
}

# --- ASC-MHL (2.0) verify exit codes ----------------------------------------
# These come from the vendored ascmhl/errors.py (each a click.ClickException
# subclass carrying an exit_code), surfaced in-process by mhl_suite.ascmhl.verify.
#
# As with the classic MHL table, mhlver gives a single short status line per
# manifest; the per-file detail (which file mismatched, which manifest is
# missing) comes from the structured AscVerifyReport, rendered by
# _render_ascmhl_lines. The exit code preserves the precise failure category.
_ASCMHL_VERIFY_RESULTS: dict[int, tuple[str, str]] = {
    0: ("✅ ASC-MHL verified: {target}", "success"),
    10: ("❌ ASC-MHL verification failed: {target}", "error"),
    11: ("❌ ASC-MHL verification failed: {target}", "error"),
    12: ("❌ ASC-MHL verification failed: {target}", "error"),
    20: ("❌ ASC-MHL verification failed: {target}", "error"),
    21: (
        "⚠️ ASC-MHL: new files found in {target} that are not recorded in history.",
        "error",
    ),
    30: ("❌ ASC-MHL verification failed: {target}", "error"),
    31: ("❌ ASC-MHL verification failed: {target}", "error"),
    32: ("❌ ASC-MHL verification failed: {target}", "error"),
    33: ("❌ ASC-MHL verification failed: {target}", "error"),
}

# ASC-MHL xsd-schema-check uses VerificationFailedException (code 11) for
# schema-non-compliance, which deserves its own message distinct from the
# verify path's "hash mismatch" interpretation of the same code.
_ASCMHL_SCHEMA_RESULTS: dict[int, tuple[str, str]] = {
    0: ("📝 ASC-MHL schema valid: {target}", "success"),
    11: (
        "⚠️ ASC-MHL schema non-compliant: {target} does not match the ASC-MHL schema.",
        "error",
    ),
}
# -----------------------------------------------------------------------------
# Verify backends — the port
# -----------------------------------------------------------------------------
# Both backends verify in-process and return the same (exit_code, ManifestResult
# | None), so the orchestrator stays uniform. ClassicMHLBackend drives
# mhl_suite.classicmhl.verify; AscMHLBackend drives mhl_suite.ascmhl.verify. Both
# advance the progress bar through the same on_bytes hook as each file is hashed.


class VerifyBackend(Protocol):
    """A manifest-verification backend.

    Print-free: it returns `(exit_code, ManifestResult | None)` and reports each
    per-manifest status to the injected `emit` callback (a StatusLine the CLI
    renders). `on_bytes` advances a progress bar from the in-process hasher as
    each file finishes hashing (called when verifying, not in schema mode).
    """

    def verify(
        self,
        target: Path,
        verbose: bool,
        schema: bool,
        *,
        size_only: bool = False,
        emit: "Callable[[StatusLine], None] | None" = None,
        on_bytes: "Callable[[int], None] | None" = None,
    ) -> "tuple[int, ManifestResult | None]": ...


class ClassicMHLBackend:
    """Verifies classic MHL in-process via the core engine."""

    def verify(
        self,
        target: Path,
        verbose: bool,
        schema: bool,
        *,
        size_only: bool = False,
        emit: "Callable[[StatusLine], None] | None" = None,
        on_bytes: "Callable[[int], None] | None" = None,
    ) -> "tuple[int, ManifestResult | None]":
        return _verify_classicmhl(
            target,
            verbose,
            schema,
            size_only=size_only,
            emit=emit,
            on_bytes=on_bytes,
        )


class AscMHLBackend:
    """Verifies ASC-MHL in-process via the vendored engine (mhl_suite.ascmhl)."""

    def verify(
        self,
        target: Path,
        verbose: bool,
        schema: bool,
        *,
        size_only: bool = False,
        emit: "Callable[[StatusLine], None] | None" = None,
        on_bytes: "Callable[[int], None] | None" = None,
    ) -> "tuple[int, ManifestResult | None]":
        return _verify_ascmhl(
            target,
            verbose,
            schema,
            size_only=size_only,
            emit=emit,
            on_bytes=on_bytes,
        )


# -----------------------------------------------------------------------------
# verify_item — main per-MHL dispatcher
# -----------------------------------------------------------------------------


def verify_item(
    target: Path,
    verbose: bool,
    schema: bool,
    size_only: bool = False,
    emit: "Callable[[StatusLine], None] | None" = None,
    on_bytes: "Callable[[int], None] | None" = None,
) -> "tuple[int, ManifestResult | None]":
    """
    Verify a single MHL manifest by selecting the right backend.

    Detection rule: if any path component is exactly 'ascmhl' the manifest
    belongs to an ASC-MHL package and is verified through the vendored ASC-MHL
    engine (AscMHLBackend); otherwise it is classic MHL, verified through the
    classic engine (ClassicMHLBackend). Both verify in-process and satisfy the
    VerifyBackend port, so the orchestrator only ever sees
    `(exit_code, ManifestResult | None)`.

    `size_only` requests a fast size-only check. `emit`, if given, receives a
    StatusLine per manifest for the CLI to render; `on_bytes` advances a progress
    bar as each file is hashed (both backends).

    Returns (exit_code, ManifestResult | None). ManifestResult is None when
    schema-check mode is active (no per-file detail is available then).
    """
    backend: VerifyBackend = AscMHLBackend() if "ascmhl" in target.parts else ClassicMHLBackend()
    return backend.verify(
        target,
        verbose,
        schema,
        size_only=size_only,
        emit=emit,
        on_bytes=on_bytes,
    )


# --- Classic MHL (v1) path -----------------------------------------------------


def _verify_classicmhl(
    target: Path,
    verbose: bool,
    schema: bool,
    size_only: bool = False,
    emit: "Callable[[StatusLine], None] | None" = None,
    on_bytes: "Callable[[int], None] | None" = None,
) -> "tuple[int, ManifestResult | None]":
    """Verify a classic MHL manifest in-process via the core engine.

    Schema mode runs core.verify.schema_report; verify/size-only run
    core.verify.verify_manifest, whose structured FileOutcomes map straight onto
    FileResult — no subprocess, no text round-trip. render_verify_lines reproduces
    the exact `simple-mhl verify` stdout so the terminal output is unchanged.

    `on_bytes`, when given, advances the caller's progress bar as each file is
    hashed (the in-process equivalent of the old subprocess animation tick).
    """
    if schema:
        code, lines = schema_report(str(target))
        _emit(emit, _CLASSICMHL_SCHEMA_RESULTS, code, target.name, "\n".join(lines))
        return code, None

    report = verify_manifest(str(target), size_only=size_only, on_progress=on_bytes)

    if report.malformed:
        # Malformed XML: the engine read nothing and produced no per-file detail.
        template, _sev = _CLASSICMHL_RESULTS[20]
        _emit(emit, _CLASSICMHL_RESULTS, 20, target.name, "")
        mr = ManifestResult(
            manifest_path=target,
            manifest_status="error",
            manifest_error=template.format(target=target.name),
        )
        return 20, mr

    # render_verify_lines reproduces the exact `simple-mhl verify` stdout at the
    # requested verbosity (OK lines and the indented detail continuations are
    # included only when verbose), matching the old subprocess terminal output.
    output = "\n".join(render_verify_lines(report, verbose))
    _emit(emit, _CLASSICMHL_RESULTS, report.code, target.name, output)

    # FileOutcome and FileResult share the same fields — a direct, parse-free map.
    file_results = [
        FileResult(
            path=e.path,
            status=e.status,
            detail=e.detail,
            size_only=e.size_only,
            existence_only=e.existence_only,
        )
        for e in report.entries
    ]
    if report.code == 0:
        mstatus = "ok"
    elif file_results:
        mstatus = "failed"
    else:
        mstatus = "error"
    template, _ = _CLASSICMHL_RESULTS.get(report.code, ("Unexpected exit {code}", "warning"))
    merror = "" if mstatus != "error" else template.format(target=target.name)
    mr = ManifestResult(
        manifest_path=target,
        manifest_status=mstatus,
        manifest_error=merror,
        file_results=file_results,
    )
    return report.code, mr


# --- ASC-MHL (v2) path --------------------------------------------------------


def _verify_ascmhl(
    target: Path,
    verbose: bool,
    schema: bool,
    size_only: bool = False,
    emit: "Callable[[StatusLine], None] | None" = None,
    on_bytes: "Callable[[int], None] | None" = None,
) -> "tuple[int, ManifestResult | None]":
    """Verify an ASC-MHL package in-process via the vendored engine, by mode."""
    # Size-only: an integrity gate plus a byte-free size compare (ascmhl does
    # not check sizes), all in-process.
    if size_only and not schema:
        return _ascmhl_verify_sizeonly(target, verbose, emit=emit)
    if schema:
        code = _ascmhl_schema_check(target, verbose, emit=emit)
        return code, None
    return _ascmhl_verify(target, verbose, emit=emit, on_bytes=on_bytes)


def _ascmhl_schema_check(
    target: Path,
    verbose: bool,
    emit: "Callable[[StatusLine], None] | None" = None,
) -> int:
    """
    Schema-check both halves of an ASC-MHL package in-process: the manifest
    itself against ASCMHL.xsd and the sibling ascmhl_chain.xml against the
    directory schema.

    Both checks always run; the worst exit code (preferring the manifest's) is
    returned so the caller has a single signal. Validation errors are always
    shown — they carry the line numbers and structural detail an operator needs
    to fix the file.
    """
    # Step 1: the .mhl manifest against the manifest schema.
    mhl_code, mhl_lines = ascmhl_verify.schema_check(target)
    _emit(emit, _ASCMHL_SCHEMA_RESULTS, mhl_code, str(target), "\n".join(mhl_lines))

    # Step 2: ascmhl_chain.xml against the directory schema.
    chain_file = target.parent / "ascmhl_chain.xml"
    chain_code, chain_lines = ascmhl_verify.schema_check(chain_file, directory_file=True)
    _emit(emit, _ASCMHL_SCHEMA_RESULTS, chain_code, str(chain_file), "\n".join(chain_lines))

    # Manifest failure takes priority; otherwise the chain's code wins.
    return mhl_code if mhl_code != 0 else chain_code


def _ascmhl_verify(
    target: Path,
    verbose: bool,
    emit: "Callable[[StatusLine], None] | None" = None,
    on_bytes: "Callable[[int], None] | None" = None,
) -> "tuple[int, ManifestResult]":
    """
    Verify an ASC-MHL package in-process via mhl_suite.ascmhl.verify.

    ASC-MHL convention: the manifest at <root>/ascmhl/<gen>.mhl describes the
    contents of <root>, so we verify the parent of the ascmhl/ folder
    (target.parent.parent). verify_package returns structured per-file outcomes
    and reports byte progress through on_bytes as each file is hashed — the same
    progress mechanism as the classic backend. _render_ascmhl_lines reproduces
    the per-file terminal text (failure lines always, OK lines when verbose).
    """
    package_dir = target.parent.parent
    report = ascmhl_verify.verify_package(package_dir, on_progress=on_bytes)

    output = "\n".join(_render_ascmhl_lines(report, verbose))
    _emit(emit, _ASCMHL_VERIFY_RESULTS, report.code, str(package_dir), output)

    # FileOutcome and FileResult share the same fields — a direct, parse-free map.
    file_results = [FileResult(path=e.path, status=e.status, detail=e.detail) for e in report.entries]
    mstatus = "ok" if report.code == 0 else "failed"
    mr = ManifestResult(
        manifest_path=target,
        manifest_status=mstatus,
        file_results=file_results,
    )
    return report.code, mr


def _ascmhl_verify_sizeonly(
    target: Path,
    verbose: bool,
    emit: "Callable[[StatusLine], None] | None" = None,
) -> "tuple[int, ManifestResult]":
    """
    Size-only verify an ASC-MHL package, gating on manifest integrity first.

    Two phases:

      1. Integrity gate — ascmhl_verify.integrity_check loads the history
         in-process, which verifies the chain file and every generation
         manifest's own hash without hashing any media. This catches a tampered
         or missing manifest/chain before we trust their contents.
      2. Size phase — ascmhl does not check file sizes, so we use our own
         'ascmhl/sizecheck.py': verify_ascmhl_sizes parses the manifests and compares
         each recorded <path size> against the file on disk, reading no file bytes.
    """
    package_dir = target.parent.parent

    # --- Phase 1: manifest-integrity gate (in-process) ---
    gate_code, gate_msg = ascmhl_verify.integrity_check(package_dir)
    if gate_code != 0:
        template, _sev = _ASCMHL_VERIFY_RESULTS.get(
            gate_code,
            ("🚨 ASC-MHL manifest integrity check failed: {target}", "error"),
        )
        _emit(emit, _ASCMHL_VERIFY_RESULTS, gate_code, str(package_dir), gate_msg)
        mr = ManifestResult(
            manifest_path=target,
            manifest_status="error",
            manifest_error=template.format(target=package_dir),
        )
        return gate_code, mr

    # --- Phase 2: size checks (manifests proven intact above) ---
    try:
        size_results = verify_ascmhl_sizes(target)
    except (etree.XMLSyntaxError, OSError):
        msg = f"🚨 Malformed XML: {package_dir} cannot be parsed."
        # One-off error-severity status (red), matching the previous log_error call.
        _emit(emit, {20: ("🚨 Malformed XML: {target} cannot be parsed.", "error")}, 20, str(package_dir), "")
        mr = ManifestResult(manifest_path=target, manifest_status="error", manifest_error=msg)
        return 20, mr

    # Translate to FileResult, flagging every OK entry as size-only so the report
    # summary reads "VERIFIED (SIZE-ONLY CHECKS)". The OK path carries its size in
    # the displayed path, matching the output from simple-mhl: "<path>  size: <n>" form.
    file_results: list[FileResult] = []
    out_lines: list[str] = []
    for r in size_results:
        if r.status == "ok":
            file_results.append(FileResult(path=f"{r.path}  {r.detail}", status="ok", size_only=True))
            if verbose:
                out_lines.append(f"[OK] {r.path}  {r.detail}")
        elif r.status == "missing":
            file_results.append(FileResult(path=r.path, status="missing"))
            out_lines.append(f"[ERROR] missing file: {r.path}")
        else:  # mismatch — detail is "size mismatch: …", "no size recorded", or "blocked …"
            file_results.append(FileResult(path=r.path, status="mismatch", detail=r.detail))
            if ": " in r.detail:
                label, paren = r.detail.split(": ", 1)
                out_lines.append(f"[ERROR] {label}: {r.path}")
                if verbose:
                    out_lines.append(f"        ({paren})")
            else:
                out_lines.append(f"[ERROR] {r.detail}: {r.path}")

    code = 0 if all(fr.status == "ok" for fr in file_results) else 10
    _emit(emit, _ASCMHL_VERIFY_RESULTS, code, str(package_dir), "\n".join(out_lines))

    mr = ManifestResult(
        manifest_path=target,
        manifest_status="ok" if code == 0 else "failed",
        file_results=file_results,
    )
    return code, mr


# -----------------------------------------------------------------------------
# Filesystem walking
# -----------------------------------------------------------------------------


def find_mhl_files(root: Path) -> Iterator[Path]:
    """
    Yield every .mhl file under `root`, case-insensitively, skipping
    macOS resource forks (filenames starting with '._').

    rglob's pattern syntax with character classes is the only portable way
    to do case-insensitive matching in pathlib without a fnmatch fallback.
    """
    for p in root.rglob("*.[mM][hH][lL]"):
        if not p.name.startswith("._"):
            yield p


def _select_mhl_files(root: Path) -> list[Path]:
    """
    Return a sorted list of MHL files to verify, deduplicating ASC-MHL
    packages (one MHL per package even if multiple .mhl files exist).

    An ASC-MHL package is identified by its `ascmhl/` folder. When that
    folder contains multiple manifests (one per generation, e.g. 0001.mhl,
    0002.mhl), running verify on any of them verifies the whole package,
    so we pick the lexicographically last one (latest generation) per
    package and skip the rest.

    Implementation: we iterate in sorted order and track the chosen manifest
    per package root in a dict. Because later entries in sorted order are
    lexicographically greater, the final value in the dict is always the
    latest generation — no list rebuild needed.
    """
    # Maps package_root -> the latest manifest seen so far for that package.
    # For classic MHL files (not inside an ascmhl/ folder) we use the file
    # path itself as its own key so they pass through unchanged.
    latest: dict[Path, Path] = {}

    for f in sorted(find_mhl_files(root)):
        key = f.parent.parent if f.parent.name == "ascmhl" else f  # ascmhl: pkg root; classic mhl: file itself
        latest[key] = f  # sorted order → last write wins

    # Re-sort the values to preserve the original output order (dict insertion
    # order is sorted-key order here, but an explicit sort is clearer).
    return sorted(latest.values())


# -----------------------------------------------------------------------------
# Progress bar helpers
# -----------------------------------------------------------------------------

# Hash element local-names simple-mhl can recompute (mirrors ALGO_MAP keys in
# simple_mhl). An entry whose only hash child is <null> — or which records no
# computable hash — is verified by size/existence alone and reads zero bytes,
# so its <size> must not weight the byte-based progress total.
_COMPUTABLE_HASH_TAGS = frozenset({"md5", "sha1", "xxhash", "xxh64", "xxhash64", "xxhash64be"})


def _mhl_total_bytes(mhl_file: Path) -> int:
    """
    Sum the <size> of every recomputable-hash entry in a classic MHL
    manifest to get the byte weight of the files verify will actually read.

    Used to weight progress-bar units by actual data volume rather than
    manifest count, giving a more accurate ETA when manifests vary wildly
    in size (e.g. 500 GB camera originals vs 2 GB proxies).

    A <null> (size-only / existence-only) entry is verified with a single
    stat() and reads zero bytes, so its <size> is excluded — counting it would
    surge the bar ahead of real hashing progress.
    """

    try:
        tree = etree.parse(str(mhl_file))
    except (OSError, etree.XMLSyntaxError):
        return 0
    total = 0
    for h in tree.iterfind(".//{*}hash"):
        size_el = h.find("{*}size")
        if size_el is None or not size_el.text or not size_el.text.strip().isdecimal():
            continue
        # Only count entries verify reads bytes for (skip <null>-only / no-hash entries).
        if any(
            isinstance(c.tag, str)
            and (c.tag.rpartition("}")[2] if "}" in c.tag else c.tag).lower() in _COMPUTABLE_HASH_TAGS
            for c in h
        ):
            total += int(size_el.text)
    return total


def _ascmhl_total_bytes(latest_mhl: Path) -> int:
    """
    Sum the ``size`` attributes on ``<path>`` elements across every .mhl
    generation file in an ASC-MHL package, counting each file path only once.

    Per the ASC-MHL 2.0 schema (ASCMHL.xsd), file sizes are stored as an
    attribute of the ``<path>`` element inside each ``<hash>`` record::

        <hash>
          <path size="1234567">relative/path/to/clip.mov</path>
          …
        </hash>

    ``latest_mhl`` is the lexicographically last generation file chosen by
    ``_select_mhl_files`` (e.g. ``ascmhl/0003.mhl``).  Because each
    generation only records *new or changed* files, summing only the latest
    generation would undercount the full corpus.  We therefore parse all
    ``.mhl`` files in the same ``ascmhl/`` directory in filename order
    (which matches the ``sequencenr`` order in ``ascmhl_chain.xml``).

    A verification pass re-records every file with ``action="verified"`` at
    the same size, so naively summing all generations double- (or triple-)
    counts files that appear in multiple passes.  We deduplicate by relative
    path: the first generation to record a path wins its size; later
    occurrences of the same path are skipped.
    """

    ascmhl_dir = latest_mhl.parent  # the ascmhl/ folder
    seen: set[str] = set()
    total = 0
    for mhl_path in sorted(ascmhl_dir.glob("*.mhl")):
        try:
            tree = etree.parse(str(mhl_path))
            for el in tree.iterfind(".//{*}path"):
                rel = (el.text or "").strip()
                if not rel or rel in seen:
                    continue
                size_str = el.get("size", "")
                if size_str.strip().isdecimal():
                    seen.add(rel)
                    total += int(size_str)
        except (OSError, ValueError, etree.XMLSyntaxError):
            pass  # skip unreadable generation files; others still count
    return total


def _manifest_weights(mhl_files: "list[Path]", size_only: bool) -> "dict[Path, int]":
    """Per-manifest progress-bar weights: byte volume normally, count under -S.

    Size-only reads no file bytes (one stat() per entry), so byte weights are
    meaningless — every manifest finishes near-instantly. Weighting each manifest
    equally then makes the bar track manifest count instead of a byte total that
    would jump straight to full.
    """
    if size_only:
        return dict.fromkeys(mhl_files, 1)
    return {f: (_ascmhl_total_bytes(f) if "ascmhl" in f.parts else _mhl_total_bytes(f)) for f in mhl_files}
