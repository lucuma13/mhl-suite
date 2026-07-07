"""
The data model (FileResult / ManifestResult) and the writer for mhlver's
`--report` log.

Kept separate from the terminal-output path so the streaming log behaviour isn't
affected. Used only by mhlver today; it lives alongside hashing and
verify_results as the cross-dialect layer that survives the ASC-MHL absorption.
"""

import getpass
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TextIO

from mhl_suite import __version__
from mhl_suite.osutils import friendly_hostname

# -----------------------------------------------------------------------------
# Report data model
# -----------------------------------------------------------------------------
# FileResult and ManifestResult are populated from each backend's structured
# result when --report is requested. They are kept entirely separate from the
# terminal output path so that the existing streaming log behaviour is not
# affected.
#
# status values:
#   * "ok"        — file verified successfully
#   * "missing"   — file not found on disk
#   * "mismatch"  — hash (or size) does not match the manifest
#   * "new".      — file found on disk but not recorded in ASC-MHL history
#   * "error"     — any other per-file problem (traversal block, bad algo, etc.)
#
# manifest_status values:
#   * "ok"        — all files verified
#   * "failed"    — one or more per-file failures
#   * "error"     — manifest-level failure (malformed XML, etc.)


@dataclass
class FileResult:
    """Outcome for a single file entry within a manifest."""

    path: str  # relative path as recorded in the manifest
    status: str  # "ok" | "missing" | "mismatch" | "new" | "error"
    detail: str = ""  # extra info: mismatch hashes, error reason, etc.
    size_only: bool = False  # size-only check (<null> tag), no hash checked
    existence_only: bool = False  # existence-only check <null> tag with no recorded <size>


@dataclass
class ManifestResult:
    """Collected results for one manifest file."""

    manifest_path: Path
    manifest_status: str  # "ok" | "failed" | "error"
    manifest_error: str = ""  # set when manifest_status == "error"
    file_results: list[FileResult] = field(default_factory=list)

    # Convenience counts — computed once after collection is complete.
    @property
    def n_ok(self) -> int:
        return sum(1 for r in self.file_results if r.status == "ok")

    @property
    def n_missing(self) -> int:
        return sum(1 for r in self.file_results if r.status == "missing")

    @property
    def n_mismatch(self) -> int:
        return sum(1 for r in self.file_results if r.status == "mismatch")

    @property
    def n_new(self) -> int:
        return sum(1 for r in self.file_results if r.status == "new")

    @property
    def n_error(self) -> int:
        return sum(1 for r in self.file_results if r.status == "error")

    @property
    def n_size_only(self) -> int:
        return sum(1 for r in self.file_results if r.status == "ok" and r.size_only)

    @property
    def n_existence_only(self) -> int:
        return sum(1 for r in self.file_results if r.status == "ok" and r.existence_only)

    @property
    def n_files(self) -> int:
        return len(self.file_results)


# -----------------------------------------------------------------------------
# Report file
# -----------------------------------------------------------------------------


@contextmanager
def _open_report(src: Path) -> Iterator[tuple[TextIO, Path]]:
    """
    Open a timestamped report log next to `src` and yield (file, path).

    Context-manager form ensures the file is always closed and we don't have to
    thread try/finally through the main flow. The path is yielded so we can echo
    it on completion ("report saved to: ...").

    Unlike the old streaming approach, this file handle is only used by
    _render_report() which writes the complete structured report at the end of
    the verification run. Nothing is written here at open time.
    """
    report_dir = src if src.is_dir() else src.parent
    timestamp = datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
    report_path = report_dir / f"mhlver_report_{src.name}_{timestamp}.log"
    with open(report_path, "w", encoding="utf-8") as fh:
        yield fh, report_path


_W = 119  # total report width (matches the === / --- separator length)
_SEP_HEAVY = "=" * _W
_SEP_LIGHT = "-" * _W


def _summary_line(
    *,
    passed: bool,
    n_files: int,
    n_ok: int,
    n_missing: int,
    n_mismatch: int,
    n_error: int,
    n_new: int,
    n_size_only: int = 0,
    n_existence_only: int = 0,
    warn_weak: bool = False,
    n_manifests: int | None = None,
) -> str:
    """
    Build the ' | '-joined verdict line shared by the global summary and each
    per-manifest sub-summary. Pass n_manifests=None to omit the manifest count
    (per-manifest lines don't repeat it).

    When the run passed but relied on weak (non-hash) checks — size-only or
    existence-only <null> entries — the verdict names which kinds were used and,
    when warn_weak is set, is downgraded to ⚠️ VERIFIED WITH WARNINGS. The two
    kinds are labelled distinctly: an existence-only entry checked neither hash
    nor size, so it must not read as a SIZE-ONLY check."""
    n_weak = n_size_only + n_existence_only
    if not passed:
        verdict = "❌ FAILED"
    elif n_weak:
        head = "⚠️ VERIFIED WITH WARNINGS" if warn_weak else "✅ VERIFIED"
        kinds = []
        if n_size_only:
            kinds.append("SIZE-ONLY")
        if n_existence_only:
            kinds.append("EXISTENCE-ONLY")
        prefix = "SOME " if n_weak != n_ok else ""
        verdict = f"{head} ({prefix}{' AND '.join(kinds)} CHECKS)"
    else:
        verdict = "✅ VERIFIED"
    parts = [verdict]
    if n_manifests is not None:
        parts.append(f"{n_manifests} {'manifest' if n_manifests == 1 else 'manifests'}")
    parts.append(f"{n_files} {'file' if n_files == 1 else 'files'}")
    parts.append(f"{n_ok} verified")
    if n_missing:
        parts.append(f"{n_missing} missing")
    if n_mismatch:
        parts.append(f"{n_mismatch} mismatch")
    if n_error:
        parts.append(f"{n_error} error")
    if n_new:
        parts.append(f"{n_new} new (untracked)")
    return " | ".join(parts)


def _render_report(
    fh: TextIO,
    src: Path,
    started_at: datetime,
    finished_at: datetime,
    manifest_results: list[ManifestResult],
    exit_status: int,
) -> None:
    """
    Write the structured verification report to fh.
    """

    def line(s: str = "") -> None:
        fh.write(s + "\n")

    # -- Header ---------------------------------------------------------------
    line(_SEP_HEAVY)
    line("MHL Verification Report")
    line(_SEP_HEAVY)
    line()

    host = friendly_hostname()
    try:
        operator = getpass.getuser()
    except (OSError, KeyError, ImportError):
        operator = "unknown"

    fmt = "%Y-%m-%d %H:%M:%S %Z"
    line(f"Source:     {src}")
    line(f"Tool:       mhlver {__version__}")
    line(f"User:       {operator}")
    line(f"Host:       {host}")
    line(f"Started:    {started_at.astimezone().strftime(fmt)}")
    line(f"Finished:   {finished_at.astimezone().strftime(fmt)}")
    line()

    # Aggregate counts across all manifests.
    n_manifests = len(manifest_results)
    n_files = sum(mr.n_files for mr in manifest_results)
    n_ok = sum(mr.n_ok for mr in manifest_results)
    n_missing = sum(mr.n_missing for mr in manifest_results)
    n_mismatch = sum(mr.n_mismatch for mr in manifest_results)
    n_new = sum(mr.n_new for mr in manifest_results)
    n_error = sum(mr.n_error for mr in manifest_results)
    n_size_only = sum(mr.n_size_only for mr in manifest_results)
    n_existence_only = sum(mr.n_existence_only for mr in manifest_results)

    # -- Summary --------------------------------------------------------------
    line("Summary")
    line(_SEP_LIGHT)
    line(
        _summary_line(
            passed=exit_status == 0,
            n_manifests=n_manifests,
            n_files=n_files,
            n_ok=n_ok,
            n_missing=n_missing,
            n_mismatch=n_mismatch,
            n_error=n_error,
            n_new=n_new,
            n_size_only=n_size_only,
            n_existence_only=n_existence_only,
            warn_weak=True,
        )
    )
    line()

    # -- Issues ---------------------------------------------------------------
    # Everything that isn't a clean OK, pulled to the top across all manifests
    # Omitted entirely when there's nothing to show.
    issue_lines: list[str] = []
    for mr in manifest_results:
        if mr.manifest_status == "error":
            issue_lines.append(f"🚨 {mr.manifest_path}: {mr.manifest_error or 'manifest-level error'}")
            continue
        issue_lines.extend(_format_file_result(fr, indent="") for fr in mr.file_results if fr.status != "ok")

    if issue_lines:
        line("Issues")
        line(_SEP_LIGHT)
        for s in issue_lines:
            line(s)
        line()

    # -- Manifests ------------------------------------------------------------
    if manifest_results:
        line("Manifest" if n_manifests == 1 else "Manifests")
        line(_SEP_LIGHT)

    for mr in manifest_results:
        # Manifest header line — show the .mhl path (for classic MHL) or the
        # asc-mhl directory (for ASC-MHL)
        line(f"📄 {mr.manifest_path}")

        if mr.manifest_status == "error":
            line(f"    ✗ {mr.manifest_error or 'manifest-level error'}")
            continue

        # Per-manifest sub-summary — same fields as the global verdict minus the
        # manifest count. New/untracked is a warning, not a verification
        # failure, so it doesn't flip the manifest's PASSED/FAILED state.
        line(
            _summary_line(
                passed=mr.n_missing == 0 and mr.n_mismatch == 0 and mr.n_error == 0,
                n_files=mr.n_files,
                n_ok=mr.n_ok,
                n_missing=mr.n_missing,
                n_mismatch=mr.n_mismatch,
                n_error=mr.n_error,
                n_new=mr.n_new,
                n_size_only=mr.n_size_only,
                n_existence_only=mr.n_existence_only,
            )
        )

        for fr in mr.file_results:
            line(_format_file_result(fr))
        line()

    line(_SEP_HEAVY)


def _format_file_result(fr: "FileResult", indent: str = "    ") -> str:
    """
    Return the report line(s) for a single FileResult (without trailing
    newline).

    `indent` is the leading whitespace for the primary line; the Details section
    indents under its manifest header (4 spaces) while the Issues section sits
    at column 0. Continuation (detail) lines are indented `indent` + 3 spaces.

    Mismatch entries with detail render across two lines, using the label
    embedded in the detail string (e.g. "hash mismatch", "size mismatch"):

        ❌ hash mismatch: path/to/file.mxf
           (calc xxh64: abc123 | stored xxh64: def456)

        ❌ size mismatch: path/to/file.mxf
           (calc size: 122 | stored size: 4170)
    """
    cont = indent + "   "  # continuation/detail line indent
    if fr.status == "ok":
        return f"{indent}✓ {fr.path}"
    if fr.status == "missing":
        return f"{indent}❌ missing: {fr.path}"
    if fr.status == "mismatch":
        if ": " in fr.detail:
            label, paren_content = fr.detail.split(": ", 1)
            return f"{indent}❌ {label}: {fr.path}\n{cont}({paren_content})"
        # Non-verbose failsafe: detail is just "hash mismatch" or "size mismatch".
        return f"{indent}❌ {fr.detail}: {fr.path}"
    if fr.status == "new":
        return f"{indent}⚠️ new (untracked): {fr.path}"
    # "error"
    if fr.detail:
        return f"{indent}🚨 error: {fr.path}\n{cont}({fr.detail})"
    return f"{indent}🚨 error: {fr.path}"
