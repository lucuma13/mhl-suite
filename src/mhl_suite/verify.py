"""
The shared verification core: what a verify run consumes, computes, and shows.

Three layers that always change together, in one module (the exit-code
vocabulary itself lives in mhl_suite._exit_codes — it is suite-wide, not
verify-specific):

  * The semantic result model — Status/ErrorKind, HashComparison, VerifyEntry,
    VerifyReport. Entries record *what was checked and what was found*, never
    terminal text.
  * verify_records() — the one engine both dialects drive. A dialect module
    (classic_verify's manifest parser, ascmhl_history's history loader) reduces
    its manifest to FileRecords — path, recorded size, recorded hashes with
    their matching rules — and the engine does everything the dialects have in
    common: resolve each path against the disk (traversal jail + Unicode-
    normalization reconciliation), pre-check sizes, hash through the adaptive
    parallel controller, compare, classify. The dialects differ in what a
    manifest *says* (generations, renames, ignore rules), not in what verifying
    *means* — that policy stays in the dialect modules, which also derive their
    own exit codes from the entries.
  * The renderer — the only place [OK]/[ERROR] terminal lines are built.
    mhl_suite.report reuses failure_label/failure_paren so the --report file
    and the terminal cannot drift. Line order (render_verify_lines): manifest-
    level notices first, then [OK] lines (verbose only, entry order), then all
    missing files, then every other failure; verbose adds each failure's
    indented detail continuation.

Never prints, never exits; per-file read failures become ERROR entries rather
than tearing down the run, and nothing here maps to "malformed XML" — parse
errors belong to the dialect parsers.
"""

import os
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING

from mhl_suite import hashing
from mhl_suite.algorithms import HashCheck
from mhl_suite.osutils import resolve_on_disk

if TYPE_CHECKING:
    from collections.abc import Callable


# -----------------------------------------------------------------------------
# The semantic result model
# -----------------------------------------------------------------------------


class Status(StrEnum):
    """Per-file verification outcome category."""

    OK = "ok"  # verified (by hash, or by size/existence for hash-less entries)
    MISSING = "missing"  # file not found on disk
    MISMATCH = "mismatch"  # a hash or size differs from the manifest
    ERROR = "error"  # any other per-file failure (see ErrorKind)
    NEW = "new"  # on disk but not recorded (ASC-MHL history check)


class ErrorKind(StrEnum):
    """Category of a Status.ERROR entry; `VerifyEntry.detail` carries kind-specific text."""

    IO = "io"  # open/read failed; detail is the OS error text
    TRAVERSAL = "traversal"  # recorded path escapes the manifest root
    MALFORMED_SIZE = "malformed-size"  # <size> text is not a decimal integer
    NO_SIZE = "no-size"  # size-only check requested but no size recorded
    HASH_NOT_STORED = "hash-not-stored"  # requested format(s) absent; detail lists them
    NO_SUPPORTED_HASH = "no-supported-hash"  # nothing recognised recorded at all
    UNUSABLE_HASH = "unusable-hash"  # entries exist but none may be used (ASC-MHL: not original/verified)


@dataclass
class HashComparison:
    """One recorded hash checked against the recomputed digest."""

    tag: str  # format name as recorded (classic element name / ASC format)
    expected: str  # stored digest text
    computed: str  # recomputed digest (hex, or a C4 ID)
    ok: bool  # accepted by the format's matching rule


@dataclass
class VerifyEntry:
    """
    Outcome for a single recorded file, in semantic fields only.

    `hashes` holds every comparison made (one per checked format; empty for
    size/existence checks). `recorded_size`/`actual_size` are filled whenever
    the manifest stored a size and the file was stat-able; a difference between
    them is a size mismatch. `size_only`/`existence_only` flag entries whose OK
    was established without any hash (a classic <null> entry, a size-only run,
    or an ASC-MHL record without the optional size attribute).

    For Status.ERROR, `error` categorises the failure and `detail` carries the
    kind-specific text (OS error message, the missing format names, …).
    """

    path: str
    status: Status
    hashes: list[HashComparison] = field(default_factory=list)
    recorded_size: "int | None" = None
    actual_size: "int | None" = None
    size_only: bool = False
    existence_only: bool = False
    error: "ErrorKind | None" = None
    detail: str = ""

    @property
    def hash_mismatch(self) -> bool:
        """True when any recorded hash failed its comparison."""
        return any(not c.ok for c in self.hashes)

    @property
    def size_mismatch(self) -> bool:
        """True when a recorded size disagrees with the file on disk."""
        return (
            self.recorded_size is not None and self.actual_size is not None and self.recorded_size != self.actual_size
        )


@dataclass
class VerifyReport:
    """
    The full outcome of verifying one manifest (either dialect).

    `code` is a value from _exit_codes.ExitCode — harmonised across both
    dialects, so a given integer means one thing everywhere. It is derived in
    one place per dialect from the entries (plus manifest-level conditions such
    as a broken ASC-MHL chain) and mapped to a process exit only in cli/.

    `notices` are manifest-level lines shown regardless of verbosity (e.g.
    "Verified with size-only checks …", or an ASC-MHL history-integrity
    message). `size_only_mode` records that the run checked sizes rather than
    hashes, so renderers can distinguish a size-only *run* from a size-only
    *entry* (a classic <null> record inside a hash run).
    """

    entries: list[VerifyEntry] = field(default_factory=list)
    code: int = 0
    malformed: bool = False
    notices: list[str] = field(default_factory=list)
    size_only_mode: bool = False

    @property
    def ok(self) -> bool:
        """True when the manifest verified cleanly (exit code 0)."""
        return self.code == 0


# -----------------------------------------------------------------------------
# The engine
# -----------------------------------------------------------------------------

# `-a all` sentinel: verify every recorded hash per entry rather than a single
# fixed format. "all" is reserved — no manifest tag can collide with it.
VERIFY_ALL = "all"


@dataclass
class FileRecord:
    """
    One recorded file, reduced to what verification needs.

    `path` is the canonical forward-slash relative path as recorded. `checks`
    holds the recognised, computable stored hashes (built by the dialect's
    algorithms.*_check helpers) — an unrecognised format never produces a
    check, exactly as if it were absent. `has_null` marks a classic <null>
    element (no digest recorded: size/existence is the whole check).

    A parse-level defect the parser wants reported per-file (e.g. a malformed
    <size> value) travels as `defect`/`defect_detail` and short-circuits the
    entry to an ERROR outcome.
    """

    path: str
    checks: list[HashCheck] = field(default_factory=list)
    recorded_size: "int | None" = None
    has_null: bool = False
    defect: "ErrorKind | None" = None
    defect_detail: str = ""


def _select_checks(
    record: FileRecord, selection: "str | list[str] | None"
) -> "tuple[list[HashCheck], VerifyEntry | None]":
    """
    Pick which of a record's checks to verify, or the entry that settles the
    record without hashing.

    `selection` is None (the single fastest recorded hash), VERIFY_ALL (every
    recorded hash), or a list of canonical tags (exactly those formats). For a
    list, requested order is irrelevant — matching checks keep manifest
    document order, so `-a md5,sha1` and `-a sha1,md5` verify identically.

    Returns (checks, entry): a non-empty check list to hash and None, or an
    empty list with the settling entry — the hash-not-stored / no-supported-
    hash error. A <null>-only record returns ([], None): the caller settles it
    by size/existence.
    """
    if isinstance(selection, list):
        wanted = set(selection)
        chosen = [c for c in record.checks if c.canonical in wanted]
        missing = sorted(wanted - {c.canonical for c in chosen})
        if missing:
            return [], VerifyEntry(
                path=record.path,
                status=Status.ERROR,
                error=ErrorKind.HASH_NOT_STORED,
                detail=", ".join(missing),
            )
        return chosen, None
    if not record.checks:
        if record.has_null:
            return [], None  # size/existence is the whole check
        return [], VerifyEntry(path=record.path, status=Status.ERROR, error=ErrorKind.NO_SUPPORTED_HASH)
    if selection == VERIFY_ALL:
        return list(record.checks), None
    return [min(record.checks, key=lambda c: c.rank)], None


def _null_entry(record: FileRecord, actual_size: "int | None") -> VerifyEntry:
    """The OK entry for a hash-less record: size-only when a size was recorded, existence-only otherwise."""
    if record.recorded_size is not None:
        return VerifyEntry(
            path=record.path,
            status=Status.OK,
            size_only=True,
            recorded_size=record.recorded_size,
            actual_size=actual_size,
        )
    return VerifyEntry(path=record.path, status=Status.OK, existence_only=True)


def _hash_job(
    record: FileRecord,
    candidate: str,
    checks: "list[HashCheck]",
    actual_size: "int | None",
    on_progress: "Callable[[int], None] | None",
) -> "hashing.HashJob[VerifyEntry]":
    """
    Build the controller job that hashes `candidate` once (read-once across all
    chosen formats) and returns the compared entry. Per-file ValueError/OSError
    becomes an IO-error outcome so a thread-pool worker reports rather than
    tearing down the whole verify.
    """

    def job(mon: "Callable[[int], None]") -> VerifyEntry:
        try:
            digests = hashing.get_hashes(
                candidate, [c.algorithm.factory for c in checks], on_progress=hashing.chain_progress(on_progress, mon)
            )
        except (ValueError, OSError) as exc:
            return VerifyEntry(path=record.path, status=Status.ERROR, error=ErrorKind.IO, detail=str(exc))
        comparisons = [
            HashComparison(tag=c.tag, expected=c.expected, computed=d, ok=c.matches(d))
            for c, d in zip(checks, digests, strict=True)
        ]
        status = Status.OK if all(c.ok for c in comparisons) else Status.MISMATCH
        return VerifyEntry(
            path=record.path,
            status=status,
            hashes=comparisons,
            recorded_size=record.recorded_size,
            actual_size=actual_size,
        )

    return job


def verify_records(  # noqa: C901 — flat per-record classification ladder, not nested complexity
    base_dir: "str | os.PathLike[str]",
    records: "list[FileRecord]",
    *,
    selection: "str | list[str] | None" = None,
    size_only: bool = False,
    missing_size_is_error: bool = True,
    on_progress: "Callable[[int], None] | None" = None,
) -> list[VerifyEntry]:
    """
    Verify `records` against the tree rooted at `base_dir` and return one
    VerifyEntry per record, in record order.

    `selection` picks which recorded hash(es) to check (see _select_checks);
    callers validate CLI names into canonical tags before reaching here.
    `size_only` skips hashing and checks recorded sizes with one stat() per
    entry; `missing_size_is_error` is the one dialect policy knob — classic
    MHL's schema makes <size> mandatory, so its absence in a size-only run is
    an error, while ASC-MHL's size attribute is optional and its absence means
    the file is existence-checked only.

    `on_progress`, if given, is called with each chunk's byte count as files
    are hashed (per-chunk, not per-file); it may fire from a worker thread
    under the adaptive controller, so it must be thread-safe.

    Every recorded size that is present is compared before hashing, for both
    dialects: a size difference already proves modification, reads zero bytes,
    and names the actual difference rather than a bare hash mismatch.
    """
    base = os.path.abspath(os.fspath(base_dir))
    # Trailing separator avoids prefix-collision: '/foo' matches '/foo/bar' but
    # not '/foobar'.
    base_with_sep = base + os.sep

    # Per-entry outcomes in record order. Records that reach the hash phase get
    # a None placeholder filled by the parallel phase below.
    results: list[VerifyEntry | None] = []
    deferred_slots: list[int] = []
    deferred_paths: list[str] = []
    deferred_sizes: list[int] = []
    deferred_jobs: list[hashing.HashJob[VerifyEntry]] = []
    calibrate_factories: list | None = None

    # Per-call cache of directory listings ({dir: {NFC(name): real_name}}),
    # populated lazily by resolve_on_disk when a literal path lookup misses.
    dir_index: dict[str, dict[str, str]] = {}

    for record in records:
        if record.defect is not None:
            results.append(
                VerifyEntry(path=record.path, status=Status.ERROR, error=record.defect, detail=record.defect_detail)
            )
            continue

        # --- Path traversal guard -----------------------------------------
        # Manifests store forward-slash paths; os.path.join/normpath accept
        # them and normalise for the on-disk lookup.
        jailed = os.path.normpath(os.path.join(base, record.path))
        if jailed != base and not jailed.startswith(base_with_sep):
            results.append(VerifyEntry(path=record.path, status=Status.ERROR, error=ErrorKind.TRAVERSAL))
            continue

        # --- Resolve to the real on-disk path ------------------------------
        candidate = resolve_on_disk(base, os.path.relpath(jailed, base), dir_index)
        if candidate is None:
            results.append(VerifyEntry(path=record.path, status=Status.MISSING))
            continue

        # --- Size pre-check -------------------------------------------------
        actual_size: int | None
        try:
            actual_size = os.path.getsize(candidate)
        except OSError:
            actual_size = None
        if record.recorded_size is not None:
            if actual_size is None:
                # Vanished between resolution and getsize().
                results.append(VerifyEntry(path=record.path, status=Status.MISSING))
                continue
            if actual_size != record.recorded_size:
                results.append(
                    VerifyEntry(
                        path=record.path,
                        status=Status.MISMATCH,
                        recorded_size=record.recorded_size,
                        actual_size=actual_size,
                        size_only=size_only,
                    )
                )
                continue

        # --- Size-only mode ---------------------------------------------------
        if size_only:
            if record.recorded_size is None and missing_size_is_error:
                results.append(VerifyEntry(path=record.path, status=Status.ERROR, error=ErrorKind.NO_SIZE))
            else:
                results.append(
                    VerifyEntry(
                        path=record.path,
                        status=Status.OK,
                        size_only=True,
                        recorded_size=record.recorded_size,
                        actual_size=actual_size if record.recorded_size is not None else None,
                    )
                )
            continue

        # --- Hash selection ---------------------------------------------------
        checks, settled = _select_checks(record, selection)
        if settled is not None:
            results.append(settled)
            continue
        if not checks:
            results.append(_null_entry(record, actual_size))
            continue

        # --- Defer to the parallel hash phase ---------------------------------
        deferred_slots.append(len(results))
        results.append(None)
        deferred_paths.append(candidate)
        deferred_sizes.append(actual_size if actual_size is not None else 0)
        deferred_jobs.append(_hash_job(record, candidate, checks, actual_size, on_progress))
        if calibrate_factories is None:
            # Calibrate the storage probe against the first deferred job's
            # format set.
            calibrate_factories = [c.algorithm.factory for c in checks]

    # --- Parallel hash phase ---------------------------------------------------
    # hashing.* resolved through the module object so test monkeypatches bite.
    if calibrate_factories is not None:
        factories = calibrate_factories
        hashed = hashing.run_hash_jobs(
            deferred_paths, deferred_sizes, deferred_jobs, lambda: hashing.calibrate_hash_bandwidth(factories)
        )
        for slot, outcome in zip(deferred_slots, hashed, strict=True):
            results[slot] = outcome

    return [r for r in results if r is not None]


# -----------------------------------------------------------------------------
# The renderer
# -----------------------------------------------------------------------------

# Indent for the verbose "(calc … | stored …)" continuation lines.
_DETAIL_INDENT = "        "


def failure_label(entry: VerifyEntry) -> str:
    """
    Short category label for a non-OK entry: "hash mismatch", "size mismatch",
    "missing file", "new file found", or the error kind's label. Shared with
    mhl_suite.report so both outputs name failures identically.
    """
    if entry.status == Status.MISSING:
        return "missing file"
    if entry.status == Status.NEW:
        return "new file found"
    if entry.status == Status.MISMATCH:
        return "hash mismatch" if entry.hash_mismatch else "size mismatch"
    # Status.ERROR
    if entry.error == ErrorKind.IO:
        return "cannot verify"
    if entry.error == ErrorKind.TRAVERSAL:
        return "blocked traversal attempt"
    if entry.error == ErrorKind.MALFORMED_SIZE:
        return "malformed size field"
    if entry.error == ErrorKind.NO_SIZE:
        return "no size recorded"
    if entry.error == ErrorKind.HASH_NOT_STORED:
        label = "hash" if "," not in entry.detail else "hashes"
        return f"requested {label} {entry.detail} not stored"
    if entry.error == ErrorKind.NO_SUPPORTED_HASH:
        return "no supported hash found"
    if entry.error == ErrorKind.UNUSABLE_HASH:
        return "no usable hash entry"
    return "error"


def failure_paren(entry: VerifyEntry) -> str:
    """
    The parenthetical comparison for a single-check mismatch, without brackets:
    "calc xxh64: … | stored xxh64: …" or "calc size: … | stored size: …".
    Empty when the entry has no single comparison to show (multi-hash
    mismatches render per-tag block lines instead; errors carry their text in
    `detail`).
    """
    if entry.status != Status.MISMATCH:
        return ""
    if entry.hash_mismatch:
        if len(entry.hashes) != 1:
            return ""
        c = entry.hashes[0]
        return f"calc {c.tag}: {c.computed} | stored {c.tag}: {c.expected}"
    return f"calc size: {entry.actual_size} | stored size: {entry.recorded_size}"


def _ok_line(entry: VerifyEntry, size_only_mode: bool) -> str:
    """The primary [OK] line for a verified entry."""
    if entry.existence_only:
        return f"[OK] {entry.path}  (existence-only check — no hash or size stored)"
    if entry.size_only:
        # actual_size is None when the record stored no size to compare (ASC-MHL's
        # size attribute is optional): the file's existence was the whole check.
        size = str(entry.actual_size) if entry.actual_size is not None else "not recorded"
        suffix = "" if size_only_mode else " (size-only check - no hash stored)"
        return f"[OK] {entry.path}  size: {size}{suffix}"
    shown = "  ".join(f"{c.tag}: {c.computed}" for c in entry.hashes)
    return f"[OK] {entry.path}  {shown}"


def status_line(entry: VerifyEntry, size_only_mode: bool = False) -> str:
    """The primary terminal line for any entry."""
    if entry.status == Status.OK:
        return _ok_line(entry, size_only_mode)
    label = failure_label(entry)
    if entry.status == Status.ERROR and entry.error == ErrorKind.IO:
        return f"[ERROR] cannot verify {entry.path}: {entry.detail}"
    if entry.status == Status.ERROR and entry.error == ErrorKind.NO_SIZE:
        return f"[ERROR] no size recorded: {entry.path} (try 'simple-mhl verify' for full hash verification)"
    return f"[ERROR] {label}: {entry.path}"


def detail_lines(entry: VerifyEntry) -> list[str]:
    """
    The verbose-only indented continuation for a failed entry: the single
    "(calc … | stored …)" parenthetical, or the per-tag block for a multi-hash
    (-a all) mismatch. Empty when there is nothing beyond the primary line.
    """
    if entry.status == Status.MISMATCH and entry.hash_mismatch and len(entry.hashes) > 1:
        return [
            f"{_DETAIL_INDENT}{c.tag} {'OK' if c.ok else 'MISMATCH'}: calc {c.computed} | stored {c.expected}"
            for c in entry.hashes
        ]
    paren = failure_paren(entry)
    return [f"{_DETAIL_INDENT}({paren})"] if paren else []


def render_verify_lines(report: VerifyReport, verbose: bool) -> list[str]:
    """
    Render a VerifyReport to the exact stdout lines the CLIs emit (see module
    docstring for the ordering contract).
    """
    out: list[str] = list(report.notices)
    if verbose:
        out.extend(status_line(e, report.size_only_mode) for e in report.entries if e.status == Status.OK)
    out.extend(status_line(e, report.size_only_mode) for e in report.entries if e.status == Status.MISSING)
    for e in report.entries:
        if e.status in (Status.MISMATCH, Status.ERROR, Status.NEW):
            out.append(status_line(e, report.size_only_mode))
            if verbose:
                out.extend(detail_lines(e))
    return out
