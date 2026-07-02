"""
ASC-MHL verification engine.

The in-process entry point mhlver drives. It mirrors classic_verify's contract: never prints, never sys.exit()s,
returns a structured report whose VerifyEntries mhlver maps straight onto its own report model — no stdout round-trip,
no regex parsing.

Hashing/parsing uses the reference `mhllib` for ASC-MHL, while the verify loop itself lives here so we can drive the
suite's adaptive parallel hasher (mhl_suite.hashing) and emit truthful per-file progress — neither of which the
library's own verify exposes.
"""

import os
import time
from dataclasses import dataclass
from functools import partial
from importlib.resources import files
from pathlib import Path
from typing import TYPE_CHECKING

import click
from ascmhl import errors
from ascmhl.commands import test_for_missing_files
from ascmhl.hasher import new_hasher_for_hash_type
from ascmhl.history import MHLHistory
from ascmhl.ignore import MHLIgnoreSpec
from ascmhl.traverse import post_order_lexicographic
from lxml import etree

from mhl_suite import hashing
from mhl_suite._exit_codes import ExitCode
from mhl_suite.osutils import resolve_on_disk
from mhl_suite.verify_results import VerifyEntry, VerifyReport

if TYPE_CHECKING:
    from collections.abc import Callable

    from ascmhl.hashlist import MHLMediaHash

# NOTE: we check only the first `original` hash entry per file (find_original_hash_entry_for_path), so a file recorded
# with several formats (the XSD allows one of each: c4/md5/sha1/xxh128/xxh3/xxh64) is verified on just one — there is no
# ASC equivalent of classic's `-a all` yet. A future multi-hash mode should arrive as verify_ascmhl(..., algorithm=...)
# mirroring classic_verify.verify_classic's shape (None / list of tags / "all").


def verify_ascmhl(
    root_path: "str | Path",
    *,
    size_only: bool = False,
    on_progress: "Callable[[int], None] | None" = None,
) -> VerifyReport:
    """
    Verify the ASC-MHL package rooted at `root_path` in-process.

    `root_path` is the directory the manifest describes (the parent of the `ascmhl/` folder). `size_only` checks
    recorded sizes against disk without hashing media (see _verify_sizes); `on_progress`, given, is called with each
    chunk's byte size as files are hashed, so a caller can drive a progress bar — the ASC-MHL counterpart to
    classic_verify.verify_classic(size_only=, on_progress=).

    Returns a verify_results.VerifyReport (same type as classic verify). `code` is the ASC-MHL exit code (see
    ascmhl.errors): 0 clean, 10 missing files, 11 hash mismatch, 20 single-file-not-found, 21 new files, 30/31/32/33
    history/chain/manifest problems — plus 13 for a size mismatch on the size-only path (a suite extension; ascmhl has
    no size check). Failure is signalled by `code`, never by an exception or process exit; `report.ok` (clean vs failed)
    and `report.code` (the precise category) give the result.
    """
    if size_only:
        return _verify_sizes(root_path)

    entries: list[VerifyEntry] = []
    try:
        _verify_entire_folder(str(root_path), entries, on_progress=on_progress)
        code = 0
    except click.ClickException as exc:
        # Every ascmhl failure mode is a click.ClickException subclass carrying an `exit_code` (see ascmhl.errors).
        # Anything else is a genuine bug and propagates.
        code = getattr(exc, "exit_code", 1)
    return VerifyReport(entries=entries, code=code)


def _verify_entire_folder(
    root_path: str,
    report: list[VerifyEntry],
    *,
    on_progress: "Callable[[int], None] | None" = None,
) -> None:
    """
    Hash every file recorded in the ASC-MHL history and compare to disk.

    A faithful reimplementation of ascmhl.commands.verify_entire_folder (file verify, no directory-hash / single-file /
    packing-list modes), split into two passes so the hashing runs through mhl_suite.hashing's adaptive parallel
    controller and fills `report` with structured VerifyEntries. Raises the same ascmhl.errors exceptions on failure
    (their exit_code drives verify_ascmhl's `code`); the library's logger is never touched, so the caller owns all
    output.
    """
    if not Path(root_path).is_absolute():
        root_path = str(Path.cwd() / root_path)

    existing_history = MHLHistory.load_from_path(root_path)
    if len(existing_history.hash_lists) == 0:
        raise errors.NoMHLHistoryException(root_path)

    # Collect everything we expect to find; discard each as we meet it on disk so what remains is the set of missing
    # files.
    not_found_paths = existing_history.set_of_file_paths()
    renamed_files = existing_history.renamed_path_with_previous_path()
    not_found_paths = {p if renamed_files.get(p, None) is None else renamed_files[p] for p in not_found_paths}

    ignore_spec = MHLIgnoreSpec(existing_history.latest_ignore_patterns())

    deferred = _collect_deferred(existing_history, root_path, ignore_spec, not_found_paths, report)
    num_failed_verifications = _hash_and_compare(deferred, report, on_progress)

    # Record still-missing files (mirroring test_for_missing_files' ignore filter), then let it raise the
    # completeness-check exception (exit 10) if any remain.
    ignore_path_spec = ignore_spec.get_path_spec()
    for path in not_found_paths:
        if ignore_path_spec.match_file(path):
            continue
        rel = Path(path).relative_to(root_path).as_posix()
        report.append(VerifyEntry(path=rel, status="missing", line=f"[ERROR] missing file: {rel}"))

    # Exception precedence mirrors ascmhl.commands.verify_entire_folder exactly: a hash mismatch (11) trumps new files
    # (21), which trump "no file found at all" (20), which trumps a missing-file completeness failure (10).
    exception = test_for_missing_files(not_found_paths, root_path, ignore_spec)
    if not deferred:
        exception = errors.SingleFileNotFoundException()
    if any(e.status == "new" for e in report):
        exception = errors.NewFilesFoundException()
    if num_failed_verifications > 0:
        exception = errors.VerificationFailedException()
    if exception:
        raise exception


def _collect_deferred(
    existing_history: MHLHistory,
    root_path: str,
    ignore_spec: MHLIgnoreSpec,
    not_found_paths: set,
    report: list[VerifyEntry],
) -> list[tuple[str, str, object, int]]:
    """
    PASS 1 — traverse the tree, resolve each file against the history.

    New files (no recorded hash) read no bytes and are reported inline; files needing a hash are returned as
    `(file_path, rel_path, original_hash_entry, size)` tuples in post-order-lexicographic traversal order so PASS
    2's emit order matches the library's inline order. `not_found_paths` is discarded in place as files are met on disk,
    leaving the still-missing set.
    """
    deferred: list[tuple[str, str, object, int]] = []
    for folder_path, children in post_order_lexicographic(root_path, ignore_spec.get_path_spec()):
        for item_name, is_dir in children:
            file_path = str(Path(folder_path) / item_name)
            not_found_paths.discard(file_path)
            if is_dir:
                continue
            rel_path, original_hash_entry = _find_original_hash_entry(existing_history, file_path)
            if original_hash_entry is None:
                # The library's rel_path uses the native separator (os.path.relpath); the report keeps the
                # canonical forward-slash form, so normalise here.
                rel = Path(rel_path).as_posix()
                report.append(VerifyEntry(path=rel, status="new", line=f"[ERROR] new file found: {rel}"))
                continue

            try:
                size = Path(file_path).stat().st_size
            except OSError:
                size = 0
            deferred.append((file_path, rel_path, original_hash_entry, size))
    return deferred


def _find_original_hash_entry(existing_history: MHLHistory, file_path: str) -> "tuple[str, object]":
    """
    Resolve an absolute file path to its ORIGINAL hash entry.

    Routes the path to its owning history, follows a recorded ``previousPath`` back to the pre-rename name, then returns
    the first-generation entry for it. Returns ``(rel_path, original_hash_entry | None)`` where ``rel_path`` is
    native-separator and relative to the top history root (the report normalises it to forward slashes); ``None`` means
    the path has no original record (a new file).

    Shared by the hash path (``_collect_deferred``) and the size path (``verify_ascmhl_sizes``) so both group files
    across generations identically.
    """
    rel_path = existing_history.get_relative_file_path(file_path)
    history, history_rel_path = existing_history.find_history_for_path(rel_path)

    for hash_list in existing_history.hash_lists:
        for media_hash in hash_list.media_hashes:
            if media_hash.path != history_rel_path:
                continue
            history_rel_path = media_hash.previous_path or history_rel_path
            break

    return rel_path, history.find_original_hash_entry_for_path(history_rel_path)


def _hash_and_compare(
    deferred: list,
    report: list[VerifyEntry],
    on_progress: "Callable[[int], None] | None",
) -> int:
    """
    PASS 2 — hash the deferred files in parallel, compare, fill `report`.

    Returns the number of hash mismatches. Hashing is driven through mhl_suite.hashing's adaptive controller so ASC-MHL
    verify gets the same auto-tuned concurrency as classic MHL.
    """
    if not deferred:
        return 0

    paths = [d[0] for d in deferred]
    sizes = [d[3] for d in deferred]
    calib_format = deferred[0][2].hash_format

    jobs: list[Callable[[], str]] = [
        partial(_hash_file, fp, entry.hash_format, on_progress) for fp, _r, entry, _s in deferred
    ]
    hashed = hashing._hash_jobs_auto(paths, sizes, jobs, lambda: _calibrate_hash_bw(calib_format))

    num_failed = 0
    for (_fp, rel_path, original_hash_entry, _size), current_hash in zip(deferred, hashed, strict=True):
        fmt = original_hash_entry.hash_format
        # rel_path comes from the library as a native-separator path; the report keeps the canonical forward-slash
        # form (matching the .mhl).
        rel = Path(rel_path).as_posix()
        if original_hash_entry.hash_string == current_hash:
            report.append(VerifyEntry(path=rel, status="ok", line=f"[OK] {rel}  {fmt}: {current_hash}"))
        else:
            num_failed += 1
            stored = original_hash_entry.hash_string
            report.append(
                VerifyEntry(
                    path=rel,
                    status="mismatch",
                    detail=f"hash mismatch: calc {fmt}: {current_hash} | stored {fmt}: {stored}",
                    line=f"[ERROR] hash mismatch: {rel}",
                    detail_line=f"        (calc {fmt}: {current_hash} | stored {fmt}: {stored})",
                )
            )
    return num_failed


def _hash_file(filepath: str, hash_format: str, on_progress: "Callable[[int], None] | None") -> str:
    """
    Hash `filepath` with the library's incremental hasher, reporting progress.

    The library's own ascmhl.hasher.hash_file reads in chunks but exposes no progress hook, so we own the read loop here
    (using its hasher classes) to advance a progress bar within large files — `on_progress(nbytes)` fires per chunk and
    may run on a worker thread.
    """
    hasher = new_hasher_for_hash_type(hash_format)
    with open(filepath, "rb") as f:
        while chunk := f.read(hashing.HASH_CHUNK_SIZE):
            hasher.update(chunk)
            if on_progress is not None:
                on_progress(len(chunk))
    return hasher.string_digest()


def _calibrate_hash_bw(hash_format: str) -> float:
    """
    In-RAM hashing throughput (bytes/sec) for an ASC-MHL hash format.

    mhl_suite.hashing's adaptive controller needs the pure-CPU hash bandwidth to decide whether the disk can outrun a
    single hash thread. mhl_suite.hashing only knows md5/sha1/xxh64; ASC-MHL also uses xxh128/xxh3/c4, so this
    calibrates against the library's own incremental hasher. Mirrors mhl_suite.hashing._calibrate_hash_bw.
    """
    buf = bytes(hashing.HASH_CHUNK_SIZE)
    hasher = new_hasher_for_hash_type(hash_format)
    done = 0
    start = time.perf_counter()
    while time.perf_counter() - start < hashing._AUTO_CALIBRATION_SECONDS:
        hasher.update(buf)
        done += len(buf)
    elapsed = time.perf_counter() - start
    return done / elapsed if elapsed > 0 else float("inf")


# ---------------------------------------------------------------------------------------------------------------------
# Size-only verification.
#
# The ASC-MHL library's `verify` always re-hashes the whole package; there is no size-only mode. So we drive our own
# check off the same loaded MHLHistory the hash path uses (mhl_suite.ascmhl_verify._verify_entire_folder and the
# reference's verify_entire_folder): for every recorded file — across the top history and every nested child history —
# we compare the original generation's recorded size to the file on disk, reading no file bytes (one stat() per entry).
# Grouping across generations, rename (previousPath) resolution and child-history descent are therefore consistent with
# ASC-MHL reference implementation. ASC-MHL's <path size> is defined as an optional attribute on the specification,
# whose absence has no defined meaning, so such a file is existence-checked only, not failed. Driven by _verify_sizes
# below.
# ---------------------------------------------------------------------------------------------------------------------


@dataclass
class SizeCheckResult:
    """
    Outcome of a single size-only check for one recorded ASC-MHL entry.

    `status` is one of "ok" | "missing" | "mismatch". For "ok", `detail` holds the human-readable size ("size: 4170",
    or "size: not recorded" when the file exists but the optional <path size> was omitted); for a mismatch it carries
    the reason in the same shape the report formatter expects ("size mismatch: calc size: … | stored size: …",
    "blocked traversal attempt").
    """

    path: str
    status: str
    detail: str = ""


def verify_ascmhl_sizes(existing_history: MHLHistory, root_path: "str | Path") -> list[SizeCheckResult]:
    """
    Size-only verify a loaded ASC-MHL history, returning one result per recorded file.

    ``existing_history`` is the ``MHLHistory`` loaded by ``_verify_sizes`` (its load doubles as the integrity gate);
    ``root_path`` is the package root (parent of the top ``ascmhl/`` folder). The recorded file set comes from
    ``existing_history.set_of_file_paths()``, which spans the top history AND every nested child history, and a recorded
    rename contributes only its post-rename path (via ``renamed_path_with_previous_path``) — exactly as the hash path
    builds its set. For each file we take the first generation's recorded size
    (``_find_original_hash_entry(...).media_hash.file_size``), so generation grouping and rename resolution match the
    reference by construction rather than being re-derived from XML.

    Each entry compares that recorded size to the file on disk — no bytes are read. Results, in sorted-path order:
      * ok        — the file exists and its size matches, or the file exists but the record stored no size (the
                    ``<path size>`` attribute is optional in ASC-MHL)
      * missing   — the file is not on disk
      * mismatch  — the size differs, or the path escapes the root

    Path matching reuses ``resolve_on_disk`` so NFC/NFD filename forms reconcile exactly as simple-mhl's verify does.
    """
    root_path = os.path.abspath(str(root_path))
    # Trailing separator avoids prefix-collision: '/foo' matches '/foo/bar' but not '/foobar' — the same jail check
    # simple_mhl.verify applies.
    root_path_with_sep = root_path + os.sep

    # The full recorded set across the top history and all nested child histories; a rename contributes its post-rename
    # path only, mirroring _verify_entire_folder's not_found_paths construction.
    recorded_paths = existing_history.set_of_file_paths()
    renamed_files = existing_history.renamed_path_with_previous_path()
    recorded_paths = {p if renamed_files.get(p, None) is None else renamed_files[p] for p in recorded_paths}

    results: list[SizeCheckResult] = []
    # Per-call cache of directory listings used by resolve_on_disk; a fresh view per verify run (never module-global) so
    # a stale listing can't leak across runs.
    dir_index: dict[str, dict[str, str]] = {}

    for abs_path in sorted(recorded_paths):
        rel_native = os.path.relpath(abs_path, root_path)
        rel_posix = Path(rel_native).as_posix()

        # Path traversal guard: collapse '..'/'.' then require the result inside root, blocking a malicious manifest
        # pointing at "../../etc/passwd".
        jailed = os.path.normpath(abs_path)
        if jailed != root_path and not jailed.startswith(root_path_with_sep):
            results.append(SizeCheckResult(rel_posix, "mismatch", "blocked traversal attempt"))
            continue

        # A recorded path with no original file entry is a directory hash or a nested child-history reference, not a
        # file to size-check.
        _rel, original_hash_entry = _find_original_hash_entry(existing_history, abs_path)
        if original_hash_entry is None:
            continue

        resolved_path = resolve_on_disk(root_path, rel_native, dir_index)
        if resolved_path is None:
            results.append(SizeCheckResult(rel_posix, "missing"))
            continue

        # The ASC-MHL <path size> attribute is optional and the specification assigns no meaning to its absence, so a
        # record without it simply has no size to compare. We confirm the file exists (above) and leave its size
        # unchecked. This deliberately differs from classic MHL, whose schema makes <size> a required positiveInteger,
        # so there a missing size is a genuine malformation worth failing.
        # media_hash is a runtime backref the library attaches in MHLMediaHash.append_hash but never declares on
        # MHLHashEntry, so pull it through getattr with an explicit type rather than tripping the type checker.
        owning_media_hash: MHLMediaHash | None = getattr(original_hash_entry, "media_hash", None)
        recorded_size = owning_media_hash.file_size if owning_media_hash is not None else None
        if recorded_size is None:
            results.append(SizeCheckResult(rel_posix, "ok", "size: not recorded"))
            continue

        try:
            actual_size = os.path.getsize(resolved_path)
        except OSError:
            # Vanished between resolution and getsize() — report missing.
            results.append(SizeCheckResult(rel_posix, "missing"))
            continue

        if actual_size != recorded_size:
            results.append(
                SizeCheckResult(
                    rel_posix, "mismatch", f"size mismatch: calc size: {actual_size} | stored size: {recorded_size}"
                )
            )
        else:
            results.append(SizeCheckResult(rel_posix, "ok", f"size: {actual_size}"))

    return results


def _verify_sizes(root_path: "str | Path") -> VerifyReport:
    """
    Size-only verify: load the history (integrity gate + source), then compare recorded sizes to disk.

    A single ``MHLHistory.load_from_path`` does double duty, reading no media bytes: loading validates the chain file
    and each generation manifest's own hash (the integrity gate), and the loaded history is also the source of recorded
    sizes and nested child histories that ``verify_ascmhl_sizes`` walks — so the size check groups files exactly as the
    hash path (and the reference) does. A malformed manifest/chain surfaces as MALFORMED_XML; a modified manifest or
    missing history surfaces its own ascmhl exit code (30/31/32/33) via the raised ClickException.

    Codes: 0 all match (a record with no stored size is not a failure — ASC-MHL's <path size> is optional); 10 a
    referenced file is missing; 13 a size mismatch (or a blocked-traversal size failure) — `13` is distinct from `11`
    so size failures don't masquerade as hash failures.
    """
    try:
        existing_history = MHLHistory.load_from_path(str(root_path))
        if len(existing_history.hash_lists) == 0:
            raise errors.NoMHLHistoryException(str(root_path))
    except click.ClickException as exc:
        # Every ascmhl integrity failure is a click.ClickException carrying an exit_code (see ascmhl.errors).
        return VerifyReport(code=getattr(exc, "exit_code", 1), notices=[exc.format_message()])
    except (etree.XMLSyntaxError, OSError):
        return VerifyReport(
            code=ExitCode.MALFORMED_XML, malformed=True, notices=[f"🚨 Malformed XML: {root_path} cannot be parsed."]
        )

    size_results = verify_ascmhl_sizes(existing_history, root_path)

    entries: list[VerifyEntry] = []
    for r in size_results:
        if r.status == "ok":
            # path stays the bare recorded path; the size shows only on the terminal [OK] line.
            entries.append(VerifyEntry(path=r.path, status="ok", size_only=True, line=f"[OK] {r.path}  {r.detail}"))
        elif r.status == "missing":
            entries.append(VerifyEntry(path=r.path, status="missing", line=f"[ERROR] missing file: {r.path}"))
        elif ": " in r.detail:  # mismatch: "size mismatch: calc … | stored …" -> label + parenthetical
            label, paren = r.detail.split(": ", 1)
            entries.append(
                VerifyEntry(
                    path=r.path,
                    status="mismatch",
                    detail=r.detail,
                    line=f"[ERROR] {label}: {r.path}",
                    detail_line=f"        ({paren})",
                )
            )
        else:  # mismatch with a bare reason (e.g. "blocked traversal attempt")
            entries.append(
                VerifyEntry(path=r.path, status="mismatch", detail=r.detail, line=f"[ERROR] {r.detail}: {r.path}")
            )

    statuses = {e.status for e in entries}
    code = (
        ExitCode.SIZE_MISMATCH
        if "mismatch" in statuses
        else (ExitCode.MISSING if "missing" in statuses else ExitCode.OK)
    )
    return VerifyReport(entries=entries, code=code)


def _bundled_xsd_path(schema_name: str) -> str:
    """
    Absolute path to a bundled XSD shipped in the mhl_suite.xsd package.

    The pip-installed `ascmhl` wheel does NOT ship the XSD files (upstream loads them from a CWD-relative `xsd/` path
    that only resolves inside a repo checkout), so schema validation uses our own bundled copy regardless of the
    library. Raises FileNotFoundError if the schema is missing.
    """
    path = files("mhl_suite.xsd") / schema_name
    if not path.is_file():
        raise FileNotFoundError(f"bundled XSD not found: {schema_name}")
    return str(path)


def schema_check(file_path: "str | Path", *, directory_file: bool = False) -> "tuple[int, list[str]]":
    """
    Validate an ASC-MHL file against its bundled XSD, returning (code, lines).

    `directory_file=True` validates an ascmhl_chain.xml against the directory schema; otherwise a manifest is validated
    against ASCMHL.xsd. Mirrors classic_verify.schema_report: code is 0 (valid), 41 (schema non-compliant) or 40
    (malformed/unreadable XML). Schema non-compliance has its own code, deliberately NOT the 11 ascmhl reuses for
    hash-mismatch (see _exit_codes). A missing bundled XSD is a broken install, surfaced as the generic error code (1).
    Never prints.
    """
    schema_name = "ASCMHLDirectory__combined.xsd" if directory_file else "ASCMHL.xsd"
    try:
        xsd_path = _bundled_xsd_path(schema_name)
    except FileNotFoundError as exc:
        return ExitCode.ERROR, [f"Error: {exc}"]

    try:
        tree = etree.parse(str(file_path))
        xsd = etree.XMLSchema(etree.parse(xsd_path))
    except etree.XMLSyntaxError as exc:
        return ExitCode.MALFORMED_XML, [f"Error: XML parsing failed - {exc}"]
    except OSError as exc:
        return ExitCode.MALFORMED_XML, [f"Error: file read failed - {exc}"]

    if not xsd.validate(tree):
        return ExitCode.SCHEMA_NONCOMPLIANT, [
            f"Error: XSD validation failed - {err.message} (line {err.line})" for err in xsd.error_log
        ]
    return ExitCode.OK, []
