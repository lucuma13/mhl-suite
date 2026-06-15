#!/usr/bin/env python3
# =============================================================================
# simple-mhl — Modern verification and sealing tool for classic MHL files
# =============================================================================
# This is a focused rewrite of the original simple-mhl tool. It produces and
# verifies MediaHashList v1.1 XML manifests for media offloads.
#
# Three subcommands are exposed via argparse:
#
#     simple-mhl seal <directory>          — walk a directory and write an MHL
#     simple-mhl verify <file.mhl>         — re-hash files listed in a manifest
#     simple-mhl xsd-schema-check <file>   — validate XML structure against XSD
#
# =============================================================================

import argparse
import getpass
import hashlib
import importlib.metadata
import importlib.resources
import os
import sys
import time
import unicodedata
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, TypeVar, cast, runtime_checkable

import xxhash
from lxml import etree

from mhl_suite._internal.hostinfo import friendly_hostname
from mhl_suite._internal.ignorelist import is_os_junk
from mhl_suite._internal.unicodepaths import (
    normalization_variant_on_disk,
    resolve_on_disk,
)

# Generic result type for the shared hashing controller (str digests for seal,
# (kind, line) tuples for verify).
_T = TypeVar("_T")

# -----------------------------------------------------------------------------
# Version
# -----------------------------------------------------------------------------

try:
    __version__ = importlib.metadata.version("mhl-suite")
except importlib.metadata.PackageNotFoundError:  # pragma: no cover
    __version__ = "unknown"

# -----------------------------------------------------------------------------
# Hasher protocol
# -----------------------------------------------------------------------------
# Both xxhash and hashlib hashers expose .update() and .hexdigest() but share
# no common ABC. We define a structural Protocol so the type checker understands
# what ALGO_MAP factories return without depending on private hashlib internals.


@runtime_checkable
class _Hasher(Protocol):
    # Real hashers (xxhash, hashlib) accept any bytes-like buffer; we feed a
    # memoryview slice from readinto(), so the annotation must be wider than bytes.
    def update(self, data: "bytes | bytearray | memoryview") -> None: ...
    def hexdigest(self) -> str: ...


# -----------------------------------------------------------------------------
# Constants and lookups
# -----------------------------------------------------------------------------

# 1 MiB chunk size for streaming hashing is the (shallow) optimum: large enough
# to amortise read() syscall overhead, small enough to stay in CPU cache.
# Above ~4 MiB the bigger chunk only adds cache pressure. On a 1000 MB/s external
# SSD the choice barely moves the needle, seal is fully disk-bound (every
# supported hash runs faster than the disk delivers bytes), so the file read,
# not this loop, sets the pace.
HASH_CHUNK_SIZE = 1024 * 1024

# Map of CLI-accepted algorithm names to (factory, manifest-tag) pairs.
# Multiple aliases point to xxhash so callers can use whatever spelling they
# like; the manifest always records "xxhash64be" for consistency.
ALGO_MAP: dict[str, tuple[Callable[[], _Hasher], str]] = cast(
    "dict[str, tuple[Callable[[], _Hasher], str]]",
    {
        "xxhash": (xxhash.xxh64, "xxhash64be"),
        "xxh64": (xxhash.xxh64, "xxhash64be"),
        "xxhash64": (xxhash.xxh64, "xxhash64be"),
        "xxhash64be": (xxhash.xxh64, "xxhash64be"),
        "md5": (hashlib.md5, "md5"),
        "sha1": (hashlib.sha1, "sha1"),
    },
)

# Tags recognised when reading a manifest — superset of the algorithms we can
# *write*. We can verify an old manifest that uses xxhash128 or xxhash3_64
# even if we don't offer those for sealing. "null" records no digest, so
# verification falls back to existence + file-size check (per the v1.1 schema:
# <null> means "no hash, only use file size verification").
SUPPORTED_HASH_TAGS = frozenset(ALGO_MAP) | {"xxhash128", "xxhash3_64", "null"}


# -----------------------------------------------------------------------------
# XSD location
# -----------------------------------------------------------------------------


def get_xsd_path() -> str:
    """
    Locate the bundled MediaHashList_v1_1.xsd. Returns the path.

    Raises FileNotFoundError if the XSD cannot be found in either the
    installed-package location or the source-checkout fallback.

    Looks first at the importlib.resources location used when this package
    is installed normally, then at a sibling 'xsd/' folder for the case
    where simple_mhl.py is run directly from a checkout.
    """
    try:
        resource = importlib.resources.files("mhl_suite.xsd").joinpath("MediaHashList_v1_1.xsd")
        if resource.is_file():
            return str(resource)
    except (ImportError, FileNotFoundError, TypeError):
        pass

    # Source-checkout fallback
    local = Path(__file__).resolve().parent / "xsd" / "MediaHashList_v1_1.xsd"
    if local.exists():
        return str(local)

    raise FileNotFoundError(f"Could not locate MediaHashList_v1_1.xsd (tried {local})")


# -----------------------------------------------------------------------------
# Hashing
# -----------------------------------------------------------------------------


def get_hash(filepath: str, algo_key: str) -> str:
    """
    Compute the digest of `filepath` using algorithm `algo_key`.

    Returns the hex digest as a lowercase string.

    We deliberately do NOT use hashlib.file_digest(): bench measurements showed it is
    5-15% slower than this manual loop on typical media files; the wrapper overhead
    exceeds any internal optimisation it might apply. The manual loop is also
    forward-compatible with xxhash, which file_digest doesn't support anyway.
    """
    if algo_key not in ALGO_MAP:
        raise ValueError(f"Unsupported hash algorithm: {algo_key}")

    hasher: _Hasher = ALGO_MAP[algo_key][0]()
    # readinto() reuses one buffer for the whole file instead of allocating a
    # fresh bytes object per chunk, removing per-chunk allocation/GC churn —
    # measured a few percent faster than read() in a loop on the warm-cache path
    # (it's in the noise once the read is disk-bound, but never slower).
    buf = bytearray(HASH_CHUNK_SIZE)
    view = memoryview(buf)
    with open(filepath, "rb") as f:
        while True:
            n = f.readinto(buf)
            if not n:
                break
            hasher.update(view[:n])
    return hasher.hexdigest()


# -----------------------------------------------------------------------------
# Adaptive parallel hashing
# -----------------------------------------------------------------------------
# Hashing across files can run concurrently — xxhash and hashlib both RELEASE
# the GIL inside update(), so threads overlap reads and use several cores. But
# whether that helps depends entirely on the storage, and getting it wrong makes
# things worse. Measured on real media:
#
#   * Helps only when the hash is slower than the disk (CPU-bound): md5
#     (~950 MB/s) on a very fast SSD (~3000 MB/s) went ~2.7x - the disk had
#     spare bandwidth one md5 thread couldn't use.
#   * Does nothing when the disk is the bottleneck: xxhash (~13 GB/s) outruns any
#     disk, so it stays disk-bound however many workers.
#   * Hurts on a slow disk. On a slow HDD (~70 MB/s), 4 workers regressed to
#     md5 0.65x / xxhash 0.76x. Concurrent reads make the head seek between files.
#
# So we should measure:
#
#   1. Calibrate the pure in-RAM hash speed (no disk, ~50 ms).
#   2. Probe the disk: a plain timed read of the first ~1 GB (and >=0.5 s, so a
#      very fast NVMe still samples past its read ramp). This reads bytes we're
#      about to hash anyway.
#   3. If the disk can't clearly outrun one hash thread (read_bw < 1.3x hash_bw),
#      the disk is the ceiling — slow volume or very fast hash (like xxhash) —
#      so we stay sequential and never issue a concurrent read (no seek penalty).
#   4. Otherwise the hash is the bottleneck and the disk has spare bandwidth:
#      run workers = round(read_bw / hash_bw) of them. Because we hand the whole
#      file list (huge opener included) to the pool, a 100 GB first file overlaps
#      with the rest instead of blocking the decision.
#
# A 1 GB probe can't tell a warm page cache from a fast disk (cache reads look
# like a fast SSD). That false-positive is harmless on a real SSD, and on a
# spinning disk it self-corrects: each hashing window is re-measured, and if a
# parallel window can't even beat ONE hash thread (cold platter, seeking), we
# demote to sequential for the remainder. Cached data, conversely, never seeks,
# so parallelising it is fine.

# Below this total size, parallelism saves too little wall-time to bother probing.
_AUTO_MIN_BYTES = 2 * 1024 * 1024 * 1024
# Disk probe reads at least this many bytes AND runs at least this long, so the
# sample is stable whether the volume does 70 MB/s or 7 GB/s.
_AUTO_PROBE_BYTES = 1024 * 1024 * 1024
_AUTO_PROBE_SECONDS = 0.5
# The disk must beat one hash thread by this factor before parallelism is worth
# it (below this the gain is marginal and not worth the extra reads/seeks).
_AUTO_PARALLEL_THRESHOLD = 1.3
# Re-measure throughput every this many bytes so a disk that goes cold mid-run
# (warm cache exhausted) can be caught and demoted to sequential.
_AUTO_RECHECK_BYTES = 8 * 1024 * 1024 * 1024
# Never spin up more than this many workers regardless of core count.
_AUTO_MAX_WORKERS = 16
# Wall-time budget for the in-RAM hash-speed calibration — long enough to average
# out jitter, short enough to vanish beside a multi-GB seal.
_AUTO_CALIBRATION_SECONDS = 0.05


def _hash_batch(jobs: "list[Callable[[], _T]]", workers: int) -> "list[_T]":
    """Run `jobs` and return their results in input order, up to `workers` at once.

    A job is a zero-arg callable that hashes one file (seal) or hashes-and-compares
    one entry (verify). ThreadPoolExecutor.map preserves order, so the manifest /
    report stays deterministic regardless of which finishes first.
    """
    if workers <= 1 or len(jobs) <= 1:
        return [job() for job in jobs]
    with ThreadPoolExecutor(max_workers=min(workers, len(jobs))) as ex:
        return list(ex.map(lambda job: job(), jobs))


def _calibrate_hash_bw(algo_key: str) -> float:
    """Pure in-RAM hashing throughput (bytes/sec) for `algo_key`, no disk involved.

    Lets us tell whether a measured read rate is limited by the hash (CPU) or by
    the disk. Runs for a brief fixed time using HASH_CHUNK_SIZE updates so the
    figure reflects get_hash's real per-chunk cost; ~50 ms is long enough to
    average out scheduler jitter and invisible beside a multi-GB seal.
    """
    buf = bytes(HASH_CHUNK_SIZE)
    hasher = ALGO_MAP[algo_key][0]()
    done = 0
    start = time.perf_counter()
    while time.perf_counter() - start < _AUTO_CALIBRATION_SECONDS:
        hasher.update(buf)
        done += HASH_CHUNK_SIZE
    elapsed = time.perf_counter() - start
    return done / elapsed if elapsed > 0 else float("inf")


def _probe_read_bw(paths: list[str]) -> float:
    """Measure the volume's read bandwidth (bytes/sec) with a plain buffered read
    of the first files, stopping once we've read >=_AUTO_PROBE_BYTES AND spent
    >=_AUTO_PROBE_SECONDS. The byte floor gives a meaningful sample on a slow
    disk; the time floor makes a very fast one read enough to get past its ramp.

    Not hashed — just read and timed. The bytes are re-read when the files are
    hashed for real, a negligible cost against a multi-GB seal.
    """
    buf = bytearray(HASH_CHUNK_SIZE)
    read = 0
    start = time.perf_counter()
    elapsed = 0.0
    for p in paths:
        try:
            with open(p, "rb") as f:
                while f.readinto(buf):
                    read += len(buf)
                    elapsed = time.perf_counter() - start
                    if read >= _AUTO_PROBE_BYTES and elapsed >= _AUTO_PROBE_SECONDS:
                        return read / elapsed
        except OSError:
            continue  # a file that won't open is the real hash pass's problem, not the probe's
    elapsed = time.perf_counter() - start
    return read / elapsed if elapsed > 0 else float("inf")


def _hash_jobs_auto(
    paths: list[str], sizes: list[int], jobs: "list[Callable[[], _T]]", calib_algo: str
) -> "Iterator[_T]":
    """Yield each job's result in input order, auto-tuning concurrency to the
    storage (see section comment).

    `paths[i]`/`sizes[i]` describe the file job `i` will read — `paths` drives
    the disk probe, `sizes` (already known from a stat) carve the recheck
    windows — and `jobs[i]` does the hashing. `calib_algo` is the algorithm used
    for the in-RAM hash-speed calibration. Shared by seal and verify.
    """
    n = len(jobs)
    cap = min(_AUTO_MAX_WORKERS, os.cpu_count() or 4)
    # Not worth probing for a single file, a small job, or a uniprocessor.
    if n <= 1 or cap <= 1 or sum(sizes) < _AUTO_MIN_BYTES:
        for job in jobs:
            yield job()
        return

    hash_bw = _calibrate_hash_bw(calib_algo)
    read_bw = _probe_read_bw(paths)

    # Disk-bound (hash faster than the disk): one core already keeps the disk busy,
    # so more cores can't help and would seek-thrash a spinning disk - stay sequential.
    if read_bw < _AUTO_PARALLEL_THRESHOLD * hash_bw:
        for job in jobs:
            yield job()
        return

    # Hash-bound (disk faster than one hash thread), so spread the work across
    # enough threads to soak up its bandwidth. round(read_bw/hash_bw) lands near
    # the count that saturates the disk without piling on idle threads.
    workers = max(2, min(cap, round(read_bw / hash_bw)))

    # Hash in windows so we can re-measure: if a window's parallel throughput
    # can't even beat one hash thread, the disk has gone cold/seek-bound (e.g. a
    # warm cache that fooled the probe is now exhausted) — demote to sequential
    # for the remainder. Each window takes at least `workers` files so every
    # worker has something to do even when files are large.
    pos = 0
    while pos < n:
        stop = pos
        acc = 0
        while stop < n and (acc < _AUTO_RECHECK_BYTES or (stop - pos) < workers):
            acc += sizes[stop]
            stop += 1
        start = time.perf_counter()
        yield from _hash_batch(jobs[pos:stop], workers)
        elapsed = time.perf_counter() - start
        pos = stop
        rate = acc / elapsed if elapsed > 0 else float("inf")
        if rate < hash_bw:
            # Parallel isn't beating a single thread → disk is the bottleneck now.
            for job in jobs[pos:]:
                yield job()
            return


def _hash_files_auto(paths: list[str], sizes: list[int], algo_key: str) -> Iterator[str]:
    """Seal helper: yield each path's digest in order, auto-tuning concurrency.

    Wraps _hash_jobs_auto with one get_hash job per path. get_hash is resolved at
    call time (module global) so test monkeypatches still intercept it.
    """
    jobs: list[Callable[[], str]] = [(lambda p=p: get_hash(p, algo_key)) for p in paths]
    return _hash_jobs_auto(paths, sizes, jobs, algo_key)


# -----------------------------------------------------------------------------
# Filesystem walking
# -----------------------------------------------------------------------------


def _iter_files_for_seal(
    root: str,
    mhl_path: str,
    on_skip: "Callable[[str, str, bool], None] | None" = None,
) -> Iterator[tuple[str, os.stat_result]]:
    """
    Walk `root` recursively and yield (absolute_path, stat_result) for every
    file that should appear in the manifest, in deterministic sorted order.

    Hidden files and directories (names starting with '.') ARE included — a
    fixity manifest should protect everything the operator put on disk.

    Skips:
      - OS-generated metadata (see _internal.ignorelist), which the system
        rewrites on its own and would break re-verification
      - the manifest file itself (so we don't hash what we're writing)
      - entries that disappear or stat-fail mid-walk

    `on_skip`, if given, is called as on_skip(path, reason, is_warning) for each
    skipped entry (except the manifest itself). is_warning is True for an
    unreadable directory — a silently-dropped directory means media missing
    from the manifest, so the caller surfaces it regardless of verbosity.

    Implementation note: we use os.scandir rather than os.walk because
    DirEntry caches the stat() info from getdents64, saving a syscall per
    file. Bench showed ~13% faster traversal on a 1000-file tree. The code
    is structured iteratively (stack-based) rather than recursively to
    avoid Python's recursion limit on deeply nested shoots.
    """
    # Stack of directories yet to descend. We push/pop in a way that yields
    # files in deterministic order: within each directory entries are sorted
    # lexicographically, and subdirectories are explored depth-first in that
    # same order. The overall manifest is NOT globally sorted by full path —
    # a deeply nested a/b/c.mov appears before a sibling d.mov at the parent
    # level. This is fine; the manifest only needs to be deterministic, not
    # follow any specific canonical global order.
    pending = [root]

    while pending:
        current = pending.pop()
        try:
            # scandir returns DirEntry objects whose .stat() is satisfied
            # from the readdir cache (no extra syscall) on most filesystems.
            entries = list(os.scandir(current))
        except OSError as exc:
            # Permission or vanished-directory. Unlike os.walk's silent
            # onerror=None, we report it: a dropped directory means its files
            # are absent from the manifest and therefore unprotected.
            if on_skip is not None:
                on_skip(current, f"unreadable: {exc.strerror or exc}", True)
            continue

        # Sort by name within the directory for deterministic output order.
        entries.sort(key=lambda e: e.name)

        # Two passes so files in this directory get yielded before recursing
        # into subdirectories — gives a depth-first, sorted-per-level walk
        # equivalent to os.walk(topdown=True) with sorted dirnames.
        subdirs: list[str] = []
        for entry in entries:
            if is_os_junk(entry.name):
                if on_skip is not None:
                    on_skip(entry.path, "OS metadata", False)
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    subdirs.append(entry.path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    if on_skip is not None:
                        on_skip(entry.path, "not a regular file", False)
                    continue
                # Skip the manifest we're currently writing.
                if entry.path == mhl_path:
                    continue
                yield entry.path, entry.stat(follow_symlinks=False)
            except OSError:
                # File vanished between scandir and stat — skip it.
                if on_skip is not None:
                    on_skip(entry.path, "vanished", False)
                continue

        # Push subdirs in reverse so popping gives lexicographic order.
        pending.extend(reversed(subdirs))


# -----------------------------------------------------------------------------
# Seal command
# -----------------------------------------------------------------------------


def _build_creatorinfo(parent: etree._Element, tool: str, iso_now: str) -> etree._Element:
    """Append a <creatorinfo> block to `parent` and return it."""
    info = etree.SubElement(parent, "creatorinfo")
    for tag, value in [
        ("username", getpass.getuser()),
        ("hostname", friendly_hostname()),
        ("tool", tool),
        ("startdate", iso_now),
        ("finishdate", iso_now),  # placeholder, updated after the walk
    ]:
        etree.SubElement(info, tag).text = value
    return info


def seal(root: str, algorithm: str, dont_reseal: bool, verbose: bool = False) -> None:
    """
    Walk `root`, hash every non-hidden file, and write a dated MHL manifest
    at the root of the directory.

    Behaviour:
      * Manifest filename: <basename>_<UTC-timestamp>.mhl
      * Collisions: if the file already exists and --dont-reseal was passed,
        exit 0 silently. Otherwise append a numeric suffix until unique.
      * Hidden files and directories are included; only OS-generated metadata
        (.DS_Store, macOS ._* resource forks, Spotlight/Trash/Time Machine and
        other volume-internal items — see _internal.ignorelist) is skipped.
      * Files that vanish during the walk are skipped without aborting.
      * Concurrency is fully automatic and has no operator knob: _hash_files_auto
        measures the storage and parallelises only when that's faster, staying
        sequential otherwise. The manifest is identical and deterministically
        ordered regardless.

    Output format:
      [OK] <path>  <algo>: <digest>             (verbose only, per hashed file)
      [SKIP] <path> (<reason>)                  (verbose only, skipped entry)
      [WARNING] skipped: <path> (<reason>)      (always, on stderr; dropped dir)
      Created MHL: <path>                        (verbose only, on completion)

    Exits with code 2 on argument errors (handled by argparse before we get
    here) and lets unexpected OSError on the final write propagate so the
    operator sees the real diagnostic.
    """
    if algorithm not in ALGO_MAP:
        # argparse 'choices=' should have caught this, but defend anyway.
        sys.stderr.write(f"Error: unsupported algorithm '{algorithm}'\n")
        sys.exit(2)

    root = os.path.abspath(root)
    if not os.path.isdir(root):
        msg = f"Error: '{root}' is not a directory\n"
        variant = normalization_variant_on_disk(root)
        if variant is not None and os.path.isdir(variant):
            msg += f"  A directory with a different Unicode normalization exists — did you mean:\n    {variant}\n"
        sys.stderr.write(msg)
        sys.exit(2)

    base_name = os.path.basename(root)

    # iso_now stamps the run's <creationdate> and <creatorinfo> start/finish.
    # Each file's <hashdate> is captured separately as that file is hashed.
    now_dt = datetime.now(UTC)
    timestamp_for_filename = now_dt.strftime("%Y-%m-%d_%H%M%S")
    iso_now = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Find a non-colliding manifest filename and claim it atomically.
    #
    # We use O_CREAT | O_EXCL so the existence check and file creation are
    # a single syscall — eliminating the TOCTOU race that would exist if we
    # checked os.path.exists() and then separately opened the file for
    # writing.  Two parallel seal invocations (e.g. from concurrent post-
    # transfer scripts on a shared NAS) will now always land on distinct
    # paths; the second process to attempt any given path gets FileExistsError
    # and moves on to the next suffix.
    #
    # The original tool exited 0 with --dont-reseal regardless of whether a
    # same-second collision was the user's existing manifest or a brand-new
    # one being written; we preserve that behaviour because automated callers
    # depend on it.
    mhl_name = f"{base_name}_{timestamp_for_filename}.mhl"
    mhl_path = os.path.join(root, mhl_name)
    suffix = 0
    fd: int | None = None
    while fd is None:
        try:
            fd = os.open(mhl_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o666)
        except FileExistsError:
            if dont_reseal:
                sys.exit(0)
            suffix += 1
            mhl_path = os.path.join(root, f"{base_name}_{timestamp_for_filename}_{suffix}.mhl")

    # Build the manifest skeleton. We construct in memory and write at the
    # end; for typical shoots (<5000 files) the in-memory tree is a few MB
    # of XML which is fine. For pathologically large trees a streaming
    # writer (etree.xmlfile) would help, but the seal-time cost is
    # dominated by hashing the bytes, not by holding the tree in RAM.
    doc = etree.Element("hashlist", version="1.1")
    etree.SubElement(doc, "creationdate").text = iso_now

    info = _build_creatorinfo(doc, f"simple-mhl {__version__}", iso_now)

    xml_tag = ALGO_MAP[algorithm][1]

    def _on_skip(path: str, reason: str, is_warning: bool) -> None:
        rel = os.path.relpath(path, root)
        rel_posix = rel.replace(os.sep, "/") if os.sep != "/" else rel
        if is_warning:
            # Always shown: a dropped directory leaves files unprotected.
            sys.stderr.write(f"[WARNING] skipped: {rel_posix} ({reason})\n")
        elif verbose:
            print(f"[SKIP] {rel_posix} ({reason})")

    # Walk the tree first (reporting skips as we go), then hash. Materialising
    # the entry list lets us hash files concurrently while still emitting the
    # manifest in deterministic walk order. The list holds (path, stat) tuples —
    # a few tens of MB even for a 100k-frame shoot, dwarfed by the XML tree built
    # alongside it. Concurrency is decided entirely by _hash_files_auto, which
    # measures the storage and stays sequential whenever that's faster.
    entries = list(_iter_files_for_seal(root, mhl_path, on_skip=_on_skip))
    paths = [fp for fp, _ in entries]
    digests = _hash_files_auto(paths, [st.st_size for _, st in entries], algorithm)

    for (filepath, stat_result), digest in zip(entries, digests, strict=True):
        hashdate = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        rel_path = os.path.relpath(filepath, root)
        # The MHL spec requires forward slashes regardless of platform. On
        # Windows, os.path.relpath returns backslashes; replace them so the
        # manifest is portable between operating systems.
        rel_path_posix = rel_path.replace(os.sep, "/") if os.sep != "/" else rel_path
        # Normalize to NFC so accented filenames are stored as precomposed
        # codepoints (e.g. é = U+00E9) rather than the NFD decomposed form
        # (e = U+0065 + combining acute U+0301) that macOS HFS+/APFS returns
        # from the filesystem. A consistent NFC manifest round-trips correctly
        # on Linux (byte-exact path matching) and Windows, both of which use
        # NFC natively.
        rel_path_posix = unicodedata.normalize("NFC", rel_path_posix)

        h = etree.SubElement(doc, "hash")
        etree.SubElement(h, "file").text = rel_path_posix
        etree.SubElement(h, "size").text = str(stat_result.st_size)
        mtime = datetime.fromtimestamp(stat_result.st_mtime, UTC)
        etree.SubElement(h, "lastmodificationdate").text = mtime.strftime("%Y-%m-%dT%H:%M:%SZ")
        if verbose:
            print(f"[OK] {rel_path_posix}  {xml_tag}: {digest}")
        etree.SubElement(h, xml_tag).text = digest
        etree.SubElement(h, "hashdate").text = hashdate

    # Update finishdate to reflect actual completion; useful for auditing
    # how long the seal took.
    finish_el = info.find("finishdate")
    if finish_el is not None:
        finish_el.text = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Pretty-print so a human can read the manifest in a text editor; lxml
    # adds the XML declaration and UTF-8 encoding header.
    # We write via the fd we already hold from the O_EXCL open above so
    # we never re-open the file by path (which would be another race window).
    with os.fdopen(fd, "wb") as fh:
        etree.ElementTree(doc).write(fh, xml_declaration=True, encoding="UTF-8", pretty_print=True)

    if verbose:
        print(f"Created MHL: {mhl_path}")


# -----------------------------------------------------------------------------
# Verify command
# -----------------------------------------------------------------------------


def _localname(tag: object) -> str:
    """
    Return the local-name part of a possibly-namespaced XML tag.

    lxml stores namespaced tags as '{uri}localname'. rpartition('}')[2]
    gives 'localname' if the brace exists and the whole tag if it doesn't.
    Faster than etree.QName() because it skips the QName object construction.

    Non-string tags (lxml Comment and ProcessingInstruction nodes carry a
    callable as their .tag attribute) are returned as an empty string so
    callers can safely test membership in a frozenset of string tag names.
    """
    if not isinstance(tag, str):
        return ""
    return tag.rpartition("}")[2] if "}" in tag else tag


def _validate_mhl_path(mhl_file: str) -> None:
    """
    Validate that `mhl_file` is a readable MHL file path, exiting with a
    structured error message if not. Covers three cases:
      - path does not exist
      - path is a directory (with a specific hint for ASC-MHL v2 packages)
      - path lacks a .mhl extension
    """
    if not os.path.exists(mhl_file):
        msg = f"Verification Error: {mhl_file} not found\n"
        variant = normalization_variant_on_disk(mhl_file)
        if variant is not None:
            shown = variant if os.path.isabs(mhl_file) else os.path.relpath(variant)
            msg += f"  A path with a different Unicode normalization exists — did you mean:\n    {shown}\n"
        sys.stderr.write(msg)
        sys.exit(1)
    if os.path.isdir(mhl_file):
        if os.path.basename(os.path.normpath(mhl_file)) == "ascmhl":
            sys.stderr.write(
                f"Verification Error: '{mhl_file}' is an ASC-MHL v2 package directory.\n"
                "simple-mhl only handles MHL v1 (.mhl) files. "
                "You may want to use mhlver to verify ASC-MHL packages.\n"
            )
        else:
            sys.stderr.write(
                f"Verification Error: '{mhl_file}' is a directory.\n"
                "The verify command requires a path to an MHL file (e.g. manifest.mhl).\n"
            )
        sys.exit(1)
    if not mhl_file.lower().endswith(".mhl"):
        sys.stderr.write(
            f"Verification Error: '{mhl_file}' does not have a .mhl extension.\n"
            "The verify command requires a path to an MHL file (e.g. manifest.mhl).\n"
        )
        sys.exit(1)


def _verify_one_hash(candidate: str, tag: str, expected: str, rel_path: str, verbose: bool) -> tuple[str, str]:
    """Hash `candidate` with `tag` and compare against `expected`.

    Returns ("ok", rel_path) on a match, otherwise ("mismatch", line). Catches
    the per-file errors verify must report rather than abort on (an unsupported
    accept-on-read tag like xxhash128, or a file that vanished mid-run), so this
    can run inside a thread pool without a raise tearing down the whole verify.
    """
    try:
        calculated = get_hash(candidate, tag)
    except (ValueError, OSError) as e:
        return ("mismatch", f"[ERROR] cannot verify {rel_path}: {e}")

    # Some legacy MHL files stored xxhash as a *decimal integer* rather than the
    # modern big-endian hex. Detect that case and compare numerically, otherwise
    # compare hex case-insensitively (uppercase hex appears in some tool output).
    if tag == "xxhash" and expected.isdecimal():
        ok = int(calculated, 16) == int(expected)
    else:
        ok = calculated.lower() == expected.lower()

    if ok:
        return ("ok", rel_path)
    if verbose:
        return (
            "mismatch",
            f"[ERROR] hash mismatch: {rel_path}\n        (calc {tag}: {calculated} | stored {tag}: {expected})",
        )
    return ("mismatch", f"[ERROR] hash mismatch: {rel_path}")


def verify(mhl_file: str, verbose: bool = False) -> None:  # noqa: C901 — flat per-entry verify ladder, not nested complexity
    """
    Verify each file listed in `mhl_file` against its stored hash.

    Behaviour:
      * Default mode: silent on success; on failure, prints one line per
        problem file with a structured prefix (`ERROR: <category>: <path>`).
      * Verbose mode (verbose=True): also prints `OK: <path>` for every
        successfully verified file, mirroring ascmhl-debug's --verbose.
      * Path traversal attempts (manifest entries with ../ that escape the
        manifest's directory) are blocked and reported as mismatches.

      * Malformed XML exits 20 with no further output.

    Output format:
      [OK] <path>  <algo>: <digest>                (verbose only, success)
      [ERROR] hash mismatch: <path>                (verify failure)
      [ERROR] missing file: <path>                 (file not on disk)
      [ERROR] blocked traversal attempt: <path>    (security)
      [ERROR] no supported hash found: <path>      (manifest malformed)
      [ERROR] cannot verify <path>: <reason>       (algorithm not available)

    Exit codes:
       0 = clean
      20 = malformed XML
      30 = missing files only
      40 = hash mismatches only
      70 = both missing and mismatches
    """
    _validate_mhl_path(mhl_file)

    # All file references in the manifest are relative to the directory
    # the manifest lives in. We capture this once and use it as the
    # canonical jail for the path-traversal check.
    mhl_dir = os.path.abspath(os.path.dirname(os.path.abspath(mhl_file)))
    # Trailing separator avoids prefix-collision: '/foo' matches '/foo/bar'
    # but not '/foobar'.
    mhl_dir_with_sep = mhl_dir + os.sep

    # Per-entry outcomes in manifest order. Cheap failures (traversal, missing,
    # malformed/size, no-hash) and null-OK are decided inline while streaming;
    # entries that still need a hash pass get a None placeholder filled by the
    # parallel phase below. One small tuple per entry trades the old O(1)
    # streaming memory for O(files) — a few MB for a typical offload, and the
    # price of hashing files concurrently instead of strictly one at a time.
    results: list[tuple[str, str] | None] = []

    # Entries deferred to the parallel hash phase: parallel arrays plus the slot
    # in `results` each fills. `hash_sizes` reuse the size pre-check's stat, so
    # the recheck windows cost no extra syscalls.
    hash_paths: list[str] = []
    hash_sizes: list[int] = []
    hash_slots: list[int] = []
    hash_jobs: list[Callable[[], tuple[str, str]]] = []
    calib_algo: str | None = None

    # Per-call cache of directory listings ({dir: {NFC(name): real_name}}),
    # populated lazily by resolve_on_disk when a literal path lookup misses.
    dir_index: dict[str, dict[str, str]] = {}

    # iterparse yields each <hash> element as its closing tag is read, then we
    # free it — peak DOM memory stays proportional to one element, not the whole
    # document (which can reach hundreds of MB).
    #
    # OSError covers lxml raising "Invalid bytes in character encoding" (e.g. null
    # bytes mid-XML from mutation fuzzing or disk corruption) — a case
    # etree.parse() also raises as OSError. Both are malformed → exit 20.
    try:
        for _, h in etree.iterparse(mhl_file, events=("end",), tag="{*}hash"):
            # Exactly one <file> child expected; malformed entries without one
            # are silently skipped (xsd-schema-check would have caught them).
            file_el = h.find("{*}file")
            if file_el is None or file_el.text is None:
                h.clear()
                continue

            # Manifests use forward slashes; convert to the platform separator
            # for the local filesystem call. On POSIX this is a no-op.
            rel_path = file_el.text
            if os.sep != "/":
                rel_path = rel_path.replace("/", os.sep)

            # --- Path traversal guard -----------------------------------
            # Collapse '..'/'.' via normpath, then require the result inside
            # mhl_dir — blocks a malicious manifest reading "../../etc/passwd".
            # Containment is byte-structural, so guard the literal path (no NFC).
            jailed = os.path.normpath(os.path.join(mhl_dir, rel_path))
            if jailed != mhl_dir and not jailed.startswith(mhl_dir_with_sep):
                results.append(("mismatch", f"[ERROR] blocked traversal attempt: {rel_path}"))
                h.clear()
                continue

            # --- Resolve to the real on-disk path -----------------------
            # Match against actual directory entries across Unicode normalization
            # forms. A None result means the file is genuinely absent.
            candidate = resolve_on_disk(mhl_dir, os.path.relpath(jailed, mhl_dir), dir_index)
            if candidate is None:
                results.append(("missing", f"[ERROR] missing file: {rel_path}"))
                h.clear()
                continue

            # First direct child whose tag is a recognised hash algorithm.
            hash_node = None
            for child in h:
                if _localname(child.tag) in SUPPORTED_HASH_TAGS:
                    hash_node = child
                    break

            if hash_node is None:
                results.append(("mismatch", f"[ERROR] no supported hash found: {rel_path}"))
                h.clear()
                continue

            tag = _localname(hash_node.tag)
            expected = (hash_node.text or "").strip()

            # --- File size pre-check ------------------------------------
            # Compare the manifest's <size> against the file before spending a
            # full hash pass — a size mismatch is definitive and costs one stat().
            # isdecimal() rejects superscripts/other Unicode "digits" that int()
            # would silently convert to the wrong value (corruption or tampering).
            actual_size: int | None = None
            size_el = h.find("{*}size")
            if size_el is not None and size_el.text is not None:
                size_text = size_el.text.strip()
                if not size_text.isdecimal():
                    results.append(("mismatch", f"[ERROR] malformed size field: {rel_path}"))
                    h.clear()
                    continue
                try:
                    actual_size = os.path.getsize(candidate)
                except OSError:
                    # Vanished between resolution and getsize() — report missing
                    # rather than a bare OSError traceback.
                    results.append(("missing", f"[ERROR] missing file: {rel_path}"))
                    h.clear()
                    continue
                manifest_size = int(size_text)
                if manifest_size != actual_size:
                    if verbose:
                        results.append(
                            (
                                "mismatch",
                                f"[ERROR] size mismatch: {rel_path}\n"
                                f"        (calc size: {actual_size} | stored size: {manifest_size})",
                            )
                        )
                    else:
                        results.append(("mismatch", f"[ERROR] size mismatch: {rel_path}"))
                    h.clear()
                    continue

            # 'null' tag records no digest: existence + size are the whole check.
            if tag == "null":
                results.append(("ok", rel_path))
                h.clear()
                continue

            # Needs a hash pass — defer it to the parallel phase. get_hash is NOT
            # called here, so the size pre-check above still short-circuits a
            # corrupt-size file before any hashing happens.
            slot = len(results)
            results.append(None)
            hash_slots.append(slot)
            hash_paths.append(candidate)
            hash_sizes.append(actual_size if actual_size is not None else 0)
            hash_jobs.append(lambda c=candidate, t=tag, e=expected, r=rel_path: _verify_one_hash(c, t, e, r, verbose))
            # Calibrate the storage probe against the first computable algorithm.
            if calib_algo is None and tag in ALGO_MAP:
                calib_algo = tag

            # Free this element and all already-processed siblings.
            h.clear()
            parent = h.getparent()
            if parent is not None:
                while h.getprevious() is not None:
                    del parent[0]

    except (etree.XMLSyntaxError, OSError):
        sys.exit(20)

    # --- Parallel hash phase -------------------------------------------------
    # Hash the deferred entries, auto-tuning concurrency to the storage exactly
    # as seal does. With no computable algorithm (e.g. an all-xxhash128 manifest)
    # every job is an instant "cannot verify", so a disk probe would be pointless
    # — run them straight through.
    if hash_jobs:
        if calib_algo is None:
            hashed: list[tuple[str, str]] = [job() for job in hash_jobs]
        else:
            hashed = list(_hash_jobs_auto(hash_paths, hash_sizes, hash_jobs, calib_algo))
        for slot, outcome in zip(hash_slots, hashed, strict=True):
            results[slot] = outcome

    # --- Emit ----------------------------------------------------------------
    # Verbose prints [OK] per file in manifest order; failures fill two buckets
    # so the exit code can distinguish missing-only (30), mismatch-only (40), or
    # both (70). Default mode stays silent on full success.
    missing: list[str] = []
    mismatches: list[str] = []
    for entry in results:
        if entry is None:
            continue  # unreachable: every placeholder is filled by the hash phase
        kind, payload = entry
        if kind == "ok":
            if verbose:
                print(f"[OK] {payload}")
        elif kind == "missing":
            missing.append(payload)
        else:
            mismatches.append(payload)

    if missing or mismatches:
        for line in missing:
            print(line)
        for line in mismatches:
            print(line)
        if missing and mismatches:
            sys.exit(70)
        sys.exit(40 if mismatches else 30)


# -----------------------------------------------------------------------------
# XSD schema validation
# -----------------------------------------------------------------------------


def validate_schema(mhl_file: str) -> None:
    """Validate `mhl_file` against the bundled MediaHashList_v1_1.xsd."""
    # get_xsd_path raises FileNotFoundError if the XSD cannot be located.
    # We catch it here and exit 60 — the same code that mhlver maps to its
    # "schema check unavailable" warning message — keeping error-reporting
    # and exit-code responsibility together in the caller, consistent with
    # how other error paths in this file work.
    try:
        xsd_path = get_xsd_path()
    except FileNotFoundError as exc:
        sys.stderr.write(f"Error: {exc}\n")
        sys.exit(60)

    try:
        # Parse both documents and compile the schema. lxml's XMLSchema
        # constructor compiles the validator; the cost is small (a few
        # KiB schema) and not worth caching for a single-file CLI tool.
        tree = etree.parse(mhl_file)
        xsd = etree.XMLSchema(etree.parse(xsd_path))
    except etree.XMLSyntaxError as e:
        sys.stderr.write(f"XML Parsing Error: {e}\n")
        sys.exit(20)
    except OSError as e:
        sys.stderr.write(f"File Error: {e}\n")
        sys.exit(20)

    if not xsd.validate(tree):
        for err in xsd.error_log:
            sys.stderr.write(f"Schema Error: {err.message} (line {err.line})\n")
        sys.exit(10)


# -----------------------------------------------------------------------------
# CLI entry point
# -----------------------------------------------------------------------------


def main() -> None:
    # --- Smart dispatch -------------------------------------------------------
    # When invoked without an explicit subcommand we inspect the sole positional
    # argument (if there is exactly one) and infer the intended operation:
    #
    #   simple-mhl <directory>   →  simple-mhl seal <directory>
    #   simple-mhl <file>.mhl    →  simple-mhl verify <file>.mhl
    #
    # This is done by rewriting sys.argv before argparse sees it, so all normal
    # validation (choices=, required=, etc.) still applies.  We only rewrite
    # when the first token after the program name is not already a recognised
    # subcommand or flag, keeping full backwards-compatibility.
    _SUBCOMMANDS = {"seal", "verify", "xsd-schema-check"}
    _raw = sys.argv[1:]
    if _raw and _raw[0] not in _SUBCOMMANDS and not _raw[0].startswith("-"):
        # Candidate: a single bare path with no subcommand prefix.
        _candidate = _raw[0]
        if os.path.isdir(_candidate):
            # Directory → seal, injecting the subcommand into argv.
            sys.argv = [sys.argv[0], "seal", *_raw]
        elif _candidate.lower().endswith(".mhl"):
            # .mhl file → verify, injecting the subcommand into argv.
            sys.argv = [sys.argv[0], "verify", *_raw]
        # Anything else falls through to argparse, which will produce its
        # normal "argument command: invalid choice" error message.

    parser = argparse.ArgumentParser(
        prog="simple-mhl",
        description="Modern verification and sealing tool for classic MHL files",
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    # seal subcommand. argparse choices= rejects bad algorithm names before
    # we waste a directory walk on them.
    seal_p = subparsers.add_parser(
        "seal",
        help="seal directory (MHL file generated at the root)",
    )
    seal_p.add_argument("path", help="path to directory to seal")
    seal_p.add_argument(
        "-a",
        "--algorithm",
        choices=sorted(ALGO_MAP),
        default="xxhash",
        help="hash algorithm (default: xxhash)",
    )
    seal_p.add_argument(
        "--dont-reseal",
        action="store_true",
        help="abort silently if an MHL with the same timestamp already exists",
    )
    seal_p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print each file's hash as it is sealed, and skipped files",
    )
    seal_p.set_defaults(func=lambda a: seal(a.path, a.algorithm, a.dont_reseal, a.verbose))

    # verify subcommand
    verify_p = subparsers.add_parser("verify", help="verify an MHL file")
    verify_p.add_argument("path", help="path to MHL file")
    verify_p.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print per-file status",
    )
    verify_p.set_defaults(func=lambda a: verify(a.path, a.verbose))

    # xsd-schema-check subcommand
    xsd_p = subparsers.add_parser(
        "xsd-schema-check",
        help="validate XML Schema Definition",
    )
    xsd_p.add_argument("path", help="path to MHL file")
    xsd_p.set_defaults(func=lambda a: validate_schema(a.path))

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
