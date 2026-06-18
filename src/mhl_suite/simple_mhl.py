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

# Registry of the hash algorithms simple-mhl handles, keyed by every CLI / manifest
# spelling we accept. Each value is a (factory, manifest_tag, verify_rank) triple, so
# this one map drives all three jobs at once:
#   * factory      — constructs the hasher used to compute a digest (seal and verify)
#   * manifest_tag — the element name seal writes; aliases collapse, so every xxhash
#                    spelling is recorded as "xxhash64be" for consistency
#   * verify_rank  — preference when an entry records several hashes, fastest preferred
#                    (xxhash > md5 > sha1).
# It is also the recognition set for verify: a hash element whose name isn't a key here
# (and isn't <null>) is ignored exactly as if absent — an entry whose only hash is
# uncomputable falls through to "no supported hash found".
ALGO_MAP: dict[str, tuple[Callable[[], _Hasher], str, int]] = cast(
    "dict[str, tuple[Callable[[], _Hasher], str, int]]",
    {
        "xxhash": (xxhash.xxh64, "xxhash64be", 0),
        "xxh64": (xxhash.xxh64, "xxhash64be", 0),
        "xxhash64": (xxhash.xxh64, "xxhash64be", 0),
        "xxhash64be": (xxhash.xxh64, "xxhash64be", 0),
        "md5": (hashlib.md5, "md5", 1),
        "sha1": (hashlib.sha1, "sha1", 2),
    },
)

# <null> is not a real algorithm — it records no digest, so it ranks after every
# computable algorithm.
_NULL_TAG = "null"
_NULL_RANK = max(rank for *_, rank in ALGO_MAP.values()) + 1


def _seal_tag(key: str) -> str:
    """Manifest element name for a seal algorithm key.

    `null` is a valid seal selection but has no ALGO_MAP entry (it records no
    digest), so it can't go through the normal ALGO_MAP[key][1] lookup.
    """
    return _NULL_TAG if key == _NULL_TAG else ALGO_MAP[key][1]


# `verify -a all` sentinel: verify every recorded hash per entry rather than a
# single fixed format. "all" is reserved — no manifest tag can collide with it.
_VERIFY_ALL = "all"

# The distinct manifest element names seal writes (aliases collapse to these), used
# to validate a verify selection passed by a direct caller.
_CANONICAL_TAGS = frozenset(tag for _factory, tag, _rank in ALGO_MAP.values())


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


def get_hashes(filepath: str, factories: "list[Callable[[], _Hasher]]") -> list[str]:
    """
    Compute several digests of `filepath` in a single read pass.

    `factories` is a list of hasher constructors (the first element of each
    ALGO_MAP entry). Every chunk read from disk is fed to all hashers, so an
    N-format seal costs one disk read instead of N — the read-once paradigm.
    Returns the hex digests as lowercase strings, aligned to `factories`.

    We deliberately do NOT use hashlib.file_digest(): bench measurements showed it is
    5-15% slower than this manual loop on typical media files; the wrapper overhead
    exceeds any internal optimisation it might apply. The manual loop is also
    forward-compatible with xxhash, which file_digest doesn't support anyway.
    """
    hashers: list[_Hasher] = [factory() for factory in factories]
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
            chunk = view[:n]
            for hasher in hashers:
                hasher.update(chunk)
    return [hasher.hexdigest() for hasher in hashers]


def get_hash(filepath: str, algo_key: str) -> str:
    """
    Compute the digest of `filepath` using algorithm `algo_key`.

    Returns the hex digest as a lowercase string. Thin single-format wrapper
    over get_hashes; used by verify (which hashes one format per entry).
    """
    if algo_key not in ALGO_MAP:
        raise ValueError(f"Unsupported hash algorithm: {algo_key}")
    return get_hashes(filepath, [ALGO_MAP[algo_key][0]])[0]


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


def _calibrate_hash_bw_multi(factories: "list[Callable[[], _Hasher]]") -> float:
    """Combined in-RAM throughput (bytes/sec) of updating every hasher per chunk.

    With read-once multi-hashing each chunk is fed to all hashers, so the effective
    hash bandwidth is 1/Σ(1/bw_i) — slower than any single algorithm alone. Running
    the real multi-update loop captures that directly, so the storage probe in
    _hash_jobs_auto compares against the true per-byte cost rather than one algo's.
    """
    buf = bytes(HASH_CHUNK_SIZE)
    hashers = [factory() for factory in factories]
    done = 0
    start = time.perf_counter()
    while time.perf_counter() - start < _AUTO_CALIBRATION_SECONDS:
        for hasher in hashers:
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
    paths: list[str], sizes: list[int], jobs: "list[Callable[[], _T]]", calibrate: "Callable[[], float]"
) -> "Iterator[_T]":
    """Yield each job's result in input order, auto-tuning concurrency to the
    storage (see section comment).

    `paths[i]`/`sizes[i]` describe the file job `i` will read — `paths` drives
    the disk probe, `sizes` (already known from a stat) carve the recheck
    windows — and `jobs[i]` does the hashing. `calibrate` is a zero-arg callable
    returning the in-RAM hash bandwidth (bytes/sec) the job loop sustains; it is
    invoked lazily, only past the small-job early-returns. Shared by seal (which
    measures all its formats combined) and verify (one format).
    """
    n = len(jobs)
    cap = min(_AUTO_MAX_WORKERS, os.cpu_count() or 4)
    # Not worth probing for a single file, a small job, or a uniprocessor.
    if n <= 1 or cap <= 1 or sum(sizes) < _AUTO_MIN_BYTES:
        for job in jobs:
            yield job()
        return

    hash_bw = calibrate()
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


def _hash_files_auto(paths: list[str], sizes: list[int], algorithms: "list[str]") -> "Iterator[tuple[list[str], str]]":
    """Seal helper: yield (digests, hashdate) per path — one digest per algorithm
    in order, plus the ISO-8601 UTC instant hashing finished — auto-tuning
    concurrency.

    The hashdate is captured inside the worker the moment get_hashes returns, so
    it reflects when that file's read-once pass actually completed even when files
    are hashed concurrently in windows (rather than the later emit-loop time).

    get_hashes is resolved at call time (module global) so test monkeypatches still
    intercept it; the combined hash bandwidth of all `algorithms` drives the
    parallelism decision.
    """
    factories = [ALGO_MAP[a][0] for a in algorithms]
    jobs: list[Callable[[], tuple[list[str], str]]] = [
        (lambda p=p: (get_hashes(p, factories), datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))) for p in paths
    ]
    return _hash_jobs_auto(paths, sizes, jobs, lambda: _calibrate_hash_bw_multi(factories))


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


def _resolve_seal_algorithms(algorithms: "list[str]") -> list[str]:
    """Validate seal algorithm keys and collapse alias duplicates (first wins).

    argparse's type= normally catches bad names, but seal() can be called
    directly, so we re-validate here and exit 2 on an unknown algorithm. Aliases
    resolving to the same manifest tag (e.g. xxhash/xxh64/xxhash64be) are deduped,
    preserving first-appearance order, so each tag is emitted at most once.

    `null` records no digest, so combining it with any computable algorithm is
    contradictory and rejected (exit 2).
    """
    for algorithm in algorithms:
        if algorithm != _NULL_TAG and algorithm not in ALGO_MAP:
            sys.stderr.write(f"Error: unsupported algorithm '{algorithm}'\n")
            sys.exit(2)
    if _NULL_TAG in algorithms and any(a != _NULL_TAG for a in algorithms):
        sys.stderr.write("Error: 'null' cannot be combined with other algorithms\n")
        sys.exit(2)
    seen_tags: set[str] = set()
    resolved: list[str] = []
    for a in algorithms:
        tag = _seal_tag(a)
        if tag not in seen_tags:
            seen_tags.add(tag)
            resolved.append(a)
    return resolved


def _resolve_output_dir(root: str, output_dir: "str | None") -> str:
    """Resolve and validate where seal writes the manifest, exiting 2 on a bad choice.

    None keeps the manifest at the sealed root (the historic default). Otherwise it
    must be `root` itself or a parent directory: verify resolves each <file> entry
    relative to the manifest's directory and blocks any '..' escape, so only an
    ancestor keeps the recorded paths traversal-free. Returns the absolute directory.
    """
    if output_dir is None:
        return root
    output_dir = os.path.abspath(output_dir)
    if not os.path.isdir(output_dir):
        sys.stderr.write(f"Error: output directory '{output_dir}' is not a directory\n")
        sys.exit(2)
    if root != output_dir and not root.startswith(output_dir + os.sep):
        sys.stderr.write(f"Error: output directory '{output_dir}' must be the sealed directory or a parent directory\n")
        sys.exit(2)
    return output_dir


def _reject_empty_files(entries: "list[tuple[str, os.stat_result]]", root: str, fd: int, mhl_path: str) -> None:
    """Abort the seal (exit 2) if any walked entry is a zero-byte file.

    The XSD makes <size> mandatory and xs:positiveInteger (>= 1) — so an empty file
    (zero bytes) must not be represented in any seal mode. The scan is a pure in-memory
    pass over the stat info the walk already collected (no extra syscalls), running before
    any hashing so no compute is wasted. On abort it closes + unlinks the O_EXCL manifest
    the caller already claimed.
    """
    empty = [fp for fp, st in entries if st.st_size == 0]
    if not empty:
        return
    os.close(fd)
    os.unlink(mhl_path)

    for fp in empty:
        rel = os.path.relpath(fp, root)
        filename = rel.replace(os.sep, "/") if os.sep != "/" else rel
        sys.stderr.write(f"[ERROR] cannot seal empty file: {filename}\n")

    sys.stderr.write("Remove or exclude any empty files and retry.\n")
    sys.exit(2)


def seal(root: str, algorithms: "list[str]", verbose: bool = False, output_dir: "str | None" = None) -> None:
    """
    Walk `root`, hash every non-excluded file, and write an MHL manifest.

    `algorithms` is one or more hash-algorithm keys (see ALGO_MAP). When more
    than one is given, every file is read once and all digests are computed from
    that single stream (read-once multi-hashing), and the manifest records one
    hash element per format per file.

    `output_dir` chooses where the manifest is written. It defaults to the sealed
    directory root. When given, it must be `root` itself or an ancestor —
    verify resolves each <file> entry relative to the manifest's own directory and
    rejects any entry that escapes it via '..', so only an ancestor keeps every
    recorded path traversal-free. The <file> paths are therefore written relative
    to `output_dir`, gaining a leading "<sealed-folder>/…" prefix when it is a true ancestor.

    Behaviour:
      * Manifest filename: <basename>_<UTC-timestamp>.mhl (named after `root`)
      * Collisions: if the file already exists, append a numeric suffix until
        unique.
      * Hidden files and directories are included; only OS-generated metadata
        (.DS_Store, macOS ._* resource forks, Spotlight/Trash/Time Machine and
        other volume-internal items — see _internal.ignorelist) is skipped.
      * Files that vanish during the walk are skipped without aborting.
      * Concurrency is fully automatic: _hash_files_auto measures the storage
        and parallelises only when that's faster, staying sequential otherwise.

    Output format:
      [OK] <path>  <algo>: <digest>             (verbose only, per hashed file)
      [SKIP] <path> (<reason>)                  (verbose only, skipped entry)
      [WARNING] skipped: <path> (<reason>)      (always, on stderr; dropped dir)
      Created MHL: <path>                        (verbose only, on completion)

    Exits with code 2 on argument errors (handled by argparse before we get
    here) and lets unexpected OSError on the final write propagate so the
    operator sees the real diagnostic.
    """
    algorithms = _resolve_seal_algorithms(algorithms)

    root = os.path.abspath(root)
    if not os.path.isdir(root):
        msg = f"Error: '{root}' is not a directory\n"
        variant = normalization_variant_on_disk(root)
        if variant is not None and os.path.isdir(variant):
            msg += f"  A directory with a different Unicode normalization exists — did you mean:\n    {variant}\n"
        sys.stderr.write(msg)
        sys.exit(2)

    output_dir = _resolve_output_dir(root, output_dir)

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
    mhl_name = f"{base_name}_{timestamp_for_filename}.mhl"
    mhl_path = os.path.join(output_dir, mhl_name)
    suffix = 0
    fd: int | None = None
    while fd is None:
        try:
            fd = os.open(mhl_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o666)
        except FileExistsError:
            suffix += 1
            mhl_path = os.path.join(output_dir, f"{base_name}_{timestamp_for_filename}_{suffix}.mhl")

    # Build the manifest skeleton. We construct in memory and write at the
    # end; for typical shoots (<5000 files) the in-memory tree is a few MB
    # of XML which is fine. For pathologically large trees a streaming
    # writer (etree.xmlfile) would help, but the seal-time cost is
    # dominated by hashing the bytes, not by holding the tree in RAM.
    doc = etree.Element("hashlist", version="1.1")
    etree.SubElement(doc, "creationdate").text = iso_now

    info = _build_creatorinfo(doc, f"simple-mhl {__version__}", iso_now)

    # xml_tags name the manifest element each digest is written into, in the same
    # order _hash_files_auto returns them.
    xml_tags = [_seal_tag(a) for a in algorithms]

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

    # Refuse zero-byte files before any hashing (see _reject_empty_files); on abort
    # it releases the O_EXCL manifest fd we claimed above.
    _reject_empty_files(entries, root, fd, mhl_path)

    paths = [fp for fp, _ in entries]
    # `null` records no digest, so a null seal reads no bytes — each entry just gets
    # an empty <null> and the run timestamp. Any other selection hashes for real,
    # auto-tuning concurrency to the storage.
    is_null = algorithms == [_NULL_TAG]
    if is_null:
        digests: Iterator[tuple[list[str], str]] = (([""], iso_now) for _ in entries)
    else:
        digests = _hash_files_auto(paths, [st.st_size for _, st in entries], algorithms)

    for (filepath, stat_result), (file_digests, hashdate) in zip(entries, digests, strict=True):
        # Paths are relative to the manifest's own directory (output_dir) so
        # verify resolves them correctly; this equals root in the default case.
        rel_path = os.path.relpath(filepath, output_dir)
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
        # One hash element per format, in resolved order, then <hashdate>.
        for xml_tag, digest in zip(xml_tags, file_digests, strict=True):
            etree.SubElement(h, xml_tag).text = digest
        if verbose:
            if is_null:
                print(f"[OK] {rel_path_posix}  size: {stat_result.st_size}")
            else:
                shown = "  ".join(f"{t}: {d}" for t, d in zip(xml_tags, file_digests, strict=True))
                print(f"[OK] {rel_path_posix}  {shown}")
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
        msg = f"Error: {mhl_file} not found\n"
        variant = normalization_variant_on_disk(mhl_file)
        if variant is not None:
            shown = variant if os.path.isabs(mhl_file) else os.path.relpath(variant)
            msg += f"  A path with a different Unicode normalization exists — did you mean:\n    {shown}\n"
        sys.stderr.write(msg)
        sys.exit(1)
    if os.path.isdir(mhl_file):
        if os.path.basename(os.path.normpath(mhl_file)) == "ascmhl":
            sys.stderr.write(
                f"Error: '{mhl_file}' is an ASC-MHL v2 package directory.\n"
                "simple-mhl only handles classic MHL files. "
                "You may want to use mhlver to verify this ASC-MHL.\n"
            )
        else:
            sys.stderr.write(
                f"Error: '{mhl_file}' is a directory.\n"
                "The verify command requires a path to an MHL file (e.g. manifest.mhl).\n"
            )
        sys.exit(1)
    if not mhl_file.lower().endswith(".mhl"):
        sys.stderr.write(
            f"Error: '{mhl_file}' does not have a .mhl extension.\n"
            "The verify command requires a path to an MHL file (e.g. manifest.mhl).\n"
        )
        sys.exit(1)


def _is_newer_than_classic(version: str) -> bool:
    """
    True if a `version` attribute's major component is newer than classic MHL:
    classic manifests are 1.x, ASC-MHL is 2.0+. Comparing only the major part
    means minor differences within v1 don't matter and multi-part future versions
    like 2.1.1 are handled. An empty or unparsable value is treated as not-newer.
    """
    try:
        return int(version.split(".", maxsplit=1)[0]) > 1
    except ValueError:
        return False


def _reject_ascmhl_v2(mhl_file: str) -> None:
    """
    Reject an ASC-MHL v2 manifest, redirecting the operator to mhlver.

    We detect the v2 root up front: a root namespace of urn:ASC:MHL:v2.0, or a
    `version` higher than classic MHL's 1.1 (so future 2.x/3.x/10.x are caught
    even without the namespace). Malformed XML is left to verify()'s main loop,
    which maps it to exit 20 — so swallow parse errors here.
    """
    try:
        for _, root in etree.iterparse(mhl_file, events=("start",)):
            ns = etree.QName(root).namespace
            if ns == "urn:ASC:MHL:v2.0" or _is_newer_than_classic(root.get("version", "")):
                sys.stderr.write(
                    f"Error: '{mhl_file}' is an ASC-MHL v2 manifest.\n"
                    "simple-mhl only handles classic MHL files. "
                    "You may want to use mhlver to verify this ASC-MHL.\n"
                )
                sys.exit(1)
            break  # the root element is all we need
    except (etree.XMLSyntaxError, OSError):
        return


# xxHash tags may be big-endian or little-endian hex, and have historically carried a
# 32-bit integer, so verify must account for all of those cases:
#   * xxhash64be — XXH64 as big-endian hex (the canonical modern form)
#   * xxhash64   — the above, or XXH64 as little-endian hex
#   * xxhash     — the above, or XXH32 as a decimal integer (very old form!)
# Only one digest is computed per entry: the stored value's shape selects which.
_XXH64_BE_ONLY = frozenset({"xxhash64be"})
_XXH64_BE_OR_LE = frozenset({"xxhash64", "xxh64"})
# A 32-bit XXH32 in decimal is at most 10 digits (leading zeros might have been stripped).
# A longer all-digit value under <xxhash> is therefore hex, not a decimal integer.
_XXH32_MAX_DECIMAL_DIGITS = 10

# Verify-only factories. XXH32 is needed to recompute the oldest decimal xxHash but is
# never offered for sealing, so it stays out of ALGO_MAP. Cast for the same reason
# ALGO_MAP is: xxhash's constructor parameter names differ from the _Hasher protocol.
_XXH64_FACTORY = cast("Callable[[], _Hasher]", xxhash.xxh64)
_XXH32_FACTORY = cast("Callable[[], _Hasher]", xxhash.xxh32)


def _swap64(value: int) -> int:
    """Return a 64-bit value with its byte order reversed (big-endian <-> little-endian)."""
    return int.from_bytes(value.to_bytes(8, "big"), "little")


def _matches_be(expected: str, computed: int) -> bool:
    """True if `expected` (hex) equals `computed` (a big-endian intdigest), strictly."""
    try:
        return int(expected, 16) == computed
    except ValueError:
        return False


def _matches_be_or_le(expected: str, computed: int) -> bool:
    """True if `expected` (hex) equals `computed` in either byte order.

    The two orders are reorderings of the same hash, so accepting both only rescues an
    intact file recorded in the opposite endianness — it never lets a differing file pass.
    """
    try:
        stored = int(expected, 16)
    except ValueError:
        return False
    return stored == computed or stored == _swap64(computed)


def _matches_decimal(expected: str, computed: int) -> bool:
    """True if `expected` (a decimal integer) equals `computed` (an intdigest)."""
    try:
        return int(expected) == computed
    except ValueError:
        return False


def _xxhash_route(localname: str, expected: str) -> "tuple[Callable[[], _Hasher], Callable[[str], bool]] | None":
    """Choose the single hash to compute for an xxHash element and the rule that accepts
    its stored value.

    Returns (factory, matches): `matches` receives the computed big-endian hex digest.
    Returns None when `localname` is not an xxHash tag (e.g. md5/sha1), so the caller
    uses its normal path. The stored value's shape decides which algorithm to compute,
    so a hex digest never pays to compute XXH32: a 16-character hex value is XXH64; a
    decimal value of up to 10 digits (leading zeros may have been dropped) is a 32-bit XXH32.
    """
    name = localname.lower()
    if name in _XXH64_BE_ONLY:
        return _XXH64_FACTORY, lambda calc: _matches_be(expected, int(calc, 16))
    if name in _XXH64_BE_OR_LE:
        return _XXH64_FACTORY, lambda calc: _matches_be_or_le(expected, int(calc, 16))
    if name == "xxhash":
        if expected.isdecimal() and len(expected) <= _XXH32_MAX_DECIMAL_DIGITS:
            return _XXH32_FACTORY, lambda calc: _matches_decimal(expected, int(calc, 16))
        return _XXH64_FACTORY, lambda calc: _matches_be_or_le(expected, int(calc, 16))
    return None


def _make_ci_matcher(expected: str) -> "Callable[[str], bool]":
    """Return a case-insensitive exact-hex matcher for a non-xxHash digest.

    md5/sha1 are plain hex with no endianness or legacy-integer ambiguity, so the
    rule is a straight case-folded compare — the counterpart to _xxhash_route's
    shape-aware matchers, in the same (computed hex) -> bool shape so _verify_hashes
    can treat every check uniformly.
    """
    lowered = expected.lower()
    return lambda calc: calc.lower() == lowered


def _verify_hashes(candidate: str, checks: "list[tuple[str, str]]", rel_path: str, verbose: bool) -> tuple[str, str]:
    """Verify `candidate` against every (tag, expected) pair in `checks`, hashing in
    a single read pass, and return the combined ("ok"|"mismatch", line) result.

    The file is OK only when every check matches; any single mismatch fails the
    entry. All digests come from one read of the file (read-once via get_hashes), so
    verifying N recorded hashes costs one disk pass, not N. Per-file ValueError/OSError
    are caught and returned as a line so a thread-pool worker reports rather than
    tearing down the whole verify.

    With exactly one check the output is byte-identical to the historic single-hash
    form, so default and `-a <algo>` verifies are unchanged; the multi-line detail is
    produced only for `-a all` on an entry that records several hashes.
    """
    factories: list[Callable[[], _Hasher]] = []
    plans: list[tuple[str, str, Callable[[str], bool]]] = []
    for tag, raw_expected in checks:
        expected = raw_expected.strip()
        route = _xxhash_route(tag, expected)
        if route is not None:
            factory, matches = route
        else:
            factory, matches = ALGO_MAP[tag][0], _make_ci_matcher(expected)
        factories.append(factory)
        plans.append((tag, expected, matches))

    try:
        calculated = get_hashes(candidate, factories)
    except (ValueError, OSError) as e:
        return ("mismatch", f"[ERROR] cannot verify {rel_path}: {e}")

    checked = [
        (tag, expected, calc, matches(calc)) for (tag, expected, matches), calc in zip(plans, calculated, strict=True)
    ]

    if all(ok for *_, ok in checked):
        shown = "  ".join(f"{tag}: {calc}" for tag, _e, calc, _ok in checked)
        return ("ok", f"{rel_path}  {shown}")
    if not verbose:
        return ("mismatch", f"[ERROR] hash mismatch: {rel_path}")
    if len(checked) == 1:
        tag, expected, calc, _ok = checked[0]
        return (
            "mismatch",
            f"[ERROR] hash mismatch: {rel_path}\n        (calc {tag}: {calc} | stored {tag}: {expected})",
        )
    lines = [f"[ERROR] hash mismatch: {rel_path}"]
    for tag, expected, calc, ok in checked:
        lines.append(f"        {tag} {'OK' if ok else 'MISMATCH'}: calc {calc} | stored {expected}")
    return ("mismatch", "\n".join(lines))


def _manifest_tag_of(localname: str) -> str:
    """Normalize a hash element's local name to its canonical manifest tag.

    Aliases collapse the way seal records them (xxhash/xxh64/xxhash64 →
    xxhash64be); unknown / read-only tags pass through unchanged. Lets an
    `-a xxhash` override match a recorded <xxhash64be> (or legacy <xxhash>).
    """
    entry = ALGO_MAP.get(localname)
    return entry[1] if entry is not None else localname


def _verify_rank(name: str) -> "int | None":
    """Return verify's preference for a hash element's local-name, or None to ignore it.

    Computable algorithms rank by their ALGO_MAP entry; <null> ranks last. Any
    other tag — one we cannot recompute — returns None, so the selector skips it as if
    the element were absent.
    """
    entry = ALGO_MAP.get(name)
    if entry is not None:
        return entry[2]
    return _NULL_RANK if name == _NULL_TAG else None


def _select_hash_nodes(
    h: "etree._Element", selection: "str | list[str] | None"
) -> "tuple[list[tuple[etree._Element, str]], list[str] | None]":
    """Pick which child hash element(s) of `h` to verify.

    `selection` is one of:
      * None             — verify the single fastest recorded hash (default)
      * _VERIFY_ALL      — verify every recorded recognised hash (`-a all`)
      * list of manifest tags — verify exactly those formats (`-a md5,xxhash`)

    Returns (nodes, missing). On success `nodes` is a non-empty list of
    (element, localname) and `missing` is None. Otherwise `nodes` is empty and
    `missing` is: a non-empty (sorted) list of requested tags not recorded for this
    entry, or [] when nothing recognised is recorded at all.

    For a list selection, requested order is irrelevant — matching nodes are returned
    in manifest document order, so `-a md5,sha1` and `-a sha1,md5` verify identically.

    A <null> entry carries no digest, so it is only ever selected alone and only when
    no computable hash is recorded — the caller then verifies it by size.
    """
    candidates: list[tuple[int, etree._Element, str]] = []
    for child in h:
        name = _localname(child.tag)
        rank = _verify_rank(name)
        if rank is not None:
            candidates.append((rank, child, name))
    real = [(rank, node, name) for rank, node, name in candidates if name != _NULL_TAG]
    null = next(((node, name) for _r, node, name in candidates if name == _NULL_TAG), None)

    if isinstance(selection, list):
        # A specific -a md5,sha1: verify exactly the requested tags, document order.
        wanted = set(selection)
        chosen = [(node, name) for _r, node, name in real if _manifest_tag_of(name) in wanted]
        found = {_manifest_tag_of(name) for _node, name in chosen}
        missing = sorted(t for t in wanted if t not in found)
        return ([], missing) if missing else (chosen, None)
    if not real:
        # No computable hash: fall back to <null> (size-only) if present.
        return ([null], None) if null is not None else ([], [])
    if selection == _VERIFY_ALL:
        return [(node, name) for _rank, node, name in real], None
    # Default: the single fastest recorded hash (lowest rank).
    _rank, node, name = min(real, key=lambda c: c[0])
    return [(node, name)], None


def _size_check(
    h: "etree._Element", candidate: str, rel_path: str, verbose: bool
) -> "tuple[int | None, tuple[str, str] | None]":
    """Compare the manifest's <size> against the file on disk.

    Returns (actual_size, None) when the recorded size matches — actual_size is
    handed back so the hash phase can reuse it to carve recheck windows without a
    second stat(). Returns (None, None) when the entry records no <size> at all
    (nothing to pre-check). Returns (None, outcome) when there is something to
    report: a malformed <size>, a file that vanished, or a size mismatch.
    """
    size_el = h.find("{*}size")
    if size_el is None or size_el.text is None:
        return None, None
    # isdecimal() rejects superscripts/other Unicode "digits" that int() would
    # silently convert to the wrong value (corruption or tampering).
    size_text = size_el.text.strip()
    if not size_text.isdecimal():
        return None, ("mismatch", f"[ERROR] malformed size field: {rel_path}")
    try:
        actual_size = os.path.getsize(candidate)
    except OSError:
        # Vanished between resolution and getsize() — report missing rather than
        # a bare OSError traceback.
        return None, ("missing", f"[ERROR] missing file: {rel_path}")
    manifest_size = int(size_text)
    if manifest_size != actual_size:
        if verbose:
            return None, (
                "mismatch",
                f"[ERROR] size mismatch: {rel_path}\n        (calc size: {actual_size} | stored size: {manifest_size})",
            )
        return None, ("mismatch", f"[ERROR] size mismatch: {rel_path}")
    return actual_size, None


def verify(  # noqa: C901 — flat per-entry verify ladder, not nested complexity
    mhl_file: str, verbose: bool = False, algorithm: "str | list[str] | None" = None, size_only: bool = False
) -> None:
    """
    Verify each file listed in `mhl_file` against its stored hash.

    Behaviour:
      * Default mode: silent on success; on failure, prints one line per
        problem file with a structured prefix (`ERROR: <category>: <path>`).
      * Verbose mode (verbose=True): also prints `[OK] <path>  <algo>: <digest>`
        for every successfully verified file — naming the algorithm actually
        checked (the fastest recorded, or the -a override) — mirroring
        ascmhl-debug's --verbose.
      * Algorithm selection: by default each entry is verified with the fastest
        recorded hash (xxhash > md5 > sha1). `algorithm` overrides this — it may be a
        single ALGO_MAP key, a list of canonical manifest tags, or the sentinel "all""
        (_VERIFY_ALL) for every recorded hash. Verifying several hashes still reads
        the file once, and the entry passes only if every checked hash matches.
      * Size-only mode (size_only=True): skip hashing entirely and verify each
        entry by comparing its recorded <size> against the file on disk — a fast
        check that catches missing and wrong-length files without reading their
        bytes. An entry with no recorded <size> is reported as a mismatch.
      * Path traversal attempts (manifest entries with ../ that escape the
        manifest's directory) are blocked and reported as mismatches.

      * Malformed XML exits 20 with no further output.

    Output format:
      [OK] <path>  <algo>: <digest>                (verbose only, success)
      [OK] <path>  <algo>: <digest>  <algo>: <digest>   (verbose, -a all, multi-hash)
      [OK] <path>  size: <bytes>                   (verbose only, size-only success)
      [OK] <path>  (existence-only check — …)      (verbose, <null> entry lacking <size>)
      [ERROR] hash mismatch: <path>                (verify failure)
      [ERROR] size mismatch: <path>                (size/size-only failure)
      [ERROR] missing file: <path>                 (file not on disk)
      [ERROR] no size recorded: <path>             (size-only, entry lacks <size>)
      [ERROR] blocked traversal attempt: <path>    (security)
      [ERROR] no supported hash found: <path>      (manifest malformed)
      [ERROR] requested hash(es) <algo…> not recorded: <path>  (-a selection absent)
      [ERROR] cannot verify <path>: <reason>       (algorithm not available)

    Exit codes:
       0 = clean
      20 = malformed XML
      30 = missing files only
      40 = hash mismatches only
      70 = both missing and mismatches
    """
    _validate_mhl_path(mhl_file)
    _reject_ascmhl_v2(mhl_file)

    # Resolve the optional -a value to a selection: None (fastest single),
    # _VERIFY_ALL (every recorded hash), or a list of canonical manifest tags.
    # argparse's type= guards the CLI; normalise + defend direct callers too.
    selection: str | list[str] | None
    if algorithm is None or algorithm == _VERIFY_ALL:
        selection = algorithm
    elif isinstance(algorithm, str):
        if algorithm not in ALGO_MAP:
            sys.stderr.write(f"Error: unsupported algorithm '{algorithm}'\n")
            sys.exit(2)
        selection = [ALGO_MAP[algorithm][1]]
    else:
        for tag in algorithm:
            if tag not in _CANONICAL_TAGS:
                sys.stderr.write(f"Error: unsupported algorithm '{tag}'\n")
                sys.exit(2)
        selection = algorithm

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

    # Track which weak (non-hash) <null> checks were relied on and whether any entry
    # was hash-verified, so the emit phase can print a one-time notice that names the
    # kinds used and distinguishes a fully weak-checked manifest from a mixed one. A
    # <null> with a recorded <size> is a size-only check; one without is existence-only
    # (neither hash nor size verified) — the two are surfaced distinctly.
    saw_size_only = False
    saw_existence_only = False
    saw_hash = False

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

            # --- Size-only mode -----------------------------------------
            # Skip hashing altogether: existence plus a <size> match is the whole
            # check. This is the operator opting into size-only from the CLI for a fast
            # check — the same "existence + size" idea as a <null> tag, but applied
            # wholesale and explicitly. The no-<size> policy diverges on purpose: here an
            # entry without a recorded <size> is a mismatch (the operator asked to
            # check sizes and there's nothing to check), whereas a <null> entry with
            # no <size> passes on existence alone (XSD lists file sizes as optional).
            if size_only:
                actual_size, size_outcome = _size_check(h, candidate, rel_path, verbose)
                if size_outcome is not None:
                    results.append(size_outcome)
                elif actual_size is None:
                    results.append(
                        (
                            "mismatch",
                            f"[ERROR] no size recorded: {rel_path} "
                            "(try 'simple-mhl verify' for full hash verification)",
                        )
                    )
                else:
                    results.append(("ok", f"{rel_path}  size: {actual_size}"))
                h.clear()
                continue

            # Pick which recorded hash(es) to verify: the fastest computable one by
            # default, the -a override's format, or every recorded hash for -a all.
            nodes, missing = _select_hash_nodes(h, selection)
            if not nodes:
                if missing:  # requested hash(es) not stored for this entry
                    label = "hash" if len(missing) == 1 else "hashes"
                    results.append(
                        ("mismatch", f"[ERROR] requested {label} {', '.join(missing)} not stored: {rel_path}")
                    )
                else:  # nothing recognised recorded at all
                    results.append(("mismatch", f"[ERROR] no supported hash found: {rel_path}"))
                h.clear()
                continue

            # A single <null> node means this entry carries no hash. Flag which kind
            # of weak check it is now (before the size check) so the notice fires even
            # when the size mismatches; _select_hash_nodes only returns <null> alone.
            # A recorded <size> makes it size-only; its absence (mirroring _size_check)
            # makes it existence-only.
            is_null_entry = len(nodes) == 1 and nodes[0][1] == _NULL_TAG
            if is_null_entry:
                size_el = h.find("{*}size")
                if size_el is not None and size_el.text is not None:
                    saw_size_only = True
                else:
                    saw_existence_only = True

            # --- File size pre-check ------------------------------------
            # Compare the manifest's <size> against the file before spending a
            # full hash pass — a size mismatch is definitive and costs one stat().
            # actual_size is reused below to size the parallel hash recheck windows.
            actual_size, size_outcome = _size_check(h, candidate, rel_path, verbose)
            if size_outcome is not None:
                results.append(size_outcome)
                h.clear()
                continue

            # 'null' tag records no digest: existence + size are the whole check.
            # This is the sealer opting one entry into size-only at seal time. Note
            # the deliberate divergence from -S below: here a missing <size> is fine
            # (file sizes are optional on the XSD, so existence alone passes), whereas
            # under -S an absent <size> is a failure because the operator explicitly
            # asked to check sizes and there's nothing to check.
            # _select_hash_nodes only ever returns <null> alone and only when no
            # computable hash is recorded, so a single null node is the whole entry.
            if is_null_entry:
                if actual_size is not None:
                    results.append(("ok", f"{rel_path}  size: {actual_size} (size-only check - no hash stored)"))
                else:
                    results.append(("ok", f"{rel_path}  (existence-only check — no hash or size stored)"))
                h.clear()
                continue

            # Needs a hash pass — defer it to the parallel phase. No hashing happens
            # here, so the size pre-check above still short-circuits a corrupt-size
            # file first. `checks` pairs each selected format with its stored digest;
            # _verify_hashes computes them all in one read pass.
            saw_hash = True
            checks = [(name, node.text or "") for node, name in nodes]
            slot = len(results)
            results.append(None)
            hash_slots.append(slot)
            hash_paths.append(candidate)
            hash_sizes.append(actual_size if actual_size is not None else 0)
            hash_jobs.append(lambda c=candidate, ck=checks, r=rel_path: _verify_hashes(c, ck, r, verbose))
            # Calibrate the storage probe against the first deferred algorithm.
            if calib_algo is None:
                calib_algo = checks[0][0]

            # Free this element and all already-processed siblings.
            h.clear()
            parent = h.getparent()
            if parent is not None:
                while h.getprevious() is not None:
                    del parent[0]

    except (etree.XMLSyntaxError, OSError):
        sys.exit(20)

    # --- Parallel hash phase -------------------------------------------------
    # Hash the deferred entries, auto-tuning concurrency to the storage exactly as seal
    # does. calib_algo is set alongside the first deferred entry, so "is not None" here
    # is equivalent to "there are entries to hash" and narrows it for the probe.
    if calib_algo is not None:
        hashed: list[tuple[str, str]] = list(
            _hash_jobs_auto(hash_paths, hash_sizes, hash_jobs, lambda: _calibrate_hash_bw(calib_algo))
        )
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

    # A <null> entry carries no hash — surface that the manifest verified some or all
    # files on size or existence alone, naming the kinds used so an existence-only pass
    # (no size checked either) doesn't read as a size-only one. Printed regardless of
    # -v and before any failure exit, so it shows on success and failure alike.
    if saw_size_only or saw_existence_only:
        kinds = []
        if saw_size_only:
            kinds.append("size-only")
        if saw_existence_only:
            kinds.append("existence-only")
        kind_phrase = " and ".join(kinds)
        if saw_hash:
            print(f"Partially verified with {kind_phrase} checks (some hashes missing from the manifest).")
        else:
            # No hashes are stored either way. Sizes are: all present (size-only only),
            # all absent (existence-only only), or partial (a mix of both null kinds).
            if not saw_existence_only:
                stored = "hashes"
            elif saw_size_only:
                stored = "hashes and some sizes"
            else:
                stored = "hashes and sizes"
            print(f"Verified with {kind_phrase} checks ({stored} missing from the manifest).")

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
        sys.stderr.write(f"Error: XML parsing failed - {e}\n")
        sys.exit(20)
    except OSError as e:
        sys.stderr.write(f"Error: file read failed - {e}\n")
        sys.exit(20)

    if not xsd.validate(tree):
        for err in xsd.error_log:
            sys.stderr.write(f"Error: XSD validation failed - {err.message} (line {err.line})\n")
        sys.exit(10)


# -----------------------------------------------------------------------------
# CLI entry point
# -----------------------------------------------------------------------------


def _dedup_keys_by_tag(keys: list[str]) -> list[str]:
    """De-duplicate ALGO_MAP keys by their manifest tag, first occurrence wins.

    Aliases resolving to the same manifest tag collapse, so `xxhash` and
    `xxh64` together record a single <xxhash64be>.
    """
    out: list[str] = []
    seen_tags: set[str] = set()
    for name in keys:
        tag = _seal_tag(name)
        if tag not in seen_tags:
            seen_tags.add(tag)
            out.append(name)
    return out


def parse_algorithms(value: str) -> list[str]:
    """argparse type= for `seal -a`: parse a comma-separated list of algorithm
    names into a validated, de-duplicated list of ALGO_MAP keys.

    Aliases resolving to the same manifest tag are collapsed (first wins), so
    `-a xxhash,xxh64` records a single <xxhash64be>. `null` (no digest) is accepted
    here; its exclusivity is enforced later in _resolve_seal_algorithms.
    Unknown names raise argparse.ArgumentTypeError, which argparse turns into a
    usage error (exit 2).
    """
    keys: list[str] = []
    for raw in value.split(","):
        name = raw.strip().lower()
        if not name:
            continue
        if name != _NULL_TAG and name not in ALGO_MAP:
            raise argparse.ArgumentTypeError(
                f"unsupported algorithm '{name}' (choose from {', '.join(sorted([*ALGO_MAP, _NULL_TAG]))})"
            )
        keys.append(name)
    if not keys:
        raise argparse.ArgumentTypeError("no algorithm given")
    return _dedup_keys_by_tag(keys)


def combine_seal_algorithms(parsed: list[list[str]] | None) -> list[str]:
    """Merge repeated `seal -a` occurrences into one de-duplicated key list.

    With action="append" each `-a` yields its own parsed list, so `-a md5
    -a sha1` arrives as [["md5"], ["sha1"]]. None means no `-a` was given,
    so we fall back to the historic default of xxhash.
    """
    if not parsed:
        return ["xxhash"]
    flat = [name for group in parsed for name in group]
    return _dedup_keys_by_tag(flat)


def parse_verify_algorithms(value: str) -> "str | list[str]":
    """argparse type= for `verify -a`: parse a comma-separated list of algorithm names
    or the keyword 'all'.

    Returns the _VERIFY_ALL sentinel if 'all' appears anywhere (it supersedes any
    specific names), otherwise a de-duplicated list of canonical manifest tags
    (aliases collapse, e.g. xxhash/xxh64 → xxhash64be). Requested order is preserved
    for the error message only; selection itself is order-independent. Unknown names
    raise argparse.ArgumentTypeError, which argparse turns into a usage error (exit 2).
    """
    names = [raw.strip().lower() for raw in value.split(",")]
    names = [n for n in names if n]
    if not names:
        raise argparse.ArgumentTypeError("no algorithm given")
    if _VERIFY_ALL in names:
        return _VERIFY_ALL
    tags: list[str] = []
    seen: set[str] = set()
    for name in names:
        if name not in ALGO_MAP:
            raise argparse.ArgumentTypeError(
                f"unsupported algorithm '{name}' (choose from all, {', '.join(sorted(ALGO_MAP))})"
            )
        tag = ALGO_MAP[name][1]
        if tag not in seen:
            seen.add(tag)
            tags.append(tag)
    return tags


def combine_verify_algorithms(
    parsed: "list[str | list[str]] | None",
) -> "str | list[str] | None":
    """Merge repeated `verify -a` occurrences into one selection.

    With action="append" each `-a` yields its own parsed value, so `-a md5
    -a sha1` arrives as [["md5"], ["sha1"]]. None means no `-a` was given
    (verify the fastest available). 'all' supersedes any specific names, and
    specific tags are flattened and de-duplicated in order.
    """
    if not parsed:
        return None
    if _VERIFY_ALL in parsed:
        return _VERIFY_ALL
    tags: list[str] = []
    seen: set[str] = set()
    for group in parsed:
        for tag in group:
            if tag not in seen:
                seen.add(tag)
                tags.append(tag)
    return tags


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

    # -v / --verbose is a global flag: sharing it through a parent parser lets it
    # appear either before or after the subcommand, so "simple-mhl -v seal ." and
    # "simple-mhl seal -v ." behave identically. default=SUPPRESS is essential:
    # without it the subparser's own default would clobber a True set by the
    # top-level parser. With SUPPRESS, the attribute is only written when -v is
    # actually present, so whichever parser sees it wins; we fall back to False
    # below when it appears nowhere.
    global_opts = argparse.ArgumentParser(add_help=False)
    global_opts.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=argparse.SUPPRESS,
        help="enable verbose output (accepted before or after the subcommand)",
    )

    parser = argparse.ArgumentParser(
        prog="simple-mhl",
        description="Modern verification and sealing tool for classic MHL files",
        parents=[global_opts],
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    # seal subcommand. argparse choices= rejects bad algorithm names before
    # we waste a directory walk on them.
    seal_p = subparsers.add_parser(
        "seal",
        help="seal a directory",
        parents=[global_opts],
    )
    seal_p.add_argument("path", help="path to directory to seal")
    seal_p.add_argument(
        "-a",
        "--algorithm",
        type=parse_algorithms,
        action="append",
        default=None,
        metavar="ALGO[,ALGO...]",
        help="hash algorithm: xxhash (default), md5, sha1, null (size-only)",
    )
    seal_p.add_argument(
        "-o",
        "--output-dir",
        dest="output_dir",
        default=None,
        metavar="DIR",
        help="directory to write the MHL into (default: directory root)",
    )
    seal_p.set_defaults(func=lambda a: seal(a.path, combine_seal_algorithms(a.algorithm), a.verbose, a.output_dir))

    # verify subcommand
    verify_p = subparsers.add_parser("verify", help="verify an MHL file", parents=[global_opts])
    verify_p.add_argument("path", help="path to MHL file")
    verify_p.add_argument(
        "-a",
        "--algorithm",
        type=parse_verify_algorithms,
        action="append",
        default=None,
        metavar="ALGO[,ALGO...]",
        help="hash algorithm: xxhash, md5, sha1, or all (default: fastest)",
    )
    verify_p.add_argument(
        "-S",
        "--size-only",
        action="store_true",
        help="check file sizes only (skip hashing)",
    )
    verify_p.set_defaults(func=lambda a: verify(a.path, a.verbose, combine_verify_algorithms(a.algorithm), a.size_only))

    # xsd-schema-check subcommand
    xsd_p = subparsers.add_parser(
        "xsd-schema-check",
        help="validate against XML Schema Definition",
        parents=[global_opts],
    )
    xsd_p.add_argument("path", help="path to MHL file")
    xsd_p.set_defaults(func=lambda a: validate_schema(a.path))

    # --- '-h <algo>' (instead of -a <algo>) hint ------------------------------
    # A user who typed 'seal -h xxhash' probably meant '-a xxhash' ('-h' for "hash"
    # instead of -a for "algorithm"). So when '-h' is immediately followed by a
    # valid algorithm name, we prepend a hint to the help menu.
    _argv = sys.argv[1:]
    for _i in range(len(_argv) - 1):
        if _argv[_i] not in ("-h", "--help"):
            continue
        _sub = next((t for t in _argv[:_i] if t in _SUBCOMMANDS), None)
        if _sub not in ("seal", "verify"):
            continue
        _valid = set(ALGO_MAP) | ({_VERIFY_ALL} if _sub == "verify" else {_NULL_TAG})
        _algo = _argv[_i + 1]
        if _algo in _valid:
            print(f"\nDid you mean '-a {_algo}' (-a / --algorithm)?\n", file=sys.stderr)
            {"seal": seal_p, "verify": verify_p}[_sub].print_help()
            sys.exit(2)

    args = parser.parse_args()
    # SUPPRESS leaves verbose unset when -v is given nowhere; normalise to False.
    if not hasattr(args, "verbose"):
        args.verbose = False
    args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
