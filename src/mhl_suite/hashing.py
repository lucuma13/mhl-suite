"""
Hashing engine and algorithm registry.

The read-once multi-hash loop, the algorithm registry (ALGO_MAP), and the adaptive parallel-hashing controller that
both seal and verify drive. This is the leaf of the suite — it imports nothing else from mhl_suite.

Cross-module callers (classic_verify, classic_seal) reach these functions through the module object (e.g. `from
mhl_suite import hashing; hashing.get_hashes`) so a test monkeypatching `mhl_suite.hashing.get_hashes` /
`_probe_read_bw` / the calibration helpers still intercepts the call.
"""

import hashlib
import os
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Protocol, TypeVar, cast, runtime_checkable

import xxhash

# Generic result type for the shared hashing controller (str digests for seal, (kind, line) tuples for verify).
_T = TypeVar("_T")


# -----------------------------------------------------------------------------
# Hasher protocol
# -----------------------------------------------------------------------------
# Both xxhash and hashlib hashers expose .update() and .hexdigest() but share no common ABC. We define a structural
# Protocol so the type checker understands what ALGO_MAP factories return without depending on private hashlib
# internals.


@runtime_checkable
class _Hasher(Protocol):
    # Real hashers (xxhash, hashlib) accept any bytes-like buffer; we feed a memoryview slice from readinto(), so the
    # annotation must be wider than bytes.
    def update(self, data: "bytes | bytearray | memoryview") -> None: ...
    def hexdigest(self) -> str: ...


# ---------------------------------------------------------------------------------------------------------------------
# Constants and lookups
# ---------------------------------------------------------------------------------------------------------------------

# 1 MiB chunk size for streaming hashing is the (shallow) optimum: large enough to amortise read() syscall overhead,
# small enough to stay in CPU cache. Above ~4 MiB the bigger chunk only adds cache pressure. On a 1000 MB/s external SSD
# the choice barely moves the needle, seal is fully disk-bound (every supported hash runs faster than the disk delivers
# bytes), so the file read, not this loop, sets the pace.
HASH_CHUNK_SIZE = 1024 * 1024

# Registry of the hash algorithms simple-mhl handles, keyed by every CLI / manifest spelling we accept. Each value is a
# (factory, manifest_tag, verify_rank) triple, so this one map drives all three jobs at once:
#   * factory      — constructs the hasher used to compute a digest (seal and verify)
#   * manifest_tag — the element name seal writes; aliases collapse, so every xxhash spelling is recorded as
#                    "xxhash64be" for consistency
#   * verify_rank  — preference when an entry records several hashes, fastest preferred (xxhash > md5 > sha1). It is
#                    also the recognition set for verify: a hash element whose name isn't a key here (and isn't <null>)
# is ignored exactly as if absent — an entry whose only hash is uncomputable falls through to "no supported hash found".
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

# <null> is not a real algorithm — it records no digest, so it ranks after every computable algorithm.
_NULL_TAG = "null"
_NULL_RANK = max(rank for *_, rank in ALGO_MAP.values()) + 1


def _seal_tag(key: str) -> str:
    """
    Manifest element name for a seal algorithm key.

    `null` is a valid seal selection but has no ALGO_MAP entry (it records no digest), so it can't go through the normal
    ALGO_MAP[key][1] lookup.
    """
    return _NULL_TAG if key == _NULL_TAG else ALGO_MAP[key][1]


# ---------------------------------------------------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------------------------------------------------


def get_hashes(
    filepath: str,
    factories: "list[Callable[[], _Hasher]]",
    on_progress: "Callable[[int], None] | None" = None,
) -> list[str]:
    """
    Compute several digests of `filepath` in a single read pass.

    `factories` is a list of hasher constructors (the first element of each ALGO_MAP entry). Every chunk read from disk
    is fed to all hashers, so an N-format seal costs one disk read instead of N — the read-once paradigm. Returns the
    hex digests as lowercase strings, aligned to `factories`.

    `on_progress`, if given, is called with the byte count of each chunk as it is read (every HASH_CHUNK_SIZE bytes), so
    a caller can drive a progress bar that advances *within* a large file rather than jumping once it finishes. It may
    be invoked from a worker thread when the adaptive controller hashes files concurrently, so the callback must be
    thread-safe.

    We deliberately do NOT use hashlib.file_digest(): bench measurements showed it is 5-15% slower than this manual loop
    on typical media files; the wrapper overhead exceeds any internal optimisation it might apply. The manual loop is
    also forward-compatible with xxhash, which file_digest doesn't support anyway.
    """
    hashers: list[_Hasher] = [factory() for factory in factories]
    # readinto() reuses one buffer for the whole file instead of allocating a fresh bytes object per chunk, removing
    # per-chunk allocation/GC churn — measured a few percent faster than read() in a loop on the warm-cache path (it's
    # in the noise once the read is disk-bound, but never slower).
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
            if on_progress is not None:
                on_progress(n)
    return [hasher.hexdigest() for hasher in hashers]


def get_hash(filepath: str, algo_key: str, on_progress: "Callable[[int], None] | None" = None) -> str:
    """
    Compute the digest of `filepath` using algorithm `algo_key`.

    Returns the hex digest as a lowercase string. Thin single-format wrapper over get_hashes; used by verify (which
    hashes one format per entry). `on_progress` is forwarded to get_hashes (per-chunk byte counts).
    """
    if algo_key not in ALGO_MAP:
        raise ValueError(f"Unsupported hash algorithm: {algo_key}")
    return get_hashes(filepath, [ALGO_MAP[algo_key][0]], on_progress=on_progress)[0]


# -----------------------------------------------------------------------------
# Adaptive parallel hashing
# -----------------------------------------------------------------------------
# Hashing across files can run concurrently — xxhash and hashlib both RELEASE the GIL inside update(), so threads
# overlap reads and use several cores. But whether that helps depends entirely on the storage, and getting it wrong
# makes things worse. Measured on real media:
#
#   * Helps only when the hash is slower than the disk (CPU-bound): md5 (~950 MB/s) on a very fast SSD (~3000 MB/s) went
#     ~2.7x - the disk had spare bandwidth one md5 thread couldn't use.
#   * Does nothing when the disk is the bottleneck: xxhash (~13 GB/s) outruns any disk, so it stays disk-bound however
#     many workers.
#   * Hurts on a slow disk. On a slow HDD (~70 MB/s), 4 workers regressed to md5 0.65x / xxhash 0.76x. Concurrent reads
#     make the head seek between files.
#
# So we should measure:
#
#   1. Calibrate the pure in-RAM hash speed (no disk, ~50 ms).
#   2. Probe the disk: a plain timed read of the first ~1 GB (and >=0.5 s, so a very fast NVMe still samples past its
#      read ramp). This reads bytes we're about to hash anyway.
#   3. If the disk can't clearly outrun one hash thread (read_bw < 1.3x hash_bw), the disk is the ceiling — slow volume
#      or very fast hash (like xxhash) — so we stay sequential and never issue a concurrent read (no seek penalty).
#   4. Otherwise the hash is the bottleneck and the disk has spare bandwidth: run workers = round(read_bw / hash_bw) of
#      them. Because we hand the whole file list (huge opener included) to the pool, a 100 GB first file overlaps with
#      the rest instead of blocking the decision.
#
# A 1 GB probe can't tell a warm page cache from a fast disk (cache reads look like a fast SSD). That false-positive is
# harmless on a real SSD, and on a spinning disk it self-corrects: each hashing window is re-measured, and if a parallel
# window can't even beat ONE hash thread (cold platter, seeking), we demote to sequential for the remainder. Cached
# data, conversely, never seeks, so parallelising it is fine.

# Below this total size, parallelism saves too little wall-time to bother probing.
_AUTO_MIN_BYTES = 2 * 1024 * 1024 * 1024
# Disk probe reads at least this many bytes AND runs at least this long, so the sample is stable whether the volume does
# 70 MB/s or 7 GB/s.
_AUTO_PROBE_BYTES = 1024 * 1024 * 1024
_AUTO_PROBE_SECONDS = 0.5
# The disk must beat one hash thread by this factor before parallelism is worth it (below this the gain is marginal and
# not worth the extra reads/seeks).
_AUTO_PARALLEL_THRESHOLD = 1.3
# Re-measure throughput every this many bytes so a disk that goes cold mid-run (warm cache exhausted) can be caught and
# demoted to sequential.
_AUTO_RECHECK_BYTES = 8 * 1024 * 1024 * 1024
# Never spin up more than this many workers regardless of core count.
_AUTO_MAX_WORKERS = 16
# Wall-time budget for the in-RAM hash-speed calibration — long enough to average out jitter, short enough to vanish
# beside a multi-GB seal.
_AUTO_CALIBRATION_SECONDS = 0.05


def _hash_batch(jobs: "list[Callable[[], _T]]", workers: int) -> "list[_T]":
    """
    Run `jobs` and return their results in input order, up to `workers` at once.

    A job is a zero-arg callable that hashes one file (seal) or hashes-and-compares one entry (verify).
    ThreadPoolExecutor.map preserves order, so the manifest / report stays deterministic regardless of which finishes
    first.
    """
    if workers <= 1 or len(jobs) <= 1:
        return [job() for job in jobs]
    with ThreadPoolExecutor(max_workers=min(workers, len(jobs))) as ex:
        return list(ex.map(lambda job: job(), jobs))


def _calibrate_hash_bw(algo_key: str) -> float:
    """
    Pure in-RAM hashing throughput (bytes/sec) for `algo_key`, no disk involved.

    Lets us tell whether a measured read rate is limited by the hash (CPU) or by the disk. Runs for a brief fixed time
    using HASH_CHUNK_SIZE updates so the figure reflects get_hash's real per-chunk cost; ~50 ms is long enough to
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
    """
    Combined in-RAM throughput (bytes/sec) of updating every hasher per chunk.

    With read-once multi-hashing each chunk is fed to all hashers, so the effective hash bandwidth is 1/Σ(1/bw_i) —
    slower than any single algorithm alone. Running the real multi-update loop captures that directly, so the storage
    probe in _hash_jobs_auto compares against the true per-byte cost rather than one algo's.
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
    """
    Measure the volume's read bandwidth (bytes/sec) with a plain buffered read
    of the first files, stopping once we've read >=_AUTO_PROBE_BYTES AND spent >=_AUTO_PROBE_SECONDS. The byte floor
    gives a meaningful sample on a slow disk; the time floor makes a very fast one read enough to get past its ramp.

    Not hashed — just read and timed. The bytes are re-read when the files are hashed for real, a negligible cost
    against a multi-GB seal.
    """
    buf = bytearray(HASH_CHUNK_SIZE)
    read = 0
    start = time.perf_counter()
    elapsed = 0.0
    for p in paths:
        try:
            with open(p, "rb") as f:
                while n := f.readinto(buf):
                    read += n
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
    """
    Yield each job's result in input order, auto-tuning concurrency to the
    storage (see section comment).

    `paths[i]`/`sizes[i]` describe the file job `i` will read — `paths` drives the disk probe, `sizes` (already known
    from a stat) carve the recheck windows — and `jobs[i]` does the hashing. `calibrate` is a zero-arg callable
    returning the in-RAM hash bandwidth (bytes/sec) the job loop sustains; it is invoked lazily, only past the small-job
    early-returns. Shared by seal (which measures all its formats combined) and verify (one format).
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

    # Disk-bound (hash faster than the disk): one core already keeps the disk busy, so more cores can't help and would
    # seek-thrash a spinning disk - stay sequential.
    if read_bw < _AUTO_PARALLEL_THRESHOLD * hash_bw:
        for job in jobs:
            yield job()
        return

    # Hash-bound (disk faster than one hash thread), so spread the work across enough threads to soak up its bandwidth.
    # round(read_bw/hash_bw) lands near the count that saturates the disk without piling on idle threads.
    workers = max(2, min(cap, round(read_bw / hash_bw)))

    # Hash in windows so we can re-measure: if a window's parallel throughput can't even beat one hash thread, the disk
    # has gone cold/seek-bound (e.g. a warm cache that fooled the probe is now exhausted) — demote to sequential for the
    # remainder. Each window takes at least `workers` files so every worker has something to do even when files are
    # large.
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
    """
    Seal helper: yield (digests, hashdate) per path — one digest per algorithm
    in order, plus the ISO-8601 UTC instant hashing finished — auto-tuning concurrency.

    The hashdate is captured inside the worker the moment get_hashes returns, so it reflects when that file's read-once
    pass actually completed even when files are hashed concurrently in windows (rather than the later emit-loop time).

    get_hashes is resolved at call time (module global) so test monkeypatches still intercept it; the combined hash
    bandwidth of all `algorithms` drives the parallelism decision.
    """
    factories = [ALGO_MAP[a][0] for a in algorithms]
    jobs: list[Callable[[], tuple[list[str], str]]] = [
        (lambda p=p: (get_hashes(p, factories), datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))) for p in paths
    ]
    return _hash_jobs_auto(paths, sizes, jobs, lambda: _calibrate_hash_bw_multi(factories))
