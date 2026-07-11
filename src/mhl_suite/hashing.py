"""
Hashing engine: the read-once multi-hash loop and the adaptive
parallel-hashing controller that both seal and verify drive. This is the leaf
of the suite — it imports nothing else from mhl_suite (the algorithm registry
lives in mhl_suite.algorithms, one layer up).

`get_hashes` (read-once multi-hash of one file), `hash_files`
(adaptive-parallel hashing of many files), `run_hash_jobs` (the controller
itself, for callers whose per-file work varies) and the `Hasher` protocol are
public API for external consumers as well as the rest of the suite.

Cross-module callers reach these functions through the module object (e.g.
`from mhl_suite import hashing; hashing.get_hashes`) so a test monkeypatching
`mhl_suite.hashing.get_hashes` / `_probe_read_bw_multi` / `_warmup_seq_bw` /
`calibrate_hash_bandwidth` still intercepts the call.
"""

import math
import os
import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Protocol, TypeVar, runtime_checkable

# Generic result type for the shared hashing controller (str digest lists for
# seal and hash_files, richer per-entry results for the verify engine).
_T = TypeVar("_T")


# -----------------------------------------------------------------------------
# Hasher protocol
# -----------------------------------------------------------------------------
# Both xxhash and hashlib hashers expose .update() and .hexdigest() but share no
# common ABC. We define a structural Protocol so the type checker understands
# what algorithm factories return without depending on private hashlib
# internals.
# Public: it is also the contract external consumers' factories must satisfy
# (hash_files accepts any constructor of an update/hexdigest object).


@runtime_checkable
class Hasher(Protocol):
    # Real hashers (xxhash, hashlib) accept any bytes-like buffer; we feed a
    # memoryview slice from readinto(), so the annotation must be wider than
    # bytes. Positional-only, because hashlib's C hashers take it that way.
    def update(self, data: "bytes | bytearray | memoryview", /) -> None: ...
    def hexdigest(self) -> str: ...


# -----------------------------------------------------------------------------
# Constants and lookups
# -----------------------------------------------------------------------------

# 1 MiB chunk size for streaming hashing is the (shallow) optimum: large enough
# to amortise read() syscall overhead, small enough to stay in CPU cache. Above
# ~4 MiB the bigger chunk only adds cache pressure. On a 1000 MB/s external SSD
# the choice barely moves the needle, seal is fully disk-bound (every supported
# hash runs faster than the disk delivers bytes), so the file read, not this
# loop, sets the pace.
HASH_CHUNK_SIZE = 1024 * 1024

# ---------------------------------------------------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------------------------------------------------


def get_hashes(
    filepath: str,
    factories: "list[Callable[[], Hasher]]",
    on_progress: "Callable[[int], None] | None" = None,
) -> list[str]:
    """
    Compute several digests of `filepath` in a single read pass.

    `factories` is a list of hasher constructors (see the Hasher protocol;
    e.g. an Algorithm.factory). Every chunk read from disk is fed to all
    hashers, so an
    N-format seal costs one disk read instead of N — the read-once paradigm.
    Returns the hex digests as lowercase strings, aligned to `factories`.

    `on_progress`, if given, is called with the byte count of each chunk as it
    is read (every HASH_CHUNK_SIZE bytes), so a caller can drive a progress bar
    that advances *within* a large file rather than jumping once it finishes. It
    may be invoked from a worker thread when the adaptive controller hashes
    files concurrently, so the callback must be thread-safe.

    We deliberately do NOT use hashlib.file_digest(): bench measurements showed
    it is 5-15% slower than this manual loop on typical media files; the wrapper
    overhead exceeds any internal optimisation it might apply. The manual loop
    is also forward-compatible with xxhash, which file_digest doesn't support
    anyway.
    """
    hashers: list[Hasher] = [factory() for factory in factories]
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
            if on_progress is not None:
                on_progress(n)
    return [hasher.hexdigest() for hasher in hashers]


# -----------------------------------------------------------------------------
# Adaptive parallel hashing
# -----------------------------------------------------------------------------
# Hashing across files can run concurrently — xxhash and hashlib both RELEASE
# the GIL inside update(), so threads overlap reads and use several cores.
# Whether that helps depends entirely on the storage.
#
# The fact a naive "is the disk faster than the hash?" test misses: a single
# thread mostly cannot overlap I/O with hashing. get_hashes reads a chunk (disk
# busy, CPU idle) then hashes it (CPU busy, disk idle), and OS read-ahead only
# partially hides the alternation, so sequential throughput lands well below
# both the read and the hash rate — worst when the two are comparable. Parallel
#     workers overlap one thread's read with another's hash, so parallel
# throughput is bounded instead by the aggregate the storage sustains under
# concurrent reads and by the combined hash rate: par_bw(workers) =
# min(read_aggregate, workers * hash_bw) Parallelism is worth it when par_bw
# beats the sequential rate by a margin — UNLESS concurrent reads make the
# volume seek, which parallelism must never trigger. Measured on real media,
# that covers every volume type with one rule:
#
#   * Fast SSD (read ≫ hash): sequential loses ~30% to read/hash alternation and
#     the aggregate stays high, so parallelism helps (md5 ~2.7x on a ~3000 MB/s
#     SSD; ~1.2x on a USB SSD whose bus caps the aggregate).
#   * Slow SPINNING disk: concurrent reads make the head seek, so the AGGREGATE
#     collapses below single-stream → stay sequential. This is the only case
#     parallelism must avoid (a slow HDD regressed to 0.65x).
#   * Multi-stream NAS / RAID: single-stream can look slow next to the hash, yet
#     the volume sustains (or grows) bandwidth under concurrency and overlap
#     alone recovers the alternation loss → parallelise even when read_single <
#     hash (measured ~2x for md5 and ~1.5x for xxhash on an EditShare EFS).
#
# We measure three things, and none of the measured work is thrown away:
#   1. hash_bw        — pure in-RAM hash speed (no disk, ~50 ms).
#   2. read_aggregate — a timed concurrent read across a few streams over
#      DISTINCT cache-cold regions: tail files when the job has enough of them,
#      evenly spaced offsets inside the biggest tail file when it doesn't (two
#      distant offsets seek exactly like two files, so the seek-collapse signal
#      survives a job of 2-3 huge files). Cold regions stop a warm page cache
#      from faking scaling; the probe reads buffered, so the bytes it pulls stay
#      in the page cache and are served back for free when those files are
#      hashed for real. Wall-time-capped: a seek-bound disk is fully
#      characterised in ~2 s and must not be thrashed for half a minute just to
#      learn "don't do that".
#   3. seq_bw         — NOT modelled but measured on real work: hashing starts
#      sequentially (a warm-up worker runs the first job(s) exactly as a
#      sequential pass would) and the first couple of seconds of per-chunk
#      progress ARE the sequential baseline. Every warm-up byte is a finished
#      digest byte, and the measurement bakes in whatever read-ahead overlap the
#      volume really gives a single thread — a probe-based model (we tried the
#      harmonic mean of read and hash) misjudges exactly the storage this exists
#      for: SMB read-ahead flatters short single-stream reads by ~40%, which
#      made the NAS decision a coin flip.
#
# The decision, in order:
#   * read_aggregate < 0.9 * seq_bw           → concurrent reads collapse below
#                                                even the sequential hashing
#                                                rate: seek-bound disk, stay
#                                                sequential. (Generous
#                                                threshold: genuine seek
#                                                collapse is drastic, probe
#                                                noise is not.)
#   * par_bw          < 1.10 * seq_bw          → parallelism can't clear the
#                                                measured baseline by enough to
#                                                matter (e.g. xxhash on a
#                                                bus-capped USB SSD) → stay
#                                                sequential.
#   * otherwise parallelise with enough workers to soak read_aggregate (at least
#     the probed stream count — on concurrency-tolerant storage idle-ish extra
#     workers cost ~nothing, undershooting costs the win).
#
# Because the warm-up job keeps running while the pool starts, a 100 GB first
# file still overlaps with the rest.
#
# A warm page cache can still fake the aggregate probe (cold regions make that
# rare); the false-positive is harmless on real solid-state storage and
# self-corrects on a spinning disk: each hashing window is re-measured against
# the warm-up baseline, and a window that can't even match sequential throughput
# demotes to sequential for the remainder.

# Below this total size, parallelism saves too little wall-time to bother probing.
_AUTO_MIN_BYTES = 2 * 1024 * 1024 * 1024
# A disk probe reads at least this many bytes AND runs at least this long (a
# stable sample whether the volume does 70 MB/s or 7 GB/s; the 1 s floor also
# outlasts the multi-second-scale TCP/SMB ramp a NAS shows on fresh streams) but
# never longer than the cap — a slow volume is fully characterised in 2 s, and
# stretching a probe on a seek-bound disk only thrashes the head.
_AUTO_PROBE_MIN_BYTES = 128 * 1024 * 1024
_AUTO_PROBE_SECONDS = 1.0
_AUTO_PROBE_MAX_SECONDS = 2.0
# The wall floor's only job is outlasting ramp, so the multi-stream probe may
# return at the byte floor once the aggregate is demonstrably NOT ramping: it
# samples consecutive sub-windows of this length, and two adjacent windows
# agreeing within the tolerance end the probe early (a quiet SSD is
# characterised in ~0.3-0.5 s instead of padding to the 1 s floor). Any ramp
# signature or noise fails the agreement and falls through to the floors/cap
# unchanged, so NAS ramp behaviour is untouched.
_AUTO_PROBE_WINDOW_SECONDS = 0.15
_AUTO_PROBE_STABLE_TOLERANCE = 0.10
# Concurrent streams the aggregate-bandwidth probe issues (and the worker floor
# when parallelising).
_AUTO_PROBE_STREAMS = 4
# The sequential warm-up measures real hashing at least this long AND at least
# _AUTO_PROBE_MIN_BYTES deep before the rate is trusted as the baseline. Warm-up
# is real work (its bytes are finished digests), so a longer floor costs only
# decision latency, not wasted reads.
_AUTO_WARMUP_SECONDS = 2.0
# The aggregate under concurrent reads sitting below the measured sequential
# rate by more than this means the volume is seek-bound (a spinning disk):
# genuine collapse is drastic (2-4x), so 0.9 keeps probe noise from ever reading
# as collapse while still firing long before parallelism could win.
_AUTO_SEEK_COLLAPSE = 0.9
# Parallel throughput must beat the measured sequential rate by this factor
# before it's worth spinning up threads. Deliberately small: past the
# seek-collapse gate the volume tolerates concurrency, so a false positive costs
# ~nothing, while a bigger margin measurably forfeits real wins (md5 on a
# bus-capped USB SSD models ~1.14x and delivers ~1.2-1.3x — the probe's min()
# bound is conservative).
_AUTO_PARALLEL_MARGIN = 1.10
# Re-measure throughput every this many bytes so a disk that goes cold mid-run
# (warm cache exhausted) can be caught and demoted to sequential.
_AUTO_RECHECK_BYTES = 8 * 1024 * 1024 * 1024
# Never spin up more than this many workers regardless of core count.
_AUTO_MAX_WORKERS = 16
# Wall-time budget for the in-RAM hash-speed calibration — long enough to
# average out jitter, short enough to vanish beside a multi-GB seal.
_AUTO_CALIBRATION_SECONDS = 0.05


class _Progress:
    """
    Thread-safe byte counter every job feeds per chunk (via its progress
    callback).

    The controller reads deltas off it to time the sequential warm-up and each
    parallel window — measurement rides on the real hashing work instead of
    separate throwaway reads.
    """

    __slots__ = ("_lock", "bytes")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.bytes = 0

    def add(self, n: int) -> None:
        with self._lock:
            self.bytes += n


# A job takes the controller's per-chunk progress callback (chained after the
# caller's own, see chain_progress) and returns its result: hashing one file
# (seal) or hashing-and-comparing one entry (verify). Public alias so callers
# building job lists for run_hash_jobs can type them.
HashJob = Callable[[Callable[[int], None]], _T]


def chain_progress(first: "Callable[[int], None] | None", second: "Callable[[int], None]") -> "Callable[[int], None]":
    """
    Compose a caller's optional per-chunk progress callback with the
    controller's byte counter.

    Jobs report each chunk to both consumers (progress bar and throughput
    measurement) through one callable; when the caller didn't ask for progress,
    the controller's counter is used directly.
    """
    if first is None:
        return second

    def both(n: int) -> None:
        first(n)
        second(n)

    return both


def _warmup_seq_bw(nbytes: int, elapsed: float) -> float:
    """
    Sequential throughput (bytes/sec) measured over the warm-up window.

    Trivial on purpose: it is the seam tests mock to force a baseline, the way
    _probe_read_bw_multi is mocked to force an aggregate.
    """
    return nbytes / elapsed if elapsed > 0 else float("inf")


def _hash_batch(jobs: "list[HashJob[_T]]", workers: int, on_progress: "Callable[[int], None]") -> "list[_T]":
    """
    Run `jobs` and return their results in input order, up to `workers` at once.

    ThreadPoolExecutor.map preserves order, so the manifest / report stays
    deterministic regardless of which finishes first. `on_progress` (the
    controller's byte counter) is handed to every job.
    """
    if workers <= 1 or len(jobs) <= 1:
        return [job(on_progress) for job in jobs]
    with ThreadPoolExecutor(max_workers=min(workers, len(jobs))) as ex:
        return list(ex.map(lambda job: job(on_progress), jobs))


def calibrate_hash_bandwidth(factories: "list[Callable[[], Hasher]]") -> float:
    """
    Combined in-RAM throughput (bytes/sec) of updating every hasher per chunk —
    no disk involved. Lets the controller tell whether a measured read rate is
    limited by the hash (CPU) or by the disk.

    With read-once multi-hashing each chunk is fed to all hashers, so the
    effective hash bandwidth is 1/Σ(1/bw_i) — slower than any single algorithm
    alone. Running the real multi-update loop captures that directly, so the
    storage probe in run_hash_jobs compares against the true per-byte cost
    rather than one algo's. ~50 ms is long enough to average out scheduler
    jitter and invisible beside a multi-GB seal.
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
    of the first files, stopping once we've read >=_AUTO_PROBE_MIN_BYTES AND
    spent >=_AUTO_PROBE_SECONDS — the byte floor gives a meaningful sample on a
    slow disk, the time floor makes a very fast one read enough to get past its
    ramp — or unconditionally at _AUTO_PROBE_MAX_SECONDS, so a 70 MB/s (or
    dying-USB 5 MB/s) volume spends 2 s probing, not half a minute.

    Not hashed — just read and timed. The bytes are re-read when the files are
    hashed for real, a negligible cost against a multi-GB seal.
    """
    buf = bytearray(HASH_CHUNK_SIZE)
    read = 0
    start = time.perf_counter()
    for p in paths:
        try:
            with open(p, "rb") as f:
                while n := f.readinto(buf):
                    read += n
                    elapsed = time.perf_counter() - start
                    if elapsed >= _AUTO_PROBE_MAX_SECONDS or (
                        read >= _AUTO_PROBE_MIN_BYTES and elapsed >= _AUTO_PROBE_SECONDS
                    ):
                        return read / elapsed
        except OSError:
            continue  # a file that won't open is the real hash pass's problem, not the probe's
    elapsed = time.perf_counter() - start
    return read / elapsed if elapsed > 0 else float("inf")


def _probe_slots(paths: list[str], sizes: list[int], stream_count: int) -> "list[tuple[str, int]]":
    """
    Choose `stream_count` (path, byte-offset) starting points for the
    multi-stream probe.

    Prefers DISTINCT tail files — the single-stream probe reads from the head of
    the list, so the tail is cache-cold and a warm page cache can't serve a
    second reader and fake scaling. When the job has fewer files than streams (a
    handful of huge OCF files is common), the spare streams slice the same tail
    file at evenly spaced offsets: distinct regions are just as cache-cold, and
    on a spinning disk two distant offsets seek exactly like two files, so the
    seek-collapse signal the probe exists to catch still fires.
    """
    cand = list(zip(paths, sizes, strict=True))
    if len(cand) > 1:
        cand = cand[1:]  # the head file is single-stream-probe territory (warm cache)
    cand = cand[-stream_count:]
    slots: list[tuple[str, int]] = []
    base, extra = divmod(stream_count, len(cand))
    for i, (path, size) in enumerate(cand):
        per_file = base + (1 if i < extra else 0)
        slots.extend((path, size * j // per_file) for j in range(per_file))
    return slots


def _probe_read_bw_multi(slots: "list[tuple[str, int]]", stream_count: int) -> float:
    """
    Aggregate read bandwidth (bytes/sec) reading `stream_count` slots — (path,
    offset) starting points over distinct cache-cold regions, from _probe_slots
    — concurrently.

    Reveals whether the volume rewards concurrent reads (SSD / RAID /
    multi-stream NAS: aggregate >= single-stream) or is punished by them
    (seek-bound spinning disk: aggregate < single-stream). Every stream applies
    the same floors as the single-stream probe (its share of
    _AUTO_PROBE_MIN_BYTES, _AUTO_PROBE_SECONDS) and all of them stop at a shared
    _AUTO_PROBE_MAX_SECONDS deadline — the deadline matters most on exactly the
    volume this probe protects, a seek-bound disk, where the aggregate collapses
    and a byte budget alone would thrash the head for tens of seconds. Past the
    byte floor, a demonstrably stable aggregate (see the stability watch below)
    ends the probe before the wall floor, so a fast non-ramping volume pays
    almost no decision overhead. Not hashed — the bytes are re-read when the
    files are hashed for real, a negligible cost against a multi-GB seal.
    """
    n = min(stream_count, len(slots))
    if n <= 1:
        return _probe_read_bw([path for path, _offset in slots])
    per_stream = max(HASH_CHUNK_SIZE, _AUTO_PROBE_MIN_BYTES // n)
    progress = _Progress()
    stop = threading.Event()
    start = time.perf_counter()
    deadline = start + _AUTO_PROBE_MAX_SECONDS

    def _one(slot: "tuple[str, int]") -> None:
        path, offset = slot
        buf = bytearray(HASH_CHUNK_SIZE)
        got = 0
        try:
            with open(path, "rb") as f:
                if offset:
                    f.seek(offset)
                while m := f.readinto(buf):
                    got += m
                    progress.add(m)
                    now = time.perf_counter()
                    if stop.is_set() or now >= deadline or (got >= per_stream and now - start >= _AUTO_PROBE_SECONDS):
                        break
        except OSError:
            pass  # unreadable file is the real hash pass's problem; whatever it did read still counts

    with ThreadPoolExecutor(max_workers=n) as ex:
        futs = [ex.submit(_one, slot) for slot in slots[:n]]
        # Stability watch: the wall floor exists only to outlast a NAS's
        # multi-second TCP/SMB ramp on fresh streams. Once the byte floor is
        # met, sample the aggregate in consecutive sub-windows; two adjacent
        # windows agreeing within tolerance mean the streams are not ramping
        # and the sample is already representative → signal the streams to
        # stop. A ramping (later window faster) or noisy aggregate never
        # agrees and reads on to the floors/deadline exactly as before.
        prev_rate = 0.0
        win_t = 0.0
        win_bytes = 0
        while not all(fut.done() for fut in futs):
            time.sleep(0.01)
            now = time.perf_counter()
            nbytes = progress.bytes
            if now >= deadline or nbytes < _AUTO_PROBE_MIN_BYTES:
                continue  # streams enforce the deadline themselves
            if not win_t:
                win_t, win_bytes = now, nbytes
                continue
            if now - win_t < _AUTO_PROBE_WINDOW_SECONDS:
                continue
            rate = (nbytes - win_bytes) / (now - win_t)
            if prev_rate and abs(rate - prev_rate) <= _AUTO_PROBE_STABLE_TOLERANCE * max(rate, prev_rate):
                stop.set()
                break
            prev_rate = rate
            win_t, win_bytes = now, nbytes
    # Leaving the with-block joins the streams; each exits within one chunk of
    # the stop signal, and those bytes are counted, so the rate stays honest.
    elapsed = time.perf_counter() - start
    return progress.bytes / elapsed if elapsed > 0 else float("inf")


def _warmup(jobs: "list[HashJob[_T]]", warm_ex: ThreadPoolExecutor, progress: _Progress) -> "tuple[list, int, float]":
    """
    Run the sequential warm-up: real hashing, one job at a time on `warm_ex`'s
    single worker, until the measurement window closes (byte AND time floors
    met) or every job has finished first.

    Returns (futures, jobs submitted, measured sequential bytes/sec). The last
    future may still be running — the caller overlaps it with the parallel pool
    rather than waiting, so a huge first file never serialises the rest.
    """
    futs: list = []
    submitted = 0
    start = time.perf_counter()
    while True:
        if not futs or futs[-1].done():
            if submitted == len(jobs):
                break  # every job finished within the warm-up window: nothing left to parallelise
            futs.append(warm_ex.submit(jobs[submitted], progress.add))
            submitted += 1
        else:
            time.sleep(0.02)
        if progress.bytes >= _AUTO_PROBE_MIN_BYTES and time.perf_counter() - start >= _AUTO_WARMUP_SECONDS:
            break
    return futs, submitted, _warmup_seq_bw(progress.bytes, time.perf_counter() - start)


def run_hash_jobs(
    paths: list[str], sizes: list[int], jobs: "list[HashJob[_T]]", calibrate: "Callable[[], float]"
) -> "Iterator[_T]":
    """
    The adaptive controller itself, public API: yield each job's result in
    input order, auto-tuning concurrency to the storage (see section comment).

    `paths[i]`/`sizes[i]` describe the file job `i` will read — they drive the
    aggregate probe and carve the recheck windows — and `jobs[i]` does the
    hashing (typically via get_hashes), reporting per-chunk bytes to the
    progress callback it is handed (that feed is both the sequential warm-up
    measurement and each window's re-check). `calibrate` is a zero-arg callable
    returning the in-RAM hash bandwidth (bytes/sec) the job loop sustains —
    usually calibrate_hash_bandwidth(factories) — invoked lazily, only past the
    small-job early-returns. Jobs may run on worker threads; a job that raises
    tears down the run, so per-file failures a caller wants to survive must be
    caught inside the job and returned as part of its result. Shared by seal
    (which measures all its formats combined) and the verify engine (per-entry
    formats); hash_files is the simpler per-file-digests wrapper.
    """
    n = len(jobs)
    progress = _Progress()
    cap = min(_AUTO_MAX_WORKERS, os.cpu_count() or 4)
    # Not worth probing for a single file, a small job, or a uniprocessor.
    if n <= 1 or cap <= 1 or sum(sizes) < _AUTO_MIN_BYTES:
        for job in jobs:
            yield job(progress.add)
        return

    hash_bw = calibrate()

    # Aggregate read bandwidth across a few concurrent streams tells us whether
    # the volume rewards concurrency (SSD/RAID/NAS) or is punished by it
    # (seek-bound disk). Probed BEFORE any hashing starts so the sample is
    # uncontaminated, over cache-cold regions (see _probe_slots) so a warm cache
    # can't fake scaling. cap >= 2 past the early-return, so this always
    # measures.
    probe_n = min(cap, _AUTO_PROBE_STREAMS)
    read_multi = _probe_read_bw_multi(_probe_slots(paths, sizes, probe_n), probe_n)

    # Sequential warm-up: start hashing for real, one job at a time on a single
    # worker, and measure the baseline off the per-chunk progress feed. Nothing
    # here is throwaway — every byte is a finished digest byte — and the rate is
    # the true sequential throughput (read-ahead overlap included), which no
    # read-probe model reproduces. The thread lets the controller act the moment
    # the window closes even when the first file is 100 GB; that job keeps
    # running while the parallel pool (if any) starts on the rest.
    warm_ex = ThreadPoolExecutor(max_workers=1)
    try:
        warm_futs, submitted, seq_bw = _warmup(jobs, warm_ex, progress)

        workers = min(cap, max(probe_n, math.ceil(min(read_multi, hash_bw * cap) / hash_bw)))
        par_bw = min(read_multi, workers * hash_bw)

        # Stay sequential when concurrent reads collapse the aggregate below
        # even the sequential hashing rate (a seek-bound spinning disk — the
        # case parallelism must never touch), and when parallelism can't clear
        # the measured baseline by a worthwhile margin (e.g. a fast hash on a
        # bus-capped volume). Draining warm_futs first keeps results in input
        # order; the in-flight job just carries on — it IS the sequential pass.
        if read_multi < _AUTO_SEEK_COLLAPSE * seq_bw or par_bw < _AUTO_PARALLEL_MARGIN * seq_bw:
            for fut in warm_futs:
                yield fut.result()
            for job in jobs[submitted:]:
                yield job(progress.add)
            return

        # Hash in windows so we can re-measure: if a window's parallel
        # throughput can't even match the measured sequential baseline, the
        # volume has gone cold/seek-bound — demote to sequential for the
        # remainder. Each window takes at least `workers` files so every worker
        # has something to do even when files are large. Window rates come off
        # the progress feed, so bytes the still-running warm-up job contributes
        # during a window are counted rather than mistaken for parallel
        # slowdown.
        pos = submitted
        while pos < n:
            stop = pos
            acc = 0
            while stop < n and (acc < _AUTO_RECHECK_BYTES or (stop - pos) < workers):
                acc += sizes[stop]
                stop += 1
            mark = progress.bytes
            t0 = time.perf_counter()
            results = _hash_batch(jobs[pos:stop], workers, progress.add)
            elapsed = time.perf_counter() - t0
            if warm_futs:
                # First window: the warm-up job ran alongside it; collect (in
                # order) before the window's results.
                for fut in warm_futs:
                    yield fut.result()
                warm_futs = []
            yield from results
            pos = stop
            rate = (progress.bytes - mark) / elapsed if elapsed > 0 else float("inf")
            if rate < seq_bw:
                # Parallel can't even match the sequential baseline → the volume
                # has gone cold/seek-bound (e.g. a warm cache that fooled the
                # probe is now exhausted); finish sequentially.
                for job in jobs[pos:]:
                    yield job(progress.add)
                return
        # Warm-up consumed every job (pos == n, no window ran): drain what it
        # produced.
        for fut in warm_futs:
            yield fut.result()
    finally:
        # Never blocks: any in-flight warm-up job finishes on its own thread and
        # its future is drained above.
        warm_ex.shutdown(wait=False)


def hash_files(
    paths: "list[str]",
    sizes: "list[int]",
    factories: "list[Callable[[], Hasher]]",
    on_progress: "Callable[[int], None] | None" = None,
) -> "Iterator[list[str]]":
    """
    Public adaptive-parallel hashing API: yield, per path in input order, the
    file's digests — one per factory, aligned to `factories`, each file read
    once — auto-tuning concurrency to the storage (see section comment).

    This is the entry point for external consumers (e.g. triplecheck) as well
    as any future in-suite caller that doesn't need seal's hashdates.
    `factories` are hasher constructors satisfying the Hasher protocol
    (update/hexdigest) — hashlib constructors, xxhash constructors, or any
    third-party hasher such as blake3.blake3 — so callers are NOT limited to
    the suite's algorithm registry. `sizes[i]` is the byte size of
    `paths[i]` (callers usually already have it from their own walk); the
    sizes drive the storage probe and the recheck windows. `on_progress`, if
    given, receives per-chunk byte counts and may be called from worker
    threads, so it must be thread-safe.

    An OSError from an unreadable file propagates to whoever consumes the
    iterator; files after the failed one are not hashed. To hash the good files
    and collect the bad ones as errors instead of aborting, don't use this
    wrapper — build your own jobs for run_hash_jobs that catch OSError inside
    the job and return an error sentinel in place of digests (the verify engine
    does exactly this; seal deliberately does not, so an unreadable file aborts
    the whole seal rather than emitting a manifest that silently omits it).

    get_hashes is resolved at call time (module global) so test monkeypatches
    still intercept it; the combined hash bandwidth of all `factories` drives
    the parallelism decision.
    """
    jobs: list[HashJob[list[str]]] = [
        (lambda mon, p=p: get_hashes(p, factories, on_progress=chain_progress(on_progress, mon))) for p in paths
    ]
    return run_hash_jobs(paths, sizes, jobs, lambda: calibrate_hash_bandwidth(factories))
