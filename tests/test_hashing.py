"""
Tests for the adaptive hashing controller (mhl_suite.hashing).

These pin the *decisions* (sequential vs parallel-N vs demotion) and the output
invariant of run_hash_jobs / _probe_read_bw / _hash_batch, never the throughput
numbers (which are hardware-bound). The controller is driven here through
classic_seal's _hash_files wrapper (the digests+hashdate job shape seal uses);
the verify engine's integration is covered in the verify tests.
"""

import hashlib
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import TYPE_CHECKING

import pytest

from mhl_suite import hashing as core_hashing
from mhl_suite.algorithms import ALGORITHMS, get_hash
from mhl_suite.classic_seal import _hash_files as seal_hash_files

if TYPE_CHECKING:
    from collections.abc import Callable


class TestAdaptiveHashing:
    """
    Behaviour of run_hash_jobs / _probe_read_bw / _hash_batch, driven through
    seal's _hash_files job shape.

    The disk/hash measurements are mocked so the tests are deterministic on any
    machine — including the all-important guarantee that concurrency never
    changes the manifest.
    """

    @staticmethod
    def _make_files(tmp_path, count, algo="md5"):
        paths, sizes = [], []
        for i in range(count):
            p = tmp_path / f"f{i:04d}.bin"
            p.write_bytes(bytes([i % 256]) * (1000 + i))  # distinct content & size
            paths.append(str(p))
            sizes.append(p.stat().st_size)
        ref = [get_hash(p, algo) for p in paths]  # pure-sequential reference
        return paths, sizes, ref

    def _force(self, monkeypatch, *, seq_bw, hash_bw, read_bw_multi, cpu=8, min_bytes=0, recheck=8 * 1024**3):
        # seq_bw is the measured sequential baseline (normally taken off the
        # warm-up's real progress; mocked through the _warmup_seq_bw seam) and
        # read_bw_multi the aggregate the volume sustains under concurrent
        # reads. Zeroing the warm-up floors closes the measurement window
        # immediately so tiny test files exercise the decision.
        monkeypatch.setattr(core_hashing, "_AUTO_MIN_BYTES", min_bytes)
        monkeypatch.setattr(core_hashing, "_AUTO_RECHECK_BYTES", recheck)
        monkeypatch.setattr(core_hashing, "_AUTO_WARMUP_SECONDS", 0.0)
        monkeypatch.setattr(core_hashing, "_AUTO_PROBE_MIN_BYTES", 0)
        monkeypatch.setattr(core_hashing, "calibrate_hash_bandwidth", lambda factories: hash_bw)
        monkeypatch.setattr(core_hashing, "_warmup_seq_bw", lambda nbytes, elapsed: seq_bw)
        monkeypatch.setattr(core_hashing, "_probe_read_bw_multi", lambda slots, n: read_bw_multi)
        monkeypatch.setattr(core_hashing.os, "cpu_count", lambda: cpu)

    def _spy_batch(self, monkeypatch):
        calls: list[int] = []
        real = core_hashing._hash_batch

        def spy(jobs, workers, on_progress):
            calls.append(workers)
            return real(jobs, workers, on_progress)

        monkeypatch.setattr(core_hashing, "_hash_batch", spy)
        return calls

    # --- output invariance: the manifest must be identical on every path -----

    def test_output_identical_parallel_branch(self, tmp_path, monkeypatch):
        paths, sizes, ref = self._make_files(tmp_path, 30)
        self._force(monkeypatch, seq_bw=800, hash_bw=1000, read_bw_multi=4000)
        assert [d for d, _hashdate in seal_hash_files(paths, sizes, ["md5"])] == [[r] for r in ref]

    def test_output_identical_demotion_branch(self, tmp_path, monkeypatch):
        paths, sizes, ref = self._make_files(tmp_path, 30)
        # seq_bw huge => every window's measured rate < seq_bw => demote; a tiny recheck window makes demotion leave a
        # real sequential remainder.
        self._force(monkeypatch, seq_bw=1e18, hash_bw=1e18, read_bw_multi=1e30, recheck=1)
        assert [d for d, _hashdate in seal_hash_files(paths, sizes, ["md5"])] == [[r] for r in ref]

    def test_output_identical_sequential_gate(self, tmp_path, monkeypatch):
        paths, sizes, ref = self._make_files(tmp_path, 30)
        # disk-bound and concurrency doesn't scale: parallel can't clear the margin
        self._force(monkeypatch, seq_bw=95, hash_bw=1000, read_bw_multi=100)
        assert [d for d, _hashdate in seal_hash_files(paths, sizes, ["md5"])] == [[r] for r in ref]

    # --- decisions -----------------------------------------------------------

    def test_seek_bound_disk_never_parallelises(self, tmp_path, monkeypatch):
        """
        A seek-bound spinning disk (aggregate COLLAPSES under concurrent reads:
        read_multi < seq_bw) must stay sequential — the branch that protects the
        head from seek-thrash.
        """
        paths, sizes, _ = self._make_files(tmp_path, 10)
        self._force(monkeypatch, seq_bw=110, hash_bw=1000, read_bw_multi=60)
        calls = self._spy_batch(monkeypatch)
        list(seal_hash_files(paths, sizes, ["md5"]))
        assert all(w <= 1 for w in calls), f"seek-bound must not issue a concurrent batch, saw {calls}"

    def test_two_large_files_on_seek_bound_disk_stay_sequential(self, tmp_path, monkeypatch):
        """
        The few-huge-files case (n=2, common with OCF) must still consult the
        multi-stream probe — via offset slices — and stay sequential when it
        collapses. There's no demotion rescue here (the first window swallows
        both files), so the up-front decision has to be right.
        """
        paths, sizes, _ = self._make_files(tmp_path, 2)
        self._force(monkeypatch, seq_bw=140, hash_bw=1000, read_bw_multi=60)
        calls = self._spy_batch(monkeypatch)
        list(seal_hash_files(paths, sizes, ["md5"]))
        assert all(w <= 1 for w in calls), f"2-file seek-bound job must not issue a concurrent batch, saw {calls}"

    def test_hash_far_outruns_disk_stays_sequential(self, tmp_path, monkeypatch):
        """
        When the sequential baseline already sits at the aggregate ceiling (e.g.
        xxhash on a bus-capped volume: seq 99 ~ aggregate 100), parallelism
        can't clear the margin — stay sequential.
        """
        paths, sizes, _ = self._make_files(tmp_path, 10)
        self._force(monkeypatch, seq_bw=99, hash_bw=13_000, read_bw_multi=100)
        calls = self._spy_batch(monkeypatch)
        list(seal_hash_files(paths, sizes, ["md5"]))
        assert all(w <= 1 for w in calls), f"hash-dominated volume must stay sequential, saw {calls}"

    def test_nas_scaling_parallelises(self, tmp_path, monkeypatch):
        """
        The NAS case: measured sequential hashing (535) sits far below the
        concurrent-read aggregate (1500), so the controller must parallelise
        with the probed stream floor even though hash (846) outruns sequential.
        """
        paths, sizes, _ = self._make_files(tmp_path, 10)
        self._force(monkeypatch, seq_bw=535, hash_bw=846, read_bw_multi=1500, cpu=8)
        calls = self._spy_batch(monkeypatch)
        list(seal_hash_files(paths, sizes, ["md5"]))
        assert calls, "expected a concurrent batch on concurrency-scaling storage"
        assert max(calls) == 4, f"expected 4 workers (probed stream floor), saw {calls}"

    def test_overlap_parallelises_without_read_scaling(self, tmp_path, monkeypatch):
        """
        Even when concurrency does NOT raise aggregate bandwidth beyond one
        stream's rate (read_multi 950 vs a sequential baseline of 535), overlap
        alone recovers the read/hash alternation loss — parallelise, and use the
        probed stream count so the measured aggregate is actually realised.
        """
        paths, sizes, _ = self._make_files(tmp_path, 10)
        self._force(monkeypatch, seq_bw=535, hash_bw=950, read_bw_multi=950, cpu=8)
        calls = self._spy_batch(monkeypatch)
        list(seal_hash_files(paths, sizes, ["md5"]))
        assert calls, "expected a concurrent batch when overlap alone wins"
        assert max(calls) == 4, f"expected 4 workers (probed stream floor), saw {calls}"

    def test_parallel_worker_count_from_bandwidth(self, tmp_path, monkeypatch):
        """
        workers ~ ceil(read_bw_multi / hash_bw) once that exceeds the probed
        stream floor.
        """
        paths, sizes, _ = self._make_files(tmp_path, 10)
        self._force(monkeypatch, seq_bw=800, hash_bw=1000, read_bw_multi=6000, cpu=8)
        calls = self._spy_batch(monkeypatch)
        list(seal_hash_files(paths, sizes, ["md5"]))
        assert calls, "expected a concurrent batch to run"
        assert max(calls) == 6, f"expected 6 workers, saw {calls}"

    def test_worker_count_clamped_to_cores(self, tmp_path, monkeypatch):
        paths, sizes, _ = self._make_files(tmp_path, 10)
        self._force(monkeypatch, seq_bw=800, hash_bw=1000, read_bw_multi=100_000, cpu=4)  # wants 100, capped to cores
        calls = self._spy_batch(monkeypatch)
        list(seal_hash_files(paths, sizes, ["md5"]))
        assert calls, "expected a concurrent batch to run"
        assert max(calls) == 4

    def test_small_job_skips_probe(self, tmp_path, monkeypatch):
        paths, sizes, ref = self._make_files(tmp_path, 5)
        monkeypatch.setattr(core_hashing, "_AUTO_MIN_BYTES", 10 * 1024**3)  # larger than the job
        probed: list[int] = []
        monkeypatch.setattr(core_hashing, "_probe_read_bw_multi", lambda slots, n: probed.append(1) or 1.0)
        assert [d for d, _hashdate in seal_hash_files(paths, sizes, ["md5"])] == [[r] for r in ref]
        assert probed == [], "a sub-threshold job must not probe the disk"

    def test_single_file_skips_probe(self, tmp_path, monkeypatch):
        paths, sizes, ref = self._make_files(tmp_path, 1)
        monkeypatch.setattr(core_hashing, "_AUTO_MIN_BYTES", 0)
        probed: list[int] = []
        monkeypatch.setattr(core_hashing, "_probe_read_bw_multi", lambda slots, n: probed.append(1) or 9e9)
        assert [d for d, _hashdate in seal_hash_files(paths, sizes, ["md5"])] == [[r] for r in ref]
        assert probed == [], "nothing to parallelise across a single file"

    # --- helpers -------------------------------------------------------------

    def test_hash_batch_preserves_order(self, tmp_path):
        # Both the concurrent (workers>1) and the sequential (workers<=1, no
        # pool) paths must return results in input order.
        paths, sizes, ref = self._make_files(tmp_path, 20)

        def jobs() -> "list[Callable[[Callable[[int], None]], str]]":
            return [(lambda mon, p=p: get_hash(p, "md5", on_progress=mon)) for p in paths]

        sink = core_hashing._Progress()
        assert core_hashing._hash_batch(jobs(), 4, sink.add) == ref
        assert core_hashing._hash_batch(jobs(), 1, sink.add) == ref
        assert sink.bytes == 2 * sum(sizes)  # every chunk reported, both passes

    def test_hash_batch_runs_jobs_concurrently_in_order(self, tmp_path):
        """
        _hash_batch runs each job callable — whatever it is, hashing or not —
        and returns results in input order.
        """
        paths, _, _ = self._make_files(tmp_path, 6)
        jobs: list[Callable[[Callable[[int], None]], str]] = [(lambda mon, p=p: f"STUB:{p}") for p in paths]
        assert core_hashing._hash_batch(jobs, 3, lambda n: None) == [f"STUB:{p}" for p in paths]

    def test_probe_read_bw_skips_unreadable(self, tmp_path, monkeypatch):
        good = tmp_path / "g.bin"
        good.write_bytes(b"x" * 4096)
        monkeypatch.setattr(core_hashing, "_AUTO_PROBE_MIN_BYTES", 1)
        monkeypatch.setattr(core_hashing, "_AUTO_PROBE_SECONDS", 0.0)
        bw = core_hashing._probe_read_bw([str(tmp_path / "missing.bin"), str(good)])
        assert bw > 0  # unreadable path skipped without error, good file measured

    def test_carries_well_formed_per_file_hashdate(self, tmp_path):
        """
        Each file comes back paired with an ISO-8601 hashdate captured by the
        hashing worker (precise even in parallel windows), not stamped at emit.
        """
        paths, sizes, ref = self._make_files(tmp_path, 3)
        out = list(seal_hash_files(paths, sizes, ["md5"]))
        assert [d for d, _ in out] == [[r] for r in ref]
        for _digests, hashdate in out:
            assert datetime.fromisoformat(hashdate).tzinfo is not None

    def test_probe_read_bw_multi_reads_concurrently(self, tmp_path):
        """
        The multi-stream probe reads several distinct slots concurrently and
        returns a positive aggregate rate.
        """
        slots = []
        for i in range(4):
            p = tmp_path / f"m{i}.bin"
            p.write_bytes(bytes([i]) * (2 * 1024 * 1024))
            slots.append((str(p), 0))
        assert core_hashing._probe_read_bw_multi(slots, 4) > 0

    def test_probe_read_bw_multi_seeks_to_slot_offset(self, tmp_path):
        """
        A slot with a non-zero offset reads from there (the few-huge-files
        case slices one file into regions).
        """
        p = tmp_path / "big.bin"
        p.write_bytes(b"x" * (4 * 1024 * 1024))
        slots = [(str(p), 0), (str(p), 2 * 1024 * 1024)]
        assert core_hashing._probe_read_bw_multi(slots, 2) > 0

    def test_probe_read_bw_multi_single_falls_back(self, tmp_path):
        """
        With fewer than two streams there is nothing to overlap, so it defers to
        the single-stream probe.
        """
        p = tmp_path / "one.bin"
        p.write_bytes(b"x" * 4096)
        assert core_hashing._probe_read_bw_multi([(str(p), 0)], 1) > 0

    def test_probe_read_bw_multi_tolerates_unreadable(self, tmp_path):
        """
        An unreadable stream contributes zero bytes instead of raising, so the
        probe still returns a rate.
        """
        good = tmp_path / "g.bin"
        good.write_bytes(b"x" * (2 * 1024 * 1024))
        bw = core_hashing._probe_read_bw_multi([(str(tmp_path / "missing.bin"), 0), (str(good), 0)], 2)
        assert bw >= 0

    # --- probe stability early exit -------------------------------------------
    #
    # The probe's 1 s wall floor exists only to outlast a NAS's multi-second
    # TCP/SMB ramp; on a stable volume it may return at the byte floor. These
    # tests pace fake streams (module-level `open` shadowed) so ramp vs stable
    # is deterministic regardless of the machine's real disk.

    class _PacedFile:
        """Endless file-like stream delivering `chunk` bytes per read, paced by delay_fn(elapsed)."""

        CHUNK = 65536

        def __init__(self, t0, delay_fn):
            self._t0 = t0
            self._delay_fn = delay_fn

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def seek(self, offset):
            pass

        def readinto(self, buf):
            time.sleep(self._delay_fn(time.perf_counter() - self._t0))
            return self.CHUNK

    def _pace_probe(self, monkeypatch, delay_fn, *, floor_s=2.0, cap_s=4.0):
        """
        Shadow `open` inside the hashing module with paced fake streams and
        shrink the byte floor so window sampling starts quickly. Returns
        (aggregate_bw, elapsed) of a 4-stream probe.
        """
        t0 = time.perf_counter()
        monkeypatch.setattr(core_hashing, "open", lambda path, mode: self._PacedFile(t0, delay_fn), raising=False)
        monkeypatch.setattr(core_hashing, "_AUTO_PROBE_MIN_BYTES", 2 * 1024 * 1024)
        monkeypatch.setattr(core_hashing, "_AUTO_PROBE_SECONDS", floor_s)
        monkeypatch.setattr(core_hashing, "_AUTO_PROBE_MAX_SECONDS", cap_s)
        monkeypatch.setattr(core_hashing, "_AUTO_PROBE_WINDOW_SECONDS", 0.1)
        slots = [(f"/fake/{i}", 0) for i in range(4)]
        start = time.perf_counter()
        bw = core_hashing._probe_read_bw_multi(slots, 4)
        return bw, time.perf_counter() - start

    def test_probe_multi_stable_stream_exits_before_wall_floor(self, monkeypatch):
        """
        A fast, non-ramping aggregate ends the probe at the byte floor + two
        agreeing sub-windows — far before the wall floor — so disk-bound runs
        on quiet SSDs stop paying ~1 s of padding.
        """
        bw, elapsed = self._pace_probe(monkeypatch, lambda t: 0.002)  # steady ~32 MB/s per stream
        assert bw > 0
        assert elapsed < 1.0, f"stable stream should exit early, took {elapsed:.2f}s"

    def test_probe_multi_ramping_stream_reads_to_wall_floor(self, monkeypatch):
        """
        An aggregate still ramping (each sub-window measurably faster than the
        last, the NAS signature the wall floor exists for) never satisfies the
        stability check and reads to the full floor.
        """
        # Rate grows linearly 5x/s: adjacent 0.1 s windows differ by >10%
        # throughout the floor, so no two ever agree.
        bw, elapsed = self._pace_probe(monkeypatch, lambda t: 0.002 / (1 + 5 * t), floor_s=0.8, cap_s=2.0)
        assert bw > 0
        assert elapsed >= 0.8, f"ramping stream must read to the wall floor, exited at {elapsed:.2f}s"

    def test_probe_multi_slow_stable_stream_exits_early_with_low_rate(self, monkeypatch):
        """
        A collapsed-but-stable aggregate (seek-bound signature) may also exit
        early — the sample is decisive either way — and must report the low
        rate faithfully so the seek-collapse gate upstream still fires.
        """
        bw, elapsed = self._pace_probe(monkeypatch, lambda t: 0.008)  # steady ~8 MB/s per stream
        assert elapsed < 1.0, f"stable stream should exit early, took {elapsed:.2f}s"
        # ~4 streams * 64 KiB / 8 ms ≈ 32 MB/s aggregate; generous bounds, but
        # far below any rate a warm cache or accounting bug would produce.
        assert 8 * 1024**2 < bw < 48 * 1024**2

    def test_probe_slots_prefers_distinct_tail_files(self):
        """
        With enough files, every stream gets its own tail file at offset 0 and
        the head file (the single-stream probe's territory, warm cache) is never
        picked.
        """
        paths = [f"/v/f{i}" for i in range(8)]
        sizes = [10_000] * 8
        slots = core_hashing._probe_slots(paths, sizes, 4)
        assert slots == [(p, 0) for p in paths[-4:]]

    def test_probe_slots_slices_offsets_when_files_are_few(self):
        """
        A job of two huge files still yields stream_count slots: the tail file
        sliced at evenly spaced offsets, so the seek-collapse probe works even
        when a warm-cache-safe file per stream doesn't exist.
        """
        slots = core_hashing._probe_slots(["/v/a", "/v/b"], [8_000, 8_000], 4)
        assert slots == [("/v/b", 0), ("/v/b", 2_000), ("/v/b", 4_000), ("/v/b", 6_000)]

    def test_probe_slots_single_file_job(self):
        """
        Degenerate single-file input still produces usable slots rather than
        crashing.
        """
        slots = core_hashing._probe_slots(["/v/only"], [9_000], 2)
        assert slots == [("/v/only", 0), ("/v/only", 4_500)]

    def test_warmup_seq_bw_is_rate_with_zero_elapsed_guard(self):
        """
        The warm-up baseline is bytes/elapsed; a zero-time window (clock
        granularity) must not divide by zero.
        """
        assert core_hashing._warmup_seq_bw(1000, 2.0) == pytest.approx(500.0)
        assert core_hashing._warmup_seq_bw(1000, 0.0) == float("inf")

    def test_chain_progress_feeds_both_consumers(self):
        """
        A job's single progress callable must reach the caller's bar AND the
        controller's counter — and collapse to just the counter when the caller
        didn't ask for progress.
        """
        seen: list[int] = []
        counter = core_hashing._Progress()
        both = core_hashing.chain_progress(seen.append, counter.add)
        both(3)
        both(4)
        assert seen == [3, 4]
        assert counter.bytes == 7
        unchained = core_hashing.chain_progress(None, counter.add)
        unchained(5)
        assert counter.bytes == 12  # None caller-side callback collapses to the counter alone

    def test_progress_counter_is_thread_safe(self):
        """
        Parallel windows feed one counter from several workers; increments must
        not be lost.
        """
        counter = core_hashing._Progress()

        def bump(_):
            for _ in range(1000):
                counter.add(1)

        with ThreadPoolExecutor(max_workers=8) as ex:
            list(ex.map(bump, range(8)))
        assert counter.bytes == 8000

    def test_calibrate_hash_bandwidth_is_positive_and_finite(self):
        """
        The real in-RAM calibration (mocked everywhere else) returns a usable
        bytes/sec figure — for a single format and for seal's combined
        read-once multi-hash.
        """
        for names in (["md5"], ["md5", "xxh64"]):
            factories = [ALGORITHMS[n].factory for n in names]
            assert 0 < core_hashing.calibrate_hash_bandwidth(factories) < float("inf")

    def test_probe_read_bw_falls_through_when_files_smaller_than_floor(self, tmp_path):
        """
        When the byte/time floors are never reached, the probe reads every file
        and returns the rate over what it managed to read (the fall-through
        return).
        """
        small = tmp_path / "s.bin"
        small.write_bytes(b"x" * 4096)
        # The default byte floor is 128 MiB, so a 4 KiB file never trips the
        # early return — the loop exhausts the file list and returns
        # read/elapsed.
        bw = core_hashing._probe_read_bw([str(small)])
        assert bw > 0


class TestGetHashes:
    """The read-once multi-hash loop and its single-format wrapper."""

    def test_on_progress_reports_each_chunk(self, tmp_path, monkeypatch):
        """
        get_hashes invokes on_progress with the byte count of every chunk read,
        so the totals add up to the file size across multiple chunks.
        """
        monkeypatch.setattr(core_hashing, "HASH_CHUNK_SIZE", 1024)
        f = tmp_path / "big.bin"
        f.write_bytes(b"y" * 4096)
        chunks: list[int] = []
        core_hashing.get_hashes(str(f), [ALGORITHMS["md5"].factory], on_progress=chunks.append)
        assert sum(chunks) == 4096
        assert len(chunks) == 4  # 4096 / 1024


class _ByteSum:
    """
    Toy Hasher implementation registered nowhere: any object exposing
    update/hexdigest must be accepted as a factory product.
    """

    def __init__(self):
        self._n = 0

    def update(self, data):
        self._n = (self._n + sum(data)) % 65536

    def hexdigest(self):
        return f"{self._n:04x}"


class TestHashFilesPublicAPI:
    """
    hash_files is the public, factories-based entry point external consumers
    (e.g. triplecheck) build on. These tests lock in that contract:

      * factories are arbitrary Hasher constructors — hashlib, xxhash, blake3
        or home-grown — NOT registry names, so a consumer's algorithms need no
        registration in this suite;
      * digests come back aligned to `factories`, one list per path, in input
        order, whether the controller runs sequentially or in parallel;
      * OSError from an unreadable file propagates to the iterator's consumer.
    """

    @staticmethod
    def _make_files(tmp_path, count):
        paths, sizes, blobs = [], [], []
        for i in range(count):
            f = tmp_path / f"f{i}.bin"
            blob = bytes([i]) * (1024 + i)
            f.write_bytes(blob)
            paths.append(str(f))
            sizes.append(len(blob))
            blobs.append(blob)
        return paths, sizes, blobs

    def test_arbitrary_factories_outside_registry(self, tmp_path):
        """
        sha256 has no registry entry and _ByteSum isn't even a real hash, yet
        both work as factories; each yielded list is aligned to `factories`.
        """
        paths, sizes, blobs = self._make_files(tmp_path, 4)
        results = list(core_hashing.hash_files(paths, sizes, [hashlib.sha256, _ByteSum]))
        for blob, (sha_digest, bytesum_digest) in zip(blobs, results, strict=True):
            assert sha_digest == hashlib.sha256(blob).hexdigest()
            ref = _ByteSum()
            ref.update(blob)
            assert bytesum_digest == ref.hexdigest()

    def test_parallel_branch_preserves_order_and_digests(self, tmp_path, monkeypatch):
        """
        Custom factories flow through the adaptive controller's parallel branch
        (forced via mocked bandwidths) with output identical to sequential.
        """
        paths, sizes, blobs = self._make_files(tmp_path, 8)
        monkeypatch.setattr(core_hashing, "_AUTO_MIN_BYTES", 0)
        monkeypatch.setattr(core_hashing, "_AUTO_WARMUP_SECONDS", 0.0)
        monkeypatch.setattr(core_hashing, "_AUTO_PROBE_MIN_BYTES", 0)
        monkeypatch.setattr(core_hashing, "calibrate_hash_bandwidth", lambda factories: 1000)
        monkeypatch.setattr(core_hashing, "_warmup_seq_bw", lambda nbytes, elapsed: 800)
        monkeypatch.setattr(core_hashing, "_probe_read_bw_multi", lambda slots, n: 4000)
        monkeypatch.setattr(core_hashing.os, "cpu_count", lambda: 8)
        results = list(core_hashing.hash_files(paths, sizes, [hashlib.sha256]))
        assert results == [[hashlib.sha256(blob).hexdigest()] for blob in blobs]

    def test_on_progress_receives_every_byte(self, tmp_path):
        """The caller's on_progress is chained in: chunk counts sum to the total size."""
        paths, sizes, _blobs = self._make_files(tmp_path, 3)
        chunks = []
        list(core_hashing.hash_files(paths, sizes, [_ByteSum], on_progress=chunks.append))
        assert sum(chunks) == sum(sizes)

    def test_oserror_propagates_to_consumer(self, tmp_path):
        """An unreadable file raises at the consumer instead of being skipped."""
        paths, sizes, _blobs = self._make_files(tmp_path, 2)
        paths.insert(1, str(tmp_path / "missing.bin"))
        sizes.insert(1, 123)
        with pytest.raises(OSError, match=r"missing\.bin"):
            list(core_hashing.hash_files(paths, sizes, [_ByteSum]))
