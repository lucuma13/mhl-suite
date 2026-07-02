"""
Tests for the adaptive hashing controller (mhl_suite.hashing).

These pin the *decisions* (sequential vs parallel-N vs demotion) and the output invariant of _hash_files_auto /
_probe_read_bw / _hash_batch, never the throughput numbers (which are hardware-bound). seal and verify drive this
controller; their integration with it is covered in the seal/verify tests.
"""

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import pytest

from mhl_suite import hashing as core_hashing

if TYPE_CHECKING:
    from collections.abc import Callable


class TestAdaptiveHashing:
    """
    Behaviour of _hash_files_auto / _probe_read_bw / _hash_batch.

    The disk/hash measurements are mocked so the tests are deterministic on any machine — including the all-important
    guarantee that concurrency never changes the manifest.
    """

    @staticmethod
    def _make_files(tmp_path, count, algo="md5"):
        paths, sizes = [], []
        for i in range(count):
            p = tmp_path / f"f{i:04d}.bin"
            p.write_bytes(bytes([i % 256]) * (1000 + i))  # distinct content & size
            paths.append(str(p))
            sizes.append(p.stat().st_size)
        ref = [core_hashing.get_hash(p, algo) for p in paths]  # pure-sequential reference
        return paths, sizes, ref

    def _force(self, monkeypatch, *, read_bw, hash_bw, cpu=8, min_bytes=0, recheck=8 * 1024**3):
        monkeypatch.setattr(core_hashing, "_AUTO_MIN_BYTES", min_bytes)
        monkeypatch.setattr(core_hashing, "_AUTO_RECHECK_BYTES", recheck)
        monkeypatch.setattr(core_hashing, "_calibrate_hash_bw", lambda algo: hash_bw)
        # seal calibrates all formats combined via _calibrate_hash_bw_multi.
        monkeypatch.setattr(core_hashing, "_calibrate_hash_bw_multi", lambda factories: hash_bw)
        monkeypatch.setattr(core_hashing, "_probe_read_bw", lambda paths: read_bw)
        monkeypatch.setattr(core_hashing.os, "cpu_count", lambda: cpu)

    def _spy_batch(self, monkeypatch):
        calls: list[int] = []
        real = core_hashing._hash_batch

        def spy(jobs, workers):
            calls.append(workers)
            return real(jobs, workers)

        monkeypatch.setattr(core_hashing, "_hash_batch", spy)
        return calls

    # --- output invariance: the manifest must be identical on every path ---------------------------------------------

    def test_output_identical_parallel_branch(self, tmp_path, monkeypatch):
        paths, sizes, ref = self._make_files(tmp_path, 30)
        self._force(monkeypatch, read_bw=4000, hash_bw=1000)
        assert [d for d, _hashdate in core_hashing._hash_files_auto(paths, sizes, ["md5"])] == [[r] for r in ref]

    def test_output_identical_demotion_branch(self, tmp_path, monkeypatch):
        paths, sizes, ref = self._make_files(tmp_path, 30)
        # hash_bw huge => every window's measured rate < hash_bw => demote; a tiny recheck window makes demotion leave a
        # real sequential remainder.
        self._force(monkeypatch, read_bw=1e30, hash_bw=1e18, recheck=1)
        assert [d for d, _hashdate in core_hashing._hash_files_auto(paths, sizes, ["md5"])] == [[r] for r in ref]

    def test_output_identical_sequential_gate(self, tmp_path, monkeypatch):
        paths, sizes, ref = self._make_files(tmp_path, 30)
        self._force(monkeypatch, read_bw=100, hash_bw=1000)  # disk-bound
        assert [d for d, _hashdate in core_hashing._hash_files_auto(paths, sizes, ["md5"])] == [[r] for r in ref]

    # --- decisions ---------------------------------------------------------------------------------------------------

    def test_disk_bound_never_parallelises(self, tmp_path, monkeypatch):
        """read_bw below the threshold (HDD / fast hash) must stay sequential —
        the branch that protects spinning disks from seek-thrash."""
        paths, sizes, _ = self._make_files(tmp_path, 10)
        self._force(monkeypatch, read_bw=100, hash_bw=1000)
        calls = self._spy_batch(monkeypatch)
        list(core_hashing._hash_files_auto(paths, sizes, ["md5"]))
        assert all(w <= 1 for w in calls), f"disk-bound must not issue a concurrent batch, saw {calls}"

    def test_parallel_worker_count_from_bandwidth(self, tmp_path, monkeypatch):
        """workers ~= round(read_bw / hash_bw)."""
        paths, sizes, _ = self._make_files(tmp_path, 10)
        self._force(monkeypatch, read_bw=4000, hash_bw=1000, cpu=8)
        calls = self._spy_batch(monkeypatch)
        list(core_hashing._hash_files_auto(paths, sizes, ["md5"]))
        assert calls, "expected a concurrent batch to run"
        assert max(calls) == 4, f"expected 4 workers, saw {calls}"

    def test_worker_count_clamped_to_cores(self, tmp_path, monkeypatch):
        paths, sizes, _ = self._make_files(tmp_path, 10)
        self._force(monkeypatch, read_bw=100_000, hash_bw=1000, cpu=4)  # wants 100, capped to cores
        calls = self._spy_batch(monkeypatch)
        list(core_hashing._hash_files_auto(paths, sizes, ["md5"]))
        assert calls, "expected a concurrent batch to run"
        assert max(calls) == 4

    def test_small_job_skips_probe(self, tmp_path, monkeypatch):
        paths, sizes, ref = self._make_files(tmp_path, 5)
        monkeypatch.setattr(core_hashing, "_AUTO_MIN_BYTES", 10 * 1024**3)  # larger than the job
        probed: list[int] = []
        monkeypatch.setattr(core_hashing, "_probe_read_bw", lambda p: probed.append(1) or 1.0)
        assert [d for d, _hashdate in core_hashing._hash_files_auto(paths, sizes, ["md5"])] == [[r] for r in ref]
        assert probed == [], "a sub-threshold job must not probe the disk"

    def test_single_file_skips_probe(self, tmp_path, monkeypatch):
        paths, sizes, ref = self._make_files(tmp_path, 1)
        monkeypatch.setattr(core_hashing, "_AUTO_MIN_BYTES", 0)
        probed: list[int] = []
        monkeypatch.setattr(core_hashing, "_probe_read_bw", lambda p: probed.append(1) or 9e9)
        assert [d for d, _hashdate in core_hashing._hash_files_auto(paths, sizes, ["md5"])] == [[r] for r in ref]
        assert probed == [], "nothing to parallelise across a single file"

    # --- helpers -----------------------------------------------------------------------------------------------------

    def test_hash_batch_preserves_order(self, tmp_path):
        # Both the concurrent (workers>1) and the sequential (workers<=1, no pool) paths must return results in input
        # order.
        paths, _, ref = self._make_files(tmp_path, 20)

        def jobs() -> "list[Callable[[], str]]":
            return [(lambda p=p: core_hashing.get_hash(p, "md5")) for p in paths]

        assert core_hashing._hash_batch(jobs(), 4) == ref
        assert core_hashing._hash_batch(jobs(), 1) == ref

    def test_hash_batch_runs_jobs_concurrently_in_order(self, tmp_path, monkeypatch):
        """_hash_batch runs each job callable and returns results in input order;
        jobs resolve get_hash via the module global so monkeypatches intercept."""
        paths, _, _ = self._make_files(tmp_path, 6)
        monkeypatch.setattr(core_hashing, "get_hash", lambda p, a: "STUB")
        jobs: list[Callable[[], str]] = [(lambda p=p: core_hashing.get_hash(p, "md5")) for p in paths]
        assert core_hashing._hash_batch(jobs, 3) == ["STUB"] * 6

    def test_probe_read_bw_skips_unreadable(self, tmp_path, monkeypatch):
        good = tmp_path / "g.bin"
        good.write_bytes(b"x" * 4096)
        monkeypatch.setattr(core_hashing, "_AUTO_PROBE_BYTES", 1)
        monkeypatch.setattr(core_hashing, "_AUTO_PROBE_SECONDS", 0.0)
        bw = core_hashing._probe_read_bw([str(tmp_path / "missing.bin"), str(good)])
        assert bw > 0  # unreadable path skipped without error, good file measured

    def test_carries_well_formed_per_file_hashdate(self, tmp_path):
        """
        Each file comes back paired with a UTC ISO-8601 hashdate captured by the hashing worker (precise even in
        parallel windows), not stamped at emit.
        """
        paths, sizes, ref = self._make_files(tmp_path, 3)
        out = list(core_hashing._hash_files_auto(paths, sizes, ["md5"]))
        assert [d for d, _ in out] == [[r] for r in ref]
        for _digests, hashdate in out:
            datetime.strptime(hashdate, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)

    def test_calibrate_hash_bw_is_positive_and_finite(self):
        """
        The real in-RAM calibrations (mocked everywhere else) return a usable bytes/sec figure — both the
        single-algorithm and the combined-format (seal's read-once multi-hash) variants.
        """
        for algo in ("md5", "xxhash"):
            assert 0 < core_hashing._calibrate_hash_bw(algo) < float("inf")
        factories = [core_hashing.ALGO_MAP[a][0] for a in ("md5", "xxhash")]
        assert 0 < core_hashing._calibrate_hash_bw_multi(factories) < float("inf")

    def test_probe_read_bw_falls_through_when_files_smaller_than_floor(self, tmp_path):
        """
        When the byte/time floors are never reached, the probe reads every file and returns the rate over what it
        managed to read (the fall-through return).
        """
        small = tmp_path / "s.bin"
        small.write_bytes(b"x" * 4096)
        # Defaults floors are GB-scale, so a 4 KiB file never trips the early return — the loop exhausts the file list
        # and returns read/elapsed.
        bw = core_hashing._probe_read_bw([str(small)])
        assert bw > 0


class TestGetHashes:
    """The read-once multi-hash loop and its single-format wrapper."""

    def test_on_progress_reports_each_chunk(self, tmp_path, monkeypatch):
        """
        get_hashes invokes on_progress with the byte count of every chunk read, so the totals add up to the file size
        across multiple chunks.
        """
        monkeypatch.setattr(core_hashing, "HASH_CHUNK_SIZE", 1024)
        f = tmp_path / "big.bin"
        f.write_bytes(b"y" * 4096)
        chunks: list[int] = []
        core_hashing.get_hashes(str(f), [core_hashing.ALGO_MAP["md5"][0]], on_progress=chunks.append)
        assert sum(chunks) == 4096
        assert len(chunks) == 4  # 4096 / 1024

    def test_get_hash_rejects_unsupported_algorithm(self, tmp_path):
        """get_hash raises ValueError for an algorithm key absent from ALGO_MAP."""
        f = tmp_path / "a.bin"
        f.write_bytes(b"data")
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            core_hashing.get_hash(str(f), "blake2")
