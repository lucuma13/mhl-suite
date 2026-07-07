"""
ASC-MHL verification: the in-process wrapper and its size-check internals
(mhl_suite.ascmhl_verify).

Three layers, top to bottom:
  - verify_ascmhl / schema_check — the library boundary mhlver drives, across
    clean and every failure mode, asserting on the structured VerifyReport. They
    prove our own verify loop maps the ASC-MHL exit codes correctly.
  - verify_ascmhl(size_only=True) — the suite's size-only extension (ascmhl has
    no size check), with its own exit code 13 for a size mismatch, kept distinct
    from hash mismatch 11 so a size failure never masquerades as a hash failure.
  - verify_ascmhl_sizes — the size engine, driven off the same loaded MHLHistory
    the hash path uses. Exercised against real sealed packages (plus a couple of
    targeted stubs for branches a clean package can't carry).
"""

import glob
import os
from pathlib import Path

import pytest
from ascmhl import commands
from ascmhl.history import MHLHistory
from click.testing import CliRunner

from mhl_suite import ascmhl_verify as verify
from mhl_suite.ascmhl_verify import SizeCheckResult, verify_ascmhl_sizes

from .helpers import make_package, statuses


def verify_ascmhl_size_only(root, **kwargs):
    """
    verify_ascmhl in size-only mode (named to keep each test body to one line).
    """
    return verify.verify_ascmhl(root, size_only=True, **kwargs)


def sizes_for(package):
    """
    {path: SizeCheckResult} from the size engine run on a real, loadable package
    (its load is the integrity gate).
    """
    return {r.path: r for r in verify_ascmhl_sizes(MHLHistory.load_from_path(str(package)), package)}


class TestHashAndCompare:
    """PASS 2 of the ASC-MHL verify (hash + compare deferred files)."""

    def test_no_deferred_files_is_zero_failures(self):
        """
        With nothing deferred (an empty package), the hash phase short-circuits
        to zero mismatches without touching the adaptive controller.
        """
        report: list = []
        assert verify._hash_and_compare([], report, None) == 0
        assert report == []


class TestCalibrateHashBw:
    """
    The in-RAM hash-bandwidth calibration feeding the adaptive controller for
    ASC-MHL formats the shared hasher registry doesn't know (xxh128/xxh3/c4).
    """

    def test_returns_positive_finite_bandwidth(self):
        # xxh64 is always available; the calibration runs the library's own
        # incremental hasher, so any supported format gives a usable bytes/sec.
        bw = verify._calibrate_hash_bw("xxh64")
        assert 0 < bw < float("inf")


class TestVerifyPackage:
    """
    verify_ascmhl returns the upstream exit code and structured per-file
    outcomes.
    """

    def test_clean_package_passes(self, package):
        report = verify.verify_ascmhl(package)
        assert report.code == 0
        assert set(statuses(report).values()) == {"ok"}

    def test_report_paths_use_forward_slashes(self, package):
        """
        Nested per-file entries carry the canonical forward-slash path, never
        the native separator.
        """
        report = verify.verify_ascmhl(package)
        entry = next(e for e in report.entries if e.path.endswith("a1.txt"))
        assert entry.path == "A/a1.txt"
        assert "A/a1.txt" in entry.line
        assert "\\" not in entry.path
        assert "A\\a1.txt" not in entry.line

    def test_progress_reports_each_hashed_file(self, package):
        seen = []
        report = verify.verify_ascmhl(package, on_progress=seen.append)
        assert report.code == 0
        assert len(seen) == 3  # one callback per hashed file

    def test_tampered_file_is_mismatch_exit_11(self, package):
        (package / "A/a1.txt").write_bytes(b"CORRUPT\n")
        report = verify.verify_ascmhl(package)
        assert report.code == 11
        assert statuses(report)["A/a1.txt"] == "mismatch"

    def test_missing_file_is_exit_10(self, package):
        (package / "top.txt").unlink()
        report = verify.verify_ascmhl(package)
        assert report.code == 10
        assert statuses(report)["top.txt"] == "missing"

    def test_all_files_missing_is_single_file_not_found_exit_20(self, package):
        """
        When every recorded file is gone there is nothing to hash, so the result
        is 'no file found at all' (20), which trumps the per-file missing code.
        """
        for f in (package / "top.txt", package / "A/a1.txt", package / "A/a2.txt"):
            f.unlink()
        report = verify.verify_ascmhl(package)
        assert report.code == 20

    def test_relative_root_is_resolved_against_cwd(self, package, monkeypatch):
        """
        A relative root path is resolved against the current directory before
        the history loads, so verify works whether the caller passes an absolute
        or relative package path.
        """
        monkeypatch.chdir(package.parent)
        report = verify.verify_ascmhl(package.name)
        assert report.code == 0

    def test_new_file_is_exit_21(self, package):
        (package / "A/new.txt").write_bytes(b"surprise\n")
        report = verify.verify_ascmhl(package)
        assert report.code == 21
        assert statuses(report)["A/new.txt"] == "new"

    def test_default_ignore_patterns_always_apply(self, package, monkeypatch):
        """
        The spec-mandated default ignore set (.DS_Store, ascmhl) always applies,
        even when a manifest recorded custom ignore patterns without the
        defaults. Otherwise verify would descend into ascmhl/ and flag its
        manifests and chain as new files (exit 21). We simulate such a foreign
        manifest by returning a custom-only pattern list.
        """
        monkeypatch.setattr(MHLHistory, "latest_ignore_patterns", lambda self: ["*.tmp"])
        report = verify.verify_ascmhl(package)
        assert report.code == 0
        assert set(statuses(report).values()) == {"ok"}

    def test_no_history_is_exit_30(self, tmp_path):
        (tmp_path / "bare.txt").write_bytes(b"x")
        report = verify.verify_ascmhl(tmp_path)
        assert report.code == 30

    @pytest.mark.parametrize("hash_format", ["md5", "c4", "xxh128"])
    def test_non_default_hash_formats_round_trip(self, tmp_path, hash_format):
        """Formats outside mhl_suite.hashing's registry (c4/xxh128) still verify,
        proving the ASC-format calibration drives the parallel controller."""
        pkg = make_package(tmp_path / "pkg", {"clip.mov": b"x" * 64}, hash_format=hash_format)
        assert verify.verify_ascmhl(pkg).code == 0
        (pkg / "clip.mov").write_bytes(b"y" * 64)
        assert verify.verify_ascmhl(pkg).code == 11


class TestSchemaCheck:
    """schema_check validates against the bundled XSDs in-process."""

    def test_valid_manifest(self, package):
        manifest = glob.glob(str(package / "ascmhl" / "*.mhl"))[0]
        assert verify.schema_check(manifest) == (0, [])

    def test_valid_chain(self, package):
        chain = package / "ascmhl" / "ascmhl_chain.xml"
        assert verify.schema_check(chain, directory_file=True) == (0, [])

    def test_malformed_xml_is_exit_40(self, tmp_path):
        bad = tmp_path / "bad.mhl"
        bad.write_text("<hashlist><not closed")
        code, lines = verify.schema_check(bad)
        assert code == 40
        assert lines

    def test_schema_noncompliant_is_exit_41(self, tmp_path):
        wrong = tmp_path / "wrong.mhl"
        wrong.write_text('<?xml version="1.0"?><notmhl/>')
        code, _lines = verify.schema_check(wrong)
        assert code == 41

    def test_unreadable_file_is_exit_40(self):
        """
        An unreadable/absent file raises OSError inside the parse, surfaced as
        the malformed-XML code (not a crash).
        """
        code, lines = verify.schema_check("/no/such/path/ghost.mhl")
        assert code == 40
        assert lines

    def test_missing_bundled_xsd_surfaces_error_code(self, package, monkeypatch):
        """
        A broken install (bundled XSD absent) is reported as the generic error
        code rather than raising out of schema_check.
        """
        manifest = glob.glob(str(package / "ascmhl" / "*.mhl"))[0]
        monkeypatch.setattr(
            verify, "_bundled_xsd_path", lambda name: (_ for _ in ()).throw(FileNotFoundError(f"missing: {name}"))
        )
        code, lines = verify.schema_check(manifest)
        assert code == verify.ExitCode.ERROR
        assert lines
        assert "missing" in lines[0]

    def test_bundled_xsd_path_raises_for_unknown_schema(self):
        """
        The path resolver raises FileNotFoundError for a schema name that isn't
        shipped in the mhl_suite.xsd package.
        """
        with pytest.raises(FileNotFoundError, match="bundled XSD not found"):
            verify._bundled_xsd_path("does-not-exist.xsd")


class TestSizeOnlyVerify:
    """
    verify_ascmhl(size_only=True) compares recorded sizes to disk, reading no
    bytes.
    """

    def test_clean_package_passes_without_hashing(self, package):
        seen = []
        report = verify_ascmhl_size_only(package, on_progress=seen.append)
        assert report.code == 0
        assert set(statuses(report).values()) == {"ok"}
        assert seen == []  # size-only reads no file bytes, so progress never ticks

    def test_clean_entries_are_flagged_size_only(self, package):
        report = verify_ascmhl_size_only(package)
        assert all(e.size_only for e in report.entries)

    def test_size_change_is_exit_13_not_11(self, package):
        # Append bytes: the file's hash AND size now differ, but size-only
        # reports the size mismatch (13) without ever hashing — distinct from
        # hash 11.
        (package / "top.txt").write_bytes(b"hello\nplus more\n")
        report = verify_ascmhl_size_only(package)
        assert report.code == 13
        assert statuses(report)["top.txt"] == "mismatch"

    def test_size_mismatch_carries_renderable_detail(self, package):
        (package / "top.txt").write_bytes(b"hello\nplus more\n")
        report = verify_ascmhl_size_only(package)
        entry = next(e for e in report.entries if e.status == "mismatch")
        assert entry.line.startswith("[ERROR] size mismatch:")
        assert entry.detail_line.strip().startswith("(calc size:")

    def test_missing_file_is_exit_10(self, package):
        (package / "top.txt").unlink()
        report = verify_ascmhl_size_only(package)
        assert report.code == 10
        assert statuses(report)["top.txt"] == "missing"

    def test_bare_reason_mismatch_renders_label_only(self, package, monkeypatch):
        """
        A size failure with no parenthetical detail (e.g. 'blocked traversal
        attempt') renders as a bare '[ERROR] <reason>: <path>' with no
        continuation line. The real package passes the integrity gate so the
        wrapper reaches this mapping; the size result is stubbed since a clean
        sealed package can't carry an escaping path.
        """
        monkeypatch.setattr(
            verify,
            "verify_ascmhl_sizes",
            lambda history, root_path: [SizeCheckResult("top.txt", "mismatch", "blocked traversal attempt")],
        )
        report = verify_ascmhl_size_only(package)
        assert report.code == 13
        entry = next(e for e in report.entries if e.status == "mismatch")
        assert entry.line == "[ERROR] blocked traversal attempt: top.txt"
        assert entry.detail_line == ""

    def test_integrity_gate_failure_passes_through(self, tmp_path):
        # No ASC-MHL history at all: the history load (which doubles as the
        # integrity gate) fails (30) before any size check, and its code/notice
        # surface instead of a size verdict.
        (tmp_path / "loose.txt").write_bytes(b"x")
        report = verify_ascmhl_size_only(tmp_path)
        assert report.code == 30
        assert report.entries == []
        assert report.notices

    def test_tampered_manifest_surfaces_gate_error(self, package):
        # The single history load is the integrity gate: corrupting a generation
        # manifest so it no longer matches its own recorded hash makes the load
        # fail, and size-only reports that manifest error instead of a size
        # verdict.
        manifest = Path(glob.glob(str(package / "ascmhl" / "*.mhl"))[0])
        manifest.write_text(manifest.read_text().replace("<creatorinfo>", "<creatorinfo> "))
        report = verify_ascmhl_size_only(package)
        assert report.code != 0
        assert report.entries == []
        assert report.notices


class TestVerifyAscmhlSizes:
    """
    verify_ascmhl_sizes turns each recorded file into one ok / missing /
    mismatch SizeCheckResult.

    It runs off the loaded MHLHistory, so generation grouping, rename resolution
    and child-history descent are the reference's, not re-derived. We drive it
    against real sealed packages; the two branches a clean package can't reach
    (a path escaping the root, the resolve->getsize race) are provoked with
    targeted stubs.
    """

    def test_matching_size_is_ok(self, package):
        assert sizes_for(package)["top.txt"].status == "ok"

    def test_wrong_size_is_mismatch_with_detail(self, package):
        (package / "top.txt").write_bytes(b"x")  # 1 byte on disk, 6 recorded
        r = sizes_for(package)["top.txt"]
        assert r.status == "mismatch"
        assert r.detail == "size mismatch: calc size: 1 | stored size: 6"

    def test_absent_file_is_missing(self, package):
        (package / "top.txt").unlink()
        assert sizes_for(package)["top.txt"].status == "missing"

    def test_missing_recorded_size_is_ok_not_a_failure(self, tmp_path):
        # ascmhl omits the optional <path size> for a 0-byte file. The spec
        # gives absence no meaning, so an existing
        # file with no recorded size is verified for existence only and passes.
        pkg = make_package(tmp_path / "pkg", {"empty.mov": b"", "full.mov": b"data"})
        results = sizes_for(pkg)
        assert results["empty.mov"].status == "ok"
        assert results["empty.mov"].detail == "size: not recorded"
        assert results["full.mov"].status == "ok"

    def test_missing_recorded_size_still_checks_existence(self, tmp_path):
        # A sizeless record is existence-checked, not blindly passed: if its
        # file is gone it is still reported missing.
        pkg = make_package(tmp_path / "pkg", {"empty.mov": b""})
        (pkg / "empty.mov").unlink()
        assert sizes_for(pkg)["empty.mov"].status == "missing"

    def test_directory_and_child_reference_entries_are_skipped(self, package):
        # The recorded set includes the A/ directory hash; only real files are
        # size-checked (as the reference's verify reaches files only), so the
        # directory entry never leaks into the results.
        assert set(sizes_for(package)) == {"top.txt", "A/a1.txt", "A/a2.txt"}

    def test_nested_child_history_files_are_covered(self, tmp_path):
        # A sub-folder sealed as its own ASC-MHL history, then wrapped by a
        # parent seal. The parent's size verify must descend into the child,
        # matching the hash path and the reference's combined-history grouping.
        root = tmp_path / "pkg"
        make_package(root / "sub", {"child.mov": b"child\n"})  # child history first
        make_package(root, {"top.txt": b"top\n"})  # parent wraps it (references the child)
        results = sizes_for(root)
        assert results["sub/child.mov"].status == "ok"
        assert results["top.txt"].status == "ok"

    def test_original_generation_size_wins(self, tmp_path):
        # Seal a.mov at 100 bytes, then grow it to 200 and re-seal (creating gen
        # 2). The recorded ORIGINAL size is gen1's 100, so the on-disk 200 must
        # mismatch — proving we compare against the first generation, not gen2.
        pkg = make_package(tmp_path / "pkg", {"a.mov": b"x" * 100})
        (pkg / "a.mov").write_bytes(b"x" * 200)
        CliRunner().invoke(commands.create, [str(pkg), "-h", "xxh64"])  # gen 2 records size 200
        r = sizes_for(pkg)["a.mov"]
        assert r.status == "mismatch"
        assert r.detail == "size mismatch: calc size: 200 | stored size: 100"

    def test_path_escaping_root_is_blocked(self, package, monkeypatch):
        # A manifest can't normally record an escaping path, so stub the
        # recorded set to force the traversal guard.
        history = MHLHistory.load_from_path(str(package))
        escaping = os.path.join(str(package), "..", "escape.txt")
        monkeypatch.setattr(history, "set_of_file_paths", lambda: {escaping})
        (result,) = verify_ascmhl_sizes(history, package)
        assert result.status == "mismatch"
        assert result.detail == "blocked traversal attempt"

    def test_file_vanishing_after_resolution_is_missing(self, package, monkeypatch):
        # Models the resolve->getsize race: the entry resolves, then getsize raises.
        def _raise(_path):
            raise OSError(2, "vanished")

        monkeypatch.setattr("mhl_suite.ascmhl_verify.os.path.getsize", _raise)
        assert sizes_for(package)["top.txt"].status == "missing"
