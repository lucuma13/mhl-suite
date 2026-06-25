"""Fidelity oracle for the vendored ASC-MHL engine + the in-process wrapper.

These build a real ASC-MHL package on disk with the vendored `create` command and
then exercise mhl_suite.ascmhl.verify end to end — verify_package, schema_check,
integrity_check — across clean and every failure mode. This proves the vendored
engine (mhl_suite.ascmhl.vendor.commands.verify_entire_folder, refactored to
two-phase parallel hashing) still produces the upstream exit codes and that our
structured wrapper maps them correctly, without needing upstream's pyfakefs harness.
"""

import glob
from pathlib import Path

import pytest
from click.testing import CliRunner

from mhl_suite.ascmhl import verify
from mhl_suite.ascmhl.vendor import commands


def _make_package(root, files, hash_format="xxh64"):
    """Create files under *root* and seal them into an ASC-MHL package."""
    for rel, content in files.items():
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(content)
    result = CliRunner().invoke(commands.create, [str(root), "-h", hash_format])
    assert result.exit_code == 0, result.output
    return root


@pytest.fixture
def package(tmp_path):
    """A sealed, clean ASC-MHL package with a couple of files."""
    return _make_package(tmp_path / "pkg", {"top.txt": b"hello\n", "A/a1.txt": b"aaa\n", "A/a2.txt": b"bbb\n"})


def _statuses(report):
    return {e.path: e.status for e in report.entries}


class TestVerifyPackage:
    """verify_package returns the upstream exit code and structured per-file outcomes."""

    def test_clean_package_passes(self, package):
        report = verify.verify_package(package)
        assert report.code == 0
        assert set(_statuses(report).values()) == {"ok"}

    def test_progress_reports_each_hashed_file(self, package):
        seen = []
        report = verify.verify_package(package, on_progress=seen.append)
        assert report.code == 0
        assert len(seen) == 3  # one callback per hashed file

    def test_tampered_file_is_mismatch_exit_11(self, package):
        (package / "A/a1.txt").write_bytes(b"CORRUPT\n")
        report = verify.verify_package(package)
        assert report.code == 11
        assert _statuses(report)["A/a1.txt"] == "mismatch"

    def test_missing_file_is_exit_10(self, package):
        (package / "top.txt").unlink()
        report = verify.verify_package(package)
        assert report.code == 10
        assert _statuses(report)["top.txt"] == "missing"

    def test_new_file_is_exit_21(self, package):
        (package / "A/new.txt").write_bytes(b"surprise\n")
        report = verify.verify_package(package)
        assert report.code == 21
        assert _statuses(report)["A/new.txt"] == "new"

    def test_no_history_is_exit_30(self, tmp_path):
        (tmp_path / "bare.txt").write_bytes(b"x")
        report = verify.verify_package(tmp_path)
        assert report.code == 30

    @pytest.mark.parametrize("hash_format", ["md5", "c4", "xxh128"])
    def test_non_default_hash_formats_round_trip(self, tmp_path, hash_format):
        """Formats outside shared.hashing's registry (c4/xxh128) still verify,
        proving the ASC-format calibration drives the parallel controller."""
        pkg = _make_package(tmp_path / "pkg", {"clip.mov": b"x" * 64}, hash_format=hash_format)
        assert verify.verify_package(pkg).code == 0
        (pkg / "clip.mov").write_bytes(b"y" * 64)
        assert verify.verify_package(pkg).code == 11


class TestSchemaCheck:
    """schema_check validates against the bundled XSDs in-process."""

    def test_valid_manifest(self, package):
        manifest = glob.glob(str(package / "ascmhl" / "*.mhl"))[0]
        assert verify.schema_check(manifest) == (0, [])

    def test_valid_chain(self, package):
        chain = package / "ascmhl" / "ascmhl_chain.xml"
        assert verify.schema_check(chain, directory_file=True) == (0, [])

    def test_malformed_xml_is_exit_20(self, tmp_path):
        bad = tmp_path / "bad.mhl"
        bad.write_text("<hashlist><not closed")
        code, lines = verify.schema_check(bad)
        assert code == 20
        assert lines

    def test_schema_noncompliant_is_exit_11(self, tmp_path):
        wrong = tmp_path / "wrong.mhl"
        wrong.write_text('<?xml version="1.0"?><notmhl/>')
        code, _lines = verify.schema_check(wrong)
        assert code == 11


class TestIntegrityCheck:
    """integrity_check gates on manifest/chain integrity without hashing media."""

    def test_intact_package_passes(self, package):
        assert verify.integrity_check(package) == (0, "")

    def test_missing_history_is_nonzero(self, tmp_path):
        code, msg = verify.integrity_check(tmp_path)
        assert code != 0
        assert msg

    def test_tampered_manifest_detected(self, package):
        # Corrupt a generation manifest after sealing: loading the history
        # recomputes and compares each manifest's own hash, so this must fail.
        manifest = Path(glob.glob(str(package / "ascmhl" / "*.mhl"))[0])
        manifest.write_text(manifest.read_text().replace("<creatorinfo>", "<creatorinfo> "))
        code, _msg = verify.integrity_check(package)
        assert code != 0
