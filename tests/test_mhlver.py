#!/usr/bin/env python3
"""Test suite for mhlver.py orchestrator and ASC-MHL dispatch.

Covers:
  - mhlver: directory walking, ASC-MHL detection, report generation
"""
import pytest
from pathlib import Path

from mhl_suite import mhlver


class TestMhlver:
    """Tests for mhlver — the orchestrator."""

    def test_find_mhl_files(self, tmp_path):
        """find_mhl_files yields case-insensitively and skips ._ files."""
        (tmp_path / "a.mhl").write_text("")
        (tmp_path / "b.MHL").write_text("")
        (tmp_path / "._meta.mhl").write_text("")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "c.MhL").write_text("")

        found = sorted(p.name for p in mhlver.find_mhl_files(tmp_path))
        assert found == ["a.mhl", "b.MHL", "c.MhL"]

    def test_select_mhl_files_dedups_ascmhl(self, tmp_path):
        """ASC-MHL packages should yield only one manifest per package."""
        # Two packages, each with two ascmhl manifests.
        for pkg in ["pkg1", "pkg2"]:
            ascdir = tmp_path / pkg / "ascmhl"
            ascdir.mkdir(parents=True)
            (ascdir / "0001.mhl").write_text("")
            (ascdir / "0002.mhl").write_text("")
        # Plus one regular MHL outside ascmhl/
        (tmp_path / "loose.mhl").write_text("")

        selected = mhlver._select_mhl_files(tmp_path)
        # Expected: 1 from pkg1 ascmhl, 1 from pkg2 ascmhl, 1 loose = 3
        assert len(selected) == 3

    def test_format_duration(self):
        """Duration formatter renders correctly across magnitudes."""
        assert mhlver._format_duration(0.5) == "0.5s"
        assert mhlver._format_duration(45.7) == "45.7s"
        assert mhlver._format_duration(125) == "2m 5s"
        assert mhlver._format_duration(3725) == "1h 2m 5s"


@pytest.fixture
def ascmhl_setup(tmp_path):
    """Set up the layout ascmhl-debug expects and return the manifest path."""
    pkg = tmp_path / "pkg"
    ascdir = pkg / "ascmhl"
    ascdir.mkdir(parents=True)
    manifest = ascdir / "0001.mhl"
    manifest.write_text("<dummy/>")
    return manifest


def stub_run_step(monkeypatch, exit_code: int, output: str = ""):
    """Replace _run_step with a stub that returns a fixed StepResult."""
    def _stub(cmd, cwd=None):
        return mhlver.StepResult(exit_code=exit_code, output=output)
    monkeypatch.setattr(mhlver, "_run_step", _stub)


def call_verify(manifest: Path) -> int:
    """Invoke _ascmhl_verify with sane defaults and return its exit code."""
    return mhlver._ascmhl_verify(
        target=manifest,
        cmd_path="/fake/ascmhl-debug",
        cwd=None,
        verbose=False,
        report_file=None,
    )


class TestAscmhlDispatch:
    """
    Tests for the ASC-MHL (v2) exit-code translation layer in mhlver.
    """

    def test_verify_clean_returns_zero(self, ascmhl_setup, monkeypatch):
        """Exit 0 from ascmhl-debug verify -> mhlver returns 0."""
        stub_run_step(monkeypatch, 0)
        assert call_verify(ascmhl_setup) == 0

    def test_verify_completeness_failure_propagates_10(self, ascmhl_setup, monkeypatch):
        """Exit 10 (CompletenessCheckFailedException) propagates as-is."""
        stub_run_step(monkeypatch, 10, "ERROR: 1 missing file(s):")
        assert call_verify(ascmhl_setup) == 10

    def test_verify_hash_mismatch_propagates_11(self, ascmhl_setup, monkeypatch):
        """Exit 11 (VerificationFailedException) propagates as-is."""
        stub_run_step(monkeypatch, 11, "ERROR: hash mismatch")
        assert call_verify(ascmhl_setup) == 11

    def test_verify_dir_hash_mismatch_propagates_12(self, ascmhl_setup, monkeypatch):
        """Exit 12 (VerificationDirectoriesFailedException) propagates."""
        stub_run_step(monkeypatch, 12)
        assert call_verify(ascmhl_setup) == 12

    def test_verify_no_history_propagates_30(self, ascmhl_setup, monkeypatch):
        """Exit 30 (NoMHLHistoryException) propagates."""
        stub_run_step(monkeypatch, 30)
        assert call_verify(ascmhl_setup) == 30

    def test_verify_modified_manifest_propagates_31(self, ascmhl_setup, monkeypatch):
        """Exit 31 (ModifiedMHLManifestFileException) propagates."""
        stub_run_step(monkeypatch, 31)
        assert call_verify(ascmhl_setup) == 31

    def test_verify_unknown_exit_code_falls_back(self, ascmhl_setup, monkeypatch):
        """An unknown exit code from ascmhl-debug should still be returned,
        not silently mapped to 0."""
        stub_run_step(monkeypatch, 99, "weirdness")
        assert call_verify(ascmhl_setup) == 99

    def test_schema_check_clean_returns_zero(self, ascmhl_setup, monkeypatch):
        """Both schema checks pass -> exit 0."""
        stub_run_step(monkeypatch, 0)
        rc = mhlver._ascmhl_schema_check(
            target=ascmhl_setup,
            cmd_path="/fake/ascmhl-debug",
            cwd=None,
            verbose=False,
            report_file=None,
        )
        assert rc == 0

    def test_schema_check_manifest_failure_takes_precedence(self, ascmhl_setup, monkeypatch):
        """If the manifest fails schema check, that code wins over the chain's."""
        call_count = {"n": 0}
        def _stub(cmd, cwd=None):
            call_count["n"] += 1
            return mhlver.StepResult(
                exit_code=11 if call_count["n"] == 1 else 0,
                output="manifest failed" if call_count["n"] == 1 else "",
            )
        monkeypatch.setattr(mhlver, "_run_step", _stub)
        
        rc = mhlver._ascmhl_schema_check(
            target=ascmhl_setup,
            cmd_path="/fake/ascmhl-debug",
            cwd=None,
            verbose=False,
            report_file=None,
        )
        assert rc == 11

    def test_dispatch_table_covers_all_known_codes(self):
        """The ASC-MHL verify dispatch table must cover every code that
        ascmhl/errors.py defines, so we never fall through to the
        'unexpected exit' branch for a documented failure."""
        documented_codes = {0, 10, 11, 12, 20, 21, 30, 31, 32, 33, 127}
        missing = documented_codes - set(mhlver._ASCMHL_VERIFY_RESULTS.keys())
        assert missing == set(), f"Dispatch table missing codes: {missing}"

    def test_ascmhl_backend_output_shown_by_default(self, ascmhl_setup, monkeypatch, capsys):
        """ascmhl's per-file output is shown on terminal by default."""
        stub_run_step(monkeypatch, 30, "ERROR: no MHL history found at /pkg")
        
        # capsys from pytest automatically captures output cleanly.
        mhlver._ascmhl_verify(
            target=ascmhl_setup,
            cmd_path="/fake/ascmhl-debug",
            cwd=None,
            verbose=False,
            report_file=None,
        )
        
        captured = capsys.readouterr()
        assert "ERROR: no MHL history found" in captured.err

    def test_ascmhl_backend_output_also_shown_with_verbose(self, ascmhl_setup, monkeypatch, capsys):
        """With --verbose, ascmhl's output is also shown on terminal."""
        stub_run_step(monkeypatch, 30, "ERROR: no MHL history found at /pkg")
        
        mhlver._ascmhl_verify(
            target=ascmhl_setup,
            cmd_path="/fake/ascmhl-debug",
            cwd=None,
            verbose=True,
            report_file=None,
        )
        
        captured = capsys.readouterr()
        assert "ERROR: no MHL history found" in captured.err

    def test_ascmhl_backend_output_always_in_report_file(self, ascmhl_setup, monkeypatch):
        """Report file always captures backend output, regardless of verbose."""
        import io
        stub_run_step(monkeypatch, 30, "ERROR: no MHL history found at /pkg")
        report = io.StringIO()
        
        mhlver._ascmhl_verify(
            target=ascmhl_setup,
            cmd_path="/fake/ascmhl-debug",
            cwd=None,
            verbose=False,
            report_file=report,
        )
        
        assert "ERROR: no MHL history found" in report.getvalue()