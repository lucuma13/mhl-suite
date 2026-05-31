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


# =============================================================================
# TestAscmhlTotalBytes
# =============================================================================
# Covers lines 808-829: _ascmhl_total_bytes — path/@size deduplication across
# ASC-MHL generation files.
#
# Fixtures write minimal but schema-valid ASC-MHL 2.0 XML directly to
# tmp_path so no external tools or mocking of the XML layer are needed.

class TestAscmhlTotalBytes:
    """Unit tests for _ascmhl_total_bytes — byte-weight pre-read for ASC-MHL."""

    def test_single_generation_sums_all_sizes(self, tmp_path, write_mhl):
        """All path/@size values in a single generation file are summed."""
        ascdir = tmp_path / "ascmhl"
        ascdir.mkdir()
        write_mhl(ascdir, "0001.mhl", [
            {"path": "Card/Clip/A001.jpg", "size": "223591", "action": "original", "digest": "aabbccdd"},
            {"path": "Card/Clip/A002.jpg", "size": "329746", "action": "original", "digest": "11223344"},
        ])
        assert mhlver._ascmhl_total_bytes(ascdir / "0001.mhl") == 223591 + 329746

    def test_verification_pass_does_not_double_count(self, tmp_path, write_mhl):
        """A second generation that re-verifies the same files must not add to the total."""
        ascdir = tmp_path / "ascmhl"
        ascdir.mkdir()
        entries = [
            {"path": "Card/Clip/A001.jpg", "size": "223591", "action": "original", "digest": "aabbccdd"},
            {"path": "Card/Clip/A002.jpg", "size": "329746", "action": "original", "digest": "11223344"},
        ]
        write_mhl(ascdir, "0001.mhl", entries)
        write_mhl(ascdir, "0002.mhl", [{**e, "action": "verified"} for e in entries])
        # Must equal single-generation total, not double it.
        assert mhlver._ascmhl_total_bytes(ascdir / "0002.mhl") == 223591 + 329746

    def test_new_files_in_later_generation_are_included(self, tmp_path, write_mhl):
        """Files introduced in a later generation are counted exactly once."""
        ascdir = tmp_path / "ascmhl"
        ascdir.mkdir()
        write_mhl(ascdir, "0001.mhl", [
            {"path": "clip_A.mov", "size": "1000000", "action": "original", "digest": "aaaaaaaa"},
        ])
        write_mhl(ascdir, "0002.mhl", [
            {"path": "clip_A.mov", "size": "1000000", "action": "verified", "digest": "aaaaaaaa"},
            {"path": "clip_B.mov", "size": "2000000", "action": "original", "digest": "bbbbbbbb"},
        ])
        assert mhlver._ascmhl_total_bytes(ascdir / "0002.mhl") == 1000000 + 2000000

    def test_directory_hashes_without_size_are_skipped(self, tmp_path, write_mhl):
        """<directoryhash><path> elements carry no size attribute and must be silently ignored.

        ASC-MHL packages produced by transfer tools include <directoryhash> blocks
        alongside <hash> blocks. Their <path> elements have no size attribute —
        only lastmodificationdate and creationdate — so the size guard must skip them
        without raising and without affecting the total.
        """
        ascdir = tmp_path / "ascmhl"
        ascdir.mkdir()
        mhl = ascdir / "0001.mhl"
        mhl.write_text("""\
<?xml version="1.0" encoding="UTF-8"?>
<hashlist version="2.0" xmlns="urn:ASC:MHL:v2.0">
  <hashes>
    <hash>
      <path size="1073741824" lastmodificationdate="2026-01-01T00:00:00+00:00">Card/Clip/A001/A001C001.mxf</path>
      <xxh64 action="original" hashdate="2026-01-01T00:00:00+00:00">aabbccddeeff0011</xxh64>
    </hash>
    <directoryhash>
      <path lastmodificationdate="2026-01-01T00:00:00+00:00">Card/Clip/A001</path>
      <content>
        <xxh64 hashdate="2026-01-01T00:00:00+00:00">1122334455667788</xxh64>
      </content>
    </directoryhash>
  </hashes>
</hashlist>""")
        # Only the <hash><path> contributes; <directoryhash><path> has no size.
        assert mhlver._ascmhl_total_bytes(mhl) == 1073741824

    def test_ascmhl_from_shotputpro_two_generation_transfer(self, tmp_path, write_mhl):
        """Six files transferred in generation 1, all re-verified in generation 2.

        Exercises the full deduplication path with a realistic file count and
        a mix of large and small sizes (video + sidecar XML pattern).
        Expected total: 223591+329746+363999+153415+288179+452705 = 1_811_635
        """
        ascdir = tmp_path / "ascmhl"
        ascdir.mkdir()
        files = [
            ("Card/Clip/A001.jpg", "223591", "dd445194b1a1d26c"),
            ("Card/Clip/A002.jpg", "329746", "53999809e5545be1"),
            ("Card/Clip/A003.jpg", "363999", "b18c71bad0e551b2"),
            ("Card/Clip/A004.jpg", "153415", "5fb3c7f42e4d3470"),
            ("Card/Clip/A005.jpg", "288179", "29e214aa106f9037"),
            ("Card/Clip/A006.jpg", "452705", "5ec873de8ba744bc"),
        ]
        write_mhl(ascdir, "0001.mhl", [{"path": p, "size": s, "action": "original", "digest": d} for p, s, d in files])
        write_mhl(ascdir, "0002.mhl", [{"path": p, "size": s, "action": "verified",  "digest": d} for p, s, d in files])
        assert mhlver._ascmhl_total_bytes(ascdir / "0002.mhl") == 1_811_635

    def test_ascmhl_from_shotputpro_single_generation_with_directory_hashes(self, tmp_path):
        """Six MXF+sidecar pairs plus a manifest file, interspersed with directory hashes.

        Reproduces the structure a transfer tool generates for a camera card:
        each clip folder gets a <directoryhash> with no size, while each file
        gets a <hash> with a size attribute. The parent folder and a top-level
        metadata file are also present.

        Expected total (13 files with size):
          2246896176 + 4170 + 15758019120 + 4172 + 14349986352 + 4172
        + 5392501296 + 4170 + 10904799792 + 4172 + 13421283888 + 4172 + 2945
        = 62_073_514_597
        """
        ascdir = tmp_path / "ascmhl"
        ascdir.mkdir()
        mhl = ascdir / "0001.mhl"
        mhl.write_text("""\
<?xml version="1.0" encoding="UTF-8"?>
<hashlist version="2.0" xmlns="urn:ASC:MHL:v2.0">
  <hashes>
    <hash>
      <path size="2246896176" lastmodificationdate="2026-01-01T00:00:00+00:00">Card/Clip/A001/A001C001.mxf</path>
      <xxh64 action="original" hashdate="2026-01-01T00:00:00+00:00">d4b2ab4a3e2619c6</xxh64>
    </hash>
    <hash>
      <path size="4170" lastmodificationdate="2026-01-01T00:00:00+00:00">Card/Clip/A001/A001C001M01.xml</path>
      <xxh64 action="original" hashdate="2026-01-01T00:00:00+00:00">fb5ba52fd1791f62</xxh64>
    </hash>
    <directoryhash>
      <path lastmodificationdate="2026-01-01T00:00:00+00:00">Card/Clip/A001</path>
      <content><xxh64 hashdate="2026-01-01T00:00:00+00:00">3995de7ad212a6f6</xxh64></content>
    </directoryhash>
    <hash>
      <path size="15758019120" lastmodificationdate="2026-01-01T00:00:00+00:00">Card/Clip/A002/A002C001.mxf</path>
      <xxh64 action="original" hashdate="2026-01-01T00:00:00+00:00">958a6c5a73c506bf</xxh64>
    </hash>
    <hash>
      <path size="4172" lastmodificationdate="2026-01-01T00:00:00+00:00">Card/Clip/A002/A002C001M01.xml</path>
      <xxh64 action="original" hashdate="2026-01-01T00:00:00+00:00">cde877e7e0079f3d</xxh64>
    </hash>
    <directoryhash>
      <path lastmodificationdate="2026-01-01T00:00:00+00:00">Card/Clip/A002</path>
      <content><xxh64 hashdate="2026-01-01T00:00:00+00:00">92ff6973ff1159b6</xxh64></content>
    </directoryhash>
    <hash>
      <path size="14349986352" lastmodificationdate="2026-01-01T00:00:00+00:00">Card/Clip/A003/A003C001.mxf</path>
      <xxh64 action="original" hashdate="2026-01-01T00:00:00+00:00">fd9f619aa924c818</xxh64>
    </hash>
    <hash>
      <path size="4172" lastmodificationdate="2026-01-01T00:00:00+00:00">Card/Clip/A003/A003C001M01.xml</path>
      <xxh64 action="original" hashdate="2026-01-01T00:00:00+00:00">56c61ebd8b38365b</xxh64>
    </hash>
    <directoryhash>
      <path lastmodificationdate="2026-01-01T00:00:00+00:00">Card/Clip/A003</path>
      <content><xxh64 hashdate="2026-01-01T00:00:00+00:00">b8c58576b4441883</xxh64></content>
    </directoryhash>
    <hash>
      <path size="5392501296" lastmodificationdate="2026-01-01T00:00:00+00:00">Card/Clip/A004/A004C001.mxf</path>
      <xxh64 action="original" hashdate="2026-01-01T00:00:00+00:00">a7bda6dee54d41e9</xxh64>
    </hash>
    <hash>
      <path size="4170" lastmodificationdate="2026-01-01T00:00:00+00:00">Card/Clip/A004/A004C001M01.xml</path>
      <xxh64 action="original" hashdate="2026-01-01T00:00:00+00:00">967a863160e4bade</xxh64>
    </hash>
    <directoryhash>
      <path lastmodificationdate="2026-01-01T00:00:00+00:00">Card/Clip/A004</path>
      <content><xxh64 hashdate="2026-01-01T00:00:00+00:00">c02ddd33f04c3378</xxh64></content>
    </directoryhash>
    <hash>
      <path size="10904799792" lastmodificationdate="2026-01-01T00:00:00+00:00">Card/Clip/A005/A005C001.mxf</path>
      <xxh64 action="original" hashdate="2026-01-01T00:00:00+00:00">947991d5d2dfe31f</xxh64>
    </hash>
    <hash>
      <path size="4172" lastmodificationdate="2026-01-01T00:00:00+00:00">Card/Clip/A005/A005C001M01.xml</path>
      <xxh64 action="original" hashdate="2026-01-01T00:00:00+00:00">e25972c74459f110</xxh64>
    </hash>
    <directoryhash>
      <path lastmodificationdate="2026-01-01T00:00:00+00:00">Card/Clip/A005</path>
      <content><xxh64 hashdate="2026-01-01T00:00:00+00:00">1c44cbd0b2aa08d0</xxh64></content>
    </directoryhash>
    <hash>
      <path size="13421283888" lastmodificationdate="2026-01-01T00:00:00+00:00">Card/Clip/A006/A006C001.mxf</path>
      <xxh64 action="original" hashdate="2026-01-01T00:00:00+00:00">02df4015bd2ba8ae</xxh64>
    </hash>
    <hash>
      <path size="4172" lastmodificationdate="2026-01-01T00:00:00+00:00">Card/Clip/A006/A006C001M01.xml</path>
      <xxh64 action="original" hashdate="2026-01-01T00:00:00+00:00">5c5026562225f157</xxh64>
    </hash>
    <directoryhash>
      <path lastmodificationdate="2026-01-01T00:00:00+00:00">Card/Clip/A006</path>
      <content><xxh64 hashdate="2026-01-01T00:00:00+00:00">d04b1d08aa1c2cfd</xxh64></content>
    </directoryhash>
    <directoryhash>
      <path lastmodificationdate="2026-01-01T00:00:00+00:00">Card/Clip</path>
      <content><xxh64 hashdate="2026-01-01T00:00:00+00:00">e72e32641f908e9b</xxh64></content>
    </directoryhash>
    <directoryhash>
      <path lastmodificationdate="2026-01-01T00:00:00+00:00">Card/General</path>
      <content><xxh64 hashdate="2026-01-01T00:00:00+00:00">ef46db3751d8e999</xxh64></content>
    </directoryhash>
    <hash>
      <path size="2945" lastmodificationdate="2026-01-01T00:00:00+00:00">Card/MEDIAPRO.xml</path>
      <xxh64 action="original" hashdate="2026-01-01T00:00:00+00:00">d7dd876f790aa002</xxh64>
    </hash>
    <directoryhash>
      <path lastmodificationdate="2026-01-01T00:00:00+00:00">Card</path>
      <content><xxh64 hashdate="2026-01-01T00:00:00+00:00">bf9d9533d19dc938</xxh64></content>
    </directoryhash>
  </hashes>
</hashlist>""")
        assert mhlver._ascmhl_total_bytes(mhl) == 62_073_514_597

    def test_ascmhl_from_ocopy_in_place_single_generation(self, tmp_path):
        """o/COPY in-place seal: <directoryhash> with empty <content/> and <structure/>, sub-second hashdate.

        o/COPY emits <directoryhash> blocks when subfolders are present, but unlike
        ShotPutPro their <content/> and <structure/> child elements are self-closing
        empty tags rather than containing a hash value. The <path> inside still
        carries no size attribute, so the size guard must skip it correctly regardless.
        Hashdate timestamps include sub-second precision.

        Expected total: 436085 + 2775033 + 161713671 = 164_924_789
        """
        ascdir = tmp_path / "ascmhl"
        ascdir.mkdir()
        mhl = ascdir / "0001.mhl"
        mhl.write_text("""\
<?xml version="1.0" encoding="UTF-8"?>
<hashlist version="2.0" xmlns="urn:ASC:MHL:v2.0">
  <creatorinfo>
    <creationdate>2026-01-01T00:00:00+00:00</creationdate>
    <hostname>hostname.local</hostname>
    <tool version="0.9.2">o/COPY</tool>
    <author>author</author>
  </creatorinfo>
  <processinfo>
    <process>in-place</process>
    <ignore><pattern>.DS_Store</pattern></ignore>
  </processinfo>
  <hashes>
    <directoryhash>
      <path lastmodificationdate="2026-01-01T00:00:00+00:00">subfolder</path>
      <content/>
      <structure/>
    </directoryhash>
    <hash>
      <path size="436085" lastmodificationdate="2026-01-01T00:00:00+00:00">aaaaaaaa-0000-0000-0000-aaaaaaaaaaaa.JPG</path>
      <xxh64 action="original" hashdate="2026-01-01T00:00:00.000001+00:00">e8142245c45a9730</xxh64>
    </hash>
    <hash>
      <path size="2775033" lastmodificationdate="2026-01-01T00:00:00+00:00">A001.HEIC</path>
      <xxh64 action="original" hashdate="2026-01-01T00:00:00.000002+00:00">cbb243888a8034de</xxh64>
    </hash>
    <hash>
      <path size="161713671" lastmodificationdate="2026-01-01T00:00:00+00:00">A002.MOV</path>
      <xxh64 action="original" hashdate="2026-01-01T00:00:00.000003+00:00">fe53d4b59c94d282</xxh64>
    </hash>
  </hashes>
</hashlist>""")
        assert mhlver._ascmhl_total_bytes(mhl) == 436085 + 2775033 + 161713671

    def test_corrupt_generation_file_is_skipped_others_still_counted(self, tmp_path, write_mhl):
        """A corrupt .mhl in the ascmhl dir must be silently skipped; valid
        generations still contribute their sizes to the total.

        The inner exception handler in _ascmhl_total_bytes swallows parse
        failures per-file so a single bad generation doesn't zero out the
        entire package weight.
        """
        ascdir = tmp_path / "ascmhl"
        ascdir.mkdir()
        write_mhl(ascdir, "0001.mhl", [
            {"path": "clip_A.mov", "size": "1000000", "action": "original", "digest": "aaaaaaaa"},
        ])
        (ascdir / "0002.mhl").write_text("<not valid xml")
        assert mhlver._ascmhl_total_bytes(ascdir / "0002.mhl") == 1000000

    def test_generations_parsed_in_filename_order(self, tmp_path, write_mhl):
        """Earlier generation's size wins when the same path appears in multiple files."""
        ascdir = tmp_path / "ascmhl"
        ascdir.mkdir()
        write_mhl(ascdir, "0001.mhl", [
            {"path": "file.mov", "size": "100", "action": "original", "digest": "aaaaaaaa"},
        ])
        # 0002 re-records file.mov — must be ignored since 0001 wins.
        write_mhl(ascdir, "0002.mhl", [
            {"path": "file.mov", "size": "999", "action": "verified", "digest": "aaaaaaaa"},
        ])
        assert mhlver._ascmhl_total_bytes(ascdir / "0002.mhl") == 100


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

    def _stub(cmd, cwd=None, **kwargs):
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

    def test_schema_check_manifest_failure_takes_precedence(
        self, ascmhl_setup, monkeypatch
    ):
        """If the manifest fails schema check, that code wins over the chain's."""
        call_count = {"n": 0}

        def _stub(cmd, cwd=None, **kwargs):
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

    def test_ascmhl_backend_output_shown_by_default(
        self, ascmhl_setup, monkeypatch, capsys
    ):
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

    def test_ascmhl_backend_output_also_shown_with_verbose(
        self, ascmhl_setup, monkeypatch, capsys
    ):
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

    def test_ascmhl_backend_output_always_in_report_file(
        self, ascmhl_setup, monkeypatch
    ):
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


class TestLegacyDispatch:
    """Tests for the MHL v1 exit-code translation layer in _verify_legacy."""

    def test_verify_legacy_clean_returns_zero(self, tmp_path, monkeypatch):
        """Exit 0 from simple-mhl -> _verify_legacy returns 0."""
        mhl = tmp_path / "dummy.mhl"
        mhl.write_text("")
        stub_run_step(monkeypatch, 0)
        rc = mhlver._verify_legacy(
            target=mhl,
            verbose=False,
            schema=False,
            report_file=None,
        )
        assert rc == 0

    def test_verify_legacy_invalid_argument_propagates_1(self, tmp_path, monkeypatch):
        """Exit 1 from simple-mhl (bad argument) -> _verify_legacy returns 1."""
        mhl = tmp_path / "dummy.mhl"
        mhl.write_text("")
        stub_run_step(monkeypatch, 1, "Verification Error: not an MHL file")
        rc = mhlver._verify_legacy(
            target=mhl,
            verbose=False,
            schema=False,
            report_file=None,
        )
        assert rc == 1

    def test_verify_legacy_malformed_xml_propagates_20(self, tmp_path, monkeypatch):
        """Exit 20 from simple-mhl (malformed XML) -> _verify_legacy returns 20."""
        mhl = tmp_path / "dummy.mhl"
        mhl.write_text("")
        stub_run_step(monkeypatch, 20, "Malformed XML")
        rc = mhlver._verify_legacy(
            target=mhl,
            verbose=False,
            schema=False,
            report_file=None,
        )
        assert rc == 20

    def test_verify_legacy_missing_files_propagates_30(self, tmp_path, monkeypatch):
        """Exit 30 from simple-mhl (missing files) -> _verify_legacy returns 30."""
        mhl = tmp_path / "dummy.mhl"
        mhl.write_text("")
        stub_run_step(monkeypatch, 30)
        rc = mhlver._verify_legacy(
            target=mhl,
            verbose=False,
            schema=False,
            report_file=None,
        )
        assert rc == 30

    def test_verify_legacy_hash_mismatch_propagates_40(self, tmp_path, monkeypatch):
        """Exit 40 from simple-mhl (hash mismatch) -> _verify_legacy returns 40."""
        mhl = tmp_path / "dummy.mhl"
        mhl.write_text("")
        stub_run_step(monkeypatch, 40)
        rc = mhlver._verify_legacy(
            target=mhl,
            verbose=False,
            schema=False,
            report_file=None,
        )
        assert rc == 40

    def test_verify_legacy_both_failures_propagates_70(self, tmp_path, monkeypatch):
        """Exit 70 from simple-mhl (missing + mismatch) -> _verify_legacy returns 70."""
        mhl = tmp_path / "dummy.mhl"
        mhl.write_text("")
        stub_run_step(monkeypatch, 70)
        rc = mhlver._verify_legacy(
            target=mhl,
            verbose=False,
            schema=False,
            report_file=None,
        )
        assert rc == 70

    def test_verify_legacy_dispatch_table_covers_all_known_codes(self):
        """_LEGACY_RESULTS must cover every exit code simple-mhl can emit."""
        documented_codes = {0, 1, 20, 30, 40, 70, 127}
        missing = documented_codes - set(mhlver._LEGACY_RESULTS.keys())
        assert missing == set(), f"Dispatch table missing codes: {missing}"

# =============================================================================
# TestLogHelpers
# =============================================================================
# Covers _log's console branch (line 103), _emit_step_output's success and
# console paths (lines 246, 250-253), and _verbose_announce's cwd/console/
# report_file branches (lines 433, 435, 439).


class TestLogHelpers:
    """Unit tests for _log, _emit_step_output, and _verbose_announce."""

    def test_log_routes_through_console(self, capsys):
        """When a console object is passed, _log uses console.print, not print()."""
        import io as _io
        console_out = _io.StringIO()

        class FakeConsole:
            def print(self, msg, **kwargs):
                console_out.write(msg + "\n")

        mhlver._log(
            "hello",
            colour="",
            stream=None,
            report_file=None,
            console=FakeConsole(),
        )
        assert "hello" in console_out.getvalue()
        # Nothing should have leaked to the real stdout/stderr.
        captured = capsys.readouterr()
        assert "hello" not in captured.out
        assert "hello" not in captured.err

    def test_log_writes_to_report_file(self):
        """_log always writes a timestamped line to report_file."""
        import io as _io
        buf = _io.StringIO()
        mhlver._log("audit line", colour="", stream=None, report_file=buf)
        assert "audit line" in buf.getvalue()

    def test_emit_step_output_success_prints_to_stdout(self, capsys):
        """On exit_code==0 with show_on_terminal, output goes to stdout."""
        mhlver._emit_step_output("OK: file.bin", 0, None, show_on_terminal=True)
        captured = capsys.readouterr()
        assert "OK: file.bin" in captured.out

    def test_emit_step_output_success_via_console(self, capsys):
        """On exit_code==0, a console object is used instead of print()."""
        import io as _io
        console_out = _io.StringIO()

        class FakeConsole:
            def print(self, msg, **kwargs):
                console_out.write(msg + "\n")

        mhlver._emit_step_output(
            "OK: file.bin", 0, None, show_on_terminal=True, console=FakeConsole()
        )
        assert "OK: file.bin" in console_out.getvalue()

    def test_emit_step_output_failure_via_console(self, capsys):
        """On exit_code!=0, a console object is used for the error output."""
        import io as _io
        console_out = _io.StringIO()

        class FakeConsole:
            def print(self, msg, **kwargs):
                console_out.write(msg + "\n")

        mhlver._emit_step_output(
            "ERR: file.bin", 1, None, show_on_terminal=True, console=FakeConsole()
        )
        assert "ERR: file.bin" in console_out.getvalue()
        # Nothing should have leaked to real stderr.
        assert "ERR: file.bin" not in capsys.readouterr().err

    def test_emit_step_output_empty_is_noop(self, capsys):
        """Empty output string produces no output at all."""
        mhlver._emit_step_output("", 1, None, show_on_terminal=True)
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    def test_emit_step_output_always_writes_report_file(self):
        """Report file always gets the output regardless of show_on_terminal."""
        import io as _io
        buf = _io.StringIO()
        mhlver._emit_step_output("detail", 0, buf, show_on_terminal=False)
        assert "detail" in buf.getvalue()

    def test_verbose_announce_with_cwd_includes_cwd(self, capsys):
        """_verbose_announce includes (cwd=...) when cwd is not None."""
        mhlver._verbose_announce(
            ["/bin/cmd", "arg"], cwd=Path("/some/dir"), verbose=True, report_file=None
        )
        captured = capsys.readouterr()
        assert "cwd=/some/dir" in captured.err

    def test_verbose_announce_without_cwd_omits_cwd(self, capsys):
        """_verbose_announce omits cwd when it is None."""
        mhlver._verbose_announce(
            ["/bin/cmd"], cwd=None, verbose=True, report_file=None
        )
        captured = capsys.readouterr()
        assert "cwd" not in captured.err

    def test_verbose_announce_via_console(self):
        """_verbose_announce routes through console when provided."""
        import io as _io
        console_out = _io.StringIO()

        class FakeConsole:
            def print(self, msg, **kwargs):
                console_out.write(msg + "\n")

        mhlver._verbose_announce(
            ["/bin/cmd"], cwd=None, verbose=True, report_file=None, console=FakeConsole()
        )
        assert "running:" in console_out.getvalue()

    def test_verbose_announce_writes_report_file(self):
        """_verbose_announce mirrors the command line to the report file."""
        import io as _io
        buf = _io.StringIO()
        mhlver._verbose_announce(
            ["/bin/cmd", "arg"], cwd=None, verbose=True, report_file=buf
        )
        assert "running:" in buf.getvalue()

    def test_verbose_announce_noop_when_not_verbose(self, capsys):
        """_verbose_announce produces no output when verbose=False."""
        import io as _io
        buf = _io.StringIO()
        mhlver._verbose_announce(["/bin/cmd"], cwd=None, verbose=False, report_file=buf)
        captured = capsys.readouterr()
        assert captured.out == "" and captured.err == ""
        assert buf.getvalue() == ""


# =============================================================================
# TestReportViaTable
# =============================================================================
# Covers the suppressed-success-but-report-file branch (lines 398-401):
# show_status_on_terminal=False AND severity=="success" AND report_file set.


class TestReportViaTable:
    """Tests for _report_via_table edge cases."""

    def test_suppressed_success_still_writes_report_file(self, capsys):
        """When show_status_on_terminal=False and exit=0, the success line must
        still be written to the report file (the silent-progress-bar path)."""
        import io as _io
        buf = _io.StringIO()
        mhlver._report_via_table(
            mhlver._LEGACY_RESULTS,
            0,
            "manifest.mhl",
            "",
            buf,
            show_backend_output=False,
            show_status_on_terminal=False,
        )
        assert "manifest.mhl" in buf.getvalue()
        # But nothing on terminal.
        captured = capsys.readouterr()
        assert "manifest.mhl" not in captured.out
        assert "manifest.mhl" not in captured.err

    def test_suppressed_success_no_report_file_does_not_raise(self, capsys):
        """When show_status_on_terminal=False, severity==success, and report_file
        is None, the elif branch is skipped entirely — nothing is written and
        no exception is raised."""
        mhlver._report_via_table(
            mhlver._LEGACY_RESULTS,
            0,
            "manifest.mhl",
            "",
            None,
            show_backend_output=False,
            show_status_on_terminal=False,
        )
        captured = capsys.readouterr()
        assert captured.out == "" and captured.err == ""
        """Errors must always appear on the terminal regardless of
        show_status_on_terminal, because operators need immediate visibility."""
        mhlver._report_via_table(
            mhlver._LEGACY_RESULTS,
            40,
            "bad.mhl",
            "",
            None,
            show_backend_output=False,
            show_status_on_terminal=False,
        )
        captured = capsys.readouterr()
        assert "bad.mhl" in captured.err


# =============================================================================
# TestGetCommandPath
# =============================================================================
# Covers line 155: the shutil.which fallback when the venv candidate
# doesn't exist.


class TestGetCommandPath:
    """Tests for get_command_path venv-first lookup."""

    def test_falls_back_to_which_when_venv_candidate_missing(self, monkeypatch, tmp_path):
        """When the venv bin candidate doesn't exist, shutil.which is tried."""
        monkeypatch.setattr(mhlver.shutil, "which", lambda cmd: f"/usr/bin/{cmd}")
        # Point sys.prefix at tmp_path so the venv candidate definitely won't exist.
        monkeypatch.setattr(mhlver.sys, "prefix", str(tmp_path))
        result = mhlver.get_command_path("simple-mhl")
        assert result == "/usr/bin/simple-mhl"

    def test_returns_none_when_not_found_anywhere(self, monkeypatch, tmp_path):
        """Returns None when neither the venv candidate nor PATH has the command."""
        monkeypatch.setattr(mhlver.shutil, "which", lambda cmd: None)
        monkeypatch.setattr(mhlver.sys, "prefix", str(tmp_path))
        assert mhlver.get_command_path("nonexistent-tool") is None

    def test_prefers_venv_candidate_when_present(self, monkeypatch, tmp_path):
        """Venv bin candidate is returned without calling shutil.which."""
        venv_bin = tmp_path / "bin"
        venv_bin.mkdir()
        candidate = venv_bin / "simple-mhl"
        candidate.write_text("#!/bin/sh")
        monkeypatch.setattr(mhlver.sys, "prefix", str(tmp_path))
        # which would return a different path — we must NOT see it.
        monkeypatch.setattr(mhlver.shutil, "which", lambda cmd: "/wrong/path")
        assert mhlver.get_command_path("simple-mhl") == str(candidate)


# =============================================================================
# TestVerifyLegacyExtended
# =============================================================================
# Covers lines 507-509 (command not found → 127), 518 (verbose+schema),
# and the schema table selection path.


class TestVerifyLegacyExtended:
    """Additional _verify_legacy branch coverage."""

    def test_command_not_found_returns_127(self, tmp_path, monkeypatch):
        """When simple-mhl is not found, _verify_legacy returns 127."""
        monkeypatch.setattr(mhlver, "get_command_path", lambda cmd: None)
        mhl = tmp_path / "dummy.mhl"
        mhl.write_text("")
        rc = mhlver._verify_legacy(mhl, verbose=False, schema=False, report_file=None)
        assert rc == 127

    def test_verbose_with_schema_does_not_add_v_flag(self, tmp_path, monkeypatch):
        """With verbose=True and schema=True, -v must NOT be appended
        (xsd-schema-check has no per-file output)."""
        captured_cmd = {}

        def _stub(cmd, cwd=None, **kwargs):
            captured_cmd["cmd"] = cmd
            return mhlver.StepResult(exit_code=0, output="")

        monkeypatch.setattr(mhlver, "get_command_path", lambda cmd: "/fake/simple-mhl")
        monkeypatch.setattr(mhlver, "_run_step", _stub)
        mhl = tmp_path / "dummy.mhl"
        mhl.write_text("")
        mhlver._verify_legacy(mhl, verbose=True, schema=True, report_file=None)
        assert "-v" not in captured_cmd["cmd"]
        assert "xsd-schema-check" in captured_cmd["cmd"]

    def test_verbose_without_schema_adds_v_flag(self, tmp_path, monkeypatch):
        """With verbose=True and schema=False, -v IS appended."""
        captured_cmd = {}

        def _stub(cmd, cwd=None, **kwargs):
            captured_cmd["cmd"] = cmd
            return mhlver.StepResult(exit_code=0, output="")

        monkeypatch.setattr(mhlver, "get_command_path", lambda cmd: "/fake/simple-mhl")
        monkeypatch.setattr(mhlver, "_run_step", _stub)
        mhl = tmp_path / "dummy.mhl"
        mhl.write_text("")
        mhlver._verify_legacy(mhl, verbose=True, schema=False, report_file=None)
        assert "-v" in captured_cmd["cmd"]

    def test_schema_uses_legacy_schema_results_table(self, tmp_path, monkeypatch, capsys):
        """With schema=True, exit 60 is looked up in _LEGACY_SCHEMA_RESULTS
        (which has a specific message) not _LEGACY_RESULTS (which doesn't)."""
        monkeypatch.setattr(mhlver, "get_command_path", lambda cmd: "/fake/simple-mhl")
        monkeypatch.setattr(
            mhlver, "_run_step", lambda cmd, **kw: mhlver.StepResult(60, "")
        )
        mhl = tmp_path / "dummy.mhl"
        mhl.write_text("")
        rc = mhlver._verify_legacy(mhl, verbose=False, schema=True, report_file=None)
        assert rc == 60
        captured = capsys.readouterr()
        assert "schema" in (captured.out + captured.err).lower()


# =============================================================================
# TestVerifyAscmhlExtended
# =============================================================================
# Covers lines 556-591: command-not-found (127), suite_dir warning,
# and schema dispatch.


class TestVerifyAscmhlExtended:
    """Additional _verify_ascmhl branch coverage."""

    def test_command_not_found_returns_127(self, ascmhl_setup, monkeypatch):
        """When ascmhl-debug is not found, _verify_ascmhl returns 127."""
        monkeypatch.setattr(mhlver, "get_command_path", lambda cmd: None)
        rc = mhlver._verify_ascmhl(
            ascmhl_setup, verbose=False, schema=False, report_file=None
        )
        assert rc == 127

    def test_suite_dir_missing_logs_warning(self, ascmhl_setup, monkeypatch, capsys):
        """When suite_dir doesn't exist, a warning is logged and execution continues."""
        import unittest.mock as _mock

        monkeypatch.setattr(mhlver, "get_command_path", lambda cmd: "/fake/ascmhl-debug")
        monkeypatch.setattr(
            mhlver, "_run_step", lambda cmd, **kw: mhlver.StepResult(0, "")
        )
        monkeypatch.setattr(mhlver, "_ascmhl_verify", lambda *a, **kw: 0)

        # Patch __file__ to a path whose parent definitely doesn't exist,
        # so suite_dir.exists() returns False and the warning branch fires.
        with _mock.patch.object(mhlver, "__file__", "/nonexistent/suite/mhlver.py"):
            mhlver._verify_ascmhl(
                ascmhl_setup, verbose=False, schema=False, report_file=None
            )

        captured = capsys.readouterr()
        assert "warning" in (captured.out + captured.err).lower()

    def test_schema_true_dispatches_to_ascmhl_schema_check(self, ascmhl_setup, monkeypatch):
        """With schema=True, _verify_ascmhl calls _ascmhl_schema_check."""
        monkeypatch.setattr(mhlver, "get_command_path", lambda cmd: "/fake/ascmhl-debug")
        called = {}

        def _stub_schema_check(target, cmd_path, cwd, verbose, report_file, **kw):
            called["yes"] = True
            return 0

        monkeypatch.setattr(mhlver, "_ascmhl_schema_check", _stub_schema_check)
        rc = mhlver._verify_ascmhl(
            ascmhl_setup, verbose=False, schema=True, report_file=None
        )
        assert called.get("yes") is True
        assert rc == 0


# =============================================================================
# TestVerifyItem
# =============================================================================
# Covers lines 470-479: verify_item dispatching to the ASC-MHL path.


class TestVerifyItem:
    """Tests for verify_item dispatch logic."""

    def test_dispatches_to_ascmhl_for_ascmhl_path(self, tmp_path, monkeypatch):
        """A path containing 'ascmhl' in its parts routes to _verify_ascmhl."""
        called = {}

        def _stub(target, verbose, schema, report_file, **kw):
            called["ascmhl"] = True
            return 0

        monkeypatch.setattr(mhlver, "_verify_ascmhl", _stub)
        ascmhl_dir = tmp_path / "pkg" / "ascmhl"
        ascmhl_dir.mkdir(parents=True)
        manifest = ascmhl_dir / "0001.mhl"
        manifest.write_text("")
        mhlver.verify_item(manifest, verbose=False, schema=False, report_file=None)
        assert called.get("ascmhl") is True

    def test_dispatches_to_legacy_for_plain_mhl(self, tmp_path, monkeypatch):
        """A plain .mhl path routes to _verify_legacy."""
        called = {}

        def _stub(target, verbose, schema, report_file, **kw):
            called["legacy"] = True
            return 0

        monkeypatch.setattr(mhlver, "_verify_legacy", _stub)
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        mhlver.verify_item(mhl, verbose=False, schema=False, report_file=None)
        assert called.get("legacy") is True


# =============================================================================
# TestMhlTotalBytes
# =============================================================================
# Covers lines 783-793.


class TestMhlTotalBytes:
    """Tests for _mhl_total_bytes."""

    def test_sums_size_elements(self, tmp_path):
        """Returns the sum of all <size> values in a manifest."""
        mhl = tmp_path / "test.mhl"
        mhl.write_text(
            '<?xml version="1.0"?>\n'
            '<hashlist version="1.1">'
            '<hash><file>a.bin</file><size>100</size></hash>'
            '<hash><file>b.bin</file><size>200</size></hash>'
            '</hashlist>'
        )
        assert mhlver._mhl_total_bytes(mhl) == 300

    def test_returns_zero_on_parse_failure(self, tmp_path):
        """Returns 0 when the file cannot be parsed."""
        mhl = tmp_path / "broken.mhl"
        mhl.write_text("<not valid xml")
        assert mhlver._mhl_total_bytes(mhl) == 0

    def test_returns_zero_for_missing_file(self, tmp_path):
        """Returns 0 when the file doesn't exist."""
        assert mhlver._mhl_total_bytes(tmp_path / "ghost.mhl") == 0

    def test_skips_non_digit_size_elements(self, tmp_path):
        """Non-numeric <size> values are ignored rather than raising."""
        mhl = tmp_path / "test.mhl"
        mhl.write_text(
            '<?xml version="1.0"?>\n'
            '<hashlist version="1.1">'
            '<hash><file>a.bin</file><size>bad</size></hash>'
            '<hash><file>b.bin</file><size>50</size></hash>'
            '</hashlist>'
        )
        assert mhlver._mhl_total_bytes(mhl) == 50

    def test_legacy_mhl_from_shotputpro(self, tmp_path):
        """ShotPutPro legacy MHL 1.1: <size> as child element of <hash>, path in <file>.

        Legacy MHL 1.x stores size as a <size> child element rather than a
        path/@size attribute as in ASC-MHL 2.0. ShotPutPro produces hashlist
        version="1.1" with no XML namespace. The structure is flat — there is
        no <directoryhash> equivalent.

        Representative subset of three files (two MXF clips + sidecar XML)
        matching the real ShotPutPro legacy output structure.

        Expected total: 2246896176 + 4170 + 15758019120 = 18_004_919_466
        """
        mhl = tmp_path / "test.mhl"
        mhl.write_text("""\
<?xml version="1.0" encoding="UTF-8"?>
<hashlist version="1.1">
  <creatorinfo>
    <tool>ShotPutPro</tool>
    <startdate>2026-01-01T00:00:00</startdate>
    <finishdate>2026-01-01T00:05:00</finishdate>
  </creatorinfo>
  <hash>
    <file>Card/Clip/A001/A001C001.mxf</file>
    <size>2246896176</size>
    <xxhash64be>d4b2ab4a3e2619c6</xxhash64be>
    <hashdate>2026-01-01T00:05:00</hashdate>
  </hash>
  <hash>
    <file>Card/Clip/A001/A001C001M01.xml</file>
    <size>4170</size>
    <xxhash64be>fb5ba52fd1791f62</xxhash64be>
    <hashdate>2026-01-01T00:05:00</hashdate>
  </hash>
  <hash>
    <file>Card/Clip/A002/A002C001.mxf</file>
    <size>15758019120</size>
    <xxhash64be>958a6c5a73c506bf</xxhash64be>
    <hashdate>2026-01-01T00:05:00</hashdate>
  </hash>
</hashlist>""")
        assert mhlver._mhl_total_bytes(mhl) == 2246896176 + 4170 + 15758019120

    def test_legacy_mhl_from_ocopy(self, tmp_path):
        """o/COPY legacy MHL 1.1: structurally identical to ShotPutPro but with
        single-quoted XML declaration and UTC Z-suffix dates.

        o/COPY writes <?xml version='1.0' encoding='utf-8'?> (single quotes)
        and uses Zulu timestamps (e.g. 2026-05-31T02:09:06Z) rather than
        explicit UTC offsets. lxml handles both transparently — this test
        confirms neither quirk causes a parse failure or size miscount.

        Expected total: 436085 + 2775033 + 161713671 = 164_924_789
        """
        mhl = tmp_path / "test.mhl"
        mhl.write_text("""\
<?xml version='1.0' encoding='utf-8'?>
<hashlist version="1.1">
  <creatorinfo>
    <tool>o/COPY</tool>
    <startdate>2026-01-01T00:00:00Z</startdate>
    <finishdate>2026-01-01T00:00:00Z</finishdate>
  </creatorinfo>
  <hash>
    <file>aaaaaaaa-0000-0000-0000-aaaaaaaaaaaa.JPG</file>
    <size>436085</size>
    <lastmodificationdate>2026-01-01T00:00:00Z</lastmodificationdate>
    <xxhash64be>e8142245c45a9730</xxhash64be>
    <hashdate>2026-01-01T00:00:00Z</hashdate>
  </hash>
  <hash>
    <file>A001.HEIC</file>
    <size>2775033</size>
    <lastmodificationdate>2026-01-01T00:00:00Z</lastmodificationdate>
    <xxhash64be>cbb243888a8034de</xxhash64be>
    <hashdate>2026-01-01T00:00:00Z</hashdate>
  </hash>
  <hash>
    <file>A002.MOV</file>
    <size>161713671</size>
    <lastmodificationdate>2026-01-01T00:00:00Z</lastmodificationdate>
    <xxhash64be>fe53d4b59c94d282</xxhash64be>
    <hashdate>2026-01-01T00:00:00Z</hashdate>
  </hash>
</hashlist>""")
        assert mhlver._mhl_total_bytes(mhl) == 436085 + 2775033 + 161713671

    def test_legacy_mhl_from_offshoot(self, tmp_path):
        """OffShoot legacy MHL 1.1: vendor <hedge> block and dual hash elements per entry.

        OffShoot extends the MHL 1.1 format in two ways: it prepends a <hedge>
        block containing a <rootPath> element before <creatorinfo>, and each
        <hash> entry carries both <xxhash64be> and <xxhash64> child elements.
        Neither extension introduces a <size> element, so the total must be
        unaffected. The <hedge> block is the meaningful structural difference
        to pin — a future OffShoot version adding a <size> inside <hedge>
        would be picked up by the wildcard iterfind and inflate the total.

        Expected total: 436085 + 2775033 + 161713671 = 164_924_789
        """
        mhl = tmp_path / "test.mhl"
        mhl.write_text("""\
<?xml version="1.0" encoding="UTF-8"?>
<hashlist version="1.1">
    <hedge>
        <rootPath>/volume/destination</rootPath>
    </hedge>
    <creatorinfo>
        <tool>OffShoot 26.1.2 (Build 1990)</tool>
        <startdate>2026-01-01T00:00:00Z</startdate>
        <finishdate>2026-01-01T00:00:00Z</finishdate>
    </creatorinfo>
    <hash>
        <file>aaaaaaaa-0000-0000-0000-aaaaaaaaaaaa.JPG</file>
        <size>436085</size>
        <lastmodificationdate>2026-01-01T00:00:00Z</lastmodificationdate>
        <xxhash64be>e8142245c45a9730</xxhash64be>
        <xxhash64>30975ac4452214e8</xxhash64>
        <hashdate>2026-01-01T00:00:00Z</hashdate>
    </hash>
    <hash>
        <file>A001.HEIC</file>
        <size>2775033</size>
        <lastmodificationdate>2026-01-01T00:00:00Z</lastmodificationdate>
        <xxhash64be>cbb243888a8034de</xxhash64be>
        <xxhash64>de34808a8843b2cb</xxhash64>
        <hashdate>2026-01-01T00:00:00Z</hashdate>
    </hash>
    <hash>
        <file>A002.MOV</file>
        <size>161713671</size>
        <lastmodificationdate>2026-01-01T00:00:00Z</lastmodificationdate>
        <xxhash64be>fe53d4b59c94d282</xxhash64be>
        <xxhash64>82d2949cb5d453fe</xxhash64>
        <hashdate>2026-01-01T00:00:00Z</hashdate>
    </hash>
</hashlist>""")
        assert mhlver._mhl_total_bytes(mhl) == 436085 + 2775033 + 161713671


# =============================================================================
# TestOpenReport
# =============================================================================
# Covers lines 858-872.


class TestOpenReport:
    """Tests for _open_report context manager."""

    def test_creates_report_file_with_header(self, tmp_path):
        """Report file is created, contains a header, and is closed after the block."""
        with mhlver._open_report(tmp_path) as (fh, rp):
            assert rp.exists()
            assert not fh.closed
            fh.write("test line\n")
        assert fh.closed
        content = rp.read_text()
        assert "mhlver" in content
        assert "test line" in content

    def test_report_path_uses_src_name(self, tmp_path):
        """The report filename contains the source directory name."""
        with mhlver._open_report(tmp_path) as (fh, rp):
            pass
        assert tmp_path.name in rp.name

    def test_report_for_file_src_writes_to_parent(self, tmp_path):
        """When src is a file, the report is created in src's parent directory."""
        src_file = tmp_path / "manifest.mhl"
        src_file.write_text("")
        with mhlver._open_report(src_file) as (fh, rp):
            pass
        assert rp.parent == tmp_path


# =============================================================================
# TestRun
# =============================================================================
# Covers lines 977-1081: _run with file input, dir input (no-progress path),
# empty dir, and the success/failure summary lines.


class TestRun:
    """Tests for the _run orchestration function."""

    def _stub_verify_item(self, monkeypatch, return_code: int):
        monkeypatch.setattr(
            mhlver, "verify_item", lambda *a, **kw: return_code
        )

    def test_run_with_single_file_success(self, tmp_path, monkeypatch, capsys):
        """_run with a file path calls verify_item and returns 0 on success."""
        self._stub_verify_item(monkeypatch, 0)
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        rc = mhlver._run(mhl, verbose=False, schema=False, report_file=None)
        assert rc == 0
        assert "successfully verified" in capsys.readouterr().out

    def test_run_with_single_file_failure(self, tmp_path, monkeypatch, capsys):
        """_run with a file path returns the non-zero exit code on failure."""
        self._stub_verify_item(monkeypatch, 40)
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        rc = mhlver._run(mhl, verbose=False, schema=False, report_file=None)
        assert rc == 40
        assert "failed" in capsys.readouterr().err.lower()

    def test_run_empty_directory_warns(self, tmp_path, monkeypatch, capsys):
        """_run on a dir with no MHL files logs a warning and returns 0."""
        # Force use_progress=False so we stay in the simple branch.
        monkeypatch.setattr(mhlver.sys.stdout, "isatty", lambda: False)
        rc = mhlver._run(tmp_path, verbose=False, schema=False, report_file=None)
        assert rc == 0
        captured = capsys.readouterr()
        assert "no mhl" in (captured.out + captured.err).lower()

    def test_run_directory_first_failure_wins(self, tmp_path, monkeypatch, capsys):
        """First non-zero exit code is returned; subsequent failures don't override."""
        monkeypatch.setattr(mhlver.sys.stdout, "isatty", lambda: False)
        results = iter([30, 40])
        monkeypatch.setattr(mhlver, "verify_item", lambda *a, **kw: next(results))
        for name in ["a.mhl", "b.mhl"]:
            (tmp_path / name).write_text("")
        rc = mhlver._run(tmp_path, verbose=False, schema=False, report_file=None)
        assert rc == 30

    def test_run_directory_all_pass(self, tmp_path, monkeypatch, capsys):
        """All manifests passing returns 0 with the success summary."""
        monkeypatch.setattr(mhlver.sys.stdout, "isatty", lambda: False)
        monkeypatch.setattr(mhlver, "verify_item", lambda *a, **kw: 0)
        (tmp_path / "a.mhl").write_text("")
        (tmp_path / "b.mhl").write_text("")
        rc = mhlver._run(tmp_path, verbose=False, schema=False, report_file=None)
        assert rc == 0
        assert "successfully verified" in capsys.readouterr().out

    def test_src_is_neither_file_nor_dir_still_succeeds(self, tmp_path, monkeypatch):
        """When src exists but is neither a file nor a directory (e.g. a named
        pipe), _run takes the else branch (console = None) and returns 0."""
        import os
        pipe = tmp_path / "fifo.mhl"
        os.mkfifo(pipe)
        # verify_item is never called — exit_status stays 0.
        rc = mhlver._run(pipe, verbose=False, schema=False, report_file=None)
        assert rc == 0

    def test_run_writes_to_report_file(self, tmp_path, monkeypatch):
        """_run mirrors output to the report file when one is provided."""
        import io as _io
        monkeypatch.setattr(mhlver.sys.stdout, "isatty", lambda: False)
        monkeypatch.setattr(mhlver, "verify_item", lambda *a, **kw: 0)
        (tmp_path / "a.mhl").write_text("")
        buf = _io.StringIO()
        mhlver._run(tmp_path, verbose=False, schema=False, report_file=buf)
        assert "successfully verified" in buf.getvalue()

    def test_run_with_report_file_includes_separator(self, tmp_path, monkeypatch):
        """Each manifest verification is separated by '---' in the report."""
        import io as _io
        monkeypatch.setattr(mhlver.sys.stdout, "isatty", lambda: False)
        monkeypatch.setattr(mhlver, "verify_item", lambda *a, **kw: 0)
        (tmp_path / "a.mhl").write_text("")
        buf = _io.StringIO()
        mhlver._run(tmp_path, verbose=False, schema=False, report_file=buf)
        assert "---" in buf.getvalue()


# =============================================================================
# TestRunStep
# =============================================================================
# Covers lines 186-202: _run_step with on_poll set during subprocess execution.
#
# The on_poll event is the signal the progress bar thread waits on to trigger
# a Live refresh. If _run_step never calls on_poll.set() the bar freezes for
# the duration of the subprocess. We verify it is set at least once for a
# real (fast) subprocess.


class TestRunStep:
    """Tests for _run_step — subprocess execution with progress-bar polling."""

    def test_on_poll_is_set_during_subprocess(self):
        """on_poll.set() must be called at least once while the subprocess runs.

        _run_step polls every ~100 ms while the process is alive; even a
        subprocess that exits almost immediately will trigger at least one
        poll tick on most systems. We use a no-op shell command so the test
        stays fast and cross-platform.
        """
        import threading
        event = threading.Event()
        result = mhlver._run_step(
            cmd=["python3", "-c", "import time; time.sleep(0.15)"],
            cwd=None,
            on_poll=event,
        )
        assert result.exit_code == 0
        assert event.is_set()

    def test_on_poll_none_does_not_raise(self):
        """Passing on_poll=None must not raise — it is the no-progress-bar path."""
        result = mhlver._run_step(
            cmd=["python3", "-c", "pass"],
            cwd=None,
            on_poll=None,
        )
        assert result.exit_code == 0


# =============================================================================
# TestRunWithProgress
# =============================================================================
# Covers lines 1033-1099: the use_progress=True branch of _run.
#
# We monkeypatch sys.stdout.isatty → True to activate the branch, then
# replace _build_live with a no-op stub so the test never touches a real
# terminal. The stub returns objects with the minimal interface _run uses:
# a Live context manager, a Progress with add_task/advance/update, a Text
# label, and a Console.


class TestRunWithProgress:
    """Tests for _run's progress-bar branch (use_progress=True)."""

    @staticmethod
    def _stub_build_live(monkeypatch):
        """Replace _build_live with lightweight no-op stubs."""
        import io as _io
        from unittest.mock import MagicMock

        label = MagicMock()
        label.plain = ""

        progress = MagicMock()
        progress.add_task.return_value = 0

        live = MagicMock()
        live.__enter__ = lambda s: s
        live.__exit__ = MagicMock(return_value=False)

        console = MagicMock()
        console.file = _io.StringIO()

        monkeypatch.setattr(mhlver, "_build_live", lambda: (live, progress, label, console))
        return progress

    def test_progress_branch_calls_verify_item_for_each_manifest(
        self, tmp_path, monkeypatch
    ):
        """verify_item is called once per manifest when use_progress=True."""
        monkeypatch.setattr(mhlver.sys.stdout, "isatty", lambda: True)
        self._stub_build_live(monkeypatch)
        call_count = 0

        def _counting_verify(*a, **kw):
            nonlocal call_count
            call_count += 1
            return 0

        monkeypatch.setattr(mhlver, "verify_item", _counting_verify)
        (tmp_path / "a.mhl").write_text("")
        (tmp_path / "b.mhl").write_text("")
        rc = mhlver._run(tmp_path, verbose=False, schema=False, report_file=None)
        assert rc == 0
        assert call_count == 2

    def test_progress_branch_propagates_first_failure(self, tmp_path, monkeypatch):
        """First non-zero exit code is preserved; a later one does not override it."""
        monkeypatch.setattr(mhlver.sys.stdout, "isatty", lambda: True)
        self._stub_build_live(monkeypatch)
        results = iter([30, 40])
        monkeypatch.setattr(mhlver, "verify_item", lambda *a, **kw: next(results))
        (tmp_path / "a.mhl").write_text("")
        (tmp_path / "b.mhl").write_text("")
        rc = mhlver._run(tmp_path, verbose=False, schema=False, report_file=None)
        assert rc == 30

    def test_progress_branch_advances_bar_per_manifest(self, tmp_path, monkeypatch):
        """progress.advance() is called once per manifest with its byte weight."""
        monkeypatch.setattr(mhlver.sys.stdout, "isatty", lambda: True)
        progress = self._stub_build_live(monkeypatch)
        monkeypatch.setattr(mhlver, "verify_item", lambda *a, **kw: 0)
        (tmp_path / "a.mhl").write_text("")
        (tmp_path / "b.mhl").write_text("")
        mhlver._run(tmp_path, verbose=False, schema=False, report_file=None)
        assert progress.advance.call_count == 2

    def test_progress_branch_writes_separator_to_report(self, tmp_path, monkeypatch):
        """Each manifest is preceded by '---' in the report file."""
        import io as _io
        monkeypatch.setattr(mhlver.sys.stdout, "isatty", lambda: True)
        self._stub_build_live(monkeypatch)
        monkeypatch.setattr(mhlver, "verify_item", lambda *a, **kw: 0)
        (tmp_path / "a.mhl").write_text("")
        buf = _io.StringIO()
        mhlver._run(tmp_path, verbose=False, schema=False, report_file=buf)
        assert "---" in buf.getvalue()


# =============================================================================
# mhlver_cli fixture and TestMain
# =============================================================================
# Covers lines 897-947: main() argument parsing, path validation, --report,
# --verbose, --xsd-schema-check, --version, and the default-path behaviour.
#
# The fixture mirrors mhl_cli in conftest.py: it runs main() in-process,
# captures stdout/stderr, and returns (exit_code, out, err).  We stub _run
# so tests don't touch the filesystem beyond what they set up themselves.


@pytest.fixture
def mhlver_cli(monkeypatch):
    """Run mhlver.main() in-process and return (exit_code, stdout, stderr)."""
    import io as _io
    import sys as _sys

    def _run_main(argv):
        str_argv = [str(a) for a in argv]
        old_argv = _sys.argv
        old_out, old_err = _sys.stdout, _sys.stderr
        _sys.argv = ["mhlver"] + str_argv
        out, err = _io.StringIO(), _io.StringIO()
        _sys.stdout, _sys.stderr = out, err
        exit_code = 0
        try:
            try:
                mhlver.main()
            except SystemExit as e:
                exit_code = e.code if e.code is not None else 0
        finally:
            _sys.argv = old_argv
            _sys.stdout, _sys.stderr = old_out, old_err
        return exit_code, out.getvalue(), err.getvalue()

    return _run_main


class TestMain:
    """Integration tests for mhlver.main() — argument parsing and dispatch."""

    def test_nonexistent_path_exits_2(self, mhlver_cli):
        """Passing a path that doesn't exist must exit 2 with an error message."""
        rc, _, err = mhlver_cli(["/nonexistent/path/ghost.mhl"])
        assert rc == 2
        assert "file or directory" in err.lower() or "exist" in err.lower()

    def test_default_path_is_cwd(self, mhlver_cli, monkeypatch, tmp_path):
        """Omitting the path argument defaults to the current directory."""
        called_with = {}

        def _stub_run(src, verbose, schema, report_file):
            called_with["src"] = src
            return 0

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mhlver, "_run", _stub_run)
        rc, _, _ = mhlver_cli([])
        assert rc == 0
        assert called_with["src"] == tmp_path.resolve()

    def test_explicit_file_path_passed_to_run(self, mhlver_cli, monkeypatch, tmp_path):
        """An explicit path is resolved and forwarded to _run."""
        called_with = {}

        def _stub_run(src, verbose, schema, report_file):
            called_with["src"] = src
            return 0

        monkeypatch.setattr(mhlver, "_run", _stub_run)
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        rc, _, _ = mhlver_cli([str(mhl)])
        assert rc == 0
        assert called_with["src"] == mhl.resolve()

    def test_verbose_flag_forwarded(self, mhlver_cli, monkeypatch, tmp_path):
        """--verbose is passed through to _run."""
        called_with = {}

        def _stub_run(src, verbose, schema, report_file):
            called_with["verbose"] = verbose
            return 0

        monkeypatch.setattr(mhlver, "_run", _stub_run)
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        mhlver_cli(["-v", str(mhl)])
        assert called_with["verbose"] is True

    def test_schema_flag_forwarded(self, mhlver_cli, monkeypatch, tmp_path):
        """--xsd-schema-check is passed through to _run."""
        called_with = {}

        def _stub_run(src, verbose, schema, report_file):
            called_with["schema"] = schema
            return 0

        monkeypatch.setattr(mhlver, "_run", _stub_run)
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        mhlver_cli(["-s", str(mhl)])
        assert called_with["schema"] is True

    def test_exit_code_propagated_from_run(self, mhlver_cli, monkeypatch, tmp_path):
        """The exit code returned by _run becomes mhlver's exit code."""
        monkeypatch.setattr(mhlver, "_run", lambda *a, **kw: 40)
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        rc, _, _ = mhlver_cli([str(mhl)])
        assert rc == 40

    def test_report_flag_creates_report_file(self, mhlver_cli, monkeypatch, tmp_path):
        """--report causes a report file to be created and its path printed."""
        monkeypatch.setattr(mhlver, "_run", lambda *a, **kw: 0)
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        rc, out, _ = mhlver_cli(["--report", str(mhl)])
        assert rc == 0
        # A report file must have been created in tmp_path.
        reports = list(tmp_path.glob("mhlver_report_*.log"))
        assert len(reports) == 1
        # Its path is printed to stdout.
        assert "report saved to" in out

    def test_report_file_contains_exit_status(self, mhlver_cli, monkeypatch, tmp_path):
        """The report file includes the final exit status line."""
        monkeypatch.setattr(mhlver, "_run", lambda *a, **kw: 0)
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        mhlver_cli(["--report", str(mhl)])
        report = next(tmp_path.glob("mhlver_report_*.log"))
        assert "exit status: 0" in report.read_text()

    def test_report_flag_with_failure_records_nonzero_exit(
        self, mhlver_cli, monkeypatch, tmp_path
    ):
        """A non-zero exit from _run is written to the report file."""
        monkeypatch.setattr(mhlver, "_run", lambda *a, **kw: 40)
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        rc, _, _ = mhlver_cli(["--report", str(mhl)])
        assert rc == 40
        report = next(tmp_path.glob("mhlver_report_*.log"))
        assert "exit status: 40" in report.read_text()

    def test_version_flag_exits_0(self, mhlver_cli):
        """--version prints the version string and exits 0."""
        rc, out, _ = mhlver_cli(["--version"])
        assert rc == 0
        assert out.strip() != ""
