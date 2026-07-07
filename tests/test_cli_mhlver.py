"""
CLI behaviour for the mhlver entry point: argument dispatch, run/main wiring,
progress, output routing, byte-weight pre-reads, and end-to-end verify runs.

The report model/renderer it drives is tested in test_report.py, and the
cross-dialect orchestrator seams (_select_mhl_files, verify_item) in
test_verifyall.py; this module owns the CLI surface and its integration.
"""

import io
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from hypothesis import HealthCheck, given, settings, strategies
from lxml import etree
from rich.console import Console
from rich.live import Live
from rich.progress import Progress
from rich.text import Text

from mhl_suite import verifyall
from mhl_suite.cli import mhlver
from mhl_suite.verify_results import VerifyEntry, VerifyReport

from .helpers import make_package

# -----------------------------------------------------------------------------
# Module-level helpers
# -----------------------------------------------------------------------------

_ASCMHL_NAMESPACE = "urn:ASC:MHL:v2.0"

# Windows reserves these device names at every extension; attempting to create
# e.g. CON.mhl on Windows raises PermissionError / FileNotFoundError.
_WINDOWS_RESERVED_NAMES = ["CON", "PRN", "AUX", "NUL", "COM1", "COM2", "LPT1", "LPT2"]

# All vendor example fixtures (classic + ASC-MHL) are deliberately aligned to
# this total so each parser can be checked against the same known value.
_ALIGNED_FIXTURE_TOTAL_BYTES = 18_004_919_466

#: Directory containing real-tool MHL fixture files used by the suite. Each file
# : is a verbatim (anonymised) MHL output from a specific transfer tool, named :
# <tool>_<format>.mhl (e.g. shotputpro_ascmhl.mhl).
FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Templates for the write_mhl fixture's minimal ASC-MHL 2.0 generation files.
_MHL_TMPL = """\
<?xml version="1.0" encoding="UTF-8"?>
<hashlist version="2.0" xmlns="urn:ASC:MHL:v2.0">
  <hashes>
{entries}  </hashes>
</hashlist>"""

_HASH_ENTRY = """\
    <hash>
      <path size="{size}">{path}</path>
      <xxh64 action="{action}" hashdate="2026-05-30T12:00:00+00:00">{digest}</xxh64>
    </hash>
"""


def _write_ascmhl(path: Path, entries: list[dict]) -> None:
    """Write a minimal ASC-MHL 2.0 generation file to *path*.

    Each entry dict must have "path", "size", "action", and "digest" keys. Used
    by the Unicode-guard tests that need to craft specific size attributes
    without going through the write_mhl fixture (which only writes well-formed
    decimal sizes).
    """
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<hashlist version="2.0" xmlns="{_ASCMHL_NAMESPACE}">',
        "  <hashes>",
    ]
    for e in entries:
        lines += [
            "    <hash>",
            f'      <path size="{e["size"]}" lastmodificationdate="2026-01-01T00:00:00+00:00">{e["path"]}</path>',
            f'      <xxh64 action="{e["action"]}" hashdate="2026-01-01T00:00:00+00:00">{e["digest"]}</xxh64>',
            "    </hash>",
        ]
    lines += ["  </hashes>", "</hashlist>"]
    path.write_text("\n".join(lines), encoding="utf-8")


def stub_verify_ascmhl(monkeypatch, code, entries=None):
    """Replace ascmhl.verify.verify_ascmhl with a stub returning a fixed report.

    The in-process counterpart of the old stub_run_step: ASC-MHL verify now goes
    through mhl_suite.ascmhl_verify.verify_ascmhl, so dispatch/wiring tests pin
    its structured result instead of a subprocess StepResult.
    """
    report = verifyall.VerifyReport(entries=entries or [], code=code)
    monkeypatch.setattr(verifyall.ascmhl_verify, "verify_ascmhl", lambda *a, **k: report)


def call_verify(manifest):
    """Invoke _ascmhl_verify with sane defaults and return its exit code."""
    rc, _mr = verifyall._ascmhl_verify(target=manifest, verbose=False)
    return rc


class FakeConsole:
    """
    Minimal stand-in for rich.Console: records what would be printed instead
    of emitting it, so tests can assert on routed output without touching the
    real stdout/stderr.
    """

    def __init__(self):
        self._out = io.StringIO()

    def print(self, msg, **kwargs):
        self._out.write(msg + "\n")

    def getvalue(self) -> str:
        return self._out.getvalue()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def write_mhl():
    """
    Factory fixture that writes a minimal ASC-MHL 2.0 generation file.

    Usage::

        def test_something(tmp_path, write_mhl):
            ascdir = tmp_path / "ascmhl" ascdir.mkdir() write_mhl(ascdir, "0001.mhl", [
                {"path": "clip.mov", "size": "1000000",
                 "action": "original", "digest": "aabbccdd"},
            ])

    Each entry dict must contain ``path``, ``size``, ``action``, and ``digest``.
    Returns the :class:`~pathlib.Path` of the written file.
    """

    def _write(ascdir: Path, name: str, entries: list[dict]) -> Path:
        body = "".join(_HASH_ENTRY.format(**e) for e in entries)
        mhl = ascdir / name
        mhl.write_text(_MHL_TMPL.format(entries=body))
        return mhl

    return _write


@pytest.fixture
def load_fixture_mhl():
    """
    Factory fixture that copies a fixture MHL file into a test directory.

    Usage::

        def test_something(tmp_path, load_fixture_mhl):
            ascdir = tmp_path / "ascmhl" ascdir.mkdir() mhl = load_fixture_mhl(ascdir, "shotputpro_ascmhl.mhl")

    The fixture file is read from the ``fixtures/`` directory next to this test
    module and written verbatim into *dest_dir* under its original filename.
    Returns the :class:`~pathlib.Path` of the written file.
    """

    def _load(dest_dir: Path, fixture_name: str) -> Path:
        src = FIXTURES_DIR / fixture_name
        dest = dest_dir / fixture_name
        dest.write_bytes(src.read_bytes())
        return dest

    return _load


@pytest.fixture
def ascmhl_setup(tmp_path):
    """Set up the layout ascmhl-debug expects and return the manifest path."""
    pkg = tmp_path / "pkg"
    ascdir = pkg / "ascmhl"
    ascdir.mkdir(parents=True)
    manifest = ascdir / "0001.mhl"
    manifest.write_text("<dummy/>")
    return manifest


# ---------------------------------------------------------------------------
# TestMhlver
# ---------------------------------------------------------------------------


class TestMhlver:
    """Tests for mhlver — the orchestrator."""

    def test_find_mhl_files(self, tmp_path):
        """find_mhl_files yields case-insensitively and skips ._ files."""
        (tmp_path / "a.mhl").write_text("")
        (tmp_path / "b.MHL").write_text("")
        (tmp_path / "._meta.mhl").write_text("")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "c.MhL").write_text("")

        found = sorted(p.name for p in verifyall.find_mhl_files(tmp_path))
        assert found == ["a.mhl", "b.MHL", "c.MhL"]

    def test_select_mhl_files_dedups_ascmhl(self, tmp_path):
        """ASC-MHL packages should yield only one manifest per package."""
        # Two packages, each with two ascmhl manifests.
        for pkg in ["pkg1", "pkg2"]:
            ascdir = tmp_path / pkg / "ascmhl"
            ascdir.mkdir(parents=True)
            # Real v2 header so is_ascmhl_v2() classifies these as ASC-MHL
            # generations to dedup.
            (ascdir / "0001.mhl").write_text('<hashlist version="2.0" xmlns="urn:ASC:MHL:v2.0"/>')
            (ascdir / "0002.mhl").write_text('<hashlist version="2.0" xmlns="urn:ASC:MHL:v2.0"/>')
        # Plus one regular MHL outside ascmhl/
        (tmp_path / "loose.mhl").write_text("")

        selected = mhlver._select_mhl_files(tmp_path)
        # Expected: 1 from pkg1 ascmhl, 1 from pkg2 ascmhl, 1 loose = 3
        assert len(selected) == 3

    def test_dot_underscore_filter_applies_only_to_filename_not_parent_dir(self, tmp_path):
        """
        Files inside a directory named '._hidden' must NOT be excluded.

        The macOS resource-fork filter checks p.name (the file's own name), not
        any parent directory component.
        """
        hidden_dir = tmp_path / "._hidden"
        hidden_dir.mkdir()
        (hidden_dir / "valid.mhl").write_text("")
        (tmp_path / "._resource.mhl").write_text("")

        found = list(verifyall.find_mhl_files(tmp_path))
        names = {p.name for p in found}

        assert "valid.mhl" in names, "File inside ._hidden dir should be included"
        assert "._resource.mhl" not in names, "File named ._resource.mhl should be excluded"

    def test_windows_reserved_names_are_found_when_they_exist(self, tmp_path):
        """
        Files named CON.mhl, PRN.mhl, etc. are yielded by find_mhl_files when
        they exist on disk.

        find_mhl_files must have no special-case filtering that would silently
        drop them — an operator copying media to a card with such a filename
        (unlikely but possible) must not lose it from the verification pass.
        """
        created = []
        for stem in _WINDOWS_RESERVED_NAMES:
            f = tmp_path / f"{stem}.mhl"
            try:
                f.write_text("")
                created.append(f)
            except OSError:
                pass  # Windows: reserved name, creation refused

        if not created:
            pytest.skip("OS refused to create any reserved-name files (expected on Windows)")

        found_names = {p.name for p in verifyall.find_mhl_files(tmp_path)}
        for f in created:
            assert f.name in found_names, f"{f.name} exists on disk but was not yielded by find_mhl_files"

    def test_windows_reserved_names_are_not_suppressed_by_dot_underscore_filter(self, tmp_path):
        """
        The '._' resource-fork filter must not accidentally suppress reserved
        names.

        None of the Windows reserved names start with '._', so the filter should
        never touch them.  This is a belt-and-suspenders assertion to catch any
        future broadening of the filter logic.
        """
        created = []
        for stem in _WINDOWS_RESERVED_NAMES:
            f = tmp_path / f"{stem}.mhl"
            try:
                f.write_text("")
                created.append(f)
            except OSError:
                pass

        if not created:
            pytest.skip("OS refused to create any reserved-name files (expected on Windows)")

        found_names = {p.name for p in verifyall.find_mhl_files(tmp_path)}
        for f in created:
            assert f.name in found_names, f"{f.name} was unexpectedly filtered out by find_mhl_files"


# ---------------------------------------------------------------------------
# TestAscMhlTotalBytes
# ---------------------------------------------------------------------------


class TestAscMhlTotalBytes:
    """Unit tests for _ascmhl_total_bytes — byte-weight pre-read for ASC-MHL."""

    def test_single_generation_sums_all_sizes(self, tmp_path, write_mhl):
        """All path/@size values in a single generation file are summed."""
        ascdir = tmp_path / "ascmhl"
        ascdir.mkdir()
        write_mhl(
            ascdir,
            "0001.mhl",
            [
                {
                    "path": "Card/Clip/A001.jpg",
                    "size": "223591",
                    "action": "original",
                    "digest": "aabbccdd",
                },
                {
                    "path": "Card/Clip/A002.jpg",
                    "size": "329746",
                    "action": "original",
                    "digest": "11223344",
                },
            ],
        )
        assert verifyall._ascmhl_total_bytes(ascdir / "0001.mhl") == 223591 + 329746

    def test_verification_pass_does_not_double_count(self, tmp_path, write_mhl):
        """
        A second generation that re-verifies the same files must not add to the
        total.
        """
        ascdir = tmp_path / "ascmhl"
        ascdir.mkdir()
        entries = [
            {
                "path": "Card/Clip/A001.jpg",
                "size": "223591",
                "action": "original",
                "digest": "aabbccdd",
            },
            {
                "path": "Card/Clip/A002.jpg",
                "size": "329746",
                "action": "original",
                "digest": "11223344",
            },
        ]
        write_mhl(ascdir, "0001.mhl", entries)
        write_mhl(ascdir, "0002.mhl", [{**e, "action": "verified"} for e in entries])
        # Must equal single-generation total, not double it.
        assert verifyall._ascmhl_total_bytes(ascdir / "0002.mhl") == 223591 + 329746

    def test_new_files_in_later_generation_are_included(self, tmp_path, write_mhl):
        """Files introduced in a later generation are counted exactly once."""
        ascdir = tmp_path / "ascmhl"
        ascdir.mkdir()
        write_mhl(
            ascdir,
            "0001.mhl",
            [
                {
                    "path": "clip_A.mov",
                    "size": "1000000",
                    "action": "original",
                    "digest": "aaaaaaaa",
                },
            ],
        )
        write_mhl(
            ascdir,
            "0002.mhl",
            [
                {
                    "path": "clip_A.mov",
                    "size": "1000000",
                    "action": "verified",
                    "digest": "aaaaaaaa",
                },
                {
                    "path": "clip_B.mov",
                    "size": "2000000",
                    "action": "original",
                    "digest": "bbbbbbbb",
                },
            ],
        )
        assert verifyall._ascmhl_total_bytes(ascdir / "0002.mhl") == 1000000 + 2000000

    def test_directory_hashes_without_size_are_skipped(self, tmp_path, write_mhl):
        """
        <directoryhash><path> elements carry no size attribute and must be
        silently ignored.

        ASC-MHL packages produced by transfer tools include <directoryhash>
        blocks alongside <hash> blocks. Their <path> elements have no size
        attribute — only lastmodificationdate and creationdate — so the size
        guard must skip them without raising and without affecting the total.
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
        assert verifyall._ascmhl_total_bytes(mhl) == 1073741824

    def test_ascmhl_from_shotputpro_two_generation_transfer(self, tmp_path, write_mhl):
        """
        Six files transferred in generation 1, all re-verified in generation 2.

        Exercises the full deduplication path with a realistic file count and a
        mix of large and small sizes (video + sidecar XML pattern). Expected
        total: 223591+329746+363999+153415+288179+452705 = 1_811_635
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
        write_mhl(
            ascdir,
            "0001.mhl",
            [{"path": p, "size": s, "action": "original", "digest": d} for p, s, d in files],
        )
        write_mhl(
            ascdir,
            "0002.mhl",
            [{"path": p, "size": s, "action": "verified", "digest": d} for p, s, d in files],
        )
        assert verifyall._ascmhl_total_bytes(ascdir / "0002.mhl") == 1_811_635

    @pytest.mark.parametrize(
        "fixture_name",
        [
            "shotputpro_ascmhl_example.mhl",
            "silverstack_ascmhl_example.mhl",
            "ocopy_ascmhl_example.mhl",
        ],
    )
    def test_ascmhl_real_world_single_generation_total(self, tmp_path, load_fixture_mhl, fixture_name):
        """
        Real-world single-generation ASC-MHL exports (with directory hashes)
        from each vendor sum to the same aligned total.
        """
        ascdir = tmp_path / "ascmhl"
        ascdir.mkdir()
        mhl = load_fixture_mhl(ascdir, fixture_name)
        assert verifyall._ascmhl_total_bytes(mhl) == _ALIGNED_FIXTURE_TOTAL_BYTES

    def test_corrupt_generation_file_is_skipped_others_still_counted(self, tmp_path, write_mhl):
        """
        A corrupt .mhl in the ascmhl dir must be silently skipped; valid
        generations still contribute their sizes to the total.

        The inner exception handler in _ascmhl_total_bytes swallows parse
        failures per-file so a single bad generation doesn't zero out the entire
        package weight.
        """
        ascdir = tmp_path / "ascmhl"
        ascdir.mkdir()
        write_mhl(
            ascdir,
            "0001.mhl",
            [
                {
                    "path": "clip_A.mov",
                    "size": "1000000",
                    "action": "original",
                    "digest": "aaaaaaaa",
                },
            ],
        )
        (ascdir / "0002.mhl").write_text("<not valid xml")
        assert verifyall._ascmhl_total_bytes(ascdir / "0002.mhl") == 1000000

    def test_generations_parsed_in_filename_order(self, tmp_path, write_mhl):
        """
        Earlier generation's size wins when the same path appears in multiple
        files.
        """
        ascdir = tmp_path / "ascmhl"
        ascdir.mkdir()
        write_mhl(
            ascdir,
            "0001.mhl",
            [
                {
                    "path": "file.mov",
                    "size": "100",
                    "action": "original",
                    "digest": "aaaaaaaa",
                },
            ],
        )
        # 0002 re-records file.mov — must be ignored since 0001 wins.
        write_mhl(
            ascdir,
            "0002.mhl",
            [
                {
                    "path": "file.mov",
                    "size": "999",
                    "action": "verified",
                    "digest": "aaaaaaaa",
                },
            ],
        )
        assert verifyall._ascmhl_total_bytes(ascdir / "0002.mhl") == 100

    def test_superscript_only_entry_contributes_zero_sibling_generation_unaffected(self, tmp_path):
        """
        A generation containing only a superscript size contributes 0 bytes, and
        a sibling generation is unaffected.

        With isdecimal(), the superscript entry is skipped without raising
        ValueError, so the outer except does not fire and generation 0001 still
        contributes its 1000 bytes.
        """
        ascdir = tmp_path / "ascmhl"
        ascdir.mkdir()
        _write_ascmhl(
            ascdir / "0001.mhl",
            [{"path": "good.mov", "size": "1000", "action": "original", "digest": "aabb"}],
        )
        (ascdir / "0002.mhl").write_text(
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<hashlist version="2.0" xmlns="{_ASCMHL_NAMESPACE}">\n'
            "  <hashes>\n"
            "    <hash>\n"
            '      <path size="\u00b3" lastmodificationdate="2026-01-01T00:00:00+00:00">'
            "superscript.mov</path>\n"
            '      <xxh64 action="original" hashdate="2026-01-01T00:00:00+00:00">ccdd</xxh64>\n'
            "    </hash>\n"
            "  </hashes>\n"
            "</hashlist>\n",
            encoding="utf-8",
        )
        assert verifyall._ascmhl_total_bytes(ascdir / "0002.mhl") == 1000

    def test_all_common_superscript_digits_are_rejected_by_guard(self, tmp_path):
        """
        The three common Unicode superscript digits — ¹ ² ³ — are all rejected
        by isdecimal() and produce no contribution; only the plain decimal
        sibling entry is counted.
        """
        ascdir = tmp_path / "ascmhl"
        ascdir.mkdir()
        mhl = ascdir / "0001.mhl"
        mhl.write_text(
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<hashlist version="2.0" xmlns="{_ASCMHL_NAMESPACE}">\n'
            "  <hashes>\n"
            "    <hash>\n"
            '      <path size="\u00b9" lastmodificationdate="2026-01-01T00:00:00+00:00">'
            "sup1.mov</path>\n"
            '      <xxh64 action="original" hashdate="2026-01-01T00:00:00+00:00">aa</xxh64>\n'
            "    </hash>\n"
            "    <hash>\n"
            '      <path size="\u00b2" lastmodificationdate="2026-01-01T00:00:00+00:00">'
            "sup2.mov</path>\n"
            '      <xxh64 action="original" hashdate="2026-01-01T00:00:00+00:00">bb</xxh64>\n'
            "    </hash>\n"
            "    <hash>\n"
            '      <path size="\u00b3" lastmodificationdate="2026-01-01T00:00:00+00:00">'
            "sup3.mov</path>\n"
            '      <xxh64 action="original" hashdate="2026-01-01T00:00:00+00:00">cc</xxh64>\n'
            "    </hash>\n"
            "    <hash>\n"
            '      <path size="100" lastmodificationdate="2026-01-01T00:00:00+00:00">'
            "normal.mov</path>\n"
            '      <xxh64 action="original" hashdate="2026-01-01T00:00:00+00:00">dd</xxh64>\n'
            "    </hash>\n"
            "  </hashes>\n"
            "</hashlist>\n",
            encoding="utf-8",
        )
        assert verifyall._ascmhl_total_bytes(mhl) == 100


# ---------------------------------------------------------------------------
# TestAscMhlSizeOnly
# ---------------------------------------------------------------------------


class TestAscMhlSizeOnly:
    """
    The mhlver wiring for size-only ASC-MHL verify (_verify_ascmhl
    size_only=True): the loaded-history integrity gate, the byte-free size
    compare, and how each maps to an exit code + ManifestResult. The size engine
    itself (verify_ascmhl_sizes: matching/missing/mismatch, no-size, renames,
    nested child histories) is unit-tested in test_ascmhl_verify.py — here we
    drive real sealed packages end to end through _verify_ascmhl.
    """

    @staticmethod
    def _manifest(pkg):
        return next((pkg / "ascmhl").glob("*.mhl"))

    def test_size_phase_runs_when_gate_passes(self, tmp_path):
        """
        A clean package: the history load (the gate) passes, sizes match,
        entries are flagged size-only.
        """
        pkg = make_package(tmp_path / "pkg", {"a.mov": b"x" * 100})
        rc, mr = verifyall._verify_ascmhl(self._manifest(pkg), verbose=False, schema=False, size_only=True)
        assert rc == 0
        assert mr is not None
        assert mr.manifest_status == "ok"
        assert mr.n_size_only == 1

    def test_size_mismatch_through_wiring(self, tmp_path):
        """
        A shrunk file yields exit 13 and a failed manifest with one mismatch.
        """
        pkg = make_package(tmp_path / "pkg", {"a.mov": b"x" * 100})
        (pkg / "a.mov").write_bytes(b"x" * 50)
        rc, mr = verifyall._verify_ascmhl(self._manifest(pkg), verbose=False, schema=False, size_only=True)
        assert rc == 13
        assert mr is not None
        assert mr.manifest_status == "failed"
        assert mr.n_mismatch == 1

    def test_tampered_manifest_gate_failure_is_manifest_error(self, tmp_path):
        """
        A corrupted generation manifest fails the history load (the gate), so
        the result is a manifest integrity error, not a size verdict — the size
        phase never runs.
        """
        pkg = make_package(tmp_path / "pkg", {"a.mov": b"x" * 100})
        manifest = self._manifest(pkg)
        manifest.write_text(manifest.read_text().replace("<creatorinfo>", "<creatorinfo> "))
        rc, mr = verifyall._verify_ascmhl(manifest, verbose=False, schema=False, size_only=True)
        assert rc in (30, 31, 32, 33)  # a chain/manifest integrity code
        assert mr is not None
        assert mr.manifest_status == "error"

    def test_malformed_chain_is_manifest_error(self, tmp_path):
        """
        A chain file that won't parse surfaces as the malformed-XML manifest
        error (exit 40).
        """
        pkg = make_package(tmp_path / "pkg", {"a.mov": b"x" * 100})
        (pkg / "ascmhl" / "ascmhl_chain.xml").write_text("<ascmhl_chain><not closed")
        rc, mr = verifyall._verify_ascmhl(self._manifest(pkg), verbose=False, schema=False, size_only=True)
        assert rc == 40
        assert mr is not None
        assert mr.manifest_status == "error"


# ---------------------------------------------------------------------------
# TestAscMhlDispatch
# ---------------------------------------------------------------------------


class TestAscMhlDispatch:
    """
    ASC-MHL exit-code translation, schema dispatch, and schema=False routing,
    all verified in-process via mhl_suite.ascmhl_verify.
    """

    @pytest.mark.parametrize(
        "exit_code",
        [0, 10, 11, 12, 30, 31, 99],  # documented failures plus an unknown code
    )
    def test_verify_exit_code_propagates(self, ascmhl_setup, monkeypatch, exit_code):
        """
        verify_ascmhl's code is returned unchanged — documented failures and
        unknown codes alike (an unknown code must never be mapped to 0).
        """
        entries = (
            []
            if exit_code == 0
            else [VerifyEntry(path="f.mxf", status="mismatch", line="[ERROR] hash mismatch: f.mxf")]
        )
        stub_verify_ascmhl(monkeypatch, exit_code, entries)
        assert call_verify(ascmhl_setup) == exit_code

    def test_schema_check_clean_returns_zero(self, ascmhl_setup, monkeypatch):
        """Both schema checks pass -> exit 0."""
        monkeypatch.setattr(verifyall.ascmhl_verify, "schema_check", lambda *a, **k: (0, []))
        rc = verifyall._ascmhl_schema_check(target=ascmhl_setup, verbose=False)
        assert rc == 0

    def test_schema_check_manifest_failure_takes_precedence(self, ascmhl_setup, monkeypatch):
        """
        If the manifest fails schema check, that code wins over the chain's.
        """
        calls = {"n": 0}

        def _stub(file_path, *, directory_file=False):
            calls["n"] += 1
            # first call is the manifest, second is the chain
            return (11, ["manifest failed"]) if calls["n"] == 1 else (0, [])

        monkeypatch.setattr(verifyall.ascmhl_verify, "schema_check", _stub)
        rc = verifyall._ascmhl_schema_check(target=ascmhl_setup, verbose=False)
        assert rc == 11

    def test_dispatch_table_covers_all_known_codes(self):
        """
        The ASC-MHL verify dispatch table must cover every verify exit code
        ascmhl/errors.py defines, so we never fall through to the 'unexpected
        exit' branch for a documented failure. (127 was the subprocess
        command-not-found code and no longer applies now that verify is
        in-process.)
        """
        documented_codes = {0, 10, 11, 12, 20, 21, 30, 31, 32, 33}
        missing = documented_codes - set(verifyall._ASCMHL_VERIFY_RESULTS.keys())
        assert missing == set(), f"Dispatch table missing codes: {missing}"

    def test_ascmhl_failure_detail_shown_on_terminal(self, ascmhl_setup, monkeypatch, capsys):
        """
        A failure's per-file detail (rendered from the structured report) is
        shown on the terminal so the operator sees what went wrong.
        """
        entries = [VerifyEntry(path="b.mxf", status="mismatch", line="[ERROR] hash mismatch: b.mxf")]
        stub_verify_ascmhl(monkeypatch, 11, entries)
        # The orchestrator is print-free; the CLI sink (_render_status) does the printing.
        verifyall._ascmhl_verify(target=ascmhl_setup, verbose=False, emit=mhlver._render_status)
        assert "hash mismatch: b.mxf" in capsys.readouterr().err

    def test_schema_false_dispatches_to_ascmhl_verify(self, ascmhl_setup, monkeypatch):
        """schema=False routes to _ascmhl_verify; _ascmhl_schema_check is never called."""
        called = {}

        def _stub_verify(target, verbose, **kw):
            called["verify"] = True
            return 0, None

        def _stub_schema(target, verbose, **kw):
            called["schema"] = True
            return 0

        monkeypatch.setattr(verifyall, "_ascmhl_verify", _stub_verify)
        monkeypatch.setattr(verifyall, "_ascmhl_schema_check", _stub_schema)

        rc, _mr = verifyall._verify_ascmhl(ascmhl_setup, verbose=False, schema=False)

        assert called.get("verify") is True, "_ascmhl_verify was not called"
        assert "schema" not in called, "_ascmhl_schema_check must not be called"
        assert rc == 0

    def test_schema_false_return_value_is_propagated(self, ascmhl_setup, monkeypatch):
        """The exit code from _ascmhl_verify is returned unchanged."""
        monkeypatch.setattr(verifyall, "_ascmhl_verify", lambda *a, **kw: (11, None))
        rc, _mr = verifyall._verify_ascmhl(ascmhl_setup, verbose=False, schema=False)
        assert rc == 11

    def test_schema_true_dispatches_to_ascmhl_schema_check(self, ascmhl_setup, monkeypatch):
        """With schema=True, _verify_ascmhl calls _ascmhl_schema_check."""
        called = {}

        def _stub_schema_check(target, verbose, **kw):
            called["yes"] = True
            return 0

        monkeypatch.setattr(verifyall, "_ascmhl_schema_check", _stub_schema_check)
        rc, _mr = verifyall._verify_ascmhl(ascmhl_setup, verbose=False, schema=True)
        assert called.get("yes") is True
        assert rc == 0


# ---------------------------------------------------------------------------
# TestClassicMhlDispatch
# ---------------------------------------------------------------------------


class TestClassicMhlDispatch:
    """
    Classic MHL is verified in-process via the core engine. These pin exit-code
    propagation, manifest-status derivation, size-only flagging, and
    schema-check dispatch — with verify_classic / schema_report stubbed so the
    tests don't depend on real hashing or the filesystem.
    """

    @pytest.fixture
    def classic_mhl(self, tmp_path):
        """
        A path for a classic manifest. The engine is stubbed per test, so the
        file contents are irrelevant.
        """
        mhl = tmp_path / "dummy.mhl"
        mhl.write_text("")
        return mhl

    @staticmethod
    def _stub_verify(monkeypatch, report):
        monkeypatch.setattr(verifyall, "verify_classic", lambda *a, **kw: report)

    @pytest.mark.parametrize("exit_code", [0, 40, 10, 11, 13])
    def test_verify_classicmhl_exit_code_propagates(self, classic_mhl, monkeypatch, exit_code):
        """The engine's report code is returned unchanged by _verify_classicmhl."""
        if exit_code == 40:
            report = VerifyReport(code=40, malformed=True)
        else:
            entries = (
                []
                if exit_code == 0
                else [VerifyEntry(path="f.mxf", status="mismatch", line="[ERROR] hash mismatch: f.mxf")]
            )
            report = VerifyReport(entries=entries, code=exit_code)
        self._stub_verify(monkeypatch, report)
        rc, _mr = verifyall._verify_classicmhl(target=classic_mhl, verbose=False, schema=False)
        assert rc == exit_code

    def test_manifest_status_is_failed_when_entries_present(self, classic_mhl, monkeypatch):
        """A non-zero code WITH per-file outcomes yields manifest_status 'failed'."""
        report = VerifyReport(
            entries=[VerifyEntry(path="f.mxf", status="mismatch", detail="hash mismatch")],
            code=11,
        )
        self._stub_verify(monkeypatch, report)
        rc, mr = verifyall._verify_classicmhl(target=classic_mhl, verbose=False, schema=False)
        assert rc == 11
        assert mr is not None
        assert mr.manifest_status == "failed"

    def test_manifest_status_is_error_on_malformed(self, classic_mhl, monkeypatch):
        """Malformed XML (no per-file outcomes) yields manifest_status 'error'."""
        self._stub_verify(monkeypatch, VerifyReport(code=40, malformed=True))
        rc, mr = verifyall._verify_classicmhl(target=classic_mhl, verbose=False, schema=False)
        assert rc == 40
        assert mr is not None
        assert mr.manifest_status == "error"

    def test_size_only_is_passed_through_and_flagged(self, classic_mhl, monkeypatch):
        """size_only reaches verify_classic and OK results carry the size-only flag."""
        seen: dict[str, bool] = {}

        def _stub(mhl_file, *, size_only=False, on_progress=None):
            seen["size_only"] = size_only
            return VerifyReport(
                entries=[VerifyEntry(path="clip.mxf", status="ok", size_only=True, line="[OK] clip.mxf  size: 4170")],
                code=0,
            )

        monkeypatch.setattr(verifyall, "verify_classic", _stub)
        rc, mr = verifyall._verify_classicmhl(target=classic_mhl, verbose=False, schema=False, size_only=True)
        assert rc == 0
        assert seen["size_only"] is True
        assert mr is not None
        assert mr.n_size_only == 1

    def test_verify_classicmhl_dispatch_table_covers_engine_codes(self):
        """_CLASSICMHL_RESULTS must cover every exit code the classic engine emits."""
        engine_codes = {0, 10, 11, 13, 40}
        missing = engine_codes - set(verifyall._CLASSICMHL_RESULTS.keys())
        assert missing == set(), f"Dispatch table missing codes: {missing}"

    def test_schema_uses_classicmhl_schema_results_table(self, classic_mhl, monkeypatch, capsys):
        """Schema mode runs schema_report and maps the code via
        _CLASSICMHL_SCHEMA_RESULTS — exit 41 has a specific 'schema' message."""
        monkeypatch.setattr(verifyall, "schema_report", lambda mhl_file: (41, ["Error: XSD validation failed"]))
        rc, _mr = verifyall._verify_classicmhl(classic_mhl, verbose=False, schema=True, emit=mhlver._render_status)
        assert rc == 41
        captured = capsys.readouterr()
        assert "schema" in (captured.out + captured.err).lower()


# ---------------------------------------------------------------------------
# TestLogHelpers
# ---------------------------------------------------------------------------


class TestLogHelpers:
    """Unit tests for _log and _emit_step_output."""

    def test_log_routes_through_console(self, capsys):
        """
        When a console object is passed, _log uses console.print, not print().
        """
        console = FakeConsole()
        mhlver._log("hello", colour="", stream=None, console=console)
        assert "hello" in console.getvalue()
        # Nothing should have leaked to the real stdout/stderr.
        captured = capsys.readouterr()
        assert "hello" not in captured.out
        assert "hello" not in captured.err

    def test_emit_step_output_success_prints_to_stdout(self, capsys):
        """On exit_code==0 with show_on_terminal, output goes to stdout."""
        mhlver._emit_step_output("OK: file.bin", 0, show_on_terminal=True)
        captured = capsys.readouterr()
        assert "OK: file.bin" in captured.out

    def test_emit_step_output_success_via_console(self, capsys):
        """On exit_code==0, a console object is used instead of print()."""
        console = FakeConsole()
        mhlver._emit_step_output("OK: file.bin", 0, show_on_terminal=True, console=console)
        assert "OK: file.bin" in console.getvalue()

    def test_emit_step_output_failure_via_console(self, capsys):
        """On exit_code!=0, a console object is used for the error output."""
        console = FakeConsole()
        mhlver._emit_step_output("ERR: file.bin", 1, show_on_terminal=True, console=console)
        assert "ERR: file.bin" in console.getvalue()
        # Nothing should have leaked to real stderr.
        assert "ERR: file.bin" not in capsys.readouterr().err

    def test_emit_step_output_empty_is_noop(self, capsys):
        """Empty output string produces no output at all."""
        mhlver._emit_step_output("", 1, show_on_terminal=True)
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    def test_emit_step_output_suppressed_is_silent(self, capsys):
        """show_on_terminal=False produces no terminal output."""
        mhlver._emit_step_output("detail", 0, show_on_terminal=False)
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    def test_report_via_table_shown_success_logs_to_terminal(self, capsys):
        """
        With show_status_on_terminal=True an exit-0 entry surfaces its success
        line (the inverse of test_suppressed_success_is_silent).
        """
        mhlver._report_via_table(
            verifyall._CLASSICMHL_RESULTS,
            0,
            "manifest.mhl",
            "",
            show_backend_output=False,
            show_status_on_terminal=True,
        )
        assert "manifest.mhl" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# TestReportViaTable
# ---------------------------------------------------------------------------


class TestReportViaTable:
    """Tests for _report_via_table edge cases."""

    def test_suppressed_success_is_silent(self, capsys):
        """
        When show_status_on_terminal=False and exit=0, the success line is
        suppressed entirely (the silent-progress-bar path).
        """
        mhlver._report_via_table(
            verifyall._CLASSICMHL_RESULTS,
            0,
            "manifest.mhl",
            "",
            show_backend_output=False,
            show_status_on_terminal=False,
        )
        captured = capsys.readouterr()
        assert captured.out == ""
        assert captured.err == ""

    def test_errors_always_shown_on_terminal_regardless_of_suppression(self, capsys):
        """
        Errors must always appear on the terminal regardless of
        show_status_on_terminal, because operators need immediate visibility.
        """
        mhlver._report_via_table(
            verifyall._CLASSICMHL_RESULTS,
            40,
            "bad.mhl",
            "",
            show_backend_output=False,
            show_status_on_terminal=False,
        )
        captured = capsys.readouterr()
        assert "bad.mhl" in captured.err


# ---------------------------------------------------------------------------
# TestMhlTotalBytes
# ---------------------------------------------------------------------------


class TestMhlTotalBytes:
    """Tests for _mhl_total_bytes."""

    def test_sums_size_elements(self, tmp_path):
        """Returns the sum of <size> values for entries with a recomputable hash."""
        mhl = tmp_path / "test.mhl"
        mhl.write_text(
            '<?xml version="1.0"?>\n'
            '<hashlist version="1.1">'
            "<hash><file>a.bin</file><size>100</size><xxhash64be>aa</xxhash64be></hash>"
            "<hash><file>b.bin</file><size>200</size><xxhash64be>bb</xxhash64be></hash>"
            "</hashlist>"
        )
        assert verifyall._mhl_total_bytes(mhl) == 300

    def test_returns_zero_on_parse_failure(self, tmp_path):
        """Returns 0 when the file cannot be parsed."""
        mhl = tmp_path / "broken.mhl"
        mhl.write_text("<not valid xml")
        assert verifyall._mhl_total_bytes(mhl) == 0

    def test_returns_zero_for_missing_file(self, tmp_path):
        """Returns 0 when the file doesn't exist."""
        assert verifyall._mhl_total_bytes(tmp_path / "ghost.mhl") == 0

    def test_skips_non_digit_size_elements(self, tmp_path):
        """Non-numeric <size> values are ignored rather than raising."""
        mhl = tmp_path / "test.mhl"
        mhl.write_text(
            '<?xml version="1.0"?>\n'
            '<hashlist version="1.1">'
            "<hash><file>a.bin</file><size>bad</size><xxhash64be>aa</xxhash64be></hash>"
            "<hash><file>b.bin</file><size>50</size><xxhash64be>bb</xxhash64be></hash>"
            "</hashlist>"
        )
        assert verifyall._mhl_total_bytes(mhl) == 50

    def test_null_entry_excluded(self, tmp_path):
        """A <null> (size-only) entry reads zero bytes at verify time, so its
        <size> is excluded — only the hashed entry's size is counted."""
        mhl = tmp_path / "mixed.mhl"
        mhl.write_text(
            '<?xml version="1.0"?>\n'
            '<hashlist version="1.1">'
            "<hash><file>a.bin</file><size>100</size><xxhash64be>aa</xxhash64be></hash>"
            "<hash><file>b.bin</file><size>200</size><null></null></hash>"
            "</hashlist>"
        )
        assert verifyall._mhl_total_bytes(mhl) == 100

    def test_existence_only_entry_is_zero(self, tmp_path):
        """A <null> entry with no <size> (existence-only) contributes nothing."""
        mhl = tmp_path / "existence.mhl"
        mhl.write_text(
            '<?xml version="1.0"?>\n<hashlist version="1.1"><hash><file>a.bin</file><null></null></hash></hashlist>'
        )
        assert verifyall._mhl_total_bytes(mhl) == 0

    @pytest.mark.parametrize(
        "fixture_name",
        [
            "shotputpro_classicmhl_example.mhl",
            "silverstack_classicmhl_example.mhl",
            "ocopy_classicmhl_example.mhl",
            "offshoot_classicmhl_example.mhl",
        ],
    )
    def test_classicmhl_real_world_total(self, tmp_path, load_fixture_mhl, fixture_name):
        """Real-world classic MHL exports from each vendor sum to the same
        aligned total."""
        mhl = load_fixture_mhl(tmp_path, fixture_name)
        assert verifyall._mhl_total_bytes(mhl) == _ALIGNED_FIXTURE_TOTAL_BYTES


# ---------------------------------------------------------------------------
# TestOpenReport
# ---------------------------------------------------------------------------


class TestOpenReport:
    """Tests for _open_report context manager."""

    def test_creates_report_file_with_header(self, tmp_path):
        """Report file is created, is writable inside the block, and closed after."""
        with mhlver._open_report(tmp_path) as (fh, rp):
            assert rp.exists()
            assert not fh.closed
            fh.write("mhlver\n")
            fh.write("test line\n")
        assert fh.closed
        content = rp.read_text(encoding="utf-8")
        assert "mhlver" in content
        assert "test line" in content

    def test_report_path_uses_src_name(self, tmp_path):
        """The report filename contains the source directory name."""
        with mhlver._open_report(tmp_path) as (_fh, rp):
            pass
        assert tmp_path.name in rp.name

    def test_report_for_file_src_writes_to_parent(self, tmp_path):
        """When src is a file, the report is created in src's parent directory."""
        src_file = tmp_path / "manifest.mhl"
        src_file.write_text("")
        with mhlver._open_report(src_file) as (_fh, rp):
            pass
        assert rp.parent == tmp_path


# ---------------------------------------------------------------------------
# TestRun
# ---------------------------------------------------------------------------


class TestRun:
    """Tests for the _run orchestration function."""

    def _stub_verify_item(self, monkeypatch, return_code: int):
        monkeypatch.setattr(mhlver, "verify_item", lambda *a, **kw: (return_code, None))

    def test_run_with_single_file_success(self, tmp_path, monkeypatch, capsys):
        """_run with a file path calls verify_item and returns 0 on success."""
        self._stub_verify_item(monkeypatch, 0)
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        rc, _, _ = mhlver._run(mhl, verbose=False, schema=False)
        assert rc == 0
        assert "successfully verified" in capsys.readouterr().out

    def test_run_success_notes_size_only_checks(self, tmp_path, monkeypatch, capsys):
        """A clean run that relied on a size-only (<null>) check appends the
        size-only qualifier to the success summary."""
        mr = mhlver.ManifestResult(
            manifest_path=tmp_path / "manifest.mhl",
            manifest_status="ok",
            file_results=[mhlver.FileResult(path="a.bin", status="ok", size_only=True)],
        )
        monkeypatch.setattr(mhlver, "verify_item", lambda *a, **kw: (0, mr))
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        rc, _, _ = mhlver._run(mhl, verbose=False, schema=False)
        assert rc == 0
        out = capsys.readouterr().out
        assert "⚠️ All MHL manifests have been successfully verified (some of them with size-only checks)." in out
        assert "✨️" not in out

    def test_run_success_notes_existence_only_checks(self, tmp_path, monkeypatch, capsys):
        """A clean run that relied on an existence-only (<null>, no <size>) check warns
        and names the existence-only qualifier distinctly from size-only."""
        mr = mhlver.ManifestResult(
            manifest_path=tmp_path / "manifest.mhl",
            manifest_status="ok",
            file_results=[mhlver.FileResult(path="a.bin", status="ok", existence_only=True)],
        )
        monkeypatch.setattr(mhlver, "verify_item", lambda *a, **kw: (0, mr))
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        rc, _, _ = mhlver._run(mhl, verbose=False, schema=False)
        assert rc == 0
        out = capsys.readouterr().out
        assert "⚠️ All MHL manifests have been successfully verified (some of them with existence-only checks)." in out
        assert "✨️" not in out

    def test_run_with_single_file_failure(self, tmp_path, monkeypatch, capsys):
        """_run with a file path returns the non-zero exit code on failure."""
        self._stub_verify_item(monkeypatch, 40)
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        rc, _, _ = mhlver._run(mhl, verbose=False, schema=False)
        assert rc == 40
        assert "failed" in capsys.readouterr().err.lower()

    def test_run_empty_directory_warns(self, tmp_path, monkeypatch, capsys):
        """_run on a dir with no MHL files logs a warning and returns 0."""
        # Force use_progress=False so we stay in the simple branch.
        monkeypatch.setattr(mhlver.sys.stdout, "isatty", lambda: False)
        rc, _, found = mhlver._run(tmp_path, verbose=False, schema=False)
        assert rc == 0
        assert found is False
        captured = capsys.readouterr()
        out = captured.out + captured.err
        assert "no mhl" in out.lower()
        # No manifests found means nothing to declare verified.
        assert "successfully verified" not in out

    def test_run_directory_first_failure_wins(self, tmp_path, monkeypatch, capsys):
        """First non-zero exit code is returned; subsequent failures don't override."""
        monkeypatch.setattr(mhlver.sys.stdout, "isatty", lambda: False)
        results = iter([30, 40])
        monkeypatch.setattr(mhlver, "verify_item", lambda *a, **kw: (next(results), None))
        for name in ["a.mhl", "b.mhl"]:
            (tmp_path / name).write_text("")
        rc, _, _ = mhlver._run(tmp_path, verbose=False, schema=False)
        assert rc == 30

    def test_run_directory_all_pass(self, tmp_path, monkeypatch, capsys):
        """All manifests passing returns 0 with the success summary."""
        monkeypatch.setattr(mhlver.sys.stdout, "isatty", lambda: False)
        monkeypatch.setattr(mhlver, "verify_item", lambda *a, **kw: (0, None))
        (tmp_path / "a.mhl").write_text("")
        (tmp_path / "b.mhl").write_text("")
        rc, _, _ = mhlver._run(tmp_path, verbose=False, schema=False)
        assert rc == 0
        assert "successfully verified" in capsys.readouterr().out

    def test_run_directory_collects_manifest_results_without_progress(self, tmp_path, monkeypatch):
        """In the non-TTY directory path, each verify_item's ManifestResult is
        collected for the report (the no-progress-bar counterpart of the bar path)."""
        monkeypatch.setattr(mhlver.sys.stdout, "isatty", lambda: False)
        mr = mhlver.ManifestResult(
            manifest_path=tmp_path / "a.mhl",
            manifest_status="ok",
            file_results=[mhlver.FileResult(path="a.bin", status="ok")],
        )
        monkeypatch.setattr(mhlver, "verify_item", lambda *a, **kw: (0, mr))
        (tmp_path / "a.mhl").write_text("")
        rc, mrs, _ = mhlver._run(tmp_path, verbose=False, schema=False)
        assert rc == 0
        assert mrs == [mr]

    @pytest.mark.skipif(sys.platform == "win32", reason="os.mkfifo is not available on Windows")
    def test_src_is_neither_file_nor_dir_still_succeeds(self, tmp_path, monkeypatch):
        """When src exists but is neither a file nor a directory (e.g. a named
        pipe), _run takes the else branch (console = None) and returns 0."""

        pipe = tmp_path / "fifo.mhl"
        os.mkfifo(pipe)
        # verify_item is never called — exit_status stays 0.
        rc, _, _ = mhlver._run(pipe, verbose=False, schema=False)
        assert rc == 0

    def test_run_writes_structured_report(self, tmp_path, monkeypatch):
        """A successful _run feeds _render_report a result that renders both the
        PASSED summary line and the separator rules."""
        monkeypatch.setattr(mhlver.sys.stdout, "isatty", lambda: False)
        monkeypatch.setattr(mhlver, "verify_item", lambda *a, **kw: (0, None))
        (tmp_path / "a.mhl").write_text("")
        rc, mrs, _ = mhlver._run(tmp_path, verbose=False, schema=False)
        buf = io.StringIO()
        mhlver._render_report(buf, tmp_path, mhlver.datetime.now(), mhlver.datetime.now(), mrs, rc)
        report = buf.getvalue()
        assert "VERIFIED" in report
        assert "---" in report


# ---------------------------------------------------------------------------
# TestRunWithProgress
# ---------------------------------------------------------------------------


class TestRunWithProgress:
    """Tests for _run's progress-bar branch (use_progress=True)."""

    @staticmethod
    def _stub_build_live(monkeypatch):
        """Replace _build_live with lightweight no-op stubs."""

        label = MagicMock()
        label.plain = ""

        progress = MagicMock()
        progress.add_task.return_value = 0

        live = MagicMock()
        live.__enter__ = lambda s: s
        live.__exit__ = MagicMock(return_value=False)

        console = MagicMock()
        console.file = io.StringIO()

        monkeypatch.setattr(mhlver, "_build_live", lambda: (live, progress, label, console))
        return progress

    def test_progress_branch_calls_verify_item_for_each_manifest(self, tmp_path, monkeypatch):
        """verify_item is called once per manifest when use_progress=True."""
        monkeypatch.setattr(mhlver.sys.stdout, "isatty", lambda: True)
        self._stub_build_live(monkeypatch)
        call_count = 0

        def _counting_verify(*a, **kw):
            nonlocal call_count
            call_count += 1
            return 0, None

        monkeypatch.setattr(mhlver, "verify_item", _counting_verify)
        (tmp_path / "a.mhl").write_text("")
        (tmp_path / "b.mhl").write_text("")
        rc, _, _ = mhlver._run(tmp_path, verbose=False, schema=False)
        assert rc == 0
        assert call_count == 2

    def test_progress_branch_propagates_first_failure(self, tmp_path, monkeypatch):
        """First non-zero exit code is preserved; a later one does not override it."""
        monkeypatch.setattr(mhlver.sys.stdout, "isatty", lambda: True)
        self._stub_build_live(monkeypatch)
        results = iter([(30, None), (40, None)])
        monkeypatch.setattr(mhlver, "verify_item", lambda *a, **kw: next(results))
        (tmp_path / "a.mhl").write_text("")
        (tmp_path / "b.mhl").write_text("")
        rc, _, _ = mhlver._run(tmp_path, verbose=False, schema=False)
        assert rc == 30

    def test_progress_branch_advances_bar_per_manifest(self, tmp_path, monkeypatch):
        """progress.advance() is called once per manifest with its byte weight."""
        monkeypatch.setattr(mhlver.sys.stdout, "isatty", lambda: True)
        progress = self._stub_build_live(monkeypatch)
        monkeypatch.setattr(mhlver, "verify_item", lambda *a, **kw: (0, None))
        (tmp_path / "a.mhl").write_text("")
        (tmp_path / "b.mhl").write_text("")
        mhlver._run(tmp_path, verbose=False, schema=False)
        assert progress.advance.call_count == 2

    def test_progress_branch_collects_manifest_result_and_advances_via_on_bytes(self, tmp_path, monkeypatch):
        """
        When verify_item returns a ManifestResult and reports bytes through
        on_bytes, the result is collected and the per-chunk _advance callback
        runs (driving progress.advance with the streamed byte counts).
        """
        monkeypatch.setattr(mhlver.sys.stdout, "isatty", lambda: True)
        progress = self._stub_build_live(monkeypatch)
        mr = mhlver.ManifestResult(
            manifest_path=tmp_path / "a.mhl",
            manifest_status="ok",
            file_results=[mhlver.FileResult(path="a.bin", status="ok")],
        )

        def _verify(f, verbose, schema, size_only, emit=None, on_bytes=None):
            assert on_bytes is not None
            on_bytes(100)  # exercise the _advance callback from the progress branch
            return 0, mr

        monkeypatch.setattr(mhlver, "verify_item", _verify)
        (tmp_path / "a.mhl").write_text("")
        rc, mrs, _ = mhlver._run(tmp_path, verbose=False, schema=False)
        assert rc == 0
        assert mrs == [mr]
        # _advance(100) plus the post-manifest top-up both call progress.advance.
        assert progress.advance.call_count >= 1

    def test_build_live_returns_live_progress_label_console(self):
        """
        _build_live constructs the rich Live display: a Live, a Progress, a Text
        label and a Console, all bound together (no stubbing — the real
        builder).
        """
        live, progress, label, console = mhlver._build_live()
        assert isinstance(live, Live)
        assert isinstance(progress, Progress)
        assert isinstance(label, Text)
        assert isinstance(console, Console)

    def test_progress_branch_writes_separator_to_report(self, tmp_path, monkeypatch):
        """_render_report includes separator lines in its output."""

        monkeypatch.setattr(mhlver.sys.stdout, "isatty", lambda: True)
        self._stub_build_live(monkeypatch)
        monkeypatch.setattr(mhlver, "verify_item", lambda *a, **kw: (0, None))
        (tmp_path / "a.mhl").write_text("")
        rc, mrs, _ = mhlver._run(tmp_path, verbose=False, schema=False)
        buf = io.StringIO()
        mhlver._render_report(buf, tmp_path, mhlver.datetime.now(), mhlver.datetime.now(), mrs, rc)
        assert "---" in buf.getvalue()


# ---------------------------------------------------------------------------
# TestMain
# ---------------------------------------------------------------------------


class TestMain:
    """Integration tests for mhlver.main() — argument parsing and dispatch."""

    def test_nonexistent_path_exits_2(self, mhlver_cli):
        """
        Passing a path that doesn't exist must exit 2 with an error message.
        """
        rc, _, err = mhlver_cli(["/nonexistent/path/ghost.mhl"])
        assert rc == 2
        assert "file or directory" in err.lower() or "exist" in err.lower()

    def test_nonexistent_path_suggests_normalization_variant(self, mhlver_cli, monkeypatch):
        """
        When the typed path is missing but a Unicode-normalization variant
        exists, mhlver appends a 'did you mean' hint — parity with simple-mhl
        via the shared osutils helper. The helper is stubbed here; its own
        resolution logic is covered by the simple-mhl test suite.
        """
        monkeypatch.setattr(mhlver, "normalization_variant_on_disk", lambda p: "/vol/rosé_nfd.mhl")
        rc, _, err = mhlver_cli(["/vol/rosé_nfc.mhl"])
        assert rc == 2
        assert "did you mean" in err.lower()
        assert "rosé_nfd.mhl" in err

    def test_nonexistent_path_no_variant_is_plain_error(self, mhlver_cli, monkeypatch):
        """
        A genuine typo (no normalization variant) gives the plain error, no
        hint.
        """
        monkeypatch.setattr(mhlver, "normalization_variant_on_disk", lambda p: None)
        rc, _, err = mhlver_cli(["/vol/ghost.mhl"])
        assert rc == 2
        assert "did you mean" not in err.lower()

    def test_default_path_is_cwd(self, mhlver_cli, monkeypatch, tmp_path):
        """Omitting the path argument defaults to the current directory."""
        called_with = {}

        def _stub_run(src, verbose, schema, size_only=False):
            called_with["src"] = src
            return 0, [], True

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mhlver, "_run", _stub_run)
        rc, _, _ = mhlver_cli([])
        assert rc == 0
        assert called_with["src"] == tmp_path.resolve()

    def test_explicit_file_path_passed_to_run(self, mhlver_cli, monkeypatch, tmp_path):
        """An explicit path is resolved and forwarded to _run."""
        called_with = {}

        def _stub_run(src, verbose, schema, size_only=False):
            called_with["src"] = src
            return 0, [], True

        monkeypatch.setattr(mhlver, "_run", _stub_run)
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        rc, _, _ = mhlver_cli([str(mhl)])
        assert rc == 0
        assert called_with["src"] == mhl.resolve()

    def test_verbose_flag_forwarded(self, mhlver_cli, monkeypatch, tmp_path):
        """--verbose is passed through to _run."""
        called_with = {}

        def _stub_run(src, verbose, schema, size_only=False):
            called_with["verbose"] = verbose
            return 0, [], True

        monkeypatch.setattr(mhlver, "_run", _stub_run)
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        mhlver_cli(["-v", str(mhl)])
        assert called_with["verbose"] is True

    def test_schema_flag_forwarded(self, mhlver_cli, monkeypatch, tmp_path):
        """--xsd-schema-check is passed through to _run."""
        called_with = {}

        def _stub_run(src, verbose, schema, size_only=False):
            called_with["schema"] = schema
            return 0, [], True

        monkeypatch.setattr(mhlver, "_run", _stub_run)
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        mhlver_cli(["-s", str(mhl)])
        assert called_with["schema"] is True

    def test_exit_code_propagated_from_run(self, mhlver_cli, monkeypatch, tmp_path):
        """The exit code returned by _run becomes mhlver's exit code."""
        monkeypatch.setattr(mhlver, "_run", lambda *a, **kw: (40, [], True))
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        rc, _, _ = mhlver_cli([str(mhl)])
        assert rc == 40

    def test_report_flag_creates_report_file(self, mhlver_cli, monkeypatch, tmp_path):
        """--report causes a report file to be created and its path printed."""
        monkeypatch.setattr(mhlver, "_run", lambda *a, **kw: (0, [], True))
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
        """The report file includes the overall PASSED/FAILED status."""
        monkeypatch.setattr(mhlver, "_run", lambda *a, **kw: (0, [], True))
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        mhlver_cli(["--report", str(mhl)])
        report = next(tmp_path.glob("mhlver_report_*.log"))
        assert "VERIFIED" in report.read_text(encoding="utf-8")

    def test_report_flag_with_failure_records_nonzero_exit(self, mhlver_cli, monkeypatch, tmp_path):
        """A non-zero exit from _run is reflected as FAILED in the report file."""
        monkeypatch.setattr(mhlver, "_run", lambda *a, **kw: (40, [], True))
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        rc, _, _ = mhlver_cli(["--report", str(mhl)])
        assert rc == 40
        report = next(tmp_path.glob("mhlver_report_*.log"))
        assert "FAILED" in report.read_text(encoding="utf-8")

    def test_schema_and_report_are_mutually_exclusive(self, mhlver_cli, tmp_path):
        """-s and -r cannot be combined: schema-check has no per-manifest detail."""
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        rc, _, err = mhlver_cli(["-s", "-r", str(mhl)])
        assert rc == 2
        assert "are not supported" in err
        assert list(tmp_path.glob("mhlver_report_*.log")) == []

    def test_schema_and_size_only_are_mutually_exclusive(self, mhlver_cli, tmp_path):
        """-s (schema-check) and -S (size-only) are distinct modes and can't combine."""
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        rc, _, err = mhlver_cli(["-s", "-S", str(mhl)])
        assert rc == 2
        assert "cannot be executed together" in err

    def test_report_not_created_when_no_manifests_found(self, mhlver_cli, monkeypatch, tmp_path):
        """An empty directory leaves no report log behind."""
        monkeypatch.setattr(mhlver, "_run", lambda *a, **kw: (0, [], False))
        rc, out, _ = mhlver_cli(["--report", str(tmp_path)])
        assert rc == 0
        assert list(tmp_path.glob("mhlver_report_*.log")) == []
        assert "report saved to" not in out


# ---------------------------------------------------------------------------
# TestSchemaShapedAscMhlFuzz
# ---------------------------------------------------------------------------

# Adversarial leaf values for the typed fields the ASC-MHL 2.0 schema defines.
# The <path size="…"> attribute is xs:integer (so negatives are schema-legal),
# and the byte-counting helpers must treat anything non-decimal as "no size".
_fuzz_text = strategies.text(
    alphabet=strategies.characters(blacklist_categories=("Cs", "Cc", "Cn")),
    max_size=40,
)
_fuzz_size_attr = strategies.one_of(
    strategies.sampled_from(
        ["0", "1", "-5", "12345", "9" * 40, "1.5", "", "  10  ", "007", "0x1F", "abc", "+3", "NaN", "१२३"]
    ),
    strategies.integers(min_value=-10, max_value=10**15).map(str),
    strategies.none(),  # omit the attribute entirely
)
_fuzz_action = strategies.sampled_from(["original", "verified", "failed", "bogus", "", "ORIGINAL"])
# (path_text, size_attr, action, digest, is_directoryhash)
_asc_entry = strategies.tuples(_fuzz_text, _fuzz_size_attr, _fuzz_action, _fuzz_text, strategies.booleans())


def _build_ascmhl_fuzz(entries) -> bytes:
    """
    Build a well-formed ASC-MHL 2.0 manifest (correct namespace + structure)
    with fuzzed <path> text/size and hash action/digest. lxml guarantees
    well-formedness so the fuzzing targets size parsing, not the serializer.

    Tags use Clark notation (``{ns}tag``) so the namespace URI is correct; we
    don't force a default-namespace nsmap because the parser under test queries
    with a ``{*}`` wildcard, so the prefix style is irrelevant.
    """
    root = etree.Element(f"{{{_ASCMHL_NAMESPACE}}}hashlist", version="2.0")
    hashes = etree.SubElement(root, f"{{{_ASCMHL_NAMESPACE}}}hashes")
    for path_text, size_attr, action, digest, is_dir in entries:
        kind = "directoryhash" if is_dir else "hash"
        h = etree.SubElement(hashes, f"{{{_ASCMHL_NAMESPACE}}}{kind}")
        p = etree.SubElement(h, f"{{{_ASCMHL_NAMESPACE}}}path")
        p.text = path_text or None
        if size_attr is not None:
            p.set("size", size_attr)
        xx = etree.SubElement(h, f"{{{_ASCMHL_NAMESPACE}}}xxh64")
        xx.text = digest or None
        if action:
            xx.set("action", action)
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


class TestSchemaShapedAscMhlFuzz:
    """
    Schema-shaped value fuzzing of the byte-counting helpers that parse manifest
    XML directly (no external backend needed). For any well-formed, XSD-shaped
    manifest with adversarial typed values, the helpers must return a
    non-negative int and never raise — they are called while building the
    progress bar, so a crash there aborts an otherwise-fine verify run.
    """

    @given(entries=strategies.lists(_asc_entry, min_size=1, max_size=6))
    @settings(max_examples=120, suppress_health_check=[HealthCheck.too_slow])
    def test_ascmhl_total_bytes_is_nonnegative_and_never_raises(self, entries):
        xml = _build_ascmhl_fuzz(entries)
        with tempfile.TemporaryDirectory() as tmp:
            ascdir = Path(tmp) / "ascmhl"
            ascdir.mkdir()
            mhl = ascdir / "0001.mhl"
            mhl.write_bytes(xml)
            total = verifyall._ascmhl_total_bytes(mhl)
            assert isinstance(total, int)
            assert total >= 0

    @given(entries=strategies.lists(strategies.tuples(_fuzz_text, _fuzz_size_attr), max_size=6))
    @settings(max_examples=120, suppress_health_check=[HealthCheck.too_slow])
    def test_mhl_total_bytes_is_nonnegative_and_never_raises(self, entries):
        root = etree.Element("hashlist", version="1.1")
        for file_text, size_text in entries:
            h = etree.SubElement(root, "hash")
            etree.SubElement(h, "file").text = file_text or None
            if size_text is not None:
                etree.SubElement(h, "size").text = size_text
        xml = etree.tostring(root, xml_declaration=True, encoding="UTF-8")
        with tempfile.TemporaryDirectory() as tmp:
            mhl = Path(tmp) / "classic.mhl"
            mhl.write_bytes(xml)
            total = verifyall._mhl_total_bytes(mhl)
            assert isinstance(total, int)
            assert total >= 0


# ---------------------------------------------------------------------------
# TestSinglePassVerify — the non-verbose path must spawn each backend ONCE
# ---------------------------------------------------------------------------


class TestSinglePassVerify:
    """
    Locks the single-pass property: a default (non-verbose) ASC-MHL verify
    hashes the package exactly once. verify_ascmhl is the sole hashing pass now
    (the old code shelled out to ascmhl-debug twice — once -v for the report,
    once plain for the terminal — re-hashing everything), so a regression that
    reintroduced a second pass would call verify_ascmhl more than once. (Classic
    MHL is in-process too; see TestClassicMhlDispatch.)
    """

    def test_ascmhl_verify_invokes_engine_once(self, monkeypatch, tmp_path):
        calls = {"n": 0}

        def _spy(root_path, *, size_only=False, on_progress=None):
            calls["n"] += 1
            return verifyall.VerifyReport(entries=[], code=0)

        monkeypatch.setattr(verifyall.ascmhl_verify, "verify_ascmhl", _spy)
        pkg = tmp_path / "ascmhl"
        pkg.mkdir()
        target = pkg / "0001.mhl"
        target.write_text("<x/>")

        verifyall._ascmhl_verify(target, verbose=False)

        assert calls["n"] == 1, f"expected 1 hashing pass, got {calls['n']}"
