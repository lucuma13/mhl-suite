"""Test suite for mhlver.py orchestrator and ASC-MHL dispatch."""

import io
import os
import sys
import tempfile
import unicodedata
from collections import Counter
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from hypothesis import HealthCheck, assume, given, settings, strategies
from lxml import etree

from mhl_suite import mhlver, verifyall
from mhl_suite.ascmhl import sizecheck as ascmhl_sizecheck
from mhl_suite.shared.results import FileOutcome, VerifyReport

# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

_ASCMHL_NAMESPACE = "urn:ASC:MHL:v2.0"

# Windows reserves these device names at every extension; attempting to create
# e.g. CON.mhl on Windows raises PermissionError / FileNotFoundError.
_WINDOWS_RESERVED_NAMES = ["CON", "PRN", "AUX", "NUL", "COM1", "COM2", "LPT1", "LPT2"]

# Hypothesis strategy for valid filename stems: Unicode letters, digits and
# symbols (including emoji), plus "_-". Path separators can't occur: they're
# punctuation (outside the whitelisted categories.
# We keep only NFC-normalised stems so two "distinct" names can't
# collapse onto the same file on a normalisation-insensitive filesystem
# (APFS/HFS+), which would otherwise under-create files and flake the count
# invariants. Also skip leading "._" (the resource-fork filter) and blank names.
_filename_stem = strategies.text(
    alphabet=strategies.characters(
        whitelist_categories=("Ll", "Lu", "Nd", "So"),
        whitelist_characters="_-",
    ),
    min_size=1,
    max_size=20,
).filter(lambda s: not s.startswith("._") and s.strip() and unicodedata.is_normalized("NFC", s))

_generations_per_pkg = strategies.integers(min_value=1, max_value=4)

# All vendor example fixtures (classic + ASC-MHL) are deliberately aligned to
# this total so each parser can be checked against the same known value.
_ALIGNED_FIXTURE_TOTAL_BYTES = 18_004_919_466

#: Directory containing real-tool MHL fixture files used by the suite. Each file
#: is a verbatim (anonymised) MHL output from a specific transfer tool, named
#: <tool>_<format>.mhl (e.g. shotputpro_ascmhl.mhl).
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

    Each entry dict must have "path", "size", "action", and "digest" keys.
    Used by the Unicode-guard tests that need to craft specific size attributes
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


def stub_verify_package(monkeypatch, code, entries=None):
    """Replace ascmhl.verify.verify_package with a stub returning a fixed report.

    The in-process counterpart of the old stub_run_step: ASC-MHL verify now goes
    through mhl_suite.ascmhl.verify.verify_package, so dispatch/wiring tests pin
    its structured result instead of a subprocess StepResult.
    """
    report = verifyall.ascmhl_verify.AscVerifyReport(entries=entries or [], code=code)
    monkeypatch.setattr(verifyall.ascmhl_verify, "verify_package", lambda *a, **k: report)


def stub_integrity_check(monkeypatch, code, message=""):
    """Replace ascmhl.verify.integrity_check (the size-only integrity gate)."""
    monkeypatch.setattr(verifyall.ascmhl_verify, "integrity_check", lambda *a, **k: (code, message))


def call_verify(manifest):
    """Invoke _ascmhl_verify with sane defaults and return its exit code."""
    rc, _mr = verifyall._ascmhl_verify(target=manifest, verbose=False)
    return rc


class FakeConsole:
    """Minimal stand-in for rich.Console: records what would be printed instead
    of emitting it, so tests can assert on routed output without touching the
    real stdout/stderr."""

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
    """Factory fixture that writes a minimal ASC-MHL 2.0 generation file.

    Usage::

        def test_something(tmp_path, write_mhl):
            ascdir = tmp_path / "ascmhl"
            ascdir.mkdir()
            write_mhl(ascdir, "0001.mhl", [
                {"path": "clip.mov", "size": "1000000",
                 "action": "original", "digest": "aabbccdd"},
            ])

    Each entry dict must contain ``path``, ``size``, ``action``, and
    ``digest``.  Returns the :class:`~pathlib.Path` of the written file.
    """

    def _write(ascdir: Path, name: str, entries: list[dict]) -> Path:
        body = "".join(_HASH_ENTRY.format(**e) for e in entries)
        mhl = ascdir / name
        mhl.write_text(_MHL_TMPL.format(entries=body))
        return mhl

    return _write


@pytest.fixture
def load_fixture_mhl():
    """Factory fixture that copies a fixture MHL file into a test directory.

    Usage::

        def test_something(tmp_path, load_fixture_mhl):
            ascdir = tmp_path / "ascmhl"
            ascdir.mkdir()
            mhl = load_fixture_mhl(ascdir, "shotputpro_ascmhl.mhl")

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


@pytest.fixture
def mhlver_cli():
    """Run mhlver.main() in-process and return (exit_code, stdout, stderr)."""

    def _run_main(argv):
        str_argv = [str(a) for a in argv]
        old_argv = sys.argv
        old_out, old_err = sys.stdout, sys.stderr
        sys.argv = ["mhlver", *str_argv]
        out, err = io.StringIO(), io.StringIO()
        sys.stdout, sys.stderr = out, err
        exit_code = 0
        try:
            try:
                mhlver.main()
            except SystemExit as e:
                exit_code = e.code if e.code is not None else 0
        finally:
            sys.argv = old_argv
            sys.stdout, sys.stderr = old_out, old_err
        return exit_code, out.getvalue(), err.getvalue()

    return _run_main


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
            (ascdir / "0001.mhl").write_text("")
            (ascdir / "0002.mhl").write_text("")
        # Plus one regular MHL outside ascmhl/
        (tmp_path / "loose.mhl").write_text("")

        selected = mhlver._select_mhl_files(tmp_path)
        # Expected: 1 from pkg1 ascmhl, 1 from pkg2 ascmhl, 1 loose = 3
        assert len(selected) == 3

    def test_dot_underscore_filter_applies_only_to_filename_not_parent_dir(self, tmp_path):
        """Files inside a directory named '._hidden' must NOT be excluded.

        The macOS resource-fork filter checks p.name (the file's own name),
        not any parent directory component.
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
        """Files named CON.mhl, PRN.mhl, etc. are yielded by find_mhl_files
        when they exist on disk.

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
        """The '._' resource-fork filter must not accidentally suppress reserved names.

        None of the Windows reserved names start with '._', so the filter
        should never touch them.  This is a belt-and-suspenders assertion to
        catch any future broadening of the filter logic.
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
# TestSelectMhlFiles
# ---------------------------------------------------------------------------


class TestSelectMhlFiles:
    """Property-based and unit tests for _select_mhl_files.

    The @given tests verify structural invariants over generated directory
    layouts (at least-once, latest-generation, output-count, sort-order).
    The remaining tests cover specific layout patterns that complement
    the Hypothesis properties.

    Note: @given tests must not use function-scoped fixtures like tmp_path
    because the fixture is not reset between generated examples; each manages
    its own TemporaryDirectory.
    """

    @given(
        pkg_names=strategies.lists(_filename_stem, min_size=1, max_size=5, unique=True),
        gen_counts=strategies.lists(_generations_per_pkg, min_size=1, max_size=5),
    )
    @settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
    def test_each_ascmhl_package_selected_at_most_once(self, pkg_names, gen_counts):
        """No matter how many generation files a package has, _select_mhl_files
        must return at most one manifest per ascmhl/ directory.
        """
        counts = (gen_counts + [1] * len(pkg_names))[: len(pkg_names)]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package_dirs = set()
            for name, n_gens in zip(pkg_names, counts, strict=True):
                ascdir = root / name / "ascmhl"
                ascdir.mkdir(parents=True, exist_ok=True)
                package_dirs.add(ascdir)
                for i in range(1, n_gens + 1):
                    (ascdir / f"{i:04d}.mhl").write_text("")

            selected = mhlver._select_mhl_files(root)

            dir_counts = Counter(f.parent for f in selected if f.parent in package_dirs)
            for ascdir, count in dir_counts.items():
                assert count == 1, f"{ascdir} appears {count} times in selection; expected exactly 1"

    @given(
        pkg_names=strategies.lists(_filename_stem, min_size=1, max_size=4, unique=True),
        gen_counts=strategies.lists(_generations_per_pkg, min_size=1, max_size=4),
    )
    @settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
    def test_latest_generation_is_always_selected(self, pkg_names, gen_counts):
        """_select_mhl_files must pick the lexicographically largest filename
        (i.e. the latest generation) for each ASC-MHL package.
        """
        counts = (gen_counts + [1] * len(pkg_names))[: len(pkg_names)]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            expected: dict[Path, Path] = {}
            for name, n_gens in zip(pkg_names, counts, strict=True):
                ascdir = root / name / "ascmhl"
                ascdir.mkdir(parents=True, exist_ok=True)
                for i in range(1, n_gens + 1):
                    (ascdir / f"{i:04d}.mhl").write_text("")
                expected[ascdir] = ascdir / f"{n_gens:04d}.mhl"

            selected = mhlver._select_mhl_files(root)
            selected_set = set(selected)

            for ascdir, latest in expected.items():
                assert latest in selected_set, (
                    f"Expected latest generation {latest.name} to be selected for package {ascdir.parent.name}"
                )

    @given(
        mhl_names=strategies.lists(_filename_stem, min_size=1, max_size=6, unique=True),
    )
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_loose_mhl_files_are_never_deduplicated_against_each_other(self, mhl_names):
        """Each distinct loose .mhl file must appear exactly once in the output.

        Classic MHL files (not inside an ascmhl/ folder) each use their own
        path as their deduplication key, so N distinct loose files must yield
        N results.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in mhl_names:
                (root / f"{name}.mhl").write_text("")

            # Distinct names can still collide on a case-insensitive filesystem (e.g. APFS),
            # so compare against the files on disk.
            on_disk = list(root.glob("*.mhl"))
            selected = mhlver._select_mhl_files(root)
            assert len(selected) == len(on_disk), (
                f"Expected {len(on_disk)} loose files, got {len(selected)}: {[p.name for p in selected]}"
            )

    @given(
        pkg_names=strategies.lists(_filename_stem, min_size=1, max_size=3, unique=True),
        mhl_names=strategies.lists(_filename_stem, min_size=1, max_size=3, unique=True),
        gen_counts=strategies.lists(_generations_per_pkg, min_size=1, max_size=3),
    )
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_output_count_never_exceeds_input_count(self, pkg_names, mhl_names, gen_counts):
        """Total selected files ≤ total .mhl files on disk.

        Deduplication can only reduce the count; it must never invent new
        files or duplicate existing ones.
        """
        assume(not (set(pkg_names) & set(mhl_names)))
        counts = (gen_counts + [1] * len(pkg_names))[: len(pkg_names)]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            total_files = 0

            for name, n_gens in zip(pkg_names, counts, strict=True):
                ascdir = root / name / "ascmhl"
                ascdir.mkdir(parents=True, exist_ok=True)
                for i in range(1, n_gens + 1):
                    (ascdir / f"{i:04d}.mhl").write_text("")
                    total_files += 1

            for name in mhl_names:
                (root / f"{name}.mhl").write_text("")
                total_files += 1

            selected = mhlver._select_mhl_files(root)
            assert len(selected) <= total_files

    @given(
        n_pkgs=strategies.integers(min_value=0, max_value=3),
        n_loose=strategies.integers(min_value=0, max_value=3),
    )
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_output_is_always_sorted(self, n_pkgs, n_loose):
        """_select_mhl_files must return paths in sorted order regardless of
        how many packages or loose files are present.
        """
        assume(n_pkgs + n_loose > 0)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            for i in range(n_pkgs):
                ascdir = root / f"pkg{i}" / "ascmhl"
                ascdir.mkdir(parents=True, exist_ok=True)
                (ascdir / "0001.mhl").write_text("")

            for i in range(n_loose):
                (root / f"loose{i}.mhl").write_text("")

            selected = mhlver._select_mhl_files(root)
            assert selected == sorted(selected)

    def test_ascmhl_folder_directly_under_scan_root_yields_latest(self, tmp_path):
        """When ascmhl/ is immediately under the scan root, the latest
        generation is selected and exactly one manifest is returned.
        """
        ascdir = tmp_path / "ascmhl"
        ascdir.mkdir()
        (ascdir / "0001.mhl").write_text("")
        (ascdir / "0002.mhl").write_text("")
        (ascdir / "0003.mhl").write_text("")

        selected = mhlver._select_mhl_files(tmp_path)

        assert len(selected) == 1
        assert selected[0].name == "0003.mhl"

    def test_top_level_ascmhl_and_nested_package_are_independent(self, tmp_path):
        """A top-level ascmhl/ folder and a sibling package each contribute
        exactly one manifest and do not share a deduplication key.
        """
        top_ascmhl = tmp_path / "ascmhl"
        top_ascmhl.mkdir()
        (top_ascmhl / "0001.mhl").write_text("")

        pkg_ascmhl = tmp_path / "pkg" / "ascmhl"
        pkg_ascmhl.mkdir(parents=True)
        (pkg_ascmhl / "0001.mhl").write_text("")
        (pkg_ascmhl / "0002.mhl").write_text("")

        selected = mhlver._select_mhl_files(tmp_path)

        assert len(selected) == 2
        names = {p.name for p in selected}
        assert "0001.mhl" in names
        assert "0002.mhl" in names


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
        """A second generation that re-verifies the same files must not add to the total."""
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
        assert verifyall._ascmhl_total_bytes(mhl) == 1073741824

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
        """Real-world single-generation ASC-MHL exports (with directory hashes)
        from each vendor sum to the same aligned total."""
        ascdir = tmp_path / "ascmhl"
        ascdir.mkdir()
        mhl = load_fixture_mhl(ascdir, fixture_name)
        assert verifyall._ascmhl_total_bytes(mhl) == _ALIGNED_FIXTURE_TOTAL_BYTES

    def test_corrupt_generation_file_is_skipped_others_still_counted(self, tmp_path, write_mhl):
        """A corrupt .mhl in the ascmhl dir must be silently skipped; valid
        generations still contribute their sizes to the total.

        The inner exception handler in _ascmhl_total_bytes swallows parse
        failures per-file so a single bad generation doesn't zero out the
        entire package weight.
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
        """Earlier generation's size wins when the same path appears in multiple files."""
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
        """A generation containing only a superscript size contributes 0 bytes,
        and a sibling generation is unaffected.

        With isdecimal(), the superscript entry is skipped without raising
        ValueError, so the outer except does not fire and generation 0001
        still contributes its 1000 bytes.
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
        """The three common Unicode superscript digits — ¹ ² ³ — are all
        rejected by isdecimal() and produce no contribution; only the plain
        decimal sibling entry is counted.
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


_CHAIN_TMPL = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<ascmhldirectory xmlns="urn:ASC:MHL:DIRECTORY:v2.0">\n'
    "{entries}"
    "</ascmhldirectory>\n"
)
_CHAIN_ENTRY = '  <hashlist sequencenr="{seq}">\n    <path>{name}</path>\n    <c4>c4dummy</c4>\n  </hashlist>\n'


def _write_chain(ascdir: Path, manifests: list[str]) -> Path:
    """Write a minimal ascmhl_chain.xml listing *manifests* in sequence order.

    The size-only checker reads this only for generation order; its c4 values are
    dummies because manifest integrity is gated separately (via `ascmhl info`).
    """
    entries = "".join(_CHAIN_ENTRY.format(seq=i + 1, name=name) for i, name in enumerate(manifests))
    chain = ascdir / "ascmhl_chain.xml"
    chain.write_text(_CHAIN_TMPL.format(entries=entries))
    return chain


def _build_ascmhl_package(root: Path, files: dict[str, int]) -> Path:
    """Create an ASC-MHL package under *root* (one generation + chain) and write files.

    *files* maps each relative path to the byte size to create on disk. A single
    generation (0001.mhl) records each file at that same size and is listed in the
    chain, so a plain size-only verify passes; tests then mutate disk or manifest
    to provoke failures. Returns the manifest path.
    """
    ascdir = root / "ascmhl"
    ascdir.mkdir(parents=True)
    entries = []
    for rel, size in files.items():
        disk = root / rel
        disk.parent.mkdir(parents=True, exist_ok=True)
        disk.write_bytes(b"x" * size)
        entries.append({"path": rel, "size": str(size), "action": "original", "digest": "aabbccdd"})
    body = "".join(_HASH_ENTRY.format(**e) for e in entries)
    manifest = ascdir / "0001.mhl"
    manifest.write_text(_MHL_TMPL.format(entries=body))
    _write_chain(ascdir, ["0001.mhl"])
    return manifest


class TestAscMhlSizeOnly:
    """The ASC-MHL size-only checker (verify_ascmhl_sizes) and its mhlver wiring
    (_ascmhl_verify_sizeonly, _verify_ascmhl size_only=True). The helper-level tests
    call verify_ascmhl_sizes directly (no integrity gate); the wiring tests go through
    _verify_ascmhl and stub the in-process integrity gate (ascmhl.verify.integrity_check)."""

    def test_all_sizes_match_passes(self, tmp_path):
        """Every recorded size matches disk -> all ok."""
        manifest = _build_ascmhl_package(tmp_path / "pkg", {"a.mov": 100, "sub/b.mov": 200})
        results = ascmhl_sizecheck.verify_ascmhl_sizes(manifest)
        assert {r.path: r.status for r in results} == {"a.mov": "ok", "sub/b.mov": "ok"}

    def test_size_mismatch_reported(self, tmp_path):
        """A file whose on-disk size differs from the manifest is a mismatch."""
        pkg = tmp_path / "pkg"
        manifest = _build_ascmhl_package(pkg, {"a.mov": 100})
        (pkg / "a.mov").write_bytes(b"x" * 99)  # shrink on disk
        (result,) = ascmhl_sizecheck.verify_ascmhl_sizes(manifest)
        assert result.status == "mismatch"
        assert "calc size: 99" in result.detail
        assert "stored size: 100" in result.detail

    def test_missing_file_reported(self, tmp_path):
        """A recorded file absent from disk is reported missing."""
        pkg = tmp_path / "pkg"
        manifest = _build_ascmhl_package(pkg, {"a.mov": 100})
        (pkg / "a.mov").unlink()
        (result,) = ascmhl_sizecheck.verify_ascmhl_sizes(manifest)
        assert result.status == "missing"

    def test_entry_without_size_fails(self, tmp_path):
        """A recorded file with no stored size fails (mirrors simple-mhl -S)."""
        pkg = tmp_path / "pkg"
        ascdir = pkg / "ascmhl"
        ascdir.mkdir(parents=True)
        (pkg / "a.mov").write_bytes(b"x" * 100)
        _write_ascmhl(ascdir / "0001.mhl", [{"size": "", "path": "a.mov", "action": "original", "digest": "aa"}])
        # _write_ascmhl emits size="" — strip it to model a truly absent attribute.
        text = (ascdir / "0001.mhl").read_text().replace(' size=""', "")
        (ascdir / "0001.mhl").write_text(text)
        _write_chain(ascdir, ["0001.mhl"])
        (result,) = ascmhl_sizecheck.verify_ascmhl_sizes(ascdir / "0001.mhl")
        assert result.status == "mismatch"
        assert result.detail == "no size recorded"

    def test_directory_hashes_are_skipped(self, tmp_path):
        """<directoryhash> entries carry no size and must not be size-checked."""
        pkg = tmp_path / "pkg"
        ascdir = pkg / "ascmhl"
        ascdir.mkdir(parents=True)
        (pkg / "a.mov").write_bytes(b"x" * 100)
        (ascdir / "0001.mhl").write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<hashlist version="2.0" xmlns="{_ASCMHL_NAMESPACE}">\n'
            "  <hashes>\n"
            "    <hash>\n"
            '      <path size="100">a.mov</path>\n'
            '      <xxh64 action="original">aa</xxh64>\n'
            "    </hash>\n"
            "    <directoryhash>\n"
            "      <path>subfolder</path>\n"
            "      <content/>\n"
            "      <structure/>\n"
            "    </directoryhash>\n"
            "  </hashes>\n"
            "</hashlist>\n",
            encoding="utf-8",
        )
        _write_chain(ascdir, ["0001.mhl"])
        results = ascmhl_sizecheck.verify_ascmhl_sizes(ascdir / "0001.mhl")
        assert [r.path for r in results] == ["a.mov"]  # subfolder skipped

    def test_original_generation_size_wins(self, tmp_path, write_mhl):
        """A file's expected size is its FIRST-recorded size; later generations don't override."""
        pkg = tmp_path / "pkg"
        ascdir = pkg / "ascmhl"
        ascdir.mkdir(parents=True)
        write_mhl(ascdir, "0001.mhl", [{"path": "a.mov", "size": "100", "action": "original", "digest": "aa"}])
        write_mhl(ascdir, "0002.mhl", [{"path": "a.mov", "size": "200", "action": "verified", "digest": "bb"}])
        _write_chain(ascdir, ["0001.mhl", "0002.mhl"])

        (pkg / "a.mov").write_bytes(b"x" * 100)  # matches the ORIGINAL (gen1) size
        (result,) = ascmhl_sizecheck.verify_ascmhl_sizes(ascdir / "0002.mhl")
        assert result.status == "ok"  # checked against 100 (original), not 200 (gen2)

        (pkg / "a.mov").write_bytes(b"x" * 200)  # gen2's size — must NOT be accepted
        (result,) = ascmhl_sizecheck.verify_ascmhl_sizes(ascdir / "0002.mhl")
        assert result.status == "mismatch"

    def test_renamed_file_not_reported_missing(self, tmp_path, write_mhl):
        """A <previousPath> rename drops the old name and carries the original size forward."""
        pkg = tmp_path / "pkg"
        ascdir = pkg / "ascmhl"
        ascdir.mkdir(parents=True)
        (pkg / "b.mov").write_bytes(b"x" * 100)  # only the renamed (new) name exists on disk
        write_mhl(ascdir, "0001.mhl", [{"path": "a.mov", "size": "100", "action": "original", "digest": "aa"}])
        (ascdir / "0002.mhl").write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<hashlist version="2.0" xmlns="{_ASCMHL_NAMESPACE}">\n'
            "  <hashes>\n"
            "    <hash>\n"
            '      <path size="100">b.mov</path>\n'
            "      <previousPath>a.mov</previousPath>\n"
            '      <xxh64 action="verified">bb</xxh64>\n'
            "    </hash>\n"
            "  </hashes>\n"
            "</hashlist>\n",
            encoding="utf-8",
        )
        _write_chain(ascdir, ["0001.mhl", "0002.mhl"])
        results = ascmhl_sizecheck.verify_ascmhl_sizes(ascdir / "0002.mhl")
        assert {r.path: r.status for r in results} == {"b.mov": "ok"}  # a.mov dropped, not missing

    def test_generation_order_follows_chain_not_filename(self, tmp_path, write_mhl):
        """Original-wins order comes from the chain's sequencenr, even with custom basenames."""
        pkg = tmp_path / "pkg"
        ascdir = pkg / "ascmhl"
        ascdir.mkdir(parents=True)
        # "later.mhl" sorts before "zzz.mhl" by filename, but the chain says zzz is gen 1.
        write_mhl(ascdir, "zzz.mhl", [{"path": "a.mov", "size": "100", "action": "original", "digest": "aa"}])
        write_mhl(ascdir, "later.mhl", [{"path": "a.mov", "size": "200", "action": "verified", "digest": "bb"}])
        _write_chain(ascdir, ["zzz.mhl", "later.mhl"])  # gen1 = zzz (size 100), gen2 = later

        (pkg / "a.mov").write_bytes(b"x" * 100)  # original (zzz) size
        (result,) = ascmhl_sizecheck.verify_ascmhl_sizes(ascdir / "later.mhl")
        assert result.status == "ok"

    def test_traversal_attempt_blocked(self, tmp_path):
        """A manifest path escaping the package root is blocked, never resolved."""
        pkg = tmp_path / "pkg"
        ascdir = pkg / "ascmhl"
        ascdir.mkdir(parents=True)
        _write_ascmhl(
            ascdir / "0001.mhl",
            [{"size": "100", "path": "../../escape.mov", "action": "original", "digest": "aa"}],
        )
        _write_chain(ascdir, ["0001.mhl"])
        (result,) = ascmhl_sizecheck.verify_ascmhl_sizes(ascdir / "0001.mhl")
        assert result.status == "mismatch"
        assert result.detail == "blocked traversal attempt"

    def test_size_phase_runs_when_gate_passes(self, tmp_path, monkeypatch):
        """`ascmhl info` exit 0 -> size phase runs; OK entries are flagged size-only."""
        manifest = _build_ascmhl_package(tmp_path / "pkg", {"a.mov": 100})
        stub_integrity_check(monkeypatch, 0)  # integrity gate passes
        rc, mr = verifyall._verify_ascmhl(manifest, verbose=False, schema=False, size_only=True)
        assert rc == 0
        assert mr is not None
        assert mr.manifest_status == "ok"
        assert mr.n_size_only == 1

    def test_size_mismatch_through_wiring(self, tmp_path, monkeypatch):
        """With the gate passing, a size mismatch yields exit 10 and a failed manifest."""
        pkg = tmp_path / "pkg"
        manifest = _build_ascmhl_package(pkg, {"a.mov": 100})
        (pkg / "a.mov").write_bytes(b"x" * 50)
        stub_integrity_check(monkeypatch, 0)  # gate passes
        rc, mr = verifyall._verify_ascmhl(manifest, verbose=False, schema=False, size_only=True)
        assert rc == 10
        assert mr is not None
        assert mr.manifest_status == "failed"
        assert mr.n_mismatch == 1

    @pytest.mark.parametrize("gate_code", [30, 31, 32, 33])
    def test_integrity_gate_failure_skips_size_checks(self, tmp_path, monkeypatch, gate_code):
        """A non-zero `ascmhl info` (tamper/missing chain or manifest) fails before sizes."""
        manifest = _build_ascmhl_package(tmp_path / "pkg", {"a.mov": 100})
        stub_integrity_check(monkeypatch, gate_code, "Modified ASC MHL manifest in history")
        monkeypatch.setattr(
            verifyall,
            "verify_ascmhl_sizes",
            lambda *a, **k: (_ for _ in ()).throw(AssertionError("size phase must be skipped")),
        )
        rc, mr = verifyall._verify_ascmhl(manifest, verbose=False, schema=False, size_only=True)
        assert rc == gate_code
        assert mr is not None
        assert mr.manifest_status == "error"

    def test_malformed_manifest_is_manifest_error(self, tmp_path, monkeypatch):
        """With the gate passing, a manifest that won't parse becomes a manifest error (exit 20)."""
        ascdir = tmp_path / "pkg" / "ascmhl"
        ascdir.mkdir(parents=True)
        (ascdir / "0001.mhl").write_text("<hashlist><not closed")
        _write_chain(ascdir, ["0001.mhl"])
        stub_integrity_check(monkeypatch, 0)  # gate passes; size phase hits the malformed manifest
        rc, mr = verifyall._verify_ascmhl(ascdir / "0001.mhl", verbose=False, schema=False, size_only=True)
        assert rc == 20
        assert mr is not None
        assert mr.manifest_status == "error"


# ---------------------------------------------------------------------------
# TestAscMhlDispatch
# ---------------------------------------------------------------------------


class TestAscMhlDispatch:
    """ASC-MHL exit-code translation, schema dispatch, and schema=False routing,
    all verified in-process via mhl_suite.ascmhl.verify.
    """

    @pytest.mark.parametrize(
        "exit_code",
        [0, 10, 11, 12, 30, 31, 99],  # documented failures plus an unknown code
    )
    def test_verify_exit_code_propagates(self, ascmhl_setup, monkeypatch, exit_code):
        """verify_package's code is returned unchanged — documented failures and
        unknown codes alike (an unknown code must never be mapped to 0)."""
        entries = (
            []
            if exit_code == 0
            else [FileOutcome(path="f.mxf", status="mismatch", line="ERROR: hash mismatch for f.mxf")]
        )
        stub_verify_package(monkeypatch, exit_code, entries)
        assert call_verify(ascmhl_setup) == exit_code

    def test_schema_check_clean_returns_zero(self, ascmhl_setup, monkeypatch):
        """Both schema checks pass -> exit 0."""
        monkeypatch.setattr(verifyall.ascmhl_verify, "schema_check", lambda *a, **k: (0, []))
        rc = verifyall._ascmhl_schema_check(target=ascmhl_setup, verbose=False)
        assert rc == 0

    def test_schema_check_manifest_failure_takes_precedence(self, ascmhl_setup, monkeypatch):
        """If the manifest fails schema check, that code wins over the chain's."""
        calls = {"n": 0}

        def _stub(file_path, *, directory_file=False):
            calls["n"] += 1
            # first call is the manifest, second is the chain
            return (11, ["manifest failed"]) if calls["n"] == 1 else (0, [])

        monkeypatch.setattr(verifyall.ascmhl_verify, "schema_check", _stub)
        rc = verifyall._ascmhl_schema_check(target=ascmhl_setup, verbose=False)
        assert rc == 11

    def test_dispatch_table_covers_all_known_codes(self):
        """The ASC-MHL verify dispatch table must cover every verify exit code
        ascmhl/errors.py defines, so we never fall through to the 'unexpected
        exit' branch for a documented failure. (127 was the subprocess
        command-not-found code and no longer applies now that verify is in-process.)"""
        documented_codes = {0, 10, 11, 12, 20, 21, 30, 31, 32, 33}
        missing = documented_codes - set(verifyall._ASCMHL_VERIFY_RESULTS.keys())
        assert missing == set(), f"Dispatch table missing codes: {missing}"

    def test_ascmhl_failure_detail_shown_on_terminal(self, ascmhl_setup, monkeypatch, capsys):
        """A failure's per-file detail (rendered from the structured report) is
        shown on the terminal so the operator sees what went wrong."""
        entries = [FileOutcome(path="b.mxf", status="mismatch", line="ERROR: hash mismatch for b.mxf")]
        stub_verify_package(monkeypatch, 11, entries)
        # The orchestrator is print-free; the CLI sink (_render_status) does the printing.
        verifyall._ascmhl_verify(target=ascmhl_setup, verbose=False, emit=mhlver._render_status)
        assert "hash mismatch for b.mxf" in capsys.readouterr().err

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
    """Classic MHL is verified in-process via the core engine. These pin
    exit-code propagation, manifest-status derivation, size-only flagging, and
    schema-check dispatch — with verify_manifest / schema_report stubbed so the
    tests don't depend on real hashing or the filesystem."""

    @pytest.fixture
    def classic_mhl(self, tmp_path):
        """A path for a classic manifest. The engine is stubbed per test, so the
        file contents are irrelevant."""
        mhl = tmp_path / "dummy.mhl"
        mhl.write_text("")
        return mhl

    @staticmethod
    def _stub_verify(monkeypatch, report):
        monkeypatch.setattr(verifyall, "verify_manifest", lambda *a, **kw: report)

    @pytest.mark.parametrize("exit_code", [0, 20, 30, 40, 70])
    def test_verify_classicmhl_exit_code_propagates(self, classic_mhl, monkeypatch, exit_code):
        """The engine's report code is returned unchanged by _verify_classicmhl."""
        if exit_code == 20:
            report = VerifyReport(code=20, malformed=True)
        else:
            entries = (
                []
                if exit_code == 0
                else [FileOutcome(path="f.mxf", status="mismatch", line="[ERROR] hash mismatch: f.mxf")]
            )
            report = VerifyReport(entries=entries, code=exit_code)
        self._stub_verify(monkeypatch, report)
        rc, _mr = verifyall._verify_classicmhl(target=classic_mhl, verbose=False, schema=False)
        assert rc == exit_code

    def test_manifest_status_is_failed_when_entries_present(self, classic_mhl, monkeypatch):
        """A non-zero code WITH per-file outcomes yields manifest_status 'failed'."""
        report = VerifyReport(
            entries=[FileOutcome(path="f.mxf", status="mismatch", detail="hash mismatch")],
            code=40,
        )
        self._stub_verify(monkeypatch, report)
        rc, mr = verifyall._verify_classicmhl(target=classic_mhl, verbose=False, schema=False)
        assert rc == 40
        assert mr is not None
        assert mr.manifest_status == "failed"

    def test_manifest_status_is_error_on_malformed(self, classic_mhl, monkeypatch):
        """Malformed XML (no per-file outcomes) yields manifest_status 'error'."""
        self._stub_verify(monkeypatch, VerifyReport(code=20, malformed=True))
        rc, mr = verifyall._verify_classicmhl(target=classic_mhl, verbose=False, schema=False)
        assert rc == 20
        assert mr is not None
        assert mr.manifest_status == "error"

    def test_size_only_is_passed_through_and_flagged(self, classic_mhl, monkeypatch):
        """size_only reaches verify_manifest and OK results carry the size-only flag."""
        seen: dict[str, bool] = {}

        def _stub(mhl_file, *, size_only=False, on_progress=None):
            seen["size_only"] = size_only
            return VerifyReport(
                entries=[FileOutcome(path="clip.mxf", status="ok", size_only=True, line="[OK] clip.mxf  size: 4170")],
                code=0,
            )

        monkeypatch.setattr(verifyall, "verify_manifest", _stub)
        rc, mr = verifyall._verify_classicmhl(target=classic_mhl, verbose=False, schema=False, size_only=True)
        assert rc == 0
        assert seen["size_only"] is True
        assert mr is not None
        assert mr.n_size_only == 1

    def test_verify_classicmhl_dispatch_table_covers_engine_codes(self):
        """_CLASSICMHL_RESULTS must cover every exit code the classic engine emits."""
        engine_codes = {0, 20, 30, 40, 70}
        missing = engine_codes - set(verifyall._CLASSICMHL_RESULTS.keys())
        assert missing == set(), f"Dispatch table missing codes: {missing}"

    def test_schema_uses_classicmhl_schema_results_table(self, classic_mhl, monkeypatch, capsys):
        """Schema mode runs schema_report and maps the code via
        _CLASSICMHL_SCHEMA_RESULTS — exit 60 has a specific 'schema' message."""
        monkeypatch.setattr(verifyall, "schema_report", lambda mhl_file: (60, ["Error: could not locate XSD"]))
        rc, _mr = verifyall._verify_classicmhl(classic_mhl, verbose=False, schema=True, emit=mhlver._render_status)
        assert rc == 60
        captured = capsys.readouterr()
        assert "schema" in (captured.out + captured.err).lower()


# ---------------------------------------------------------------------------
# TestLogHelpers
# ---------------------------------------------------------------------------


class TestLogHelpers:
    """Unit tests for _log and _emit_step_output."""

    def test_log_routes_through_console(self, capsys):
        """When a console object is passed, _log uses console.print, not print()."""
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


# ---------------------------------------------------------------------------
# TestReportViaTable
# ---------------------------------------------------------------------------


class TestReportViaTable:
    """Tests for _report_via_table edge cases."""

    def test_suppressed_success_is_silent(self, capsys):
        """When show_status_on_terminal=False and exit=0, the success line is
        suppressed entirely (the silent-progress-bar path)."""
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
        """Errors must always appear on the terminal regardless of
        show_status_on_terminal, because operators need immediate visibility."""
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
# TestVerifyItem
# ---------------------------------------------------------------------------


class TestVerifyItem:
    """Tests for verify_item dispatch logic."""

    def test_dispatches_to_ascmhl_for_ascmhl_path(self, tmp_path, monkeypatch):
        """A path containing 'ascmhl' in its parts routes to _verify_ascmhl."""
        called = {}

        def _stub(target, verbose, schema, **kw):
            called["ascmhl"] = True
            return 0

        monkeypatch.setattr(verifyall, "_verify_ascmhl", _stub)
        ascmhl_dir = tmp_path / "pkg" / "ascmhl"
        ascmhl_dir.mkdir(parents=True)
        manifest = ascmhl_dir / "0001.mhl"
        manifest.write_text("")
        mhlver.verify_item(manifest, verbose=False, schema=False)
        assert called.get("ascmhl") is True

    def test_dispatches_to_classicmhl_for_plain_mhl(self, tmp_path, monkeypatch):
        """A plain .mhl path routes to _verify_classicmhl."""
        called = {}

        def _stub(target, verbose, schema, **kw):
            called["classicmhl"] = True
            return 0

        monkeypatch.setattr(verifyall, "_verify_classicmhl", _stub)
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        mhlver.verify_item(mhl, verbose=False, schema=False)
        assert called.get("classicmhl") is True


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
        """Passing a path that doesn't exist must exit 2 with an error message."""
        rc, _, err = mhlver_cli(["/nonexistent/path/ghost.mhl"])
        assert rc == 2
        assert "file or directory" in err.lower() or "exist" in err.lower()

    def test_nonexistent_path_suggests_normalization_variant(self, mhlver_cli, monkeypatch):
        """When the typed path is missing but a Unicode-normalization variant
        exists, mhlver appends a 'did you mean' hint — parity with simple-mhl
        via the shared unicodepaths helper. The helper is stubbed here; its own
        resolution logic is covered by the simple-mhl test suite."""
        monkeypatch.setattr(mhlver, "normalization_variant_on_disk", lambda p: "/vol/rosé_nfd.mhl")
        rc, _, err = mhlver_cli(["/vol/rosé_nfc.mhl"])
        assert rc == 2
        assert "did you mean" in err.lower()
        assert "rosé_nfd.mhl" in err

    def test_nonexistent_path_no_variant_is_plain_error(self, mhlver_cli, monkeypatch):
        """A genuine typo (no normalization variant) gives the plain error, no hint."""
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

    def test_report_not_created_when_no_manifests_found(self, mhlver_cli, monkeypatch, tmp_path):
        """An empty directory leaves no report log behind."""
        monkeypatch.setattr(mhlver, "_run", lambda *a, **kw: (0, [], False))
        rc, out, _ = mhlver_cli(["--report", str(tmp_path)])
        assert rc == 0
        assert list(tmp_path.glob("mhlver_report_*.log")) == []
        assert "report saved to" not in out

    def test_version_flag_exits_0(self, mhlver_cli):
        """--version prints the version string and exits 0."""
        rc, out, _ = mhlver_cli(["--version"])
        assert rc == 0
        assert out.strip() != ""


# ---------------------------------------------------------------------------
# TestManifestResultCounts
# ---------------------------------------------------------------------------


class TestManifestResultCounts:
    """The n_* convenience properties on ManifestResult tally file_results by
    status; verify each counts only its own status."""

    def test_counts_by_status(self):
        mr = mhlver.ManifestResult(
            manifest_path=Path("m.mhl"),
            manifest_status="failed",
            file_results=[
                mhlver.FileResult(path="a", status="ok"),
                mhlver.FileResult(path="b", status="ok"),
                mhlver.FileResult(path="c", status="missing"),
                mhlver.FileResult(path="d", status="mismatch"),
                mhlver.FileResult(path="e", status="new"),
                mhlver.FileResult(path="f", status="error"),
            ],
        )
        assert mr.n_ok == 2
        assert mr.n_missing == 1
        assert mr.n_mismatch == 1
        assert mr.n_new == 1
        assert mr.n_error == 1
        assert mr.n_files == 6

    def test_empty_results_are_all_zero(self):
        mr = mhlver.ManifestResult(manifest_path=Path("m.mhl"), manifest_status="ok")
        assert (mr.n_ok, mr.n_missing, mr.n_mismatch, mr.n_new, mr.n_error, mr.n_files) == (0, 0, 0, 0, 0, 0)


# ---------------------------------------------------------------------------
# TestRenderReportDetails
# ---------------------------------------------------------------------------


class TestRenderReportDetails:
    """_render_report is a pure fn writing to a file handle. The TestRun cases
    only feed it empty/all-OK results, leaving the per-status summary appends,
    the Details section, and the manifest-error line uncovered. Here we feed it
    populated ManifestResults to exercise those branches."""

    def _render(self, manifest_results, exit_status):
        buf = io.StringIO()
        now = mhlver.datetime.now()
        mhlver._render_report(buf, Path("/src"), now, now, manifest_results, exit_status)
        return buf.getvalue()

    def test_summary_lists_each_nonzero_status(self):
        """A manifest with one of every failing status produces a summary line
        naming missing / hash mismatch / error / new counts."""
        mr = mhlver.ManifestResult(
            manifest_path=Path("m.mhl"),
            manifest_status="failed",
            file_results=[
                mhlver.FileResult(path="ok.mxf", status="ok"),
                mhlver.FileResult(path="gone.mxf", status="missing"),
                mhlver.FileResult(path="bad.mxf", status="mismatch"),
                mhlver.FileResult(path="boom.mxf", status="error", detail="boom"),
                mhlver.FileResult(path="extra.mxf", status="new"),
            ],
        )
        out = self._render([mr], exit_status=40)

        assert "❌ FAILED" in out
        assert "1 missing" in out
        assert "1 hash mismatch" in out
        assert "1 error" in out
        assert "1 new (untracked)" in out
        # Manifest section is rendered for a non-empty result set (singular
        # header for a single manifest).
        assert "Manifest\n" in out
        assert "📄 m.mhl" in out
        # Per-file lines come from _format_file_result.
        assert "gone.mxf" in out
        assert "extra.mxf" in out

    def test_summary_all_size_only_verdict(self):
        """All-size-only: the global summary is downgraded to a warning while the
        per-manifest line keeps the plain ✅ VERIFIED prefix."""
        mr = mhlver.ManifestResult(
            manifest_path=Path("m.mhl"),
            manifest_status="ok",
            file_results=[
                mhlver.FileResult(path="a.mxf", status="ok", size_only=True),
                mhlver.FileResult(path="b.mxf", status="ok", size_only=True),
            ],
        )
        out = self._render([mr], exit_status=0)
        assert "⚠️ VERIFIED WITH WARNINGS (SIZE-ONLY CHECKS)" in out  # global summary
        assert "✅ VERIFIED (SIZE-ONLY CHECKS)" in out  # per-manifest, unchanged
        assert "PARTIAL" not in out

    def test_summary_partial_size_only_verdict(self):
        """Partial size-only: global downgraded to a warning, per-manifest stays plain."""
        mr = mhlver.ManifestResult(
            manifest_path=Path("m.mhl"),
            manifest_status="ok",
            file_results=[
                mhlver.FileResult(path="a.mxf", status="ok"),
                mhlver.FileResult(path="b.mxf", status="ok", size_only=True),
            ],
        )
        out = self._render([mr], exit_status=0)
        assert "⚠️ VERIFIED WITH WARNINGS (SOME SIZE-ONLY CHECKS)" in out  # global
        assert "✅ VERIFIED (SOME SIZE-ONLY CHECKS)" in out  # per-manifest

    def test_summary_no_size_only_is_plain_verified(self):
        """A fully hash-verified manifest keeps the plain VERIFIED verdict."""
        mr = mhlver.ManifestResult(
            manifest_path=Path("m.mhl"),
            manifest_status="ok",
            file_results=[mhlver.FileResult(path="a.mxf", status="ok")],
        )
        out = self._render([mr], exit_status=0)
        assert "✅ VERIFIED" in out
        assert "SIZE-ONLY" not in out

    def test_summary_existence_only_verdict_is_labelled_distinctly(self):
        """An existence-only entry (null, no <size>) downgrades the global verdict to a
        warning and is labelled EXISTENCE-ONLY — never SIZE-ONLY, since no size was checked."""
        mr = mhlver.ManifestResult(
            manifest_path=Path("m.mhl"),
            manifest_status="ok",
            file_results=[
                mhlver.FileResult(path="a.mxf", status="ok"),
                mhlver.FileResult(path="b.mxf", status="ok", existence_only=True),
            ],
        )
        out = self._render([mr], exit_status=0)
        assert "⚠️ VERIFIED WITH WARNINGS (SOME EXISTENCE-ONLY CHECKS)" in out  # global
        assert "✅ VERIFIED (SOME EXISTENCE-ONLY CHECKS)" in out  # per-manifest
        assert "SIZE-ONLY" not in out

    def test_summary_mixed_size_and_existence_only_names_both(self):
        """When a run mixes size-only and existence-only entries, the verdict names both."""
        mr = mhlver.ManifestResult(
            manifest_path=Path("m.mhl"),
            manifest_status="ok",
            file_results=[
                mhlver.FileResult(path="a.mxf", status="ok", size_only=True),
                mhlver.FileResult(path="b.mxf", status="ok", existence_only=True),
            ],
        )
        out = self._render([mr], exit_status=0)
        assert "⚠️ VERIFIED WITH WARNINGS (SIZE-ONLY AND EXISTENCE-ONLY CHECKS)" in out

    def test_manifest_level_error_renders_error_line(self):
        """A manifest whose own status is 'error' prints the manifest error and
        skips per-file rendering."""
        mr = mhlver.ManifestResult(
            manifest_path=Path("broken.mhl"),
            manifest_status="error",
            manifest_error="could not read manifest",
        )
        out = self._render([mr], exit_status=20)
        assert "📄 broken.mhl" in out
        assert "could not read manifest" in out

    def test_manifest_error_falls_back_to_default_text(self):
        """When manifest_status is 'error' but no message was attached, a generic
        label is printed instead."""
        mr = mhlver.ManifestResult(
            manifest_path=Path("broken.mhl"),
            manifest_status="error",
            manifest_error="",
        )
        out = self._render([mr], exit_status=20)
        assert "manifest-level error" in out

    def test_header_carries_provenance_fields(self):
        """The header records tool, host, user, source, and the start/finish
        window that anchor a fixity record for archival."""
        out = self._render([], exit_status=0)
        for label in ("Tool:", "Host:", "User:", "Source:", "Started:", "Finished:"):
            assert label in out

    def test_operator_falls_back_when_lookup_fails(self, monkeypatch):
        """Environments that can't resolve a username must not crash the report."""
        monkeypatch.setattr("getpass.getuser", lambda: (_ for _ in ()).throw(OSError()))
        out = self._render([], exit_status=0)
        assert "User:       unknown" in out

    def test_issues_section_collects_non_ok_across_manifests(self):
        """The Issues section surfaces every non-OK entry — including new/untracked
        warnings and manifest-level errors — pulled above the per-manifest Manifests section."""
        good = mhlver.ManifestResult(
            manifest_path=Path("good.mhl"),
            manifest_status="ok",
            file_results=[mhlver.FileResult(path="ok.mxf", status="ok")],
        )
        bad = mhlver.ManifestResult(
            manifest_path=Path("bad.mhl"),
            manifest_status="failed",
            file_results=[
                mhlver.FileResult(path="bad.mxf", status="mismatch"),
                mhlver.FileResult(path="extra.mxf", status="new"),
            ],
        )
        broken = mhlver.ManifestResult(
            manifest_path=Path("broken.mhl"),
            manifest_status="error",
            manifest_error="parse failed",
        )
        out = self._render([good, bad, broken], exit_status=40)
        issues = out.split("Issues", 1)[1].split("Manifests", 1)[0]
        assert "bad.mxf" in issues
        assert "extra.mxf" in issues  # new/untracked included
        assert "parse failed" in issues  # manifest-level error included
        assert "ok.mxf" not in issues  # clean entries stay out

    def test_issues_section_omitted_when_all_ok(self):
        """No Issues heading when every file passed."""
        mr = mhlver.ManifestResult(
            manifest_path=Path("m.mhl"),
            manifest_status="ok",
            file_results=[mhlver.FileResult(path="ok.mxf", status="ok")],
        )
        out = self._render([mr], exit_status=0)
        assert "Issues" not in out

    def test_per_manifest_sub_summary_line(self):
        """Each manifest header is followed by its own verdict line; new/untracked
        is a warning and does not flip the manifest to FAILED."""
        mr = mhlver.ManifestResult(
            manifest_path=Path("m.mhl"),
            manifest_status="ok",
            file_results=[
                mhlver.FileResult(path="ok.mxf", status="ok"),
                mhlver.FileResult(path="extra.mxf", status="new"),
            ],
        )
        details = self._render([mr], exit_status=0).split("Manifest\n", 1)[1]
        assert "📄 m.mhl" in details
        assert "✅ VERIFIED | 2 files | 1 verified | 1 new (untracked)" in details


# ---------------------------------------------------------------------------
# TestFormatFileResult
# ---------------------------------------------------------------------------


class TestFormatFileResult:
    """_format_file_result is a pure status→string mapper; cover every arm."""

    def test_ok(self):
        out = mhlver._format_file_result(mhlver.FileResult(path="f.mxf", status="ok"))
        assert "✓" in out
        assert "f.mxf" in out

    def test_missing(self):
        out = mhlver._format_file_result(mhlver.FileResult(path="f.mxf", status="missing"))
        assert "missing" in out
        assert "f.mxf" in out

    def test_mismatch_with_verbose_detail_splits_label_and_parenthetical(self):
        fr = mhlver.FileResult(path="f.mxf", status="mismatch", detail="hash mismatch: calc a | stored b")
        out = mhlver._format_file_result(fr)
        assert "hash mismatch: f.mxf" in out
        assert "(calc a | stored b)" in out

    def test_mismatch_without_detail_uses_fallback(self):
        fr = mhlver.FileResult(path="f.mxf", status="mismatch", detail="size mismatch")
        out = mhlver._format_file_result(fr)
        assert "size mismatch: f.mxf" in out
        assert "\n" not in out  # no parenthetical second line

    def test_new(self):
        out = mhlver._format_file_result(mhlver.FileResult(path="f.mxf", status="new"))
        assert "new (untracked)" in out
        assert "f.mxf" in out

    def test_error_with_detail(self):
        fr = mhlver.FileResult(path="f.mxf", status="error", detail="boom")
        out = mhlver._format_file_result(fr)
        assert "error" in out
        assert "f.mxf" in out
        assert "(boom)" in out

    def test_error_without_detail(self):
        out = mhlver._format_file_result(mhlver.FileResult(path="f.mxf", status="error"))
        assert "error" in out
        assert "f.mxf" in out
        assert "\n" not in out  # no detail line


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
    """Build a well-formed ASC-MHL 2.0 manifest (correct namespace + structure)
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
    """Schema-shaped value fuzzing of the byte-counting helpers that parse
    manifest XML directly (no external backend needed). For any well-formed,
    XSD-shaped manifest with adversarial typed values, the helpers must return a
    non-negative int and never raise — they are called while building the
    progress bar, so a crash there aborts an otherwise-fine verify run."""

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
    """Locks the single-pass property: a default (non-verbose) ASC-MHL verify
    hashes the package exactly once. verify_package is the sole hashing pass now
    (the old code shelled out to ascmhl-debug twice — once -v for the report, once
    plain for the terminal — re-hashing everything), so a regression that
    reintroduced a second pass would call verify_package more than once. (Classic
    MHL is in-process too; see TestClassicMhlDispatch.)"""

    def test_ascmhl_verify_invokes_engine_once(self, monkeypatch, tmp_path):
        calls = {"n": 0}

        def _spy(root_path, *, on_progress=None):
            calls["n"] += 1
            return verifyall.ascmhl_verify.AscVerifyReport(entries=[], code=0)

        monkeypatch.setattr(verifyall.ascmhl_verify, "verify_package", _spy)
        pkg = tmp_path / "ascmhl"
        pkg.mkdir()
        target = pkg / "0001.mhl"
        target.write_text("<x/>")

        verifyall._ascmhl_verify(target, verbose=False)

        assert calls["n"] == 1, f"expected 1 hashing pass, got {calls['n']}"
