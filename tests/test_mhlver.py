#!/usr/bin/env python3
"""Test suite for mhlver.py orchestrator and ASC-MHL dispatch."""

import io
import os
import sys
import tempfile
import threading
from collections import Counter
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from hypothesis import HealthCheck, assume, given, settings, strategies

from mhl_suite import mhlver

# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

_ASCMHL_NAMESPACE = "urn:ASC:MHL:v2.0"

# Windows reserves these device names at every extension; attempting to create
# e.g. CON.mhl on Windows raises PermissionError / FileNotFoundError.
_WINDOWS_RESERVED_NAMES = ["CON", "PRN", "AUX", "NUL", "COM1", "COM2", "LPT1", "LPT2"]

# Hypothesis strategy for valid filename stems: ASCII letters and digits only,
# no leading dots (avoids the ._ resource-fork filter), no path separators.
_filename_stem = strategies.text(
    alphabet=strategies.characters(
        whitelist_categories=("Ll", "Lu", "Nd"),
        whitelist_characters="_-",
    ),
    min_size=1,
    max_size=20,
).filter(lambda s: not s.startswith("._") and s.strip())

_generations_per_pkg = strategies.integers(min_value=1, max_value=4)


def _write_ascmhl(path: Path, entries: list[dict]) -> None:
    """Write a minimal ASC-MHL 2.0 generation file to *path*.

    Each entry dict must have "path", "size", "action", and "digest" keys.
    Used by the Unicode-guard tests that need to craft specific size attributes
    without going through the write_mhl conftest fixture (which only writes
    well-formed decimal sizes).
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


def stub_run_step(monkeypatch, exit_code: int, output: str = ""):
    """Replace _run_step with a stub that returns a fixed StepResult."""

    def _stub(cmd, cwd=None, **kwargs):
        return mhlver.StepResult(exit_code=exit_code, output=output)

    monkeypatch.setattr(mhlver, "_run_step", _stub)


def call_verify(manifest):
    """Invoke _ascmhl_verify with sane defaults and return its exit code."""

    rc, _mr = mhlver._ascmhl_verify(
        target=manifest,
        cmd_path="/fake/ascmhl-debug",
        cwd=None,
        verbose=False,
    )
    return rc


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

    def test_dot_underscore_filter_applies_only_to_filename_not_parent_dir(self, tmp_path):
        """Files inside a directory named '._hidden' must NOT be excluded.

        The macOS resource-fork filter checks p.name (the file's own name),
        not any parent directory component.
        """
        hidden_dir = tmp_path / "._hidden"
        hidden_dir.mkdir()
        (hidden_dir / "valid.mhl").write_text("")
        (tmp_path / "._resource.mhl").write_text("")

        found = list(mhlver.find_mhl_files(tmp_path))
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

        found_names = {p.name for p in mhlver.find_mhl_files(tmp_path)}
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

        found_names = {p.name for p in mhlver.find_mhl_files(tmp_path)}
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

            selected = mhlver._select_mhl_files(root)
            assert len(selected) == len(mhl_names), (
                f"Expected {len(mhl_names)} loose files, got {len(selected)}: {[p.name for p in selected]}"
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
        assert mhlver._ascmhl_total_bytes(ascdir / "0001.mhl") == 223591 + 329746

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
        assert mhlver._ascmhl_total_bytes(ascdir / "0002.mhl") == 223591 + 329746

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
        assert mhlver._ascmhl_total_bytes(ascdir / "0002.mhl") == 1_811_635

    def test_ascmhl_from_shotputpro_single_generation_with_directory_hashes(self, tmp_path, load_fixture_mhl):
        """ShotPut Pro ASC-MHL

        Expected total: 2246896176 + 4170 + 15758019120 + 4172 = 18_004_923_638
        """
        ascdir = tmp_path / "ascmhl"
        ascdir.mkdir()
        mhl = load_fixture_mhl(ascdir, "shotputpro_ascmhl_example.mhl")
        assert mhlver._ascmhl_total_bytes(mhl) == 18_004_923_638

    def test_ascmhl_from_silverstack_single_generation_with_directory_hashes(self, tmp_path, load_fixture_mhl):
        """Silverstack Lab ASC-MHL

        Expected total: 2246896176 + 4170 + 15758019120 + 4172 = 18_004_923_638
        """
        ascdir = tmp_path / "ascmhl"
        ascdir.mkdir()
        mhl = load_fixture_mhl(ascdir, "shotputpro_ascmhl_example.mhl")
        assert mhlver._ascmhl_total_bytes(mhl) == 18_004_923_638

    def test_ascmhl_from_ocopy_in_place_single_generation(self, tmp_path, load_fixture_mhl):
        """o/COPY ASC-MHL

        Expected total: 436085 + 2775033 + 161713671 = 164_924_789
        """
        ascdir = tmp_path / "ascmhl"
        ascdir.mkdir()
        mhl = load_fixture_mhl(ascdir, "ocopy_ascmhl_example.mhl")
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
        assert mhlver._ascmhl_total_bytes(ascdir / "0002.mhl") == 1000000

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
        assert mhlver._ascmhl_total_bytes(ascdir / "0002.mhl") == 100

    def test_superscript_size_attr_is_ignored_and_sibling_entry_counted(self, tmp_path):
        """A superscript-digit size attribute ('²') is rejected by isdecimal()
        and the sibling entry with a valid decimal size IS counted.

        Before the fix (isdigit guard): '²' passed the guard, int('²') raised
        ValueError, and the outer except dropped the ENTIRE generation — the
        500-byte sibling was also lost.

        After the fix (isdecimal guard): '²'.isdecimal() is False, the guard
        skips that entry cleanly, and the loop continues to count the 500-byte
        sibling.
        """
        ascdir = tmp_path / "ascmhl"
        ascdir.mkdir()
        mhl = ascdir / "0001.mhl"
        mhl.write_text(
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<hashlist version="2.0" xmlns="{_ASCMHL_NAMESPACE}">\n'
            "  <hashes>\n"
            "    <hash>\n"
            '      <path size="\u00b2" lastmodificationdate="2026-01-01T00:00:00+00:00">'
            "superscript_file.mov</path>\n"
            '      <xxh64 action="original" hashdate="2026-01-01T00:00:00+00:00">aabb</xxh64>\n'
            "    </hash>\n"
            "    <hash>\n"
            '      <path size="500" lastmodificationdate="2026-01-01T00:00:00+00:00">'
            "good_file.mov</path>\n"
            '      <xxh64 action="original" hashdate="2026-01-01T00:00:00+00:00">ccdd</xxh64>\n'
            "    </hash>\n"
            "  </hashes>\n"
            "</hashlist>\n",
            encoding="utf-8",
        )
        assert mhlver._ascmhl_total_bytes(mhl) == 500

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
        assert mhlver._ascmhl_total_bytes(ascdir / "0002.mhl") == 1000

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
        assert mhlver._ascmhl_total_bytes(mhl) == 100


# ---------------------------------------------------------------------------
# TestAscMhlDispatch
# ---------------------------------------------------------------------------


class TestAscMhlDispatch:
    """ASC-MHL exit-code translation, schema dispatch, schema=False routing,
    output visibility, and command-not-found (127).
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
        )
        assert rc == 0

    def test_schema_check_manifest_failure_takes_precedence(self, ascmhl_setup, monkeypatch):
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
        )

        captured = capsys.readouterr()
        assert "ERROR: no MHL history found" in captured.err

    def test_ascmhl_backend_output_also_shown_with_verbose(self, ascmhl_setup, capsys, monkeypatch):
        """With --verbose, ascmhl's output is also shown on terminal."""
        stub_run_step(monkeypatch, 30, "ERROR: no MHL history found at /pkg")

        mhlver._ascmhl_verify(
            target=ascmhl_setup,
            cmd_path="/fake/ascmhl-debug",
            cwd=None,
            verbose=True,
        )

        captured = capsys.readouterr()
        assert "ERROR: no MHL history found" in captured.err

    def test_schema_false_dispatches_to_ascmhl_verify(self, ascmhl_setup, monkeypatch):
        """schema=False routes to _ascmhl_verify; _ascmhl_schema_check is never called."""
        monkeypatch.setattr(mhlver, "get_command_path", lambda cmd: "/fake/ascmhl-debug")

        called = {}

        def _stub_verify(target, cmd_path, cwd, verbose, **kw):
            called["verify"] = True
            return 0, None

        def _stub_schema(target, cmd_path, cwd, verbose, **kw):
            called["schema"] = True
            return 0

        monkeypatch.setattr(mhlver, "_ascmhl_verify", _stub_verify)
        monkeypatch.setattr(mhlver, "_ascmhl_schema_check", _stub_schema)

        rc, _mr = mhlver._verify_ascmhl(ascmhl_setup, verbose=False, schema=False)

        assert called.get("verify") is True, "_ascmhl_verify was not called"
        assert "schema" not in called, "_ascmhl_schema_check must not be called"
        assert rc == 0

    def test_schema_false_return_value_is_propagated(self, ascmhl_setup, monkeypatch):
        """The exit code from _ascmhl_verify is returned unchanged."""
        monkeypatch.setattr(mhlver, "get_command_path", lambda cmd: "/fake/ascmhl-debug")
        monkeypatch.setattr(mhlver, "_ascmhl_verify", lambda *a, **kw: (11, None))
        rc, _mr = mhlver._verify_ascmhl(ascmhl_setup, verbose=False, schema=False)
        assert rc == 11

    def test_command_not_found_returns_127(self, ascmhl_setup, monkeypatch):
        """When ascmhl-debug is not found, _verify_ascmhl returns 127."""
        monkeypatch.setattr(mhlver, "get_command_path", lambda cmd: None)
        rc, _mr = mhlver._verify_ascmhl(ascmhl_setup, verbose=False, schema=False)
        assert rc == 127

    def test_schema_true_dispatches_to_ascmhl_schema_check(self, ascmhl_setup, monkeypatch):
        """With schema=True, _verify_ascmhl calls _ascmhl_schema_check."""
        monkeypatch.setattr(mhlver, "get_command_path", lambda cmd: "/fake/ascmhl-debug")
        called = {}

        def _stub_schema_check(target, cmd_path, cwd, verbose, **kw):
            called["yes"] = True
            return 0

        monkeypatch.setattr(mhlver, "_ascmhl_schema_check", _stub_schema_check)
        rc, _mr = mhlver._verify_ascmhl(ascmhl_setup, verbose=False, schema=True)
        assert called.get("yes") is True
        assert rc == 0


# ---------------------------------------------------------------------------
# TestClassicMhlDispatch
# ---------------------------------------------------------------------------


class TestClassicMhlDispatch:
    """MHL v1 exit-code translation, verbose/schema flags, dispatch table, and command-not-found.

    Both get_command_path and _run_step are patched so no real subprocess
    is spawned and tests are independent of the installed environment.
    """

    def test_verify_classicmhl_clean_returns_zero(self, tmp_path, monkeypatch):
        """Exit 0 from simple-mhl -> _verify_classicmhl returns 0."""
        mhl = tmp_path / "dummy.mhl"
        mhl.write_text("")
        monkeypatch.setattr(mhlver, "get_command_path", lambda _: Path("/fake/simple-mhl"))
        stub_run_step(monkeypatch, 0)
        rc, _mr = mhlver._verify_classicmhl(
            target=mhl,
            verbose=False,
            schema=False,
        )
        assert rc == 0

    def test_verify_classicmhl_invalid_argument_propagates_1(self, tmp_path, monkeypatch):
        """Exit 1 from simple-mhl (bad argument) -> _verify_classicmhl returns 1."""
        mhl = tmp_path / "dummy.mhl"
        mhl.write_text("")
        monkeypatch.setattr(mhlver, "get_command_path", lambda _: Path("/fake/simple-mhl"))
        stub_run_step(monkeypatch, 1, "Verification Error: not an MHL file")
        rc, _mr = mhlver._verify_classicmhl(
            target=mhl,
            verbose=False,
            schema=False,
        )
        assert rc == 1

    def test_verify_classicmhl_malformed_xml_propagates_20(self, tmp_path, monkeypatch):
        """Exit 20 from simple-mhl (malformed XML) -> _verify_classicmhl returns 20."""
        mhl = tmp_path / "dummy.mhl"
        mhl.write_text("")
        monkeypatch.setattr(mhlver, "get_command_path", lambda _: Path("/fake/simple-mhl"))
        stub_run_step(monkeypatch, 20, "Malformed XML")
        rc, _mr = mhlver._verify_classicmhl(
            target=mhl,
            verbose=False,
            schema=False,
        )
        assert rc == 20

    def test_verify_classicmhl_missing_files_propagates_30(self, tmp_path, monkeypatch):
        """Exit 30 from simple-mhl (missing files) -> _verify_classicmhl returns 30."""
        mhl = tmp_path / "dummy.mhl"
        mhl.write_text("")
        monkeypatch.setattr(mhlver, "get_command_path", lambda _: Path("/fake/simple-mhl"))
        stub_run_step(monkeypatch, 30)
        rc, _mr = mhlver._verify_classicmhl(
            target=mhl,
            verbose=False,
            schema=False,
        )
        assert rc == 30

    def test_verify_classicmhl_hash_mismatch_propagates_40(self, tmp_path, monkeypatch):
        """Exit 40 from simple-mhl (hash mismatch) -> _verify_classicmhl returns 40."""
        mhl = tmp_path / "dummy.mhl"
        mhl.write_text("")
        monkeypatch.setattr(mhlver, "get_command_path", lambda _: Path("/fake/simple-mhl"))
        stub_run_step(monkeypatch, 40)
        rc, _mr = mhlver._verify_classicmhl(
            target=mhl,
            verbose=False,
            schema=False,
        )
        assert rc == 40

    def test_verify_classicmhl_both_failures_propagates_70(self, tmp_path, monkeypatch):
        """Exit 70 from simple-mhl (missing + mismatch) -> _verify_classicmhl returns 70."""
        mhl = tmp_path / "dummy.mhl"
        mhl.write_text("")
        monkeypatch.setattr(mhlver, "get_command_path", lambda _: Path("/fake/simple-mhl"))
        stub_run_step(monkeypatch, 70)
        rc, _mr = mhlver._verify_classicmhl(
            target=mhl,
            verbose=False,
            schema=False,
        )
        assert rc == 70

    def test_verify_classicmhl_dispatch_table_covers_all_known_codes(self):
        """_CLASSICMHL_RESULTS must cover every exit code simple-mhl can emit."""
        documented_codes = {0, 1, 20, 30, 40, 70, 127}
        missing = documented_codes - set(mhlver._CLASSICMHL_RESULTS.keys())
        assert missing == set(), f"Dispatch table missing codes: {missing}"

    def test_command_not_found_returns_127(self, tmp_path, monkeypatch):
        """When simple-mhl is not found, _verify_classicmhl returns 127."""
        monkeypatch.setattr(mhlver, "get_command_path", lambda cmd: None)
        mhl = tmp_path / "dummy.mhl"
        mhl.write_text("")
        rc, _mr = mhlver._verify_classicmhl(mhl, verbose=False, schema=False)
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
        mhlver._verify_classicmhl(mhl, verbose=True, schema=True)
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
        mhlver._verify_classicmhl(mhl, verbose=True, schema=False)
        assert "-v" in captured_cmd["cmd"]

    def test_schema_uses_classicmhl_schema_results_table(self, tmp_path, monkeypatch, capsys):
        """With schema=True, exit 60 is looked up in _CLASSICMHL_SCHEMA_RESULTS
        (which has a specific message) not _CLASSICMHL_RESULTS (which doesn't)."""
        monkeypatch.setattr(mhlver, "get_command_path", lambda cmd: "/fake/simple-mhl")
        monkeypatch.setattr(mhlver, "_run_step", lambda cmd, **kw: mhlver.StepResult(60, ""))
        mhl = tmp_path / "dummy.mhl"
        mhl.write_text("")
        rc, _mr = mhlver._verify_classicmhl(mhl, verbose=False, schema=True)
        assert rc == 60
        captured = capsys.readouterr()
        assert "schema" in (captured.out + captured.err).lower()


# ---------------------------------------------------------------------------
# TestLogHelpers
# ---------------------------------------------------------------------------


class TestLogHelpers:
    """Unit tests for _log, _emit_step_output, and _verbose_announce."""

    def test_log_routes_through_console(self, capsys):
        """When a console object is passed, _log uses console.print, not print()."""

        console_out = io.StringIO()

        class FakeConsole:
            def print(self, msg, **kwargs):
                console_out.write(msg + "\n")

        mhlver._log(
            "hello",
            colour="",
            stream=None,
            console=FakeConsole(),
        )
        assert "hello" in console_out.getvalue()
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

        console_out = io.StringIO()

        class FakeConsole:
            def print(self, msg, **kwargs):
                console_out.write(msg + "\n")

        mhlver._emit_step_output("OK: file.bin", 0, show_on_terminal=True, console=FakeConsole())
        assert "OK: file.bin" in console_out.getvalue()

    def test_emit_step_output_failure_via_console(self, capsys):
        """On exit_code!=0, a console object is used for the error output."""

        console_out = io.StringIO()

        class FakeConsole:
            def print(self, msg, **kwargs):
                console_out.write(msg + "\n")

        mhlver._emit_step_output("ERR: file.bin", 1, show_on_terminal=True, console=FakeConsole())
        assert "ERR: file.bin" in console_out.getvalue()
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

    def test_verbose_announce_with_cwd_includes_cwd(self, capsys):
        """_verbose_announce includes (cwd=...) when cwd is not None."""
        cwd = Path("/some/dir")
        mhlver._verbose_announce(["/bin/cmd", "arg"], cwd=cwd, verbose=True)
        captured = capsys.readouterr()
        assert f"cwd={cwd}" in captured.err

    def test_verbose_announce_without_cwd_omits_cwd(self, capsys):
        """_verbose_announce omits cwd when it is None."""
        mhlver._verbose_announce(["/bin/cmd"], cwd=None, verbose=True)
        captured = capsys.readouterr()
        assert "cwd" not in captured.err

    def test_verbose_announce_via_console(self):
        """_verbose_announce routes through console when provided."""

        console_out = io.StringIO()

        class FakeConsole:
            def print(self, msg, **kwargs):
                console_out.write(msg + "\n")

        mhlver._verbose_announce(
            ["/bin/cmd"],
            cwd=None,
            verbose=True,
            console=FakeConsole(),
        )
        assert "running:" in console_out.getvalue()

    def test_verbose_announce_noop_when_not_verbose(self, capsys):
        """_verbose_announce produces no output when verbose=False."""
        mhlver._verbose_announce(["/bin/cmd"], cwd=None, verbose=False)
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
            mhlver._CLASSICMHL_RESULTS,
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
            mhlver._CLASSICMHL_RESULTS,
            40,
            "bad.mhl",
            "",
            show_backend_output=False,
            show_status_on_terminal=False,
        )
        captured = capsys.readouterr()
        assert "bad.mhl" in captured.err


# ---------------------------------------------------------------------------
# TestGetCommandPath
# ---------------------------------------------------------------------------


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

        venv_bin = tmp_path / ("Scripts" if sys.platform == "win32" else "bin")
        venv_bin.mkdir()
        candidate = venv_bin / "simple-mhl"
        candidate.write_text("#!/bin/sh")
        monkeypatch.setattr(mhlver.sys, "prefix", str(tmp_path))
        # which would return a different path — we must NOT see it.
        monkeypatch.setattr(mhlver.shutil, "which", lambda cmd: "/wrong/path")
        assert mhlver.get_command_path("simple-mhl") == str(candidate)


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

        monkeypatch.setattr(mhlver, "_verify_ascmhl", _stub)
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

        monkeypatch.setattr(mhlver, "_verify_classicmhl", _stub)
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
        """Returns the sum of all <size> values in a manifest."""
        mhl = tmp_path / "test.mhl"
        mhl.write_text(
            '<?xml version="1.0"?>\n'
            '<hashlist version="1.1">'
            "<hash><file>a.bin</file><size>100</size></hash>"
            "<hash><file>b.bin</file><size>200</size></hash>"
            "</hashlist>"
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
            "<hash><file>a.bin</file><size>bad</size></hash>"
            "<hash><file>b.bin</file><size>50</size></hash>"
            "</hashlist>"
        )
        assert mhlver._mhl_total_bytes(mhl) == 50

    def test_classicmhl_from_shotputpro(self, tmp_path, load_fixture_mhl):
        """ShotPutPro classic MHL

        Expected total: 2246896176 + 4170 + 15758019120 = 18_004_919_466
        """
        mhl = load_fixture_mhl(tmp_path, "shotputpro_classicmhl_example.mhl")
        assert mhlver._mhl_total_bytes(mhl) == 2246896176 + 4170 + 15758019120

    def test_classicmhl_from_silverstack(self, tmp_path, load_fixture_mhl):
        """ShotPutPro classic MHL

        Expected total: 2246896176 + 4170 + 15758019120 = 18_004_919_466
        """
        mhl = load_fixture_mhl(tmp_path, "silverstack_classicmhl_example.mhl")
        assert mhlver._mhl_total_bytes(mhl) == 2246896176 + 4170 + 15758019120

    def test_classicmhl_from_ocopy(self, tmp_path, load_fixture_mhl):
        """o/COPY classic MHL

        Expected total: 2246896176 + 4170 + 15758019120 = 18_004_919,466
        """
        mhl = load_fixture_mhl(tmp_path, "ocopy_classicmhl_example.mhl")
        assert mhlver._mhl_total_bytes(mhl) == 18_004_919_466

    def test_classicmhl_from_offshoot(self, tmp_path, load_fixture_mhl):
        """OffShoot classic MHL
        Expected total: 2246896176 + 4170 + 15758019120 = 18_004_919,466
        """
        mhl = load_fixture_mhl(tmp_path, "offshoot_classicmhl_example.mhl")
        assert mhlver._mhl_total_bytes(mhl) == 18_004_919_466


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
        content = rp.read_text()
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
        rc, _ = mhlver._run(mhl, verbose=False, schema=False)
        assert rc == 0
        assert "successfully verified" in capsys.readouterr().out

    def test_run_with_single_file_failure(self, tmp_path, monkeypatch, capsys):
        """_run with a file path returns the non-zero exit code on failure."""
        self._stub_verify_item(monkeypatch, 40)
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        rc, _ = mhlver._run(mhl, verbose=False, schema=False)
        assert rc == 40
        assert "failed" in capsys.readouterr().err.lower()

    def test_run_empty_directory_warns(self, tmp_path, monkeypatch, capsys):
        """_run on a dir with no MHL files logs a warning and returns 0."""
        # Force use_progress=False so we stay in the simple branch.
        monkeypatch.setattr(mhlver.sys.stdout, "isatty", lambda: False)
        rc, _ = mhlver._run(tmp_path, verbose=False, schema=False)
        assert rc == 0
        captured = capsys.readouterr()
        assert "no mhl" in (captured.out + captured.err).lower()

    def test_run_directory_first_failure_wins(self, tmp_path, monkeypatch, capsys):
        """First non-zero exit code is returned; subsequent failures don't override."""
        monkeypatch.setattr(mhlver.sys.stdout, "isatty", lambda: False)
        results = iter([30, 40])
        monkeypatch.setattr(mhlver, "verify_item", lambda *a, **kw: (next(results), None))
        for name in ["a.mhl", "b.mhl"]:
            (tmp_path / name).write_text("")
        rc, _ = mhlver._run(tmp_path, verbose=False, schema=False)
        assert rc == 30

    def test_run_directory_all_pass(self, tmp_path, monkeypatch, capsys):
        """All manifests passing returns 0 with the success summary."""
        monkeypatch.setattr(mhlver.sys.stdout, "isatty", lambda: False)
        monkeypatch.setattr(mhlver, "verify_item", lambda *a, **kw: (0, None))
        (tmp_path / "a.mhl").write_text("")
        (tmp_path / "b.mhl").write_text("")
        rc, _ = mhlver._run(tmp_path, verbose=False, schema=False)
        assert rc == 0
        assert "successfully verified" in capsys.readouterr().out

    @pytest.mark.skipif(sys.platform == "win32", reason="os.mkfifo is not available on Windows")
    def test_src_is_neither_file_nor_dir_still_succeeds(self, tmp_path, monkeypatch):
        """When src exists but is neither a file nor a directory (e.g. a named
        pipe), _run takes the else branch (console = None) and returns 0."""

        pipe = tmp_path / "fifo.mhl"
        os.mkfifo(pipe)
        # verify_item is never called — exit_status stays 0.
        rc, _ = mhlver._run(pipe, verbose=False, schema=False)
        assert rc == 0

    def test_run_writes_to_report_file(self, tmp_path, monkeypatch):
        """_render_report writes a structured report with a summary line."""

        monkeypatch.setattr(mhlver.sys.stdout, "isatty", lambda: False)
        monkeypatch.setattr(mhlver, "verify_item", lambda *a, **kw: (0, None))
        (tmp_path / "a.mhl").write_text("")
        rc, mrs = mhlver._run(tmp_path, verbose=False, schema=False)
        buf = io.StringIO()
        mhlver._render_report(buf, tmp_path, mhlver.datetime.now(), mrs, rc)
        assert "PASSED" in buf.getvalue()

    def test_run_with_report_file_includes_separator(self, tmp_path, monkeypatch):
        """_render_report includes separator lines in its output."""

        monkeypatch.setattr(mhlver.sys.stdout, "isatty", lambda: False)
        monkeypatch.setattr(mhlver, "verify_item", lambda *a, **kw: (0, None))
        (tmp_path / "a.mhl").write_text("")
        rc, mrs = mhlver._run(tmp_path, verbose=False, schema=False)
        buf = io.StringIO()
        mhlver._render_report(buf, tmp_path, mhlver.datetime.now(), mrs, rc)
        assert "---" in buf.getvalue()


# ---------------------------------------------------------------------------
# TestRunStep
# ---------------------------------------------------------------------------


class TestRunStep:
    """Tests for _run_step — subprocess execution with progress-bar polling."""

    def test_on_poll_is_set_during_subprocess(self):
        """on_poll.set() must be called at least once while the subprocess runs.

        _run_step polls every ~100 ms while the process is alive; even a
        subprocess that exits almost immediately will trigger at least one
        poll tick on most systems. We use a no-op shell command so the test
        stays fast and cross-platform.
        """
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

    def test_large_stderr_output_does_not_deadlock(self):
        """_run_step must not deadlock when the child writes > 64 KB to stderr.

        The kernel pipe buffer is 64 KB on macOS/Linux. The old implementation
        called proc.wait() in a loop before proc.communicate(), so the child
        would block on its first write() that exceeded the buffer cap and the
        parent would spin forever waiting for it to exit — a classic deadlock.

        The fix calls proc.communicate() immediately (which drains both pipes
        via internal reader threads) and drives on_poll ticks from a separate
        ticker thread. This test encodes that contract: if the deadlock ever
        regresses, the test will hang and pytest-timeout will report a failure
        rather than letting the suite stall silently, which mirrors exactly
        how `mhlver --report --verbose` stalled before the fix.

        128 KB is chosen as double the pipe buffer so the test catches any
        single-stream overflow regardless of platform-specific buffer sizes.
        """
        # Write 128 KB to stderr — well past the 64 KB pipe-buffer ceiling.
        large_stderr_script = "import sys; sys.stderr.write('x' * 128 * 1024); sys.stderr.flush()"
        result = mhlver._run_step(
            cmd=["python3", "-c", large_stderr_script],
            cwd=None,
            on_poll=None,
        )
        # The subprocess exits cleanly; we just need it to finish at all.
        assert result.exit_code == 0
        # communicate() merges stdout+stderr into result.output, so the 'x'
        # flood must appear there and must be at least 128 KB in total.
        assert len(result.output) >= 128 * 1024

    def test_on_poll_ticker_fires_multiple_times(self):
        """The _ticker thread inside _run_step must call on_poll.set() on every
        iteration of its loop, not just once.

        This directly exercises the branch at lines 211-213:

            def _ticker() -> None:
                while not stop_ticking.is_set():
                    if on_poll is not None:   # <- line 211
                        on_poll.set()         # <- line 212 (the branch under test)
                    stop_ticking.wait(timeout=0.1)

        We replace the threading.Event with a counting shim so we can observe
        how many times set() is called. The subprocess sleeps for 0.4 s;
        with a 100 ms ticker interval that is at least 3 ticks. We assert >= 2
        to give one tick of headroom for scheduling jitter on slow CI hosts.
        """

        class _CountingEvent:
            """Drop-in threading.Event replacement that counts set() calls."""

            def __init__(self):
                self._real = threading.Event()
                self.set_count = 0

            def set(self):
                self.set_count += 1
                self._real.set()

            def is_set(self):
                return self._real.is_set()

            def wait(self, timeout=None):
                return self._real.wait(timeout=timeout)

        counter = _CountingEvent()
        result = mhlver._run_step(
            cmd=["python3", "-c", "import time; time.sleep(0.4)"],
            cwd=None,
            on_poll=counter,
        )
        assert result.exit_code == 0
        assert counter.set_count >= 2, (
            f"Expected _ticker to fire on_poll.set() at least twice in 0.4 s "
            f"(100 ms interval), but it fired {counter.set_count} time(s). "
            "The 'if on_poll is not None: on_poll.set()' branch may not be looping."
        )


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
        rc, _ = mhlver._run(tmp_path, verbose=False, schema=False)
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
        rc, _ = mhlver._run(tmp_path, verbose=False, schema=False)
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
        rc, mrs = mhlver._run(tmp_path, verbose=False, schema=False)
        buf = io.StringIO()
        mhlver._render_report(buf, tmp_path, mhlver.datetime.now(), mrs, rc)
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
        monkeypatch.setattr(mhlver, "normalization_variant_on_disk", lambda p: "/vol/café_nfd.mhl")
        rc, _, err = mhlver_cli(["/vol/café_nfc.mhl"])
        assert rc == 2
        assert "did you mean" in err.lower()
        assert "café_nfd.mhl" in err

    def test_nonexistent_path_no_variant_is_plain_error(self, mhlver_cli, monkeypatch):
        """A genuine typo (no normalization variant) gives the plain error, no hint."""
        monkeypatch.setattr(mhlver, "normalization_variant_on_disk", lambda p: None)
        rc, _, err = mhlver_cli(["/vol/ghost.mhl"])
        assert rc == 2
        assert "did you mean" not in err.lower()

    def test_default_path_is_cwd(self, mhlver_cli, monkeypatch, tmp_path):
        """Omitting the path argument defaults to the current directory."""
        called_with = {}

        def _stub_run(src, verbose, schema):
            called_with["src"] = src
            return 0, []

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(mhlver, "_run", _stub_run)
        rc, _, _ = mhlver_cli([])
        assert rc == 0
        assert called_with["src"] == tmp_path.resolve()

    def test_explicit_file_path_passed_to_run(self, mhlver_cli, monkeypatch, tmp_path):
        """An explicit path is resolved and forwarded to _run."""
        called_with = {}

        def _stub_run(src, verbose, schema):
            called_with["src"] = src
            return 0, []

        monkeypatch.setattr(mhlver, "_run", _stub_run)
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        rc, _, _ = mhlver_cli([str(mhl)])
        assert rc == 0
        assert called_with["src"] == mhl.resolve()

    def test_verbose_flag_forwarded(self, mhlver_cli, monkeypatch, tmp_path):
        """--verbose is passed through to _run."""
        called_with = {}

        def _stub_run(src, verbose, schema):
            called_with["verbose"] = verbose
            return 0, []

        monkeypatch.setattr(mhlver, "_run", _stub_run)
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        mhlver_cli(["-v", str(mhl)])
        assert called_with["verbose"] is True

    def test_schema_flag_forwarded(self, mhlver_cli, monkeypatch, tmp_path):
        """--xsd-schema-check is passed through to _run."""
        called_with = {}

        def _stub_run(src, verbose, schema):
            called_with["schema"] = schema
            return 0, []

        monkeypatch.setattr(mhlver, "_run", _stub_run)
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        mhlver_cli(["-s", str(mhl)])
        assert called_with["schema"] is True

    def test_exit_code_propagated_from_run(self, mhlver_cli, monkeypatch, tmp_path):
        """The exit code returned by _run becomes mhlver's exit code."""
        monkeypatch.setattr(mhlver, "_run", lambda *a, **kw: (40, []))
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        rc, _, _ = mhlver_cli([str(mhl)])
        assert rc == 40

    def test_report_flag_creates_report_file(self, mhlver_cli, monkeypatch, tmp_path):
        """--report causes a report file to be created and its path printed."""
        monkeypatch.setattr(mhlver, "_run", lambda *a, **kw: (0, []))
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
        monkeypatch.setattr(mhlver, "_run", lambda *a, **kw: (0, []))
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        mhlver_cli(["--report", str(mhl)])
        report = next(tmp_path.glob("mhlver_report_*.log"))
        assert "PASSED" in report.read_text()

    def test_report_flag_with_failure_records_nonzero_exit(self, mhlver_cli, monkeypatch, tmp_path):
        """A non-zero exit from _run is reflected as FAILED in the report file."""
        monkeypatch.setattr(mhlver, "_run", lambda *a, **kw: (40, []))
        mhl = tmp_path / "manifest.mhl"
        mhl.write_text("")
        rc, _, _ = mhlver_cli(["--report", str(mhl)])
        assert rc == 40
        report = next(tmp_path.glob("mhlver_report_*.log"))
        assert "FAILED" in report.read_text()

    def test_version_flag_exits_0(self, mhlver_cli):
        """--version prints the version string and exits 0."""
        rc, out, _ = mhlver_cli(["--version"])
        assert rc == 0
        assert out.strip() != ""
