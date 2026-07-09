"""
Discovery and the cross-dialect orchestrator (mhl_suite.discovery).

This is where "both dialects verify in-process" actually happens: discover
every manifest under a tree once into typed items (ASC-MHL generations
deduplicated to one package item) and route each to the right dialect engine.
The mhlver CLI owns aggregation and is tested separately; the shared renderer
lives in test_verify. Here we pin discovery filtering, generation dedup,
dispatch, and progress weighting.
"""

import tempfile
import unicodedata
from collections import Counter
from pathlib import Path

from hypothesis import HealthCheck, assume, given, settings, strategies

from mhl_suite import discovery
from mhl_suite.discovery import AscmhlPackage, ClassicManifest
from mhl_suite.verify import VerifyReport

from .helpers import make_mhl_with_size, make_package, make_tree

# Minimal ASC-MHL v2 manifest body — enough for is_ascmhl_v2()'s header check
# (namespace + version) to classify a file as ASC-MHL during selection. Dedup
# groups generations by their `ascmhl/` package only when the header says v2.
_V2_MHL = b'<hashlist version="2.0" xmlns="urn:ASC:MHL:v2.0"/>'

# Hypothesis strategy for valid filename stems: Unicode letters, digits and
# symbols (including emoji), plus "_-". We keep only NFC-normalised stems so two
# "distinct" names can't collapse onto the same file on a
# normalisation-insensitive filesystem (APFS/HFS+), and skip leading "._" (the
# resource-fork filter) and blanks.
_filename_stem = strategies.text(
    alphabet=strategies.characters(
        whitelist_categories=("Ll", "Lu", "Nd", "So"),
        whitelist_characters="_-",
    ),
    min_size=1,
    max_size=20,
).filter(lambda s: not s.startswith("._") and s.strip() and unicodedata.is_normalized("NFC", s))

_generations_per_pkg = strategies.integers(min_value=1, max_value=4)


def _fs_name_key(name: str) -> str:
    """
    Key under which two stems become the *same* file on a case-insensitive,
    normalisation-insensitive filesystem (macOS APFS/HFS+): case-folded and
    NFC-normalised. Package-name lists are made unique by this key, not by plain
    string equality, so generated names like "Ŭ"/"ŭ" can't map to one on-disk
    directory and break the one-package-per-name assumption these tests rely on.
    """
    return unicodedata.normalize("NFC", name.casefold())


def _selected_paths(root: Path) -> list[Path]:
    """Each discovered item's representative manifest file (a package is represented by its latest generation)."""
    return [item.latest if isinstance(item, AscmhlPackage) else item.path for item in discovery.discover(root)]


class TestFindMhlFiles:
    """Discovery walks case-insensitively and skips macOS resource forks."""

    def test_case_insensitive_recursive(self, tmp_path):
        make_tree(tmp_path, {"a.mhl": b"", "sub/B.MHL": b"", "sub/deep/c.MhL": b""})
        found = {p.name for p in discovery._find_mhl_files(tmp_path)}
        assert found == {"a.mhl", "B.MHL", "c.MhL"}

    def test_skips_resource_forks(self, tmp_path):
        make_tree(tmp_path, {"real.mhl": b"", "._real.mhl": b""})
        found = [p.name for p in discovery._find_mhl_files(tmp_path)]
        assert found == ["real.mhl"]

    def test_ignores_non_mhl(self, tmp_path):
        make_tree(tmp_path, {"keep.mhl": b"", "notes.txt": b"", "data.xml": b""})
        found = {p.name for p in discovery._find_mhl_files(tmp_path)}
        assert found == {"keep.mhl"}


class TestDiscover:
    """
    discover() keeps one item per ASC package and passes classic manifests
    through as their own items.
    """

    def test_ascmhl_package_dedups_to_latest_generation(self, tmp_path):
        make_tree(
            tmp_path,
            {
                "pkg/ascmhl/0001.mhl": _V2_MHL,
                "pkg/ascmhl/0002.mhl": _V2_MHL,
                "pkg/ascmhl/0003.mhl": _V2_MHL,
            },
        )
        (item,) = discovery.discover(tmp_path)
        assert isinstance(item, AscmhlPackage)
        assert item.latest.name == "0003.mhl"
        assert [p.name for p in item.manifests] == ["0001.mhl", "0002.mhl", "0003.mhl"]

    def test_classic_files_pass_through(self, tmp_path):
        make_tree(tmp_path, {"one.mhl": b"", "sub/two.mhl": b""})
        items = discovery.discover(tmp_path)
        assert all(isinstance(i, ClassicManifest) for i in items)
        assert {p.name for p in _selected_paths(tmp_path)} == {"one.mhl", "two.mhl"}

    def test_mixed_tree_keeps_classic_and_latest_asc(self, tmp_path):
        make_tree(
            tmp_path,
            {
                "data.mhl": b"",
                "pkg/ascmhl/0001.mhl": _V2_MHL,
                "pkg/ascmhl/0002.mhl": _V2_MHL,
                "._fork.mhl": b"",
            },
        )
        assert {p.name for p in _selected_paths(tmp_path)} == {"data.mhl", "0002.mhl"}

    def test_ascmhl_folder_directly_under_scan_root_yields_latest(self, tmp_path):
        """
        An ascmhl/ immediately under the scan root (no package dir) still dedups
        to exactly one item — represented by the latest generation.
        """
        make_tree(
            tmp_path,
            {
                "ascmhl/0001.mhl": _V2_MHL,
                "ascmhl/0002.mhl": _V2_MHL,
                "ascmhl/0003.mhl": _V2_MHL,
            },
        )
        selected = _selected_paths(tmp_path)
        assert len(selected) == 1
        assert selected[0].name == "0003.mhl"

    def test_top_level_and_nested_ascmhl_dedup_independently(self, tmp_path):
        """
        A top-level ascmhl/ and a nested package's ascmhl/ each contribute one
        item — they must not share a dedup key despite both being 'ascmhl'.
        """
        make_tree(
            tmp_path,
            {
                "ascmhl/0001.mhl": _V2_MHL,
                "pkg/ascmhl/0001.mhl": _V2_MHL,
                "pkg/ascmhl/0002.mhl": _V2_MHL,
            },
        )
        assert {p.name for p in _selected_paths(tmp_path)} == {"0001.mhl", "0002.mhl"}

    def test_classic_v1_inside_ascmhl_folder_is_not_grouped_as_package(self, tmp_path):
        """
        Dialect is decided by the header, not the folder name: a classic v1
        manifest that happens to sit inside an `ascmhl/` folder passes through
        as its own classic item instead of being folded into — and distorting —
        the real v2 package's generation dedup.
        """
        make_tree(
            tmp_path,
            {
                "pkg/ascmhl/0001.mhl": _V2_MHL,
                "pkg/ascmhl/0002.mhl": _V2_MHL,
                "pkg/ascmhl/legacy.mhl": b'<hashlist version="1.1"/>',
            },
        )
        # The v2 package dedups to its latest generation (0002); the v1 file
        # stands on its own key.
        assert {p.name for p in _selected_paths(tmp_path)} == {"0002.mhl", "legacy.mhl"}

    def test_single_file_src_classifies_directly(self, tmp_path):
        make_tree(tmp_path, {"pkg/ascmhl/0001.mhl": _V2_MHL, "loose.mhl": b""})
        (pkg_item,) = discovery.discover(tmp_path / "pkg" / "ascmhl" / "0001.mhl")
        assert isinstance(pkg_item, AscmhlPackage)
        assert pkg_item.root == tmp_path / "pkg"
        (classic_item,) = discovery.discover(tmp_path / "loose.mhl")
        assert isinstance(classic_item, ClassicManifest)


class TestDiscoverInvariants:
    """
    Property-based invariants over generated layouts, complementing the unit
    cases above. @given tests manage their own TemporaryDirectory rather than
    the function-scoped tmp_path, which is not reset between generated examples.
    """

    @given(
        pkg_names=strategies.lists(_filename_stem, min_size=1, max_size=5, unique_by=_fs_name_key),
        gen_counts=strategies.lists(_generations_per_pkg, min_size=1, max_size=5),
    )
    @settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
    def test_each_ascmhl_package_selected_at_most_once(self, pkg_names, gen_counts):
        """No matter how many generation files a package has, discover() must
        return at most one item per ascmhl/ directory."""
        counts = (gen_counts + [1] * len(pkg_names))[: len(pkg_names)]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package_dirs = set()
            for name, n_gens in zip(pkg_names, counts, strict=True):
                ascdir = root / name / "ascmhl"
                ascdir.mkdir(parents=True, exist_ok=True)
                package_dirs.add(ascdir)
                for i in range(1, n_gens + 1):
                    (ascdir / f"{i:04d}.mhl").write_bytes(_V2_MHL)

            selected = _selected_paths(root)

            dir_counts = Counter(f.parent for f in selected if f.parent in package_dirs)
            for ascdir, count in dir_counts.items():
                assert count == 1, f"{ascdir} appears {count} times in selection; expected exactly 1"

    @given(
        pkg_names=strategies.lists(_filename_stem, min_size=1, max_size=4, unique_by=_fs_name_key),
        gen_counts=strategies.lists(_generations_per_pkg, min_size=1, max_size=4),
    )
    @settings(max_examples=80, suppress_health_check=[HealthCheck.too_slow])
    def test_latest_generation_is_always_selected(self, pkg_names, gen_counts):
        """discover() must represent each ASC-MHL package by its
        lexicographically largest filename (i.e. the latest generation)."""
        counts = (gen_counts + [1] * len(pkg_names))[: len(pkg_names)]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            expected: dict[Path, Path] = {}
            for name, n_gens in zip(pkg_names, counts, strict=True):
                ascdir = root / name / "ascmhl"
                ascdir.mkdir(parents=True, exist_ok=True)
                for i in range(1, n_gens + 1):
                    (ascdir / f"{i:04d}.mhl").write_bytes(_V2_MHL)
                expected[ascdir] = ascdir / f"{n_gens:04d}.mhl"

            selected_set = set(_selected_paths(root))

            for ascdir, latest in expected.items():
                assert latest in selected_set, (
                    f"Expected latest generation {latest.name} to be selected for package {ascdir.parent.name}"
                )

    @given(mhl_names=strategies.lists(_filename_stem, min_size=1, max_size=6, unique=True))
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_loose_mhl_files_are_never_deduplicated_against_each_other(self, mhl_names):
        """Each distinct loose .mhl file (not inside an ascmhl/ folder) uses its own
        path as its dedup key, so N distinct loose files must yield N results."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in mhl_names:
                (root / f"{name}.mhl").write_text("")

            # Distinct names can still collide on a case-insensitive filesystem
            # (e.g. APFS), so compare against the files on disk.
            on_disk = list(root.glob("*.mhl"))
            selected = _selected_paths(root)
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
        """Total discovered items ≤ total .mhl files on disk: dedup can only
        reduce the count, never invent or duplicate items."""
        assume(not (set(pkg_names) & set(mhl_names)))
        counts = (gen_counts + [1] * len(pkg_names))[: len(pkg_names)]

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            total_files = 0

            for name, n_gens in zip(pkg_names, counts, strict=True):
                ascdir = root / name / "ascmhl"
                ascdir.mkdir(parents=True, exist_ok=True)
                for i in range(1, n_gens + 1):
                    (ascdir / f"{i:04d}.mhl").write_bytes(_V2_MHL)
                    total_files += 1

            for name in mhl_names:
                (root / f"{name}.mhl").write_text("")
                total_files += 1

            selected = _selected_paths(root)
            assert len(selected) <= total_files

    @given(
        n_pkgs=strategies.integers(min_value=0, max_value=3),
        n_loose=strategies.integers(min_value=0, max_value=3),
    )
    @settings(max_examples=60, suppress_health_check=[HealthCheck.too_slow])
    def test_output_is_always_sorted(self, n_pkgs, n_loose):
        """discover() must return items in sorted key order regardless of how
        many packages or loose files are present."""
        assume(n_pkgs + n_loose > 0)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)

            for i in range(n_pkgs):
                ascdir = root / f"pkg{i}" / "ascmhl"
                ascdir.mkdir(parents=True, exist_ok=True)
                (ascdir / "0001.mhl").write_bytes(_V2_MHL)

            for i in range(n_loose):
                (root / f"loose{i}.mhl").write_text("")

            keys = [i.root if isinstance(i, AscmhlPackage) else i.path for i in discovery.discover(root)]
            assert keys == sorted(keys)


class TestVerifyItemDispatch:
    """verify_item routes by item type, both dialects in-process."""

    def test_classic_manifest_routes_to_classic_engine(self, tmp_path):
        manifest = make_mhl_with_size(tmp_path, "clip.mov", b"hello world")
        code, _mr = discovery.verify_item(discovery.classify(manifest), verbose=False, schema=False)
        assert code == 0

    def test_classic_mismatch_surfaces_nonzero(self, tmp_path):
        manifest = make_mhl_with_size(tmp_path, "clip.mov", b"hello world")
        (tmp_path / "clip.mov").write_bytes(b"tampered")
        code, _mr = discovery.verify_item(discovery.classify(manifest), verbose=False, schema=False)
        assert code != 0

    def test_ascmhl_manifest_routes_to_asc_engine(self, tmp_path):
        pkg = make_package(tmp_path / "pkg", {"top.txt": b"hello\n"})
        manifest = next((pkg / "ascmhl").glob("*.mhl"))
        code, _mr = discovery.verify_item(discovery.classify(manifest), verbose=False, schema=False)
        assert code == 0

    def test_ascmhl_tamper_surfaces_mismatch(self, tmp_path):
        pkg = make_package(tmp_path / "pkg", {"top.txt": b"hello\n"})
        (pkg / "top.txt").write_bytes(b"CORRUPT\n")
        manifest = next((pkg / "ascmhl").glob("*.mhl"))
        code, _mr = discovery.verify_item(discovery.classify(manifest), verbose=False, schema=False)
        assert code == 11

    def test_classic_nonzero_with_no_file_results_is_manifest_error(self, tmp_path, monkeypatch):
        """A non-zero report carrying no per-file entries (and not the malformed-XML
        case) is classified as a manifest-level 'error', not 'failed'."""
        manifest = make_mhl_with_size(tmp_path, "clip.mov", b"hello world")
        monkeypatch.setattr(
            discovery, "verify_classic", lambda *a, **kw: VerifyReport(entries=[], code=11, malformed=False)
        )
        code, mr = discovery.verify_item(discovery.classify(manifest), verbose=False, schema=False)
        assert code == 11
        assert mr is not None
        assert mr.manifest_status == "error"


class TestItemWeights:
    """Items weight themselves by byte volume, but by count under size-only."""

    def test_size_only_weights_every_manifest_equally(self, tmp_path):
        item = discovery.classify(make_mhl_with_size(tmp_path, "clip.mov", b"x" * 50))
        assert item.weight(size_only=True) == 1

    def test_byte_weight_counts_recomputable_entry_size(self, tmp_path):
        content = b"x" * 50
        item = discovery.classify(make_mhl_with_size(tmp_path, "clip.mov", content))
        assert item.weight(size_only=False) == len(content)

    def test_ascmhl_weight_counts_recorded_original_sizes(self, tmp_path):
        pkg = make_package(tmp_path / "pkg", {"a.bin": b"x" * 30, "sub/b.bin": b"y" * 20})
        item = discovery.classify(next((pkg / "ascmhl").glob("*.mhl")))
        assert item.weight(size_only=False) == 50
