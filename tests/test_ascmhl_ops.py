"""
ASC-MHL diff / rename / flatten.

Diff never hashes (spec 5.6.3); rename records previousPath in one new
generation of the closest enclosing history (spec 5.6.6 + 5.3.2); flatten
consolidates the earliest usable hash per (file, format) into a standalone
packing list with a collection entry (spec 5.6.7 + 5.5). Interop: the
reference `ascmhl` library must keep verifying packages after our renames.
"""

import re

import pytest
from ascmhl import commands
from click.testing import CliRunner
from lxml import etree

from mhl_suite import ascmhl_history, hashing
from mhl_suite.ascmhl_ops import diff_ascmhl, flatten_ascmhl, rename_ascmhl
from mhl_suite.ascmhl_seal import AscmhlSealError, SealOptions, seal_ascmhl
from mhl_suite.verify import Status
from mhl_suite.xsd_check import ascmhl_schema_report

from .helpers import asc_hash_record, make_asc_package, make_tree, statuses


def seal(root, algorithms=("xxh64",)):
    return seal_ascmhl(root, SealOptions(algorithms=algorithms))


def sealed_tree(tmp_path, spec):
    root = tmp_path / "pkg"
    make_tree(root, spec)
    seal(root)
    return root


class TestDiff:
    def test_clean_package_diffs_empty(self, tmp_path):
        root = sealed_tree(tmp_path, {"Clips/a.mov": b"aa"})
        report = diff_ascmhl(root)
        assert (report.code, report.entries) == (0, [])

    def test_reports_unknown_and_missing_without_hashing(self, tmp_path, monkeypatch):
        root = sealed_tree(tmp_path, {"Clips/a.mov": b"aa", "Clips/b.mov": b"bb"})
        (root / "new.txt").write_bytes(b"n")
        (root / "Clips" / "b.mov").unlink()
        (root / "Clips" / "a.mov").write_bytes(b"tampered")  # content is invisible to diff

        real_get_hashes = hashing.get_hashes

        def _manifests_only(filepath, *args, **kwargs):
            # The chain gate may re-hash the (small) manifest files themselves;
            # media files must never be read.
            assert "/ascmhl/" in str(filepath).replace("\\", "/"), f"diff hashed media: {filepath}"
            return real_get_hashes(filepath, *args, **kwargs)

        monkeypatch.setattr(hashing, "get_hashes", _manifests_only)
        report = diff_ascmhl(root)
        assert report.code == 21  # unknown files win over missing
        assert statuses(report) == {"new.txt": Status.NEW, "Clips/b.mov": Status.MISSING}

    def test_missing_only_is_exit_10(self, tmp_path):
        root = sealed_tree(tmp_path, {"a.txt": b"x"})
        (root / "a.txt").unlink()
        assert diff_ascmhl(root).code == 10

    def test_history_integrity_failures_surface_like_verify(self, tmp_path):
        root = sealed_tree(tmp_path, {"a.txt": b"x"})
        (root / "ascmhl" / "ascmhl_chain.xml").unlink()
        assert diff_ascmhl(root).code == 32
        assert diff_ascmhl(tmp_path).code == 30


class TestRenameFile:
    def test_rename_records_previous_path_and_stays_verifiable(self, tmp_path):
        root = sealed_tree(tmp_path, {"Clips/a.mov": b"aa"})
        manifest, report = rename_ascmhl(root / "Clips" / "a.mov", root / "Clips" / "b.mov")

        assert report.code == 0
        assert not (root / "Clips" / "a.mov").exists()
        assert (root / "Clips" / "b.mov").exists()
        text = manifest.read_text()
        assert "<previousPath>Clips/a.mov</previousPath>" in text
        assert 'action="verified"' in text
        assert ascmhl_schema_report(str(manifest))[0] == 0
        assert ascmhl_history.verify_ascmhl(root).code == 0

    def test_rename_chain_across_generations_resolves(self, tmp_path):
        root = sealed_tree(tmp_path, {"a.mov": b"aa"})
        rename_ascmhl(root / "a.mov", root / "b.mov")
        rename_ascmhl(root / "b.mov", root / "c.mov")
        report = ascmhl_history.verify_ascmhl(root)
        assert report.code == 0
        assert statuses(report) == {"c.mov": Status.OK}

    def test_reference_tool_verifies_after_our_rename(self, tmp_path):
        root = sealed_tree(tmp_path, {"Clips/a.mov": b"aa"})
        rename_ascmhl(root / "Clips" / "a.mov", root / "Clips" / "b.mov")
        result = CliRunner().invoke(commands.verify, [str(root)])
        assert result.exit_code == 0, result.output

    def test_tampered_file_records_failed_and_reports_11(self, tmp_path):
        root = sealed_tree(tmp_path, {"a.mov": b"aa"})
        (root / "a.mov").write_bytes(b"XX")
        manifest, report = rename_ascmhl(root / "a.mov", root / "b.mov")
        assert report.code == 11
        assert 'action="failed"' in manifest.read_text()
        assert "<previousPath>a.mov</previousPath>" in manifest.read_text()

    def test_rename_updates_only_the_closest_history(self, tmp_path):
        base = tmp_path / "day"
        make_tree(base, {"A001/c1.mov": b"c1", "loose.txt": b"l"})
        seal(base / "A001")
        seal(base)
        parent_generations = len(list((base / "ascmhl").glob("*.mhl")))
        child_generations = len(list((base / "A001" / "ascmhl").glob("*.mhl")))
        rename_ascmhl(base / "A001" / "c1.mov", base / "A001" / "c2.mov")

        assert len(list((base / "A001" / "ascmhl").glob("*.mhl"))) == child_generations + 1
        assert len(list((base / "ascmhl").glob("*.mhl"))) == parent_generations  # no upward propagation
        assert ascmhl_history.verify_ascmhl(base / "A001").code == 0


class TestRenameDirectory:
    def test_directory_rename_copies_dir_hashes_and_maps_children(self, tmp_path):
        root = sealed_tree(tmp_path, {"Clips/a.mov": b"aa", "Clips/Sub/b.mov": b"bb"})
        manifest, report = rename_ascmhl(root / "Clips", root / "Footage")

        assert report.code == 0
        text = manifest.read_text()
        dirhash = re.search(r"<directoryhash>.*?<path>Footage</path>.*?</directoryhash>", text, re.DOTALL)
        assert dirhash is not None
        assert "<previousPath>Clips</previousPath>" in dirhash.group(0)
        assert 'action="verified"' in dirhash.group(0)  # copied values: a rename cannot change them
        assert "<previousPath>Clips/a.mov</previousPath>" in text
        assert "<previousPath>Clips/Sub/b.mov</previousPath>" in text
        assert ascmhl_history.verify_ascmhl(root).code == 0

    def test_reference_tool_verifies_after_our_directory_rename(self, tmp_path):
        root = sealed_tree(tmp_path, {"Clips/a.mov": b"aa"})
        rename_ascmhl(root / "Clips", root / "Footage")
        result = CliRunner().invoke(commands.verify, [str(root)])
        assert result.exit_code == 0, result.output


class TestRenameValidation:
    def test_rejects_paths_outside_any_history(self, tmp_path):
        (tmp_path / "a.txt").write_bytes(b"x")
        with pytest.raises(ascmhl_history.NoHistoryError):
            rename_ascmhl(tmp_path / "a.txt", tmp_path / "b.txt")

    def test_rejects_crossing_history_boundaries(self, tmp_path):
        base = tmp_path / "day"
        make_tree(base, {"A001/c1.mov": b"c1", "loose.txt": b"l"})
        seal(base / "A001")
        seal(base)
        with pytest.raises(AscmhlSealError, match="across ASC MHL history boundaries"):
            rename_ascmhl(base / "A001" / "c1.mov", base / "c1.mov")

    def test_rejects_unrecorded_existing_and_ascmhl_targets(self, tmp_path):
        root = sealed_tree(tmp_path, {"a.txt": b"x", "b.txt": b"y"})
        (root / "unrecorded.txt").write_bytes(b"u")
        with pytest.raises(AscmhlSealError, match="not recorded"):
            rename_ascmhl(root / "unrecorded.txt", root / "u2.txt")
        with pytest.raises(AscmhlSealError, match="already exists"):
            rename_ascmhl(root / "a.txt", root / "b.txt")
        with pytest.raises(AscmhlSealError, match="ascmhl folder"):
            rename_ascmhl(root / "a.txt", root / "ascmhl" / "a.txt")
        with pytest.raises(AscmhlSealError, match="not found"):
            rename_ascmhl(root / "absent.txt", root / "x.txt")


class TestFlatten:
    def test_flatten_produces_valid_packinglist_and_collection(self, tmp_path):
        root = sealed_tree(tmp_path, {"Clips/a.mov": b"aa", "top.txt": b"t"})
        seal(root)  # a second generation to consolidate
        packinglist, collection = flatten_ascmhl(root, tmp_path / "out")

        assert re.fullmatch(r"packinglist__\d{4}-\d{2}-\d{2}_\d{6}\.mhl", packinglist.name)
        assert collection.name == "ascmhl_collection.xml"
        assert ascmhl_schema_report(str(packinglist))[0] == 0
        assert ascmhl_schema_report(str(collection), directory_file=True)[0] == 0
        text = packinglist.read_text()
        assert "<process>flatten</process>" in text
        assert "<roothash>" not in text
        assert "<directoryhash>" not in text  # dir hashes are not consolidated

    def test_earliest_entry_per_format_wins_with_action_preserved(self, tmp_path):
        # gen1 xxh64 original; gen2 adds md5 (verified) next to xxh64 verified.
        # The flattened record keeps gen1's xxh64 as original and gen2's md5.
        root = sealed_tree(tmp_path, {"a.mov": b"aa"})
        seal(root, algorithms=("md5",))
        packinglist, _ = flatten_ascmhl(root, tmp_path / "out")
        record = etree.parse(str(packinglist)).find("{*}hashes/{*}hash")
        assert record is not None
        actions = {c.tag.rpartition("}")[2]: c.get("action") for c in record if c.get("action")}
        assert actions == {"xxh64": "original", "md5": "verified"}

    def test_failed_entries_never_transfer(self, tmp_path):
        root = tmp_path / "pkg"
        make_tree(root, {"a.txt": b"x"})
        good = "b4bd9633d79bc5b9"  # xxh64 of b"x"
        make_asc_package(
            root,
            [
                [asc_hash_record("a.txt", "0" * 16, "failed", size=1)],
                [asc_hash_record("a.txt", good, "verified", size=1)],
            ],
        )
        packinglist, _ = flatten_ascmhl(root, tmp_path / "out")
        text = packinglist.read_text()
        assert 'action="failed"' not in text
        assert good in text

    def test_flatten_covers_nested_histories_and_renames(self, tmp_path):
        base = tmp_path / "day"
        make_tree(base, {"A001/c1.mov": b"c1", "loose.txt": b"l"})
        seal(base / "A001")
        seal(base)
        rename_ascmhl(base / "A001" / "c1.mov", base / "A001" / "c2.mov")
        packinglist, _ = flatten_ascmhl(base, tmp_path / "out")
        text = packinglist.read_text()
        assert "<path" in text
        assert "A001/c2.mov" in text  # nested file under its final name
        assert "<previousPath>A001/c1.mov</previousPath>" in text
        assert "loose.txt" in text

    def test_collection_sequencenr_continues_across_flattens(self, tmp_path):
        root = sealed_tree(tmp_path, {"a.txt": b"x"})
        flatten_ascmhl(root, tmp_path / "out")
        _, collection = flatten_ascmhl(root, tmp_path / "out")
        numbers = [el.get("sequencenr") for el in etree.parse(str(collection)).iter("{*}hashlist")]
        assert numbers == ["1", "2"]

    def test_source_history_is_not_modified(self, tmp_path):
        root = sealed_tree(tmp_path, {"a.txt": b"x"})
        before = sorted(p.name for p in (root / "ascmhl").iterdir())
        flatten_ascmhl(root, tmp_path / "out")
        assert sorted(p.name for p in (root / "ascmhl").iterdir()) == before
