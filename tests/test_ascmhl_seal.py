"""
ASC-MHL sealing: the XML writers and the seal/verify-append engine.

Spec conformance is asserted structurally (XSD validation of every emitted
file, element order, action labels per 5.6.4, generation naming per 6.3,
nested propagation per 5.3.2) and interop by letting the reference `ascmhl`
library read and extend packages we sealed.
"""

import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from ascmhl import commands
from click.testing import CliRunner
from lxml import etree

from mhl_suite import ascmhl_history
from mhl_suite.ascmhl_seal import (
    AscmhlSealError,
    DirEntryOut,
    FileEntryOut,
    HashEntryOut,
    ManifestOut,
    SealOptions,
    manifest_filename,
    seal_ascmhl,
    write_directory_file,
    write_manifest,
)
from mhl_suite.verify import Status
from mhl_suite.xsd_check import ascmhl_schema_report

from .helpers import make_tree


def seal(root, *, algorithms=("xxh64",), **kwargs):
    result = seal_ascmhl(root, SealOptions(algorithms=algorithms, **kwargs))
    check_package_files(Path(root))
    return result


def check_package_files(root: Path):
    """Every manifest and chain file in the package must be schema-valid."""
    for manifest in root.rglob("ascmhl/*.mhl"):
        code, lines = ascmhl_schema_report(str(manifest))
        assert code == 0, (manifest, lines)
    for chain in root.rglob("ascmhl/ascmhl_chain.xml"):
        code, lines = ascmhl_schema_report(str(chain), directory_file=True)
        assert code == 0, (chain, lines)


def manifest_of(result, root: Path) -> Path:
    """The manifest this operation wrote for the history rooted at `root`."""
    return next(p for p in result.manifests_written if p.parent.parent == root)


def seal_statuses(result):
    return {e.path: e.status for e in result.report.entries}


def find(parent, path) -> etree._Element:
    element = parent.find(path)
    assert element is not None, path
    return element


def block(pattern: str, text: str) -> str:
    match = re.search(pattern, text, re.DOTALL)
    assert match is not None, pattern
    return match.group(0)


class TestWriters:
    def test_manifest_validates_with_every_feature(self, tmp_path):
        manifest = ManifestOut(
            creation_date="2026-01-01T00:00:00Z",
            process="in-place",
            ignore_patterns=[".DS_Store", "ascmhl"],
            root_hash=(
                [HashEntryOut("xxh64", "7680e5f98f4a80fd")],
                [HashEntryOut("xxh64", "8f4a80fd7680e5f9")],
            ),
            references=[("A001/ascmhl/0001_A001_2026-01-01_000000Z.mhl", "c4" + "1" * 88)],
        )
        manifest.files.append(
            _file_entry("Clips/a.mov", [("md5", "0" * 32), ("c4", "c4" + "1" * 88)], previous_path="Clips/old.mov")
        )
        manifest.directories.append(_dir_entry("Clips", [("md5", "0" * 32)], [("md5", "1" * 32)]))
        path = tmp_path / "0001_x_2026-01-01_000000Z.mhl"
        write_manifest(path, manifest)
        code, lines = ascmhl_schema_report(str(path))
        assert code == 0, lines

    def test_hash_format_children_follow_xsd_order(self, tmp_path):
        # c4 must precede md5 regardless of the order entries were provided in.
        manifest = ManifestOut(creation_date="2026-01-01T00:00:00Z", process="in-place")
        manifest.files.append(_file_entry("a", [("md5", "0" * 32), ("c4", "c4" + "1" * 88)]))
        path = tmp_path / "m.mhl"
        write_manifest(path, manifest)
        hash_element = find(etree.parse(str(path)), "{*}hashes/{*}hash")
        tags = [child.tag.rpartition("}")[2] for child in hash_element]
        assert tags == ["path", "c4", "md5", "previousPath"][: len(tags)]
        assert tags[1] == "c4"

    def test_manifest_never_overwrites(self, tmp_path):
        path = tmp_path / "m.mhl"
        manifest = ManifestOut(creation_date="2026-01-01T00:00:00Z", process="in-place")
        write_manifest(path, manifest)
        with pytest.raises(FileExistsError):
            write_manifest(path, manifest)

    def test_directory_file_validates_and_numbers_from_one(self, tmp_path):
        path = tmp_path / "ascmhl_chain.xml"
        write_directory_file(path, [("0001_a.mhl", "c4", "c4" + "1" * 88), ("0002_a.mhl", "c4", "c4" + "2" * 88)])
        code, lines = ascmhl_schema_report(str(path), directory_file=True)
        assert code == 0, lines
        numbers = [el.get("sequencenr") for el in etree.parse(str(path)).iter("{*}hashlist")]
        assert numbers == ["1", "2"]

    def test_manifest_filename_follows_spec_naming(self):
        moment = datetime(2026, 1, 7, 8, 2, 28, tzinfo=UTC)
        assert manifest_filename(1, "A002R2EC", moment) == "0001_A002R2EC_2026-01-07_080228Z.mhl"


class TestSealInitiate:
    def test_fresh_seal_creates_a_valid_history(self, tmp_path):
        root = tmp_path / "card"
        make_tree(root, {"Clips/a.mov": b"aa", "Sidecar.txt": b"s"})
        result = seal(root)

        assert result.seal_code == 0
        assert result.report.code == 21  # verify semantics: everything is new
        assert set(seal_statuses(result).values()) == {Status.NEW}
        manifest = manifest_of(result, root)
        assert re.fullmatch(r"0001_card_\d{4}-\d{2}-\d{2}_\d{6}Z\.mhl", manifest.name)
        assert (root / "ascmhl" / "ascmhl_chain.xml").exists()
        assert ascmhl_history.verify_ascmhl(root).code == 0

    def test_first_generation_records_original_actions(self, tmp_path):
        root = tmp_path / "card"
        make_tree(root, {"a.txt": b"x"})
        result = seal(root)
        text = manifest_of(result, root).read_text()
        assert 'action="original"' in text
        assert "<process>in-place</process>" in text

    def test_creatorinfo_is_lean_and_complete(self, tmp_path):
        # Symmetric with simple-mhl: creationdate/hostname/tool + username
        # author; no location/comment.
        root = tmp_path / "card"
        make_tree(root, {"a.txt": b"x"})
        result = seal(root)
        info = find(etree.parse(str(manifest_of(result, root))), "{*}creatorinfo")
        tags = [child.tag.rpartition("}")[2] for child in info]
        assert tags == ["creationdate", "hostname", "tool", "author"]
        tool = find(info, "{*}tool")
        assert tool.text == "simple-ascmhl"
        assert tool.get("version")

    def test_zero_byte_files_and_empty_directories_are_recorded(self, tmp_path):
        root = tmp_path / "card"
        make_tree(root, {"empty.bin": b"", "emptydir": None})
        result = seal(root)
        text = manifest_of(result, root).read_text()
        assert '<path size="0"' in text
        assert "<directoryhash>" in text  # the empty directory still gets hashes
        assert ascmhl_history.verify_ascmhl(root).code == 0

    def test_empty_scope_seals_to_a_manifest_without_hashes(self, tmp_path):
        root = tmp_path / "empty"
        root.mkdir()
        result = seal(root)
        assert result.seal_code == 0
        text = manifest_of(result, root).read_text()
        assert "<hashes>" not in text
        assert "<roothash>" in text  # the (empty) root still has a pair

    def test_rejects_unknown_algorithm_and_missing_directory(self, tmp_path):
        with pytest.raises(AscmhlSealError, match="unsupported algorithm"):
            seal_ascmhl(tmp_path, SealOptions(algorithms=("xxh32",)))
        with pytest.raises(AscmhlSealError, match="is not a directory"):
            seal_ascmhl(tmp_path / "absent", SealOptions())

    def test_directory_hashes_can_be_disabled(self, tmp_path):
        root = tmp_path / "card"
        make_tree(root, {"Clips/a.mov": b"aa"})
        result = seal(root, directory_hashes=False)
        text = manifest_of(result, root).read_text()
        assert "<roothash>" not in text
        assert "<directoryhash>" not in text


class TestSealAppend:
    def test_second_seal_verifies_and_appends_a_generation(self, tmp_path):
        root = tmp_path / "card"
        make_tree(root, {"Clips/a.mov": b"aa", "Sidecar.txt": b"s"})
        seal(root)
        result = seal(root)

        assert result.seal_code == 0
        assert result.report.code == 0
        assert set(seal_statuses(result).values()) == {Status.OK}
        manifest = manifest_of(result, root)
        assert manifest.name.startswith("0002_")
        assert 'action="verified"' in manifest.read_text()
        chain = (root / "ascmhl" / "ascmhl_chain.xml").read_text()
        assert 'sequencenr="2"' in chain

    def test_tampered_file_records_failed_and_exits_11(self, tmp_path):
        root = tmp_path / "card"
        make_tree(root, {"a.txt": b"good"})
        seal(root)
        (root / "a.txt").write_bytes(b"evil")
        result = seal(root)

        assert result.seal_code == 11
        assert result.report.code == 11
        assert seal_statuses(result)["a.txt"] == Status.MISMATCH
        assert 'action="failed"' in manifest_of(result, root).read_text()

    def test_added_file_gets_original_next_to_verified_records(self, tmp_path):
        root = tmp_path / "card"
        make_tree(root, {"a.txt": b"x"})
        seal(root)
        (root / "b.txt").write_bytes(b"y")
        result = seal(root)

        assert result.seal_code == 0  # recording additions is what seal is for
        assert result.report.code == 21  # verify semantics: drift
        assert seal_statuses(result) == {"a.txt": Status.OK, "b.txt": Status.NEW}
        text = manifest_of(result, root).read_text()
        assert 'action="original"' in text
        assert 'action="verified"' in text

    def test_missing_file_reports_10_and_writes_no_record_for_it(self, tmp_path):
        root = tmp_path / "card"
        make_tree(root, {"a.txt": b"x", "b.txt": b"y"})
        seal(root)
        (root / "b.txt").unlink()
        result = seal(root)

        assert result.seal_code == 10
        assert seal_statuses(result)["b.txt"] == Status.MISSING
        assert "b.txt" not in manifest_of(result, root).read_text()

    def test_verification_format_is_computed_alongside_requested_ones(self, tmp_path):
        # gen 1 in xxh64; a md5 seal must verify via xxh64 (the recorded
        # format, spec 5.6.4) and record BOTH digests as verified — the
        # single-read multi-format flow of Implementation Guidelines 2.3.
        root = tmp_path / "card"
        make_tree(root, {"a.txt": b"x"})
        seal(root, algorithms=("xxh64",))
        result = seal(root, algorithms=("md5",))

        assert result.report.code == 0
        record = find(etree.parse(str(manifest_of(result, root))), "{*}hashes/{*}hash")
        labelled = {c.tag.rpartition("}")[2]: c.get("action") for c in record if c.get("action")}
        assert labelled == {"md5": "verified", "xxh64": "verified"}

    def test_ignore_patterns_grow_and_apply_from_the_record(self, tmp_path):
        root = tmp_path / "card"
        make_tree(root, {"a.txt": b"x"})
        seal(root, ignore_patterns=("*.tmp",))
        (root / "junk.tmp").write_bytes(b"j")
        result = seal(root)  # no CLI patterns this time

        assert "junk.tmp" not in seal_statuses(result)  # recorded pattern still governs
        text = manifest_of(result, root).read_text()
        assert "<pattern>*.tmp</pattern>" in text  # the list only grows

    def test_renaming_a_file_fails_structure_hash_only(self, tmp_path):
        root = tmp_path / "card"
        make_tree(root, {"Clips/a.mov": b"aa"})
        seal(root)
        (root / "Clips" / "a.mov").rename(root / "Clips" / "b.mov")
        result = seal(root)

        assert result.seal_code == 12  # directory-hash mismatch, no file failed
        text = manifest_of(result, root).read_text()
        directoryhash = block(r"<directoryhash>.*?</directoryhash>", text)
        content_block = block(r"<content>.*?</content>", directoryhash)
        structure_block = block(r"<structure>.*?</structure>", directoryhash)
        assert 'action="verified"' in content_block
        assert 'action="failed"' in structure_block

    def test_broken_chain_still_gates_the_operation(self, tmp_path):
        root = tmp_path / "card"
        make_tree(root, {"a.txt": b"x"})
        seal(root)
        (root / "ascmhl" / "ascmhl_chain.xml").unlink()
        with pytest.raises(ascmhl_history.NoChainError):
            seal_ascmhl(root, SealOptions())

    def test_read_only_history_reports_write_failure_not_crash(self, tmp_path):
        root = tmp_path / "card"
        make_tree(root, {"a.txt": b"x"})
        seal(root)
        ascmhl_dir = root / "ascmhl"
        ascmhl_dir.chmod(0o555)
        try:
            result = seal_ascmhl(root, SealOptions(algorithms=("xxh64",)))
        finally:
            ascmhl_dir.chmod(0o755)
        assert result.report.code == 0  # the verification itself succeeded
        assert result.manifests_written == []
        assert result.write_failures
        assert any("cannot write new generation" in n for n in result.report.notices)

    def test_unicode_paths_round_trip_nfc(self, tmp_path):
        root = tmp_path / "card"
        make_tree(root, {"Clips/café.mov": b"aa"})  # NFC on write; APFS may store NFD
        seal(root)
        result = seal(root)
        assert seal_statuses(result) == {"Clips/café.mov": Status.OK}


class TestNestedHistories:
    def test_root_seal_propagates_into_nested_histories(self, tmp_path):
        base = tmp_path / "day"
        make_tree(base, {"A001/Clips/c1.mov": b"c1", "loose.txt": b"l"})
        seal(base / "A001")
        result = seal(base)

        # Bottom-up: the child got generation 2, the root generation 1, both
        # stamped with the operation's shared start time (spec 6.3).
        child_manifest = manifest_of(result, base / "A001")
        root_manifest = manifest_of(result, base)
        assert child_manifest.name.startswith("0002_")
        assert root_manifest.name.startswith("0001_")
        assert child_manifest.name.split("_", 2)[2] == root_manifest.name.split("_", 2)[2]

        # The parent references the child's NEW manifest (spec 5.6.2 Note 3)
        # and takes the child root's directory hashes from its roothash
        # (spec 6.5.2 Note 1); child files are recorded only in the child.
        root_text = root_manifest.read_text()
        assert f"<path>A001/ascmhl/{child_manifest.name}</path>" in root_text
        assert "c1.mov" not in root_text
        child_roothash = block(r"<roothash>.*?</roothash>", child_manifest.read_text())
        parent_a001 = block(r"<directoryhash>.*?</directoryhash>", root_text)
        for digest in re.findall(r">([0-9a-f]{16})<", child_roothash):
            assert digest in parent_a001

        assert ascmhl_history.verify_ascmhl(base).code == 0

    def test_nested_updates_receive_cli_ignore_patterns(self, tmp_path):
        # Spec 5.3.2: data-set-wide updates (ignore patterns included)
        # propagate into nested histories.
        base = tmp_path / "day"
        make_tree(base, {"A001/c1.mov": b"c1", "loose.txt": b"l"})
        seal(base / "A001")
        result = seal(base, ignore_patterns=("*.tmp",))
        child_manifest = manifest_of(result, base / "A001")
        assert "<pattern>*.tmp</pattern>" in child_manifest.read_text()


class TestReferenceToolInterop:
    def test_reference_tool_extends_and_verifies_our_package(self, tmp_path):
        root = tmp_path / "card"
        make_tree(root, {"Clips/a.mov": b"aa", "Sidecar.txt": b"s"})
        seal(root, algorithms=("xxh128",))

        created = CliRunner().invoke(commands.create, [str(root), "-h", "md5"])
        assert created.exit_code == 0, created.output
        verified = CliRunner().invoke(commands.verify, [str(root)])
        assert verified.exit_code == 0, verified.output
        assert ascmhl_history.verify_ascmhl(root).code == 0  # and we accept its generation

    def test_our_verify_accepts_reference_history_we_extended(self, package):
        result = seal(package)
        assert result.report.code == 0
        assert set(seal_statuses(result).values()) == {Status.OK}

    @pytest.mark.parametrize("fmt", ["xxh64", "c4"])
    def test_roothash_digests_match_reference_tool(self, tmp_path, fmt):
        ours, refs = tmp_path / "ours", tmp_path / "refs"
        for d in (ours, refs):
            make_tree(d, {"Clips/x.bin": b"xxdata", "top.txt": b"top"})
        seal(ours, algorithms=(fmt,))
        assert CliRunner().invoke(commands.create, [str(refs), "-h", fmt]).exit_code == 0

        def roothash_digests(root):
            text = next((root / "ascmhl").glob("0001_*.mhl")).read_text()
            return re.findall(r">([^<\s]+)</", block(r"<roothash>.*?</roothash>", text))

        assert roothash_digests(ours) == roothash_digests(refs)


def _file_entry(path, hashes, previous_path=None):
    return FileEntryOut(
        path=path,
        entries=[HashEntryOut(fmt, digest, "original", "2026-01-01T00:00:00Z") for fmt, digest in hashes],
        size=2,
        creation_date="2026-01-01T00:00:00Z",
        last_modification_date="2026-01-01T00:00:00Z",
        previous_path=previous_path,
    )


def _dir_entry(path, content, structure):
    return DirEntryOut(
        path=path,
        content=[HashEntryOut(fmt, digest, "original") for fmt, digest in content],
        structure=[HashEntryOut(fmt, digest, "original") for fmt, digest in structure],
    )
