"""
ASC-MHL verification: the native history loader and dialect policy
(mhl_suite.ascmhl_verify).

The suite owns the ASC-MHL parsing; verification semantics are pinned to the
ASC MHL specification, on two kinds of fixture: packages sealed by the
reference `ascmhl` library (helpers.make_package — proving interop with
histories in the wild) and hand-written histories (helpers.make_asc_package —
covering spec-conformant XML no sealer here can produce):

  - load_history / verify_ascmhl — clean and every failure mode, asserting on
    the structured VerifyReport and the pinned exit codes (10/11/20/21/30-33).
  - verify_ascmhl(size_only=True) — the suite's size-only extension, exit 13
    for a size mismatch, kept distinct from hash mismatch 11.
  - The spec-mandated behaviours (TestSpecConformance and beyond): rename
    chains across generations, original-or-verified entries vouching, ignore
    pattern scoping, default ignore patterns always applying,
    original-generation hashes/sizes winning over later generations, nested
    child histories.
"""

import glob
import re
from pathlib import Path

import pytest
from ascmhl import commands
from click.testing import CliRunner

from mhl_suite import ascmhl_verify as verify
from mhl_suite import hashing, xsd_check
from mhl_suite.algorithms import ALGORITHMS
from mhl_suite.hashing import get_hashes
from mhl_suite.verify import VERIFY_ALL, ErrorKind, Status

from .helpers import asc_hash_record, make_asc_package, make_package, statuses


def _write(path, content):
    """Create `path` (and parents) with `content`; returns the path as str for get_hashes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return str(path)


def verify_ascmhl_size_only(root, **kwargs):
    """verify_ascmhl in size-only mode (named to keep each test body to one line)."""
    return verify.verify_ascmhl(root, size_only=True, **kwargs)


def size_entries(package):
    """{path: VerifyEntry} from a size-only verify of a real, loadable package."""
    return {e.path: e for e in verify_ascmhl_size_only(package).entries}


class TestLoadHistory:
    """The native loader: generations, chain gate, nested histories."""

    def test_generations_load_in_sequence_order(self, package):
        # A second generation in a different format lands after the first.
        CliRunner().invoke(commands.create, [str(package), "-h", "md5"])
        history = verify.load_history(package)
        assert [g.number for g in history.generations] == [1, 2]

    def test_records_carry_original_hash_and_size(self, package):
        history = verify.load_history(package)
        gen1 = history.generations[0]
        rec = gen1.by_path["top.txt"]
        assert rec.size == len(b"hello\n")
        assert any(entry.action == "original" for entry in rec.entries)

    def test_records_carry_dirhash_entries_path_dates_and_hashdates(self, tmp_path):
        # The loader keeps what record-copying operations (rename, flatten)
        # need: directoryhash content/structure entries, the <path> element's
        # date attributes, and per-entry hashdate.
        root = tmp_path / "pkg"
        (root / "Clips").mkdir(parents=True)
        (root / "Clips" / "a.mov").write_bytes(b"x")
        dirhash = (
            "  <directoryhash>\n"
            '   <path creationdate="2026-01-01T00:00:00Z" lastmodificationdate="2026-01-02T00:00:00Z">Clips</path>\n'
            '   <content><xxh64 action="original" hashdate="2026-01-03T00:00:00Z">7680e5f98f4a80fd</xxh64></content>\n'
            '   <structure><xxh64 action="original">8f4a80fd7680e5f9</xxh64></structure>\n'
            "  </directoryhash>"
        )
        file_record = asc_hash_record("Clips/a.mov", "b4bd9633d79bc5b9", "original", size=1)
        make_asc_package(root, [[file_record, dirhash]])

        gen1 = verify.load_history(root).generations[0]
        rec = gen1.by_path["Clips"]
        assert rec.is_directory
        assert (rec.creation_date, rec.last_modification_date) == ("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")
        assert rec.dir_content == [verify.HashEntry("xxh64", "7680e5f98f4a80fd", "original", "2026-01-03T00:00:00Z")]
        assert rec.dir_structure == [verify.HashEntry("xxh64", "8f4a80fd7680e5f9", "original")]
        assert gen1.by_path["Clips/a.mov"].entries == [verify.HashEntry("xxh64", "b4bd9633d79bc5b9", "original")]

    def test_metadata_children_are_not_read_as_hash_entries(self, tmp_path):
        # <metadata> may contain arbitrary XML — an <md5> inside it is custom
        # metadata, not a recorded hash.
        root = tmp_path / "pkg"
        root.mkdir()
        (root / "a.txt").write_bytes(b"x")
        record = (
            "  <hash>\n"
            '   <path size="1">a.txt</path>\n'
            '   <xxh64 action="original">b4bd9633d79bc5b9</xxh64>\n'
            f"   <metadata><md5>{'0' * 32}</md5></metadata>\n"
            "  </hash>"
        )
        make_asc_package(root, [[record]])
        rec = verify.load_history(root).generations[0].by_path["a.txt"]
        assert [e.fmt for e in rec.entries] == ["xxh64"]

    def test_missing_chain_file_is_exit_32(self, package):
        (package / "ascmhl" / "ascmhl_chain.xml").unlink()
        report = verify.verify_ascmhl(package)
        assert report.code == 32
        assert report.notices  # names the missing chain file

    def test_chain_referencing_absent_manifest_is_exit_33(self, package):
        manifest = Path(glob.glob(str(package / "ascmhl" / "*.mhl"))[0])
        manifest.unlink()
        report = verify.verify_ascmhl(package)
        assert report.code == 33

    def test_malformed_generation_manifest_is_exit_40(self, package):
        # Truncate the manifest AND rewrite the chain entry's digest to match,
        # so the parse failure (not the chain gate) is what surfaces.
        manifest = Path(glob.glob(str(package / "ascmhl" / "*.mhl"))[0])
        manifest.write_text("<hashlist><not closed")
        chain = package / "ascmhl" / "ascmhl_chain.xml"
        new_c4 = get_hashes(str(manifest), [ALGORITHMS["c4"].factory])[0]
        chain.write_text(re.sub(r"<c4>[^<]+</c4>", f"<c4>{new_c4}</c4>", chain.read_text()))
        report = verify.verify_ascmhl(package)
        assert report.code == 40
        assert report.malformed


class TestVerifyPackage:
    """verify_ascmhl returns the pinned exit codes and structured per-file outcomes."""

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
        assert "\\" not in entry.path

    def test_ok_entries_carry_the_compared_hash(self, package):
        """Each verified entry records the format and digests actually compared."""
        report = verify.verify_ascmhl(package)
        entry = next(e for e in report.entries if e.path == "top.txt")
        (cmp_,) = entry.hashes
        assert cmp_.tag == "xxh64"
        assert cmp_.ok
        assert cmp_.expected.lower() == cmp_.computed.lower()

    def test_progress_reports_each_hashed_file(self, package):
        seen = []
        report = verify.verify_ascmhl(package, on_progress=seen.append)
        assert report.code == 0
        assert len(seen) == 3  # one chunk per (tiny) hashed file

    def test_tampered_file_is_mismatch_exit_11(self, package):
        (package / "A/a1.txt").write_bytes(b"CORRUPT\n")
        report = verify.verify_ascmhl(package)
        assert report.code == 11
        assert statuses(report)["A/a1.txt"] == "mismatch"

    def test_size_mismatch_skips_hash_computation(self, package, monkeypatch):
        """
        A size-mismatched file is settled by the stat() pre-check and never
        hashed — the shared engine gives ASC-MHL the same short-circuit as
        classic MHL: a size difference already proves modification, so
        reading the whole file would add nothing.
        """
        (package / "top.txt").write_bytes(b"hello\nplus more\n")  # 6 recorded, 16 on disk
        read: list[str] = []
        real_get_hashes = hashing.get_hashes

        def spy(filepath, factories, on_progress=None):
            read.append(Path(filepath).name)
            return real_get_hashes(filepath, factories, on_progress=on_progress)

        monkeypatch.setattr(hashing, "get_hashes", spy)
        report = verify.verify_ascmhl(package)
        assert report.code == 11
        entry = next(e for e in report.entries if e.path == "top.txt")
        assert entry.size_mismatch
        assert entry.hashes == []  # no comparison was ever computed
        assert "top.txt" not in read, "size-mismatched file must not be read for hashing"

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

    def test_mismatch_beats_new_files(self, package):
        (package / "A/new.txt").write_bytes(b"surprise\n")
        (package / "top.txt").write_bytes(b"CORRUPT")
        report = verify.verify_ascmhl(package)
        assert report.code == 11

    def test_default_ignore_patterns_always_apply(self, package, monkeypatch):
        """
        The spec-mandated default ignore set (.DS_Store, ascmhl) always applies,
        even when a manifest recorded custom ignore patterns without the
        defaults. Otherwise verify would descend into ascmhl/ and flag its
        manifests and chain as new files (exit 21). We simulate such a foreign
        manifest by returning a custom-only pattern list.
        """
        monkeypatch.setattr(verify.History, "latest_ignore_patterns", lambda self: ["*.tmp"])
        report = verify.verify_ascmhl(package)
        assert report.code == 0
        assert set(statuses(report).values()) == {"ok"}

    def test_recorded_ignore_patterns_are_honoured(self, tmp_path):
        """A pattern recorded at seal time keeps its matches out of new-file detection."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "clip.mov").write_bytes(b"x" * 16)
        result = CliRunner().invoke(commands.create, [str(pkg), "-h", "xxh64", "-i", "*.tmp"])
        assert result.exit_code == 0, result.output
        (pkg / "scratch.tmp").write_bytes(b"ignored")
        report = verify.verify_ascmhl(pkg)
        assert report.code == 0

    def test_no_history_is_exit_30(self, tmp_path):
        (tmp_path / "bare.txt").write_bytes(b"x")
        report = verify.verify_ascmhl(tmp_path)
        assert report.code == 30

    def test_renamed_file_verifies_against_original_hash(self, package):
        """
        A rename recorded in a later generation (previousPath) resolves back to
        the original generation's digest, so the renamed file still verifies.
        """
        (package / "top.txt").rename(package / "renamed.txt")
        result = CliRunner().invoke(commands.create, [str(package), "-h", "xxh64", "--detect_renaming"])
        assert result.exit_code == 0, result.output
        report = verify.verify_ascmhl(package)
        assert report.code == 0
        assert statuses(report)["renamed.txt"] == "ok"

    def test_unreadable_directory_is_reported_not_silenced(self, package):
        """
        A directory that cannot be scanned during new-file detection surfaces
        as a per-file failure — new files inside it would otherwise go
        undetected without a trace.
        """
        locked = package / "locked"
        locked.mkdir()
        (locked / "unseen.txt").write_bytes(b"x")
        locked.chmod(0o000)
        try:
            report = verify.verify_ascmhl(package)
        finally:
            locked.chmod(0o755)
        assert report.code == 11
        (entry,) = [e for e in report.entries if e.status == Status.ERROR]
        assert entry.path == "locked"
        assert entry.error == ErrorKind.IO
        assert "cannot scan directory" in entry.detail

    @pytest.mark.parametrize("hash_format", ["md5", "c4", "xxh128", "xxh3", "sha1"])
    def test_all_spec_hash_formats_round_trip(self, tmp_path, hash_format):
        """Every ASCMHL.xsd hash format — including C4's base-58 encoding —
        verifies natively and detects tampering."""
        pkg = make_package(tmp_path / "pkg", {"clip.mov": b"x" * 64}, hash_format=hash_format)
        assert verify.verify_ascmhl(pkg).code == 0
        (pkg / "clip.mov").write_bytes(b"y" * 64)
        assert verify.verify_ascmhl(pkg).code == 11


def _multi_format_block(path: str, size: int, formats: dict[str, str], action: str = "original") -> str:
    """One ASC-MHL <hash> block recording several formats for a single path."""
    lines = "\n".join(f'   <{fmt} action="{action}">{digest}</{fmt}>' for fmt, digest in formats.items())
    return f'  <hash>\n   <path size="{size}">{path}</path>\n{lines}\n  </hash>'


def _entry(report, path):
    return next(e for e in report.entries if e.path == path)


class TestMultiHashSelection:
    """A file recording several hash formats. Spec 5.6.4 verifies against "one of
    the algorithms recorded", so the default checks a single hash (the original,
    matching the reference tool); the suite additionally lets a caller check
    every recorded format (`all`) or a chosen one, and rejects a format that
    wasn't recorded."""

    @pytest.fixture
    def package(self, tmp_path):
        content = b"multi-format payload\n"
        path = tmp_path / "clip.txt"
        path.write_bytes(content)
        formats = {
            "xxh64": get_hashes(str(path), [ALGORITHMS["xxh64"].factory])[0],
            "md5": get_hashes(str(path), [ALGORITHMS["md5"].factory])[0],
        }
        return make_asc_package(tmp_path, [[_multi_format_block("clip.txt", len(content), formats)]])

    def test_default_checks_only_the_original_format(self, package):
        # No selection → a single hash, the reference tool's behaviour.
        entry = _entry(verify.verify_ascmhl(package), "clip.txt")
        assert [h.tag for h in entry.hashes] == ["xxh64"]

    def test_all_checks_every_recorded_format(self, package):
        report = verify.verify_ascmhl(package, selection=VERIFY_ALL)
        assert report.code == 0
        assert {h.tag for h in _entry(report, "clip.txt").hashes} == {"xxh64", "md5"}

    def test_named_format_checks_just_that_one(self, package):
        entry = _entry(verify.verify_ascmhl(package, selection=["md5"]), "clip.txt")
        assert [h.tag for h in entry.hashes] == ["md5"]

    def test_unrecorded_format_is_hash_not_stored(self, package):
        entry = _entry(verify.verify_ascmhl(package, selection=["sha1"]), "clip.txt")
        assert entry.status == Status.ERROR
        assert entry.error == ErrorKind.HASH_NOT_STORED

    def test_xxh32_element_is_not_a_valid_asc_format(self, tmp_path):
        # <xxh32> is absent from ASCMHL.xsd's HashType, so the parser ignores it:
        # a file recording xxh32 alongside xxh64 verifies on xxh64 alone, even
        # under `all`, and xxh32 is never a selectable format.
        content = b"legacy format\n"
        path = tmp_path / "clip.txt"
        path.write_bytes(content)
        formats = {
            "xxh32": get_hashes(str(path), [ALGORITHMS["xxh32"].factory])[0],
            "xxh64": get_hashes(str(path), [ALGORITHMS["xxh64"].factory])[0],
        }
        pkg = make_asc_package(tmp_path, [[_multi_format_block("clip.txt", len(content), formats)]])
        entry = _entry(verify.verify_ascmhl(pkg, selection=VERIFY_ALL), "clip.txt")
        assert [h.tag for h in entry.hashes] == ["xxh64"]

    def test_all_catches_a_bad_secondary_hash_the_default_misses(self, tmp_path):
        # xxh64 correct but md5 deliberately wrong: the default (xxh64 only)
        # passes, while `all` recomputes md5 and catches the discrepancy.
        content = b"defense in depth\n"
        path = tmp_path / "clip.txt"
        path.write_bytes(content)
        formats = {"xxh64": get_hashes(str(path), [ALGORITHMS["xxh64"].factory])[0], "md5": "0" * 32}
        pkg = make_asc_package(tmp_path, [[_multi_format_block("clip.txt", len(content), formats)]])
        assert verify.verify_ascmhl(pkg).code == 0
        assert verify.verify_ascmhl(pkg, selection=VERIFY_ALL).code == 11


class TestSpecConformance:
    """
    Verification semantics the specification spells out, exercised on
    hand-written histories (helpers.make_asc_package) — spec-conformant XML
    such as rename records labeled `verified` (5.6.4) or writer defects such
    as missing action attributes, neither of which a sealer here can produce.
    """

    def test_rename_chain_resolves_across_generations(self, tmp_path):
        """
        A→B→C over three generations, the rename records labeled `verified`
        as spec 5.6.4 prescribes: the original hash lives under A in gen 1
        and must be located through the whole previousPath chain (spec 5.3.3
        "renamed throughout the lifecycle").
        """
        content = b"payload"
        digest = get_hashes(_write(tmp_path / "pkg" / "C.txt", content), [ALGORITHMS["xxh64"].factory])[0]
        make_asc_package(
            tmp_path / "pkg",
            [
                [asc_hash_record("A.txt", digest, "original", size=len(content))],
                [asc_hash_record("B.txt", digest, "verified", previous_path="A.txt")],
                [asc_hash_record("C.txt", digest, "verified", previous_path="B.txt")],
            ],
        )
        report = verify.verify_ascmhl(tmp_path / "pkg")
        assert report.code == 0
        assert statuses(report) == {"C.txt": Status.OK}

    def test_verified_entry_vouches_when_no_original_exists(self, tmp_path):
        """
        Gen 1 lost its action attributes (a non-conforming writer); gen 2
        recorded a `verified` hash. Spec 5.6.4 allows verification against
        original OR verified entries.
        """
        content = b"payload"
        digest = get_hashes(_write(tmp_path / "pkg" / "clip.mov", content), [ALGORITHMS["xxh64"].factory])[0]
        make_asc_package(
            tmp_path / "pkg",
            [
                [asc_hash_record("clip.mov", digest, None, size=len(content))],
                [asc_hash_record("clip.mov", digest, "verified")],
            ],
        )
        report = verify.verify_ascmhl(tmp_path / "pkg")
        assert report.code == 0
        assert statuses(report) == {"clip.mov": Status.OK}

    @pytest.mark.parametrize("action", [None, "failed"])
    def test_record_with_no_usable_entry_is_a_failure_not_new(self, tmp_path, action):
        """
        Unlabeled and `failed` entries cannot be used for verification (spec
        5.6.4), and the file *is* recorded, so it is never an unknown/"new"
        file (spec 5.6.3): present it is an unsuccessful verification (11),
        absent a missing file (10).
        """
        content = b"payload"
        digest = get_hashes(_write(tmp_path / "pkg" / "clip.mov", content), [ALGORITHMS["xxh64"].factory])[0]
        good = get_hashes(_write(tmp_path / "pkg" / "good.mov", content), [ALGORITHMS["xxh64"].factory])[0]
        make_asc_package(
            tmp_path / "pkg",
            [
                [
                    asc_hash_record("clip.mov", digest, action, size=len(content)),
                    asc_hash_record("good.mov", good, "original", size=len(content)),
                ]
            ],
        )

        report = verify.verify_ascmhl(tmp_path / "pkg")
        assert report.code == 11
        entry = {e.path: e for e in report.entries}["clip.mov"]
        assert entry.status == Status.ERROR
        assert entry.error == ErrorKind.UNUSABLE_HASH

        (tmp_path / "pkg" / "clip.mov").unlink()
        report = verify.verify_ascmhl(tmp_path / "pkg")
        assert report.code == 10
        assert statuses(report) == {"clip.mov": Status.MISSING, "good.mov": Status.OK}

    def test_nested_history_ignore_patterns_apply_in_their_subtree(self, tmp_path):
        """
        A nested history's recorded patterns govern its own subtree (spec
        5.6.1.2) — but only its subtree: the same name outside stays an
        unknown file.
        """
        root = tmp_path / "pkg"
        make_package(root / "sub", {"child.mov": b"child\n"})
        result = CliRunner().invoke(commands.create, [str(root / "sub"), "-h", "xxh64", "-i", "*.tmp"])
        assert result.exit_code == 0, result.output
        make_package(root, {"top.txt": b"top\n"})

        (root / "sub" / "scratch.tmp").write_bytes(b"ignored in child scope")
        (root / "scratch.tmp").write_bytes(b"unknown at root scope")
        report = verify.verify_ascmhl(root)
        assert report.code == 21
        assert statuses(report)["scratch.tmp"] == Status.NEW
        assert "sub/scratch.tmp" not in statuses(report)


class TestSchemaCheck:
    """ascmhl_schema_report validates against the bundled XSDs in-process."""

    def test_valid_manifest(self, package):
        manifest = glob.glob(str(package / "ascmhl" / "*.mhl"))[0]
        assert xsd_check.ascmhl_schema_report(manifest) == (0, [])

    def test_valid_chain(self, package):
        chain = package / "ascmhl" / "ascmhl_chain.xml"
        assert xsd_check.ascmhl_schema_report(chain, directory_file=True) == (0, [])

    def test_malformed_xml_is_exit_40(self, tmp_path):
        bad = tmp_path / "bad.mhl"
        bad.write_text("<hashlist><not closed")
        code, lines = xsd_check.ascmhl_schema_report(bad)
        assert code == 40
        assert lines

    def test_schema_noncompliant_is_exit_41(self, tmp_path):
        wrong = tmp_path / "wrong.mhl"
        wrong.write_text('<?xml version="1.0"?><notmhl/>')
        code, _lines = xsd_check.ascmhl_schema_report(wrong)
        assert code == 41

    def test_unreadable_file_is_exit_40(self):
        """
        An unreadable/absent file raises OSError inside the parse, surfaced as
        the malformed-XML code (not a crash).
        """
        code, lines = xsd_check.ascmhl_schema_report("/no/such/path/ghost.mhl")
        assert code == 40
        assert lines

    def test_missing_bundled_xsd_surfaces_error_code(self, package, monkeypatch):
        """
        A broken install (bundled XSD absent) is reported as the generic error
        code rather than raising out of the schema check.
        """
        manifest = glob.glob(str(package / "ascmhl" / "*.mhl"))[0]
        monkeypatch.setattr(
            xsd_check, "bundled_xsd_path", lambda name: (_ for _ in ()).throw(FileNotFoundError(f"missing: {name}"))
        )
        code, lines = xsd_check.ascmhl_schema_report(manifest)
        assert code == 1
        assert lines
        assert "missing" in lines[0]

    def test_bundled_xsd_path_raises_for_unknown_schema(self):
        """
        The path resolver raises FileNotFoundError for a schema name that isn't
        shipped in the mhl_suite.xsd package.
        """
        with pytest.raises(FileNotFoundError, match="Could not locate"):
            xsd_check.bundled_xsd_path("does-not-exist.xsd")


class TestSizeOnlyVerify:
    """
    verify_ascmhl(size_only=True) compares recorded sizes to disk, reading no
    media bytes; the history load doubles as the integrity gate.
    """

    def test_clean_package_passes_without_hashing(self, package):
        seen = []
        report = verify_ascmhl_size_only(package, on_progress=seen.append)
        assert report.code == 0
        assert set(statuses(report).values()) == {"ok"}
        assert seen == []  # size-only reads no file bytes, so progress never ticks

    def test_clean_entries_are_flagged_size_only(self, package):
        report = verify_ascmhl_size_only(package)
        assert report.size_only_mode
        assert all(e.size_only for e in report.entries)

    def test_size_change_is_exit_13_not_11(self, package):
        # Append bytes: the file's hash AND size now differ, but size-only
        # reports the size mismatch (13) without ever hashing — distinct from
        # hash 11.
        (package / "top.txt").write_bytes(b"hello\nplus more\n")
        report = verify_ascmhl_size_only(package)
        assert report.code == 13
        assert statuses(report)["top.txt"] == "mismatch"

    def test_size_mismatch_carries_semantic_sizes(self, package):
        (package / "top.txt").write_bytes(b"hello\nplus more\n")
        report = verify_ascmhl_size_only(package)
        entry = next(e for e in report.entries if e.status == Status.MISMATCH)
        assert entry.size_mismatch
        assert entry.recorded_size == len(b"hello\n")
        assert entry.actual_size == len(b"hello\nplus more\n")

    def test_missing_file_is_exit_10(self, package):
        (package / "top.txt").unlink()
        report = verify_ascmhl_size_only(package)
        assert report.code == 10
        assert statuses(report)["top.txt"] == "missing"

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
        # The history load is the integrity gate: corrupting a generation
        # manifest so it no longer matches its own recorded chain hash makes
        # the load fail (31), and size-only reports that manifest error instead
        # of a size verdict.
        manifest = Path(glob.glob(str(package / "ascmhl" / "*.mhl"))[0])
        manifest.write_text(manifest.read_text().replace("<creatorinfo>", "<creatorinfo> "))
        report = verify_ascmhl_size_only(package)
        assert report.code == 31
        assert report.entries == []
        assert report.notices


class TestSizeOnlyRecordedSet:
    """
    The size-only pass covers exactly the recorded verifiable set: original
    generation sizes, nested child histories, no directory entries.
    """

    def test_matching_size_is_ok(self, package):
        assert size_entries(package)["top.txt"].status == Status.OK

    def test_wrong_size_is_mismatch_with_sizes(self, package):
        (package / "top.txt").write_bytes(b"x")  # 1 byte on disk, 6 recorded
        e = size_entries(package)["top.txt"]
        assert e.status == Status.MISMATCH
        assert (e.actual_size, e.recorded_size) == (1, 6)

    def test_absent_file_is_missing(self, package):
        (package / "top.txt").unlink()
        assert size_entries(package)["top.txt"].status == Status.MISSING

    def test_missing_recorded_size_is_ok_not_a_failure(self, tmp_path):
        # The size attribute is optional, and some writers omit it for a
        # 0-byte file (as the fixture sealer does here). Absence carries no
        # meaning, so an existing file with no recorded size is verified for
        # existence only and passes.
        pkg = make_package(tmp_path / "pkg", {"empty.mov": b"", "full.mov": b"data"})
        results = size_entries(pkg)
        assert results["empty.mov"].status == Status.OK
        assert results["empty.mov"].recorded_size is None
        assert results["full.mov"].status == Status.OK

    def test_missing_recorded_size_still_checks_existence(self, tmp_path):
        # A sizeless record is existence-checked, not blindly passed: if its
        # file is gone it is still reported missing.
        pkg = make_package(tmp_path / "pkg", {"empty.mov": b""})
        (pkg / "empty.mov").unlink()
        assert size_entries(pkg)["empty.mov"].status == Status.MISSING

    def test_directory_and_child_reference_entries_are_skipped(self, package):
        # The recorded set includes the A/ directory hash; only real files
        # carry verifiable content, so the directory entry never leaks into
        # the results.
        assert set(size_entries(package)) == {"top.txt", "A/a1.txt", "A/a2.txt"}

    def test_nested_child_history_files_are_covered(self, tmp_path):
        # A sub-folder sealed as its own ASC-MHL history, then wrapped by a
        # parent seal. The parent's size verify must descend into the child,
        # matching the hash path (nested histories are processed recursively).
        root = tmp_path / "pkg"
        make_package(root / "sub", {"child.mov": b"child\n"})  # child history first
        make_package(root, {"top.txt": b"top\n"})  # parent wraps it (references the child)
        results = size_entries(root)
        assert results["sub/child.mov"].status == Status.OK
        assert results["top.txt"].status == Status.OK

    def test_original_generation_size_wins(self, tmp_path):
        # Seal a.mov at 100 bytes, then grow it to 200 and re-seal (creating gen
        # 2). The recorded ORIGINAL size is gen1's 100, so the on-disk 200 must
        # mismatch — proving we compare against the first generation, not gen2.
        pkg = make_package(tmp_path / "pkg", {"a.mov": b"x" * 100})
        (pkg / "a.mov").write_bytes(b"x" * 200)
        CliRunner().invoke(commands.create, [str(pkg), "-h", "xxh64"])  # gen 2 records size 200
        e = size_entries(pkg)["a.mov"]
        assert e.status == Status.MISMATCH
        assert (e.actual_size, e.recorded_size) == (200, 100)

    def test_path_escaping_root_is_blocked(self, package, monkeypatch):
        # A manifest can't normally record an escaping path, so stub the
        # recorded set to force the engine's traversal guard.
        history = verify.load_history(package)
        record = verify.MediaRecord(path="../escape.txt", size=3)
        monkeypatch.setattr(
            verify,
            "collect_recorded",
            lambda hist, ignore: [
                verify.Recorded(
                    path="../escape.txt", record=record, original=("md5", "0" * 32), usable=[("md5", "0" * 32)]
                )
            ],
        )
        report = verify.verify_ascmhl(package, size_only=True, history=history)
        (entry,) = report.entries
        assert entry.status == Status.ERROR
        assert entry.error == ErrorKind.TRAVERSAL
        assert report.code == 13  # a blocked path is a size-only failure, not a pass

    def test_file_vanishing_after_resolution_is_missing(self, package, monkeypatch):
        # Models the resolve->getsize race: the entry resolves, then getsize
        # raises. (os.path is a shared module: patching it here is seen by the
        # engine's stat call.)
        def _raise(_path):
            raise OSError(2, "vanished")

        monkeypatch.setattr("mhl_suite.verify.os.path.getsize", _raise)
        assert size_entries(package)["top.txt"].status == Status.MISSING
