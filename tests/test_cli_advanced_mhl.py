"""
The advanced-mhl CLI: argument handling, smart dispatch, rendering, and the
exit-code contract (generate semantics vs verify semantics, pinned ASC codes).
"""

import os
import unicodedata

import pytest

from mhl_suite.ascmhl_history import load_history

from .helpers import make_tree


def generated_tree(ascmhl_cli, tmp_path, spec):
    root = tmp_path / "pkg"
    make_tree(root, spec)
    rc, _, _ = ascmhl_cli(["generate", root])
    assert rc == 0
    return root


def generation_count(root):
    return len(list((root / "ascmhl").glob("*.mhl")))


class TestGenerate:
    def test_generate_initiates_a_history(self, ascmhl_cli, tmp_path):
        root = tmp_path / "card"
        make_tree(root, {"Clips/a.mov": b"aa"})
        rc, out, err = ascmhl_cli(["generate", root])
        assert (rc, err) == (0, "")
        assert out == ""  # quiet on success, like simple-mhl
        assert generation_count(root) == 1

    def test_generate_on_managed_appends_a_generation(self, ascmhl_cli, tmp_path):
        root = generated_tree(ascmhl_cli, tmp_path, {"a.txt": b"x"})
        rc, _, _ = ascmhl_cli(["generate", root])
        assert rc == 0
        assert generation_count(root) == 2

    def test_generate_records_new_files_without_failing(self, ascmhl_cli, tmp_path):
        root = generated_tree(ascmhl_cli, tmp_path, {"a.txt": b"x"})
        (root / "b.txt").write_bytes(b"y")
        rc, _, _ = ascmhl_cli(["generate", root])
        assert rc == 0  # recording additions is the point (generate semantics)
        assert generation_count(root) == 2

    def test_verbose_generate_lists_files_and_manifest(self, ascmhl_cli, tmp_path):
        root = tmp_path / "card"
        make_tree(root, {"Clips/a.mov": b"aa"})
        rc, out, _ = ascmhl_cli(["generate", "-v", root])
        assert rc == 0
        # The CLI renders recorded (POSIX-slash) paths with the platform
        # separator for the terminal (to_terminal_sep).
        assert f"[NEW] {os.path.join('Clips', 'a.mov')}" in out
        assert "Created new generation:" in out

    def test_algorithm_selection_and_rejection(self, ascmhl_cli, tmp_path):
        root = tmp_path / "card"
        make_tree(root, {"a.txt": b"x"})
        rc, _, _ = ascmhl_cli(["generate", root, "-a", "md5,c4"])
        assert rc == 0
        manifest = next((root / "ascmhl").glob("*.mhl")).read_text()
        assert "<md5" in manifest
        assert "<c4" in manifest

        rc, _, err = ascmhl_cli(["generate", root, "-a", "sha256"])
        assert rc == 2
        assert "unsupported algorithm" in err

    def test_default_algorithm_is_xxh128(self, ascmhl_cli, tmp_path):
        root = generated_tree(ascmhl_cli, tmp_path, {"a.txt": b"x"})
        assert "<xxh128" in next((root / "ascmhl").glob("*.mhl")).read_text()

    def test_ignore_option_is_recorded_and_applied(self, ascmhl_cli, tmp_path):
        root = tmp_path / "card"
        make_tree(root, {"a.txt": b"x", "junk.tmp": b"j"})
        rc, _, _ = ascmhl_cli(["generate", root, "-i", "*.tmp"])
        assert rc == 0
        history = load_history(root)
        assert "*.tmp" in history.latest_ignore_patterns()
        assert "junk.tmp" not in {r.path for r in history.generations[0].records}

    def test_no_directory_hashes_flag(self, ascmhl_cli, tmp_path):
        root = tmp_path / "card"
        make_tree(root, {"Clips/a.mov": b"aa"})
        rc, _, _ = ascmhl_cli(["generate", root, "-n"])
        assert rc == 0
        assert "<roothash>" not in next((root / "ascmhl").glob("*.mhl")).read_text()

    def test_tamper_reports_failure(self, ascmhl_cli, tmp_path):
        root = generated_tree(ascmhl_cli, tmp_path, {"a.txt": b"good"})
        (root / "a.txt").write_bytes(b"evil")
        rc, out, _ = ascmhl_cli(["generate", root])
        assert rc == 11
        assert "[ERROR] hash mismatch: a.txt" in out


class TestCheck:
    def test_check_writes_nothing(self, ascmhl_cli, tmp_path):
        root = generated_tree(ascmhl_cli, tmp_path, {"a.txt": b"x"})
        rc, _, _ = ascmhl_cli(["check", root])
        assert rc == 0
        assert generation_count(root) == 1

    def test_new_files_exit_21_under_verify_semantics(self, ascmhl_cli, tmp_path):
        root = generated_tree(ascmhl_cli, tmp_path, {"a.txt": b"x"})
        (root / "b.txt").write_bytes(b"y")
        rc, out, _ = ascmhl_cli(["check", root])
        assert rc == 21
        assert "unknown file: b.txt" in out
        assert generation_count(root) == 1  # read-only

    def test_check_without_history_is_exit_30(self, ascmhl_cli, tmp_path):
        (tmp_path / "bare").mkdir()
        rc, _, err = ascmhl_cli(["check", tmp_path / "bare"])
        assert rc == 30
        assert "Missing ASC MHL history" in err

    def test_missing_file_exit_10(self, ascmhl_cli, tmp_path):
        root = generated_tree(ascmhl_cli, tmp_path, {"a.txt": b"x", "b.txt": b"y"})
        (root / "b.txt").unlink()
        rc, out, _ = ascmhl_cli(["check", root])
        assert rc == 10
        assert "missing file: b.txt" in out

    def test_size_only_skips_hashing_and_passes(self, ascmhl_cli, tmp_path):
        root = generated_tree(ascmhl_cli, tmp_path, {"a.txt": b"x"})
        rc, _, _ = ascmhl_cli(["check", "--size-only", root])
        assert rc == 0

    def test_size_only_detects_size_change(self, ascmhl_cli, tmp_path):
        root = generated_tree(ascmhl_cli, tmp_path, {"a.txt": b"x"})
        (root / "a.txt").write_bytes(b"much longer content")
        rc, _, _ = ascmhl_cli(["check", "-S", root])
        assert rc == 13


class TestDiff:
    def test_diff_reports_without_writing(self, ascmhl_cli, tmp_path):
        root = generated_tree(ascmhl_cli, tmp_path, {"a.txt": b"x"})
        (root / "new.txt").write_bytes(b"n")
        rc, out, _ = ascmhl_cli(["diff", root])
        assert rc == 21
        assert "unknown file: new.txt" in out
        assert generation_count(root) == 1


class TestRename:
    def test_rename_records_and_reports(self, ascmhl_cli, tmp_path):
        root = generated_tree(ascmhl_cli, tmp_path, {"a.txt": b"x"})
        rc, out, _ = ascmhl_cli(["rename", "-v", root / "a.txt", root / "b.txt"])
        assert rc == 0
        assert "Created new generation:" in out
        assert (root / "b.txt").exists()
        assert generation_count(root) == 2

    def test_rename_outside_history_is_exit_30(self, ascmhl_cli, tmp_path):
        (tmp_path / "a.txt").write_bytes(b"x")
        rc, _, err = ascmhl_cli(["rename", tmp_path / "a.txt", tmp_path / "b.txt"])
        assert rc == 30
        assert "Missing ASC MHL history" in err

    def test_rename_usage_errors_exit_2(self, ascmhl_cli, tmp_path):
        root = generated_tree(ascmhl_cli, tmp_path, {"a.txt": b"x", "b.txt": b"y"})
        rc, _, err = ascmhl_cli(["rename", root / "a.txt", root / "b.txt"])
        assert rc == 2
        assert "already exists" in err


class TestFlatten:
    def test_flatten_writes_packinglist_and_prints_it(self, ascmhl_cli, tmp_path):
        root = generated_tree(ascmhl_cli, tmp_path, {"a.txt": b"x"})
        rc, out, _ = ascmhl_cli(["flatten", root, tmp_path / "out"])
        assert rc == 0
        assert "Created packing list:" in out
        assert list((tmp_path / "out").glob("packinglist__*.mhl"))
        assert (tmp_path / "out" / "ascmhl_collection.xml").exists()


class TestSchemaCheck:
    def test_validates_manifest_and_chain(self, ascmhl_cli, tmp_path):
        root = generated_tree(ascmhl_cli, tmp_path, {"a.txt": b"x"})
        manifest = next((root / "ascmhl").glob("*.mhl"))
        assert ascmhl_cli(["xsd-schema-check", manifest])[0] == 0
        assert ascmhl_cli(["xsd-schema-check", root / "ascmhl" / "ascmhl_chain.xml"])[0] == 0

    def test_invalid_document_fails(self, ascmhl_cli, tmp_path):
        bad = tmp_path / "bad.mhl"
        bad.write_text('<?xml version="1.0"?><hashlist version="2.0"/>')
        rc, _, err = ascmhl_cli(["xsd-schema-check", bad])
        assert rc == 41
        assert err


class TestSealContextMetadata:
    """
    Every generation records where its byte-verbatim paths came from — OS,
    kernel, source volume filesystem — as a namespaced mhls:sealcontext
    element inside the hashlist-level <metadata> slot (the schema's anyType
    wildcard, so the manifest stays valid against the official XSD and other
    readers skip it as unknown vendor metadata).
    """

    def test_generation_records_namespaced_sealcontext(self, ascmhl_cli, tmp_path):
        root = generated_tree(ascmhl_cli, tmp_path, {"a.txt": b"x"})
        manifest = next((root / "ascmhl").glob("*.mhl"))
        text = manifest.read_text(encoding="utf-8")
        assert 'xmlns:mhls="urn:mhl-suite:sealcontext:1"' in text
        assert "mhls:sealcontext" in text
        assert 'os="' in text
        assert 'kernel="' in text
        # And the manifest still validates against the official ASC XSD.
        assert ascmhl_cli(["xsd-schema-check", manifest])[0] == 0

    def test_own_reader_ignores_the_metadata(self, ascmhl_cli, tmp_path):
        root = generated_tree(ascmhl_cli, tmp_path, {"a.txt": b"x"})
        rc, out, err = ascmhl_cli(["check", root])
        assert (rc, out, err) == (0, "", "")


class TestSmartDispatch:
    def test_bare_directory_without_history_generates(self, ascmhl_cli, tmp_path):
        root = tmp_path / "card"
        make_tree(root, {"a.txt": b"x"})
        rc, _, _ = ascmhl_cli([root])
        assert rc == 0
        assert generation_count(root) == 1

    def test_bare_directory_with_history_appends(self, ascmhl_cli, tmp_path):
        root = generated_tree(ascmhl_cli, tmp_path, {"a.txt": b"x"})
        rc, _, _ = ascmhl_cli([root])
        assert rc == 0
        assert generation_count(root) == 2  # generate appended

    def test_bare_manifest_file_schema_checks(self, ascmhl_cli, tmp_path):
        root = generated_tree(ascmhl_cli, tmp_path, {"a.txt": b"x"})
        manifest = next((root / "ascmhl").glob("*.mhl"))
        assert ascmhl_cli([manifest])[0] == 0

    def test_version_flag(self, ascmhl_cli):
        rc, out, _ = ascmhl_cli(["--version"])
        assert rc == 0
        assert out.strip()


class TestUnicodeForms:
    """
    The verbatim-path contract and its verify-side counterpart, end to end.

    Seal records the walk's bytes untouched (byte-exact verifiers match <path>
    against readdir literally). Verify then reconciles a name whose
    normalization form drifted in a later round-trip (here simulated with an
    in-place rename to the equivalent byte form) via the gated NFC-equivalence
    fallback: check and diff stay clean, and a follow-up generate appends
    `verified`, not a fresh original. Names are explicit escapes — a source
    literal's byte form is host-dependent.
    """

    _NFC = "ros\u00e9.txt"
    _NFD = "rose\u0301.txt"

    def _card(self, ascmhl_cli, tmp_path, name):
        root = tmp_path / "card"
        root.mkdir()
        (root / name).write_bytes(b"payload")
        (root / "plain.txt").write_bytes(b"control")
        rc, _, _ = ascmhl_cli(["generate", root])
        assert rc == 0
        return root

    def _drift(self, root, old, new):
        """
        Rename old -> new (equivalent byte forms); skip when the host filesystem
        does not let the byte form change (it would make the drift assertions
        vacuous).
        """
        os.rename(root / old, root / new)
        if new not in os.listdir(root):
            pytest.skip("host filesystem does not preserve the renamed normalization form")

    def test_generate_records_walked_bytes_verbatim(self, ascmhl_cli, tmp_path):
        root = self._card(ascmhl_cli, tmp_path, self._NFD)
        walked = next(n for n in os.listdir(root) if unicodedata.normalize("NFC", n) == self._NFC)
        manifest = next((root / "ascmhl").glob("0001*.mhl")).read_bytes()
        other = self._NFC if walked == self._NFD else self._NFD
        assert walked.encode("utf-8") in manifest
        assert other.encode("utf-8") not in manifest

    def test_check_and_diff_stay_clean_after_form_drift(self, ascmhl_cli, tmp_path):
        """
        The nfd-fixture regression: a drifted name must neither read as an
        unknown file nor leave its record missing.
        """
        root = self._card(ascmhl_cli, tmp_path, self._NFC)
        self._drift(root, self._NFC, self._NFD)

        rc, out, err = ascmhl_cli(["check", root])
        assert (rc, out, err) == (0, "", "")
        rc, out, err = ascmhl_cli(["diff", root])
        assert (rc, out, err) == (0, "", "")

    def test_generate_appends_verified_after_form_drift(self, ascmhl_cli, tmp_path):
        """
        A drifted name matches its record by identity: the new generation
        verifies it rather than restarting its lineage as an original.
        """
        root = self._card(ascmhl_cli, tmp_path, self._NFC)
        self._drift(root, self._NFC, self._NFD)

        rc, _, _ = ascmhl_cli(["generate", root])
        assert rc == 0
        gen2 = next((root / "ascmhl").glob("0002*.mhl")).read_bytes()
        assert b'action="verified"' in gen2
        assert b'action="original"' not in gen2


class TestGenerateUnicodeCollisionGuard:
    """
    Two walked names sharing one NFC identity abort generate before hashing
    (mirrors the classic seal guard). The pair coexists only on a
    normalization-sensitive filesystem, so scandir is wrapped to surface one
    real file under both spellings.
    """

    _NFC = "ros\u00e9.txt"
    _NFD = "rose\u0301.txt"

    class _TwinEntry:
        """A DirEntry double presenting a real entry under another name."""

        def __init__(self, real, name, path):
            self._real = real
            self.name = name
            self.path = path

        def is_dir(self, follow_symlinks=True):
            return self._real.is_dir(follow_symlinks=follow_symlinks)

        def is_file(self, follow_symlinks=True):
            return self._real.is_file(follow_symlinks=follow_symlinks)

        def stat(self, follow_symlinks=True):
            return self._real.stat(follow_symlinks=follow_symlinks)

    def test_generate_aborts_on_equivalent_names(self, ascmhl_cli, tmp_path, monkeypatch):
        root = tmp_path / "card"
        root.mkdir()
        (root / self._NFD).write_bytes(b"payload")
        (root / "plain.txt").write_bytes(b"control")

        real_scandir = os.scandir

        class _Listing(list):
            """
            os.scandir result double: iterable, iterator, and a context
            manager, so it serves `list(os.scandir(d))`, os.walk's `with`
            form, and the bare next() calls os.walk makes on Python <= 3.11
            (3.12+ iterates with a for loop instead).
            """

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def __next__(self):
                if not hasattr(self, "_it"):
                    self._it = iter(list(self))
                return next(self._it)

        def twin_scandir(d):
            entries = _Listing(real_scandir(d))
            if os.path.abspath(os.fspath(d)) == str(root):
                for e in list(entries):
                    if unicodedata.normalize("NFC", e.name) == self._NFC:
                        twin = self._NFC if e.name != self._NFC else self._NFD
                        entries.append(self._TwinEntry(e, twin, os.path.join(os.fspath(d), twin)))
            return entries

        monkeypatch.setattr(os, "scandir", twin_scandir)

        rc, _, err = ascmhl_cli(["generate", root])
        assert rc == 2
        assert "Unicode-equivalent" in err
        assert not (root / "ascmhl").exists(), "aborted generate must write no history"
