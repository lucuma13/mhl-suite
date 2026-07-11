"""
The advanced-mhl CLI: argument handling, smart dispatch, rendering, and the
exit-code contract (generate semantics vs verify semantics, pinned ASC codes).
"""

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
        assert "[NEW] Clips/a.mov" in out
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
