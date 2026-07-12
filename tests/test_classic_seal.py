"""Tests for classicmhl.seal, driven through the simple-mhl CLI."""

import builtins
import hashlib
import re
from datetime import UTC, datetime
from unittest.mock import patch

import pytest
import xxhash
from lxml import etree

from mhl_suite import hashing as core_hashing
from mhl_suite.classic_seal import SealError
from mhl_suite.cli import simple_mhl

from .helpers import (
    make_tree,
)


class TestSeal:
    """Tests around the seal command and its output."""

    def test_seal_basic_md5(self, mhl_cli, tmp_path):
        """A simple seal with md5 produces a valid manifest."""
        make_tree(tmp_path, {"a.bin": b"hello", "b/c.bin": b"world"})
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])

        assert rc == 0
        mhls = list(tmp_path.glob("*.mhl"))
        assert len(mhls) == 1
        text = mhls[0].read_text()
        assert "<md5>" in text
        assert text.count("<hash>") == 2

    def test_manifest_orders_subtrees_before_the_files_beside_them(self, mhl_cli, tmp_path):
        """
        Entries follow mhl_suite.sorting: at each level a subdirectory's whole
        subtree precedes that level's own files, and digit runs sort
        numerically. The walk itself runs in filesystem order, so this also pins
        that the sort is what decides the manifest — not the order readdir
        happened to return.
        """
        make_tree(
            tmp_path,
            {
                "take10.mov": b"j",
                "take2.mov": b"i",
                "Alpha/a1.mov": b"x",
                "Alpha/sub/deep.mov": b"y",
                "Bravo/b1.mov": b"z",
            },
        )
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])

        assert rc == 0
        text = next(tmp_path.glob("*.mhl")).read_text()
        assert re.findall(r"<file>(.*?)</file>", text) == [
            "Alpha/sub/deep.mov",
            "Alpha/a1.mov",
            "Bravo/b1.mov",
            "take2.mov",
            "take10.mov",
        ]

    def test_hashdates_ascend_down_the_manifest(self, mhl_cli, tmp_path):
        """
        Files are hashed in the order they are written — the sort happens before
        hashing, not after it.
        """
        make_tree(tmp_path, {f"Alpha/take{n}.mov": b"x" * (n + 1) for n in range(6)} | {"z.mov": b"y"})
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])

        assert rc == 0
        text = next(tmp_path.glob("*.mhl")).read_text()
        hashdates = re.findall(r"<hashdate>(.*?)</hashdate>", text)
        assert hashdates == sorted(hashdates)

    def test_empty_file_abort_lists_files_in_manifest_order(self, mhl_cli, tmp_path):
        """
        The empty-file abort is raised after the sort, so its [ERROR] lines read
        in the same order the manifest would have — not in the filesystem's.
        """
        make_tree(tmp_path, {"zz.bin": b"", "Alpha/a.bin": b"", "ok.bin": b"data"})
        rc, _, err = mhl_cli(["seal", str(tmp_path), "-a", "md5"])

        assert rc != 0
        assert re.findall(r"cannot seal empty file: (\S+)", err) == ["Alpha/a.bin", "zz.bin"]

    def test_manifest_paths_use_forward_slashes(self, mhl_cli, tmp_path):
        """Nested <file> entries are always forward-slash, never the native separator, so the manifest is portable
        regardless of the platform that sealed it. On Windows CI os.path.relpath yields backslashes, so this exercises
        the real backslash→'/' conversion; on POSIX it confirms we never emit native separators. Pairs with
        TestToTerminalSep, which locks the inverse — the terminal is the one place the native separator appears."""
        make_tree(tmp_path, {"sub/b.bin": b"world"})
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])

        assert rc == 0
        text = next(tmp_path.glob("*.mhl")).read_text()
        assert "sub/b.bin" in text
        assert "sub\\b.bin" not in text

    def test_seal_with_sha1(self, mhl_cli, tmp_path):
        """sha1 algorithm produces sha1 tags."""
        make_tree(tmp_path, {"a.bin": b"x"})
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "sha1"])

        assert rc == 0
        text = next(tmp_path.glob("*.mhl")).read_text()
        assert "<sha1>" in text

    def test_seal_includes_hidden_files_and_dirs(self, mhl_cli, tmp_path):
        """Hidden files and directories are part of the fixity record; only
        OS-generated junk is excluded."""
        make_tree(
            tmp_path,
            {
                "visible.bin": b"yes",
                ".hidden.bin": b"yes too",
                ".hiddendir/inside.bin": b"deep",
                ".DS_Store": b"junk",
                "._visible.bin": b"resource fork",
            },
        )
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])

        assert rc == 0
        text = next(tmp_path.glob("*.mhl")).read_text()
        assert "visible.bin" in text
        assert ".hidden.bin" in text
        assert ".hiddendir/inside.bin" in text
        # OS metadata stays out.
        assert ".DS_Store" not in text
        assert "._visible.bin" not in text

    def test_seal_unicode_filenames(self, mhl_cli, tmp_path):
        """Manifests must handle non-ASCII filenames cleanly (UTF-8)."""
        make_tree(
            tmp_path,
            {
                "日本語.bin": b"japanese",
                "rosé/résumé.txt": b"french",
                "🎬.mp4": b"emoji",
            },
        )
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])

        assert rc == 0
        text = next(tmp_path.glob("*.mhl")).read_text(encoding="utf-8")
        assert "日本語.bin" in text
        assert "rosé/résumé.txt" in text
        assert "🎬.mp4" in text

    def test_seal_aborts_on_empty_file(self, mhl_cli, tmp_path):
        """A zero-byte file can't be represented (XSD <size> >= 1), so the whole
        seal is refused, names the offender, and writes no manifest."""
        make_tree(tmp_path, {"good.bin": b"hello", "empty.bin": b""})
        rc, _, err = mhl_cli(["seal", str(tmp_path), "-a", "md5"])

        assert rc == 2
        assert "empty.bin" in err
        assert list(tmp_path.glob("*.mhl")) == []

    def test_seal_null_aborts_on_empty_file(self, mhl_cli, tmp_path):
        """The empty-file refusal is universal — it applies to a null seal too."""
        make_tree(tmp_path, {"empty.bin": b""})
        rc, _, err = mhl_cli(["seal", str(tmp_path), "-a", "null"])

        assert rc == 2
        assert "empty.bin" in err
        assert list(tmp_path.glob("*.mhl")) == []

    def test_seal_null_produces_null_tag(self, mhl_cli, tmp_path):
        """`-a null` records <null> entries with <size> and no computed digest."""
        make_tree(tmp_path, {"a.bin": b"hello", "b/c.bin": b"world"})
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "null"])

        assert rc == 0
        text = next(tmp_path.glob("*.mhl")).read_text()
        assert "<null>" in text or "<null/>" in text
        assert "<size>" in text
        assert "<md5>" not in text
        assert "<sha1>" not in text
        assert "<xxhash" not in text

    def test_seal_null_manifest_is_xsd_valid(self, mhl_cli, tmp_path):
        """A null manifest must validate against the bundled XSD (guards the
        fixed="" / positiveInteger constraints)."""
        make_tree(tmp_path, {"a.bin": b"hello"})
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "null"])
        assert rc == 0
        mhl = next(tmp_path.glob("*.mhl"))
        rc, _, _ = mhl_cli(["xsd-schema-check", str(mhl)])
        assert rc == 0

    def test_seal_null_round_trips_through_verify(self, mhl_cli, tmp_path):
        """A null manifest verifies clean (existence + size)."""
        make_tree(tmp_path, {"a.bin": b"hello", "b/c.bin": b"world"})
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "null"])
        assert rc == 0
        mhl = next(tmp_path.glob("*.mhl"))
        rc, _, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 0

    def test_seal_null_verbose_shows_size(self, mhl_cli, tmp_path):
        """`seal -v -a null` reports each file by size, not a hash."""
        make_tree(tmp_path, {"a.bin": b"hello"})  # 5 bytes
        rc, out, _ = mhl_cli(["seal", "-v", "-a", "null", str(tmp_path)])
        assert rc == 0
        assert "[OK] a.bin  size: 5" in out

    def test_seal_null_does_not_read_files(self, mhl_cli, tmp_path, monkeypatch):
        """A null seal records no digest, so it must never read file bytes."""
        make_tree(tmp_path, {"a.bin": b"hello"})

        def _boom(*_a, **_k):
            raise AssertionError("null seal must not hash files")

        monkeypatch.setattr(core_hashing, "get_hashes", _boom)
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "null"])
        assert rc == 0

    def test_seal_null_rejects_combination_one_flag(self, mhl_cli, tmp_path):
        """`-a null,md5` is contradictory (null is size-only) and rejected."""
        make_tree(tmp_path, {"a.bin": b"hello"})
        rc, _, err = mhl_cli(["seal", str(tmp_path), "-a", "null,md5"])
        assert rc == 2
        assert "null" in err
        assert list(tmp_path.glob("*.mhl")) == []

    def test_seal_null_rejects_combination_repeated_flags(self, mhl_cli, tmp_path):
        """`-a null -a md5` (separate flags) is rejected the same way."""
        make_tree(tmp_path, {"a.bin": b"hello"})
        rc, _, err = mhl_cli(["seal", str(tmp_path), "-a", "null", "-a", "md5"])
        assert rc == 2
        assert "null" in err
        assert list(tmp_path.glob("*.mhl")) == []

    def test_seal_invalid_algorithm(self, mhl_cli, tmp_path):
        """Unknown algorithm should be rejected by argparse with exit 2."""
        make_tree(tmp_path, {"a.bin": b"x"})
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "blake2"])
        assert rc == 2

    def test_seal_nonexistent_directory(self, mhl_cli):
        """Non-existent path should fail cleanly with exit 2."""
        rc, _, _ = mhl_cli(["seal", "/nonexistent/path/xyz", "-a", "md5"])
        assert rc == 2

    def test_seal_output_dir_writes_manifest_to_ancestor(self, mhl_cli, tmp_path):
        """-o writes the MHL into the chosen ancestor, with paths relative to it."""
        shoot = tmp_path / "shoot"
        make_tree(shoot, {"a.bin": b"hello", "b/c.bin": b"world"})
        rc, _, _ = mhl_cli(["seal", str(shoot), "-a", "md5", "-o", str(tmp_path)])

        assert rc == 0
        # Manifest lands in the ancestor, not the sealed directory.
        assert list(shoot.glob("*.mhl")) == []
        mhls = list(tmp_path.glob("*.mhl"))
        assert len(mhls) == 1
        text = mhls[0].read_text()
        # <file> paths are relative to the output dir, so they gain the prefix.
        assert "shoot/a.bin" in text
        assert "shoot/b/c.bin" in text

    def test_seal_output_dir_ancestor_manifest_round_trips_through_verify(self, mhl_cli, tmp_path):
        """A manifest sealed into an ancestor verifies cleanly from that location."""
        shoot = tmp_path / "shoot"
        make_tree(shoot, {"a.bin": b"hello", "b/c.bin": b"world"})
        rc, _, _ = mhl_cli(["seal", str(shoot), "-a", "md5", "-o", str(tmp_path)])
        assert rc == 0
        mhl = next(tmp_path.glob("*.mhl"))

        rc, _, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 0

    def test_seal_output_dir_default_unchanged(self, mhl_cli, tmp_path):
        """Without -o the manifest stays at the root with bare relative paths."""
        make_tree(tmp_path, {"a.bin": b"hello"})
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])

        assert rc == 0
        text = next(tmp_path.glob("*.mhl")).read_text()
        assert "<file>a.bin</file>" in text

    def test_seal_output_dir_rejects_non_ancestor(self, mhl_cli, tmp_path):
        """-o pointing outside the sealed tree's ancestry is rejected (exit 2)."""
        shoot = tmp_path / "shoot"
        make_tree(shoot, {"a.bin": b"x"})
        sibling = tmp_path / "elsewhere"
        sibling.mkdir()
        rc, _, err = mhl_cli(["seal", str(shoot), "-a", "md5", "-o", str(sibling)])
        assert rc == 2
        assert "parent directory" in err
        # A descendant of the sealed tree is likewise rejected.
        descendant = shoot / "b"
        descendant.mkdir()
        rc, _, _ = mhl_cli(["seal", str(shoot), "-a", "md5", "-o", str(descendant)])
        assert rc == 2

    def test_seal_output_dir_nonexistent_is_rejected(self, mhl_cli, tmp_path):
        """-o pointing at a non-existent / non-directory path fails with exit 2."""
        make_tree(tmp_path, {"a.bin": b"x"})
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5", "-o", str(tmp_path / "missing")])
        assert rc == 2


class TestSealVerbose:
    """seal -v streams per-file hashes, skipped files, and a completion line."""

    def test_seal_verbose_success_output(self, mhl_cli, tmp_path):
        """Umbrella for seal's verbose per-file success line — strengthen this
        rather than adding a sibling per detail (skip / completion lines have their own scenario tests)."""
        make_tree(tmp_path, {"clip.mxf": b"data"})
        rc, out, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5", "-v"])
        assert rc == 0
        assert "[OK] clip.mxf" in out
        assert "md5:" in out  # the algorithm tag and digest are shown

    def test_verbose_prints_skip_for_os_junk(self, mhl_cli, tmp_path):
        make_tree(tmp_path, {"clip.mxf": b"data", ".DS_Store": b"junk"})
        rc, out, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5", "-v"])
        assert rc == 0
        assert "[SKIP] .DS_Store (OS metadata)" in out

    def test_os_junk_skip_silent_without_verbose(self, mhl_cli, tmp_path):
        make_tree(tmp_path, {"clip.mxf": b"data", ".DS_Store": b"junk"})
        rc, out, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        assert rc == 0
        assert "[SKIP]" not in out
        assert "[OK]" not in out

    def test_verbose_prints_completion_line(self, mhl_cli, tmp_path):
        make_tree(tmp_path, {"clip.mxf": b"data"})
        rc, out, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5", "-v"])
        assert rc == 0
        assert "Created MHL:" in out
        assert ".mhl" in out


class TestSealMultiFormat:
    """seal -a md5,xxhash records multiple hashes per file in a single read pass."""

    @staticmethod
    def _hash_element(mhl_path):
        return etree.parse(str(mhl_path)).find("hash")

    def test_two_formats_emitted_per_file(self, mhl_cli, tmp_path):
        make_tree(tmp_path, {"a.bin": b"hello"})
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5,xxhash"])
        assert rc == 0
        h = self._hash_element(next(tmp_path.glob("*.mhl")))
        assert h.findtext("md5") == hashlib.md5(b"hello").hexdigest()
        assert h.findtext("xxhash64be") == xxhash.xxh64(b"hello").hexdigest()
        # Both hash elements precede a single shared <hashdate>, in -a order.
        tags = [etree.QName(e).localname for e in h]
        assert tags == ["file", "size", "lastmodificationdate", "md5", "xxhash64be", "hashdate"]

    def test_multi_format_passes_xsd(self, mhl_cli, tmp_path):
        make_tree(tmp_path, {"a.bin": b"hello", "b/c.bin": b"world"})
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5,sha1,xxhash"])
        assert rc == 0
        rc2, _, err = mhl_cli(["xsd-schema-check", str(next(tmp_path.glob("*.mhl")))])
        assert rc2 == 0, err

    def test_alias_dedup_single_element(self, mhl_cli, tmp_path):
        """Aliases that resolve to the same manifest tag collapse to one element."""
        make_tree(tmp_path, {"a.bin": b"hello"})
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "xxhash,xxh64,xxhash64be"])
        assert rc == 0
        assert next(tmp_path.glob("*.mhl")).read_text().count("<xxhash64be>") == 1

    def test_default_is_single_xxhash(self, mhl_cli, tmp_path):
        """No -a still produces exactly one xxhash64be — byte-compatible with before."""
        make_tree(tmp_path, {"a.bin": b"hello"})
        rc, _, _ = mhl_cli(["seal", str(tmp_path)])
        assert rc == 0
        text = next(tmp_path.glob("*.mhl")).read_text()
        assert text.count("<xxhash64be>") == 1
        assert "<md5>" not in text

    def test_bad_name_in_list_errors(self, mhl_cli, tmp_path):
        make_tree(tmp_path, {"a.bin": b"hello"})
        rc, _, err = mhl_cli(["seal", str(tmp_path), "-a", "md5,blake2"])
        assert rc == 2
        assert "blake2" in err

    def test_verbose_prints_each_format(self, mhl_cli, tmp_path):
        make_tree(tmp_path, {"a.bin": b"hello"})
        rc, out, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5,xxhash", "-v"])
        assert rc == 0
        assert "md5:" in out
        assert "xxhash64be:" in out

    def test_repeated_flag_records_each_format(self, mhl_cli, tmp_path):
        """-a md5 -a sha1 is equivalent to -a md5,sha1."""
        make_tree(tmp_path, {"a.bin": b"hello"})
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5", "-a", "sha1"])
        assert rc == 0
        h = self._hash_element(next(tmp_path.glob("*.mhl")))
        assert h.findtext("md5") == hashlib.md5(b"hello").hexdigest()
        assert h.findtext("sha1") == hashlib.sha1(b"hello").hexdigest()

    def test_repeated_flag_mixed_with_comma_list(self, mhl_cli, tmp_path):
        """Repeated and comma forms combine: -a md5,sha1 -a xxhash records all three."""
        make_tree(tmp_path, {"a.bin": b"hello"})
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5,sha1", "-a", "xxhash"])
        assert rc == 0
        text = next(tmp_path.glob("*.mhl")).read_text()
        assert text.count("<md5>") == 1
        assert text.count("<sha1>") == 1
        assert text.count("<xxhash64be>") == 1

    def test_repeated_flag_dedups_across_occurrences(self, mhl_cli, tmp_path):
        """-a md5 -a md5 collapses to a single md5 element."""
        make_tree(tmp_path, {"a.bin": b"hello"})
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5", "-a", "md5"])
        assert rc == 0
        assert next(tmp_path.glob("*.mhl")).read_text().count("<md5>") == 1

    def test_read_once_opens_file_a_single_time(self, mhl_cli, tmp_path, monkeypatch):
        """The whole point: N formats cost one open()/read pass, not N."""
        target = tmp_path / "a.bin"
        target.write_bytes(b"hello world")
        opens: list[str] = []
        real_open = builtins.open

        def counting_open(path, *args, **kwargs):
            if str(path) == str(target):
                opens.append(str(path))
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr(core_hashing, "open", counting_open, raising=False)
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5,sha1,xxhash"])
        assert rc == 0
        assert opens == [str(target)], f"expected one read pass, got {len(opens)}"


class TestSealUnsupportedAlgorithm:
    """seal_classic raises SealError for an unregistered algorithm; the CLI maps it to exit 2."""

    def test_unsupported_algorithm_raises_seal_error(self, tmp_path):
        """Calling seal_classic directly with an unknown algorithm raises a
        SealError naming it (the internal guard, unreachable via the CLI
        parser) — the library never exits the process itself."""

        (tmp_path / "a.bin").write_bytes(b"data")
        with pytest.raises(SealError, match="blake3"):
            simple_mhl.seal_classic(str(tmp_path), ["blake3"])


class TestSealAtomicCollision:
    """Tests for the O_EXCL atomic-collision fix in seal()."""

    # -------------------------------------------------------------------------
    # Class-scoped fixture: frozen datetime + patch
    # -------------------------------------------------------------------------
    # Two tests need to deterministically control the timestamp that seal() uses for its filename — they freeze
    # datetime.now() to a fixed value and pre-create collider files at the known path. Both tests share identical patch
    # boilerplate, so we factor it into a fixture that:
    #
    #   * patches mhl_suite.classic_seal.datetime for the duration of the test
    #   * exposes the frozen timestamp string (ts) on the yielded object
    #
    # Tests that don't need a fixed timestamp (the first three) ignore it. The fixture is function-scoped so the patch
    # is torn down with each test rather than bleeding into later tests in the class.

    @pytest.fixture
    def frozen_dt(self):
        """Freeze classic_seal's datetime to 2025-06-01T12:00:00Z for the test.

        Yields a namespace with .ts (the formatted timestamp string) so tests can construct known collision filenames
        without repeating the patch.
        """
        fixed = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)

        class _Info:
            ts = "2025-06-01_120000"

        with patch("mhl_suite.classic_seal.datetime") as mock_dt:
            mock_dt.now.return_value = fixed
            mock_dt.fromtimestamp.side_effect = datetime.fromtimestamp
            yield _Info()

    def test_no_collision_writes_primary_path(self, mhl_cli, tmp_path):
        """Under no collision the manifest lands at the bare timestamped name."""
        make_tree(tmp_path, {"a.bin": b"data"})
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        assert rc == 0
        mhls = list(tmp_path.glob("*.mhl"))
        assert len(mhls) == 1
        assert re.fullmatch(
            rf"{re.escape(tmp_path.name)}_\d{{4}}-\d{{2}}-\d{{2}}_\d{{6}}\.mhl",
            mhls[0].name,
        ), f"unexpected filename: {mhls[0].name}"

    def test_collision_creates_suffix(self, mhl_cli, tmp_path):
        """A collision must produce a _1.mhl rather than overwriting or failing.
        Two seals → two distinct files."""
        make_tree(tmp_path, {"a.bin": b"data"})
        rc1, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        assert rc1 == 0

        rc2, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        assert rc2 == 0

        mhls = sorted(tmp_path.glob("*.mhl"))
        assert len(mhls) == 2
        assert mhls[0] != mhls[1]

    def test_pre_injected_collision_suffix_loop(self, mhl_cli, tmp_path, frozen_dt):
        """Deterministically trigger the O_EXCL suffix loop by pre-creating both
        the primary *and* _1 filenames, then verifying seal lands on _2.
        """
        make_tree(tmp_path, {"a.bin": b"hello"})
        base = tmp_path.name

        (tmp_path / f"{base}_{frozen_dt.ts}.mhl").write_text("placeholder")
        (tmp_path / f"{base}_{frozen_dt.ts}_1.mhl").write_text("placeholder")

        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])

        assert rc == 0
        expected = tmp_path / f"{base}_{frozen_dt.ts}_2.mhl"
        assert expected.exists(), f"Expected _2 collision file not found. Files: {list(tmp_path.glob('*.mhl'))}"
        assert "<hashlist" in expected.read_text()


class TestSealConcurrency:
    """
    Seal always self-tunes — there is no operator knob. The adaptive path must still produce correct digests, and the
    default must actually probe.
    """

    @staticmethod
    def _force_parallel(monkeypatch):
        monkeypatch.setattr(core_hashing, "_AUTO_MIN_BYTES", 0)
        monkeypatch.setattr(core_hashing, "_AUTO_WARMUP_SECONDS", 0.0)
        monkeypatch.setattr(core_hashing, "_AUTO_PROBE_MIN_BYTES", 0)
        monkeypatch.setattr(simple_mhl.os, "cpu_count", lambda: 8)
        monkeypatch.setattr(core_hashing, "calibrate_hash_bandwidth", lambda f: 1000.0)
        monkeypatch.setattr(core_hashing, "_warmup_seq_bw", lambda nbytes, elapsed: 1000.0)
        # aggregate >> sequential baseline ⇒ parallel
        monkeypatch.setattr(core_hashing, "_probe_read_bw_multi", lambda slots, n: 8000.0)

    def test_auto_parallel_produces_correct_digests(self, mhl_cli, tmp_path, monkeypatch):
        make_tree(tmp_path, {"a.bin": b"hello", "sub/b.bin": b"world"})
        self._force_parallel(monkeypatch)
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        assert rc == 0
        text = next(tmp_path.glob("*.mhl")).read_text()
        assert hashlib.md5(b"hello").hexdigest() in text
        assert hashlib.md5(b"world").hexdigest() in text

    def test_default_uses_auto_probe(self, tmp_path, monkeypatch):
        """A plain seal routes through the adaptive probe (no operator input)."""
        make_tree(tmp_path, {"a.bin": b"x", "b.bin": b"y"})
        monkeypatch.setattr(core_hashing, "_AUTO_MIN_BYTES", 0)
        monkeypatch.setattr(simple_mhl.os, "cpu_count", lambda: 8)
        monkeypatch.setattr(core_hashing, "calibrate_hash_bandwidth", lambda f: 1000.0)
        probed: list[int] = []
        monkeypatch.setattr(core_hashing, "_probe_read_bw_multi", lambda slots, n: probed.append(1) or 100.0)
        simple_mhl.seal_classic(str(tmp_path), ["md5"], verbose=False)
        assert probed == [1], "the default must probe the disk to decide"
