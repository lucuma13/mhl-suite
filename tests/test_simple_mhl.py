"""Test suite for simple_mhl.py."""

import argparse
import builtins
import hashlib
import io
import os
import random
import re
import sys
import time
import unicodedata
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, cast
from unittest.mock import MagicMock, patch

import pytest

if TYPE_CHECKING:
    from collections.abc import Callable
import xxhash
from lxml import etree

from mhl_suite._internal import hostinfo, ignorelist, unicodepaths
from mhl_suite.classicmhl import seal as core_seal
from mhl_suite.classicmhl import verify as core_verify
from mhl_suite.cli import simple_mhl
from mhl_suite.shared import hashing as core_hashing


def make_tree(root: Path, spec: dict):
    """Create a directory tree from a {relpath: bytes_or_None_for_dir} spec."""
    root.mkdir(parents=True, exist_ok=True)
    for rel, content in spec.items():
        p = root / rel
        if content is None:
            p.mkdir(parents=True, exist_ok=True)
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content)


def seal_helper(mhl_cli, path: Path, algo="md5"):
    """Helper to seal a directory and return the manifest path."""
    rc, _, _ = mhl_cli(["seal", str(path), "-a", algo])
    assert rc == 0
    return next(path.glob("*.mhl"))


def make_mhl_with_size(dest_dir: Path, filename: str, content: bytes, size_override: str | None = None) -> Path:
    """Write a file and a matching MHL, optionally overriding the <size> value.

    Uses xxhash64 (the tool's default algorithm) for the digest so tests
    exercise the primary production code path.
    """
    filepath = dest_dir / filename
    filepath.write_bytes(content)

    digest = xxhash.xxh64(content).hexdigest()
    actual_size = str(len(content))
    recorded_size = size_override if size_override is not None else actual_size

    root = etree.Element("hashlist", version="1.1")
    h = etree.SubElement(root, "hash")
    etree.SubElement(h, "file").text = filename
    etree.SubElement(h, "size").text = recorded_size
    etree.SubElement(h, "lastmodificationdate").text = "2026-01-01T00:00:00Z"
    etree.SubElement(h, "xxhash64be").text = digest
    etree.SubElement(h, "hashdate").text = "2026-01-01T00:00:00Z"

    mhl = dest_dir / "test.mhl"
    etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")
    return mhl


def make_mhl(dest_dir: Path, entries: list[dict]) -> Path:
    """Write a minimal MHL referencing the given entries.

    Each entry dict must contain 'file', 'size', and 'md5'.
    Used by symlink tests that build manifests by hand.
    """
    root = etree.Element("hashlist", version="1.1")
    for e in entries:
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = e["file"]
        etree.SubElement(h, "size").text = e["size"]
        etree.SubElement(h, "lastmodificationdate").text = "2025-01-01T00:00:00Z"
        etree.SubElement(h, "md5").text = e["md5"]
        etree.SubElement(h, "hashdate").text = "2025-01-01T00:00:00Z"
    mhl = dest_dir / "manual.mhl"
    etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")
    return mhl


def make_multi_hash_mhl(dest_dir: Path, filename: str, content: bytes, hashes: dict[str, str]) -> Path:
    """Write a file and a manifest entry carrying the given {tag: value} hashes.

    Elements are emitted in dict order before a single <hashdate>, letting a test
    pin both which hashes are present and their document order.
    """
    target = dest_dir / filename
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)

    root = etree.Element("hashlist", version="1.1")
    h = etree.SubElement(root, "hash")
    etree.SubElement(h, "file").text = filename
    etree.SubElement(h, "size").text = str(len(content))
    etree.SubElement(h, "lastmodificationdate").text = "2026-01-01T00:00:00Z"
    for tag, value in hashes.items():
        etree.SubElement(h, tag).text = value
    etree.SubElement(h, "hashdate").text = "2026-01-01T00:00:00Z"

    mhl = dest_dir / "multi.mhl"
    etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")
    return mhl


@pytest.fixture
def mhl_cli():
    """Fixture to execute simple_mhl in-process and capture results."""

    def _run(argv):
        # Convert Path objects to strings to prevent sys.argv type errors
        str_argv = [str(arg) for arg in argv]

        old_argv, old_stdout, old_stderr = sys.argv, sys.stdout, sys.stderr
        sys.argv = ["simple-mhl", *str_argv]
        out, err = io.StringIO(), io.StringIO()
        sys.stdout, sys.stderr = out, err
        try:
            exit_code = 0
            try:
                simple_mhl.main()
            except SystemExit as e:
                exit_code = e.code if e.code is not None else 0
            return exit_code, out.getvalue(), err.getvalue()
        finally:
            sys.argv, sys.stdout, sys.stderr = old_argv, old_stdout, old_stderr

    return _run


# ---------------------------------------------------------------------------
# TestSeal
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# TestSealVerbose
# ---------------------------------------------------------------------------


class TestSealVerbose:
    """seal -v streams per-file hashes, skipped files, and a completion line."""

    def test_seal_verbose_success_output(self, mhl_cli, tmp_path):
        """Umbrella for seal's verbose per-file success line — strengthen this
        rather than adding a sibling per detail (skip / completion lines have
        their own scenario tests)."""
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


# ---------------------------------------------------------------------------
# TestSealUnsupportedAlgorithm
# ---------------------------------------------------------------------------


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


class TestVerifyAlgorithmSelection:
    """verify defaults to the fastest recorded hash (xxhash > md5 > sha1); -a overrides."""

    def test_default_uses_xxhash_when_md5_is_wrong(self, mhl_cli, tmp_path):
        """md5 deliberately wrong but xxhash correct → default (xxhash) passes."""
        content = b"hello"
        mhl = make_multi_hash_mhl(
            tmp_path, "a.bin", content, {"md5": "0" * 32, "xxhash64be": xxhash.xxh64(content).hexdigest()}
        )
        rc, _, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 0

    def test_default_picks_xxhash_even_when_listed_last(self, mhl_cli, tmp_path):
        """md5 correct but xxhash (last element) wrong → default chooses xxhash and
        fails, proving selection is by speed, not document order."""
        content = b"hello"
        mhl = make_multi_hash_mhl(
            tmp_path, "a.bin", content, {"md5": hashlib.md5(content).hexdigest(), "xxhash64be": "00" * 8}
        )
        rc, out, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 40
        assert "hash mismatch" in out

    def test_override_md5_passes_when_md5_correct(self, mhl_cli, tmp_path):
        """Same manifest where xxhash is wrong but md5 is right: -a md5 passes."""
        content = b"hello"
        mhl = make_multi_hash_mhl(
            tmp_path, "a.bin", content, {"md5": hashlib.md5(content).hexdigest(), "xxhash64be": "00" * 8}
        )
        rc, _, _ = mhl_cli(["verify", str(mhl), "-a", "md5"])
        assert rc == 0

    def test_override_md5_detects_corrupt_md5(self, mhl_cli, tmp_path):
        """-a md5 forces md5 even though the correct xxhash would pass by default."""
        content = b"hello"
        mhl = make_multi_hash_mhl(
            tmp_path, "a.bin", content, {"md5": "0" * 32, "xxhash64be": xxhash.xxh64(content).hexdigest()}
        )
        rc, _, _ = mhl_cli(["verify", str(mhl), "-a", "md5"])
        assert rc == 40

    def test_default_prefers_md5_over_sha1(self, mhl_cli, tmp_path):
        """No xxhash present: md5 (correct) wins over sha1 (wrong) → passes."""
        content = b"hello"
        mhl = make_multi_hash_mhl(
            tmp_path, "a.bin", content, {"sha1": "0" * 40, "md5": hashlib.md5(content).hexdigest()}
        )
        rc, _, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 0

    def test_override_alias_matches_recorded_tag(self, mhl_cli, tmp_path):
        """-a xxh64 resolves to the xxhash64be element via the manifest tag."""
        content = b"hello"
        mhl = make_multi_hash_mhl(
            tmp_path, "a.bin", content, {"md5": "0" * 32, "xxhash64be": xxhash.xxh64(content).hexdigest()}
        )
        rc, _, _ = mhl_cli(["verify", str(mhl), "-a", "xxh64"])
        assert rc == 0

    def test_override_absent_format_is_reported(self, mhl_cli, tmp_path):
        """Requesting a format the entry doesn't record is a per-file failure."""
        content = b"hello"
        mhl = make_multi_hash_mhl(tmp_path, "a.bin", content, {"md5": hashlib.md5(content).hexdigest()})
        rc, out, _ = mhl_cli(["verify", str(mhl), "-a", "sha1"])
        assert rc == 40
        assert "requested hash sha1 not stored" in out

    def test_sealed_multi_format_default_is_clean(self, mhl_cli, tmp_path):
        """End-to-end: a real md5,xxhash seal verifies clean by default and per -a."""
        make_tree(tmp_path, {"a.bin": b"hello", "b/c.bin": b"world"})
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5,xxhash"])
        assert rc == 0
        mhl = str(next(tmp_path.glob("*.mhl")))
        assert mhl_cli(["verify", mhl])[0] == 0
        assert mhl_cli(["verify", mhl, "-a", "md5"])[0] == 0
        assert mhl_cli(["verify", mhl, "-a", "xxhash"])[0] == 0

    def test_all_clean_checks_every_recorded_format(self, mhl_cli, tmp_path):
        """-a all verifies every recorded hash in one pass; verbose names each one."""
        content = b"hello world"
        mhl = make_multi_hash_mhl(
            tmp_path,
            "clip.bin",
            content,
            {
                "md5": hashlib.md5(content).hexdigest(),
                "sha1": hashlib.sha1(content).hexdigest(),
                "xxhash64be": xxhash.xxh64(content).hexdigest(),
            },
        )
        rc, out, _ = mhl_cli(["verify", "-a", "all", "-v", str(mhl)])
        assert rc == 0
        assert "[OK] clip.bin" in out
        assert "md5:" in out
        assert "sha1:" in out
        assert "xxhash64be:" in out

    def test_all_fails_on_any_bad_recorded_hash(self, mhl_cli, tmp_path):
        """-a all checks ALL recorded hashes, so one wrong stored digest fails the
        entry even when the fastest (default) hash matches. Verbose marks per format
        which matched and which didn't."""
        content = b"hello world"
        mhl = make_multi_hash_mhl(
            tmp_path,
            "clip.bin",
            content,
            {
                "md5": hashlib.md5(content).hexdigest(),
                "sha1": "0" * 40,  # wrong on purpose; the file itself is intact
                "xxhash64be": xxhash.xxh64(content).hexdigest(),
            },
        )
        # Default verifies only the fastest (xxhash), which matches → clean.
        assert mhl_cli(["verify", str(mhl)])[0] == 0
        # -a all checks every recorded hash, so the bad sha1 fails the entry.
        rc, out, _ = mhl_cli(["verify", "-a", "all", "-v", str(mhl)])
        assert rc == 40
        assert "hash mismatch: clip.bin" in out
        assert "sha1 MISMATCH" in out
        assert "md5 OK" in out
        assert "xxhash64be OK" in out

    def test_comma_list_checks_each_selected_hash_order_independent(self, mhl_cli, tmp_path):
        """-a md5,sha1 verifies exactly those two; the unrequested xxhash is skipped,
        and requested order doesn't change the result (output stays in manifest order)."""
        content = b"hello world"
        mhl = make_multi_hash_mhl(
            tmp_path,
            "clip.bin",
            content,
            {
                "md5": hashlib.md5(content).hexdigest(),
                "sha1": hashlib.sha1(content).hexdigest(),
                "xxhash64be": xxhash.xxh64(content).hexdigest(),
            },
        )
        for order in ("md5,sha1", "sha1,md5"):
            rc, out, _ = mhl_cli(["verify", "-a", order, "-v", str(mhl)])
            assert rc == 0, f"order {order!r}"
            assert "md5:" in out
            assert "sha1:" in out
            assert "xxhash64be:" not in out  # not requested → not checked

    def test_comma_list_reports_missing_requested_tags(self, mhl_cli, tmp_path):
        """Requesting tags the entry doesn't record fails it, naming each missing one;
        the list is sorted so the message is stable regardless of requested order."""
        content = b"hello"
        mhl = make_multi_hash_mhl(tmp_path, "a.bin", content, {"xxhash64be": xxhash.xxh64(content).hexdigest()})
        rc, out, _ = mhl_cli(["verify", "-a", "sha1,md5", str(mhl)])
        assert rc == 40
        assert "requested hashes md5, sha1 not stored" in out

    def test_repeated_flag_checks_each_selected_hash(self, mhl_cli, tmp_path):
        """-a md5 -a sha1 verifies both, order-independent, like -a md5,sha1."""
        content = b"hello world"
        mhl = make_multi_hash_mhl(
            tmp_path,
            "clip.bin",
            content,
            {
                "md5": hashlib.md5(content).hexdigest(),
                "sha1": hashlib.sha1(content).hexdigest(),
                "xxhash64be": xxhash.xxh64(content).hexdigest(),
            },
        )
        for first, second in (("md5", "sha1"), ("sha1", "md5")):
            rc, out, _ = mhl_cli(["verify", "-a", first, "-a", second, "-v", str(mhl)])
            assert rc == 0, f"order {first},{second}"
            assert "md5:" in out
            assert "sha1:" in out
            assert "xxhash64be:" not in out  # not requested → not checked

    def test_repeated_all_supersedes_specific(self, mhl_cli, tmp_path):
        """-a all -a md5 behaves as -a all: every recorded hash is checked."""
        content = b"hello world"
        mhl = make_multi_hash_mhl(
            tmp_path,
            "clip.bin",
            content,
            {
                "md5": hashlib.md5(content).hexdigest(),
                "sha1": "0" * 40,  # wrong; only -a all would catch it
                "xxhash64be": xxhash.xxh64(content).hexdigest(),
            },
        )
        rc, out, _ = mhl_cli(["verify", "-a", "all", "-a", "md5", "-v", str(mhl)])
        assert rc == 40
        assert "sha1 MISMATCH" in out


class TestCombineAlgorithms:
    """Merging repeated -a occurrences (argparse action="append" shapes)."""

    def test_seal_none_defaults_to_xxhash(self):
        assert simple_mhl.combine_seal_algorithms(None) == ["xxhash"]

    def test_seal_flattens_and_dedups_across_flags(self):
        assert simple_mhl.combine_seal_algorithms([["md5"], ["sha1"], ["md5"]]) == ["md5", "sha1"]

    def test_verify_none_means_fastest(self):
        assert simple_mhl.combine_verify_algorithms(None) is None

    def test_verify_flattens_and_dedups_in_order(self):
        assert simple_mhl.combine_verify_algorithms([["md5"], ["sha1"], ["md5"]]) == ["md5", "sha1"]

    def test_verify_all_supersedes(self):
        assert simple_mhl.combine_verify_algorithms([["md5"], "all"]) == simple_mhl._VERIFY_ALL


class TestParseAlgorithms:
    """The seal -a comma-list parser."""

    def test_single_default_name(self):
        assert simple_mhl.parse_algorithms("xxhash") == ["xxhash"]

    def test_order_preserved(self):
        assert simple_mhl.parse_algorithms("md5,sha1,xxhash") == ["md5", "sha1", "xxhash"]

    def test_dedup_by_tag_first_wins(self):
        # xxhash and xxh64 both map to xxhash64be; only the first survives.
        assert simple_mhl.parse_algorithms("xxhash,xxh64") == ["xxhash"]

    def test_whitespace_and_case_tolerated(self):
        assert simple_mhl.parse_algorithms(" MD5 , XXHash ") == ["md5", "xxhash"]

    def test_unknown_raises(self):
        with pytest.raises(argparse.ArgumentTypeError):
            simple_mhl.parse_algorithms("md5,blake2")

    def test_empty_raises(self):
        with pytest.raises(argparse.ArgumentTypeError):
            simple_mhl.parse_algorithms(" , ")


class TestSealUnsupportedAlgorithm:
    """seal() exits 2 when called directly with an algorithm not in ALGO_MAP."""

    def test_unsupported_algorithm_exits_2_with_message(self, tmp_path, capsys):
        """Calling seal() directly with an algorithm not in ALGO_MAP exits 2 and
        names it on stderr (the internal guard, unreachable via the CLI parser)."""

        (tmp_path / "a.bin").write_bytes(b"data")
        with pytest.raises(SystemExit) as exc:
            simple_mhl.seal(str(tmp_path), ["blake3"])
        assert exc.value.code == 2
        assert "blake3" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# TestVerify
# ---------------------------------------------------------------------------


class TestVerify:
    """Tests around the verify command."""

    def test_verify_clean(self, mhl_cli, tmp_path):
        """A freshly sealed dir should verify clean (exit 0)."""
        make_tree(tmp_path, {"a.bin": b"hello", "b/c.bin": b"world"})
        mhl = seal_helper(mhl_cli, tmp_path)

        rc, _out, _err = mhl_cli(["verify", str(mhl)])
        assert rc == 0

    def test_verify_missing_file(self, mhl_cli, tmp_path):
        """A deleted file should produce exit 30."""
        make_tree(tmp_path, {"a.bin": b"hello"})
        mhl = seal_helper(mhl_cli, tmp_path)
        (tmp_path / "a.bin").unlink()

        rc, out, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 30
        assert "[ERROR] missing file: a.bin" in out

    def test_verify_modified_file(self, mhl_cli, tmp_path):
        """A modified file should produce exit 40.

        The size pre-check fires before hash computation, so a replacement with
        different byte-length produces 'size mismatch' rather than 'hash mismatch'.
        Either error is a correct corruption signal; we assert on the filename and
        exit code, not the specific check that fires first.
        """
        make_tree(tmp_path, {"a.bin": b"hello"})
        mhl = seal_helper(mhl_cli, tmp_path)
        (tmp_path / "a.bin").write_bytes(b"goodbye")

        rc, out, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 40
        assert "a.bin" in out
        assert "[ERROR]" in out

    def test_verify_missing_and_modified(self, mhl_cli, tmp_path):
        """If BOTH missing and mismatch occur, exit 70 (combined failure)."""
        make_tree(tmp_path, {"a.bin": b"hello", "b.bin": b"world"})
        mhl = seal_helper(mhl_cli, tmp_path)
        (tmp_path / "a.bin").unlink()
        (tmp_path / "b.bin").write_bytes(b"changed")

        rc, out, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 70
        assert "[ERROR] missing file: a.bin" in out
        # "world" (5 bytes) → "changed" (7 bytes): size pre-check fires first.
        assert "b.bin" in out
        assert "[ERROR]" in out

    def test_verify_clean_is_silent(self, mhl_cli, tmp_path):
        """A clean verify must produce no stdout at all (exit 0 only)."""
        make_tree(tmp_path, {"a.bin": b"hello"})
        mhl = seal_helper(mhl_cli, tmp_path)

        rc, out, err = mhl_cli(["verify", str(mhl)])
        assert rc == 0
        assert out == ""
        assert err == ""

    def test_verify_verbose_success_output(self, mhl_cli, tmp_path):
        """--verbose prints one '[OK] <path>  <algo>: <digest>' line per verified
        file, naming the algorithm actually checked and its digest. Umbrella for
        verify's verbose *success* output — extend this rather than adding a
        sibling per detail (failure output lives in its own scenario tests)."""
        make_tree(tmp_path, {"a.bin": b"hello", "sub/b.bin": b"world"})
        mhl = seal_helper(mhl_cli, tmp_path, algo="md5")

        rc, out, _err = mhl_cli(["verify", "-v", str(mhl)])
        assert rc == 0
        assert f"[OK] a.bin  md5: {hashlib.md5(b'hello').hexdigest()}" in out
        assert "[OK] sub/b.bin" in out.replace(os.sep, "/")

    def test_verify_verbose_reflects_selected_algorithm(self, mhl_cli, tmp_path):
        """With md5+xxhash recorded, default picks xxhash; -a md5 names md5 instead."""
        content = b"hello"
        mhl = make_multi_hash_mhl(
            tmp_path,
            "a.bin",
            content,
            {"md5": hashlib.md5(content).hexdigest(), "xxhash64be": xxhash.xxh64(content).hexdigest()},
        )
        _, out_default, _ = mhl_cli(["verify", "-v", str(mhl)])
        assert f"xxhash64be: {xxhash.xxh64(content).hexdigest()}" in out_default
        assert "md5:" not in out_default

        _, out_md5, _ = mhl_cli(["verify", "-v", str(mhl), "-a", "md5"])
        assert f"md5: {hashlib.md5(content).hexdigest()}" in out_md5

    def test_verify_verbose_with_failures_shows_both(self, mhl_cli, tmp_path):
        """--verbose plus failures: OK for clean files, ERROR for failed."""
        make_tree(tmp_path, {"good.bin": b"hello", "bad.bin": b"world"})
        mhl = seal_helper(mhl_cli, tmp_path)
        (tmp_path / "bad.bin").write_bytes(b"changed")

        rc, out, _ = mhl_cli(["verify", "-v", str(mhl)])
        assert rc == 40
        assert "[OK] good.bin" in out
        # "world" (5 bytes) → "changed" (7 bytes): size pre-check fires first.
        assert "bad.bin" in out
        assert "[ERROR]" in out

    def test_verify_verbose_mismatch_output(self, mhl_cli, tmp_path):
        """Umbrella for verify's verbose *failure* output. A same-size content
        change passes the size pre-check and reaches the hash comparison, so
        --verbose prints the calc/stored hash detail line."""
        make_tree(tmp_path, {"a.bin": b"world"})
        mhl = seal_helper(mhl_cli, tmp_path)
        # Same byte length (5) so the size pre-check passes and the hash differs.
        (tmp_path / "a.bin").write_bytes(b"wXrld")

        rc, out, _ = mhl_cli(["verify", "-v", str(mhl)])
        assert rc == 40
        assert "hash mismatch: a.bin" in out
        assert "calc" in out
        assert "stored" in out

    def test_size_only_clean_skips_hashing(self, mhl_cli, tmp_path):
        """-s verifies on <size> alone: a same-length content change (which a hash
        pass would catch) passes clean, proving no bytes are hashed."""
        make_tree(tmp_path, {"a.bin": b"hello"})
        mhl = seal_helper(mhl_cli, tmp_path)
        (tmp_path / "a.bin").write_bytes(b"world")  # same length, different bytes

        rc, out, _ = mhl_cli(["verify", "-S", str(mhl)])
        assert rc == 0
        assert out == ""

    def test_size_only_detects_wrong_length(self, mhl_cli, tmp_path):
        """A file whose byte-length no longer matches <size> is a size mismatch (exit 40)."""
        make_tree(tmp_path, {"a.bin": b"hello"})
        mhl = seal_helper(mhl_cli, tmp_path)
        (tmp_path / "a.bin").write_bytes(b"hello world")

        rc, out, _ = mhl_cli(["verify", "--size-only", str(mhl)])
        assert rc == 40
        assert "[ERROR] size mismatch: a.bin" in out

    def test_size_only_missing_file(self, mhl_cli, tmp_path):
        """A deleted file is reported missing (exit 30) in size-only mode too."""
        make_tree(tmp_path, {"a.bin": b"hello"})
        mhl = seal_helper(mhl_cli, tmp_path)
        (tmp_path / "a.bin").unlink()

        rc, out, _ = mhl_cli(["verify", "-S", str(mhl)])
        assert rc == 30
        assert "[ERROR] missing file: a.bin" in out

    def test_size_only_entry_without_size_is_mismatch(self, mhl_cli, tmp_path):
        """An entry that records no <size> can't be size-checked, so -s reports it
        as a mismatch rather than passing it silently."""
        (tmp_path / "a.bin").write_bytes(b"hello")
        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = "a.bin"
        etree.SubElement(h, "xxhash64be").text = xxhash.xxh64(b"hello").hexdigest()
        mhl = tmp_path / "nosize.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, out, _ = mhl_cli(["verify", "-S", str(mhl)])
        assert rc == 40
        assert "[ERROR] no size recorded: a.bin" in out

    def test_size_only_verbose_output(self, mhl_cli, tmp_path):
        """--verbose -s prints one '[OK] <path>  size: <bytes>' line per file."""
        make_tree(tmp_path, {"a.bin": b"hello"})
        mhl = seal_helper(mhl_cli, tmp_path)

        rc, out, _ = mhl_cli(["verify", "-S", "-v", str(mhl)])
        assert rc == 0
        assert "[OK] a.bin  size: 5" in out

    def test_iter_files_without_on_skip_skips_os_junk(self, tmp_path):
        """_iter_files_for_seal's on_skip callback is optional. With on_skip=None
        an OS-junk entry must still be skipped silently (no callback invoked, no
        crash) and excluded, while a hidden user file IS yielded."""
        make_tree(tmp_path, {"visible.bin": b"x", ".hidden.bin": b"y", ".DS_Store": b"junk"})
        mhl_path = str(tmp_path / "out.mhl")
        yielded = sorted(os.path.basename(p) for p, _ in simple_mhl._iter_files_for_seal(str(tmp_path), mhl_path))
        assert yielded == [".hidden.bin", "visible.bin"]

    @pytest.mark.parametrize(
        ("name", "is_junk"),
        [
            # Exact names (case-insensitive)
            (".DS_Store", True),
            (".ds_store", False),  # case-sensitive: only the OS's exact casing matches
            (".Spotlight-V100", True),
            (".Trashes", True),
            (".fseventsd", True),
            ("Thumbs.db", True),
            (".localized", True),
            (".AppleDouble", True),
            (".LSOverride", True),
            (".DocumentRevisions-V100", True),
            (".TemporaryItems", True),
            (".VolumeIcon.icns", True),
            (".com.apple.timemachine.donotpresent", True),
            (".com.apple.timemachine.supported", True),
            (".PKInstallSandboxManager", True),
            (".PKInstallSandboxManager-SystemSoftware", True),
            (".hotfiles.btree", True),
            (".vol", True),
            (".file", True),
            ("lost+found", True),
            # Trailing-carriage-return names (real bytes in the on-disk name)
            ("Icon\r", True),
            (".HFS+ Private Directory Data\r", True),
            # Prefix matches
            ("._MyClip.mov", True),  # macOS AppleDouble resource fork
            ("._", True),  # bare '._' still matches the fork prefix
            (".disk_label", True),
            (".disk_label_2x", True),
            # NOT junk — hidden user content is sealed
            (".hidden.bin", False),
            (".git", False),  # hidden user dir — descended
            (".env", False),
            ("clip.mxf", False),
            ("Icon", False),  # plain 'Icon' (no CR) is a real file, not the marker
            ("lost+found2", False),  # exact match only
        ],
    )
    def test_is_os_junk(self, name, is_junk):
        """Only OS-generated metadata is junk; hidden user files/dirs are not."""
        assert ignorelist.is_os_junk(name) is is_junk

    @pytest.mark.skipif(sys.platform == "win32", reason="os.mkfifo is POSIX-only")
    def test_iter_files_without_on_skip_skips_non_regular(self, tmp_path):
        """A non-regular file (FIFO) must be skipped silently when on_skip=None."""
        make_tree(tmp_path, {"visible.bin": b"x"})
        os.mkfifo(tmp_path / "pipe")
        mhl_path = str(tmp_path / "out.mhl")
        yielded = [os.path.basename(p) for p, _ in simple_mhl._iter_files_for_seal(str(tmp_path), mhl_path)]
        assert yielded == ["visible.bin"]

    def test_verify_directory_argument(self, mhl_cli, tmp_path):
        """Passing a directory to verify should exit 1 with an error on stderr."""
        rc, _, err = mhl_cli(["verify", str(tmp_path)])
        assert rc == 1
        assert "directory" in err.lower()

    def test_verify_ascmhl_directory(self, mhl_cli, tmp_path):
        """Passing an 'ascmhl' directory should exit 1 and mention mhlver."""
        ascmhl_dir = tmp_path / "ascmhl"
        ascmhl_dir.mkdir()
        rc, _, err = mhl_cli(["verify", str(ascmhl_dir)])
        assert rc == 1
        assert "mhlver" in err.lower()

    def test_verify_ascmhl_v2_manifest(self, mhl_cli):
        """An ASC-MHL v2 .mhl manifest must be rejected (exit 1, mhlver hint).

        Its <hash> entries use <path> not <file>, so the v1 verify loop would
        skip them all and falsely exit 0 — this guards that regression.
        """
        fixture = Path(__file__).parent / "fixtures" / "silverstack_ascmhl_example.mhl"
        rc, _, err = mhl_cli(["verify", str(fixture)])
        assert rc == 1
        assert "mhlver" in err.lower()

    def test_verify_non_mhl_file(self, mhl_cli, tmp_path):
        """Passing a file without a .mhl extension should exit 1 with an error on stderr."""
        bad = tmp_path / "manifest.xml"
        bad.write_bytes(b"<hashlist/>")
        rc, _, err = mhl_cli(["verify", str(bad)])
        assert rc == 1
        assert ".mhl" in err.lower()

    def test_verify_malformed_xml(self, mhl_cli, tmp_path):
        """Malformed XML should produce exit 20."""
        bad = tmp_path / "bad.mhl"
        bad.write_text("<not valid xml")
        rc, _, _ = mhl_cli(["verify", str(bad)])
        assert rc == 20

    def test_verify_path_traversal_blocked(self, mhl_cli, tmp_path):
        """A manifest with ../ paths must NOT escape the manifest's directory."""
        outside = tmp_path.parent / "outside_secret.bin"
        outside.write_bytes(b"secret data")
        try:
            seal_root = tmp_path / "package"
            seal_root.mkdir()
            (seal_root / "good.bin").write_bytes(b"benign")
            mhl = seal_helper(mhl_cli, seal_root, "md5")

            tree = etree.parse(str(mhl))
            root = tree.getroot()
            evil = etree.SubElement(root, "hash")
            etree.SubElement(evil, "file").text = "../outside_secret.bin"
            etree.SubElement(evil, "size").text = "11"
            etree.SubElement(evil, "lastmodificationdate").text = "2025-01-01T00:00:00Z"
            etree.SubElement(evil, "md5").text = "deadbeefdeadbeefdeadbeefdeadbeef"
            etree.SubElement(evil, "hashdate").text = "2025-01-01T00:00:00Z"
            tree.write(str(mhl), xml_declaration=True, encoding="UTF-8")

            rc, out, _ = mhl_cli(["verify", str(mhl)])
            assert rc == 40
            assert "traversal" in out.lower()
        finally:
            outside.unlink(missing_ok=True)

    def test_verify_classicmhl_decimal_xxhash(self, mhl_cli, tmp_path):
        """Old MHL files stored xxhash as a decimal int (a 32-bit XXH32) — must verify."""
        make_tree(tmp_path, {"a.bin": b"x"})

        decimal_digest = str(xxhash.xxh32(b"x").intdigest())

        doc = etree.Element("hashlist", version="1.1")
        etree.SubElement(doc, "creationdate").text = "2025-01-01T00:00:00Z"
        info = etree.SubElement(doc, "creatorinfo")
        etree.SubElement(info, "username").text = "test"
        etree.SubElement(info, "hostname").text = "test"
        etree.SubElement(info, "tool").text = "test"
        etree.SubElement(info, "startdate").text = "2025-01-01T00:00:00Z"
        etree.SubElement(info, "finishdate").text = "2025-01-01T00:00:00Z"
        h_el = etree.SubElement(doc, "hash")
        etree.SubElement(h_el, "file").text = "a.bin"
        etree.SubElement(h_el, "size").text = "1"
        etree.SubElement(h_el, "lastmodificationdate").text = "2025-01-01T00:00:00Z"
        etree.SubElement(h_el, "xxhash").text = decimal_digest
        etree.SubElement(h_el, "hashdate").text = "2025-01-01T00:00:00Z"

        mhl = tmp_path / "classic.mhl"
        etree.ElementTree(doc).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, _, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 0


# ---------------------------------------------------------------------------
# TestVerifyXxhashVariants
# ---------------------------------------------------------------------------


def _le_hex(value: int, nbytes: int) -> str:
    """Little-endian hex of an integer — the byte order some xxHash tags record."""
    return value.to_bytes(nbytes, "little").hex()


class TestVerifyXxhashVariants:
    """verify accepts every byte order and width MHL has used for xxHash."""

    def test_xxhash64be_big_endian_verifies(self, mhl_cli, tmp_path):
        content = b"big endian payload"
        mhl = make_multi_hash_mhl(tmp_path, "a.bin", content, {"xxhash64be": xxhash.xxh64(content).hexdigest()})
        assert mhl_cli(["verify", str(mhl)])[0] == 0

    def test_xxhash64_little_endian_verifies(self, mhl_cli, tmp_path):
        content = b"little endian payload"
        le = _le_hex(xxhash.xxh64(content).intdigest(), 8)
        mhl = make_multi_hash_mhl(tmp_path, "a.bin", content, {"xxhash64": le})
        assert mhl_cli(["verify", str(mhl)])[0] == 0

    def test_xxhash64_tag_also_accepts_big_endian(self, mhl_cli, tmp_path):
        """The xxhash64 tag is read leniently: a big-endian value under it still verifies."""
        content = b"either byte order"
        mhl = make_multi_hash_mhl(tmp_path, "a.bin", content, {"xxhash64": xxhash.xxh64(content).hexdigest()})
        assert mhl_cli(["verify", str(mhl)])[0] == 0

    def test_xxhash_decimal_is_xxh32(self, mhl_cli, tmp_path):
        content = b"thirty-two bit decimal"
        dec = str(xxhash.xxh32(content).intdigest())
        assert len(dec) <= 10
        mhl = make_multi_hash_mhl(tmp_path, "a.bin", content, {"xxhash": dec})
        assert mhl_cli(["verify", str(mhl)])[0] == 0

    def test_xxhash_hex_is_xxh64_either_order(self, mhl_cli, tmp_path):
        content = b"old tag, hex value"
        be = xxhash.xxh64(content).hexdigest()
        le = _le_hex(xxhash.xxh64(content).intdigest(), 8)
        mhl_be = make_multi_hash_mhl(tmp_path / "be", "a.bin", content, {"xxhash": be})
        mhl_le = make_multi_hash_mhl(tmp_path / "le", "a.bin", content, {"xxhash": le})
        assert mhl_cli(["verify", str(mhl_be)])[0] == 0
        assert mhl_cli(["verify", str(mhl_le)])[0] == 0

    def test_uppercase_hex_verifies(self, mhl_cli, tmp_path):
        """Comparison is by integer value, so case does not matter."""
        content = b"shouty hex"
        mhl = make_multi_hash_mhl(tmp_path, "a.bin", content, {"xxhash64be": xxhash.xxh64(content).hexdigest().upper()})
        assert mhl_cli(["verify", str(mhl)])[0] == 0

    def test_wrong_value_reports_mismatch(self, mhl_cli, tmp_path):
        content = b"intact"
        for tag, bad in (("xxhash64be", "0" * 16), ("xxhash64", "0" * 16), ("xxhash", "1")):
            mhl = make_multi_hash_mhl(tmp_path / tag, "a.bin", content, {tag: bad})
            assert mhl_cli(["verify", str(mhl)])[0] == 40

    def test_xxhash64be_rejects_little_endian_value(self, mhl_cli, tmp_path):
        """xxhash64be is strict big-endian: the little-endian form must NOT verify."""
        content = b"strict big endian"
        be = xxhash.xxh64(content).hexdigest()
        le = _le_hex(xxhash.xxh64(content).intdigest(), 8)
        assert le != be  # palindromic digest would be astronomically unlikely
        mhl = make_multi_hash_mhl(tmp_path, "a.bin", content, {"xxhash64be": le})
        assert mhl_cli(["verify", str(mhl)])[0] == 40


# ---------------------------------------------------------------------------
# TestVerifyUtf16Manifest
# ---------------------------------------------------------------------------


class TestVerifyUtf16Manifest:
    """UTF-16 manifests (a real, supported MHL encoding) verify in both byte orders."""

    def _write(self, dest: Path, content: bytes, encoding: str, *, corrupt: bool = False) -> Path:
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "clip.bin").write_bytes(content)
        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = "clip.bin"
        etree.SubElement(h, "size").text = str(len(content))
        digest = "0" * 16 if corrupt else xxhash.xxh64(content).hexdigest()
        etree.SubElement(h, "xxhash64be").text = digest
        mhl = dest / "clip.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding=encoding)
        return mhl

    @pytest.mark.parametrize("encoding", ["UTF-16LE", "UTF-16BE", "UTF-16"])
    def test_utf16_manifest_verifies(self, mhl_cli, tmp_path, encoding):
        mhl = self._write(tmp_path / encoding, b"utf-16 payload", encoding)
        assert mhl_cli(["verify", str(mhl)])[0] == 0

    def test_utf16_manifest_detects_mismatch(self, mhl_cli, tmp_path):
        """Genuinely parsed and compared, not merely accepted."""
        mhl = self._write(tmp_path, b"utf-16 payload", "UTF-16LE", corrupt=True)
        assert mhl_cli(["verify", str(mhl)])[0] == 40


# ---------------------------------------------------------------------------
# TestRoundTrip
# ---------------------------------------------------------------------------


class TestRoundTrip:
    """End-to-end seal+verify with various tree shapes and sizes."""

    def _round_trip(self, mhl_cli, tmp_path, spec, algo="md5"):
        make_tree(tmp_path, spec)
        rc1, _, _ = mhl_cli(["seal", str(tmp_path), "-a", algo])
        assert rc1 == 0
        mhl = next(tmp_path.glob("*.mhl"))
        rc2, _, _ = mhl_cli(["verify", str(mhl)])
        assert rc2 == 0

    def test_deeply_nested(self, mhl_cli, tmp_path):
        """7-level nested directory still round-trips."""
        nested = "a/b/c/d/e/f/g/file.bin"
        self._round_trip(mhl_cli, tmp_path, {nested: b"deep"})

    def test_many_small_files(self, mhl_cli, tmp_path):
        """500 tiny files round-trip correctly."""
        spec = {f"f{i:04d}.bin": f"file-{i}".encode() for i in range(500)}
        self._round_trip(mhl_cli, tmp_path, spec)

    def test_large_file(self, mhl_cli, tmp_path):
        """A 10 MB file (multi-chunk read) round-trips correctly."""
        data = os.urandom(10 * 1024 * 1024)
        self._round_trip(mhl_cli, tmp_path, {"big.bin": data})


class TestSchemaCheck:
    """Tests for xsd-schema-check."""

    def test_schema_check_no_xsd(self, mhl_cli, tmp_path):
        """Without an XSD, the command should exit 127 (cannot locate schema)."""
        bad = tmp_path / "bad.mhl"
        bad.write_text("<not valid xml")
        rc, _, _ = mhl_cli(["xsd-schema-check", str(bad)])
        assert rc in (20, 60)

    def test_schema_check_valid_manifest(self, mhl_cli, tmp_path):
        """A properly sealed manifest should pass schema validation (exit 0)."""
        make_tree(tmp_path, {"a.bin": b"hello"})
        mhl = seal_helper(mhl_cli, tmp_path)
        rc, _, _ = mhl_cli(["xsd-schema-check", str(mhl)])
        assert rc == 0

    def test_schema_check_invalid_structure(self, mhl_cli, tmp_path):
        """A manifest with unrecognised tags should fail schema validation (exit 10)."""
        bad_mhl = tmp_path / "invalid.mhl"
        bad_mhl.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<hashlist version="1.1">\n'
            "  <fake_tag>This breaks the schema</fake_tag>\n"
            "</hashlist>\n"
        )
        rc, _, err = mhl_cli(["xsd-schema-check", str(bad_mhl)])
        assert rc == 10
        assert "XSD validation failed" in err


# ---------------------------------------------------------------------------
# TestStressAndEdgeCases
# ---------------------------------------------------------------------------


class TestStressAndEdgeCases:
    """Stress tests — adversarial and edge-case scenarios."""

    def test_thousand_files(self, mhl_cli, tmp_path):
        """Seal and verify 1000 small files in under a few seconds."""
        for i in range(1000):
            (tmp_path / f"f{i:05d}.bin").write_bytes(f"data-{i}".encode())

        t0 = time.perf_counter()
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        seal_time = time.perf_counter() - t0
        assert rc == 0
        print(f"\n  seal 1000 files: {seal_time * 1000:.0f}ms")

        mhl = next(tmp_path.glob("*.mhl"))
        t0 = time.perf_counter()
        rc, _, _ = mhl_cli(["verify", str(mhl)])
        verify_time = time.perf_counter() - t0
        assert rc == 0
        print(f"  verify 1000 files: {verify_time * 1000:.0f}ms")

    def test_pathological_filenames(self, mhl_cli, tmp_path):
        """Files with spaces, brackets, accented chars, etc."""
        weird = [
            "file with spaces.bin",
            "[brackets].bin",
            "(parens).bin",
            "ampersand&.bin",
            "single'quote.bin",
            'double"quote.bin',
            "tab\there.bin",
            "naïve.bin",
            "über.bin",
        ]
        for name in weird:
            try:
                (tmp_path / name).write_bytes(b"x")
            except OSError:
                continue

        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        assert rc == 0

        mhl = next(tmp_path.glob("*.mhl"))
        rc, out, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 0, f"verify failed: {out}"

    def test_long_filename(self, mhl_cli, tmp_path):
        """A 200-char filename (close to but not over the typical 255 limit)."""
        long_name = "a" * 200 + ".bin"
        try:
            (tmp_path / long_name).write_bytes(b"x")
        except OSError:
            pytest.skip("FS doesn't allow 200-char names")

        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        assert rc == 0

        mhl = next(tmp_path.glob("*.mhl"))
        rc, _, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 0

    def test_empty_directory(self, mhl_cli, tmp_path):
        """Sealing an empty directory should produce a manifest with no <hash>."""
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        assert rc == 0

        mhl = next(tmp_path.glob("*.mhl"))
        text = mhl.read_text()
        assert "<hash>" not in text

    def test_single_huge_file(self, mhl_cli, tmp_path):
        """A 50 MB file — exercises the chunked-read path."""
        path = tmp_path / "huge.bin"
        with open(path, "wb") as f:
            chunk = os.urandom(1024 * 1024)
            f.writelines(chunk for _ in range(50))

        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        assert rc == 0

        mhl = next(tmp_path.glob("*.mhl"))
        rc, _, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 0

    def test_subtle_corruption(self, mhl_cli, tmp_path):
        """Flipping one byte in a 10MB file should be caught."""
        (tmp_path / "data.bin").write_bytes(b"X" * (10 * 1024 * 1024))
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        assert rc == 0

        with open(tmp_path / "data.bin", "r+b") as f:
            f.seek(5 * 1024 * 1024)
            b = f.read(1)
            f.seek(-1, 1)
            f.write(bytes([b[0] ^ 1]))

        mhl = next(tmp_path.glob("*.mhl"))
        rc, out, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 40
        assert "data.bin" in out

    def test_namespace_in_manifest(self, mhl_cli, tmp_path):
        """A manifest that uses an XML namespace should still verify cleanly."""
        (tmp_path / "x.bin").write_bytes(b"hi")
        ns = "urn:foo:mhl"
        root = etree.Element(
            f"{{{ns}}}hashlist",
            version="1.1",
            nsmap=cast("dict[str, str]", {None: ns}),  # lxml requires None for default ns
        )
        h = etree.SubElement(root, f"{{{ns}}}hash")
        etree.SubElement(h, f"{{{ns}}}file").text = "x.bin"
        etree.SubElement(h, f"{{{ns}}}size").text = "2"
        etree.SubElement(h, f"{{{ns}}}lastmodificationdate").text = "2025-01-01T00:00:00Z"
        etree.SubElement(h, f"{{{ns}}}md5").text = "49f68a5c8493ec2c0bf489821c21fc3b"
        etree.SubElement(h, f"{{{ns}}}hashdate").text = "2025-01-01T00:00:00Z"

        mhl = tmp_path / "ns.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, out, err = mhl_cli(["verify", str(mhl)])
        assert rc == 0, f"out={out}\nerr={err}"

    def test_uppercase_hex_digest(self, mhl_cli, tmp_path):
        """A manifest with uppercase hex should still match (we lowercase both)."""
        (tmp_path / "x.bin").write_bytes(b"hi")
        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = "x.bin"
        etree.SubElement(h, "size").text = "2"
        etree.SubElement(h, "lastmodificationdate").text = "2025-01-01T00:00:00Z"
        etree.SubElement(h, "md5").text = "49F68A5C8493EC2C0BF489821C21FC3B"
        etree.SubElement(h, "hashdate").text = "2025-01-01T00:00:00Z"
        mhl = tmp_path / "upper.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, _, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 0


# ---------------------------------------------------------------------------
# TestSealAtomicCollision
# ---------------------------------------------------------------------------


class TestSealAtomicCollision:
    """Tests for the O_EXCL atomic-collision fix in seal()."""

    # -------------------------------------------------------------------------
    # Class-scoped fixture: frozen datetime + patch
    # -------------------------------------------------------------------------
    # Two tests need to deterministically control the timestamp that seal()
    # uses for its filename — they freeze datetime.now() to a fixed value and
    # pre-create collider files at the known path. Both tests share identical
    # patch boilerplate, so we factor it into a fixture that:
    #
    #   * patches mhl_suite.simple_mhl.datetime for the duration of the test
    #   * exposes the frozen timestamp string (ts) on the yielded object
    #
    # Tests that don't need a fixed timestamp (the first three) ignore it.
    # The fixture is function-scoped so the patch is torn down with each test
    # rather than bleeding into later tests in the class.

    @pytest.fixture
    def frozen_dt(self):
        """Freeze simple_mhl's datetime to 2025-06-01T12:00:00Z for the test.

        Yields a namespace with .ts (the formatted timestamp string) so tests
        can construct known collision filenames without repeating the patch.
        """
        fixed = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)

        class _Info:
            ts = "2025-06-01_120000"

        with patch("mhl_suite.classicmhl.seal.datetime") as mock_dt:
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


# ---------------------------------------------------------------------------
# TestValidateSchemaXsdNotFound
# ---------------------------------------------------------------------------


class TestValidateSchemaXsdNotFound:
    """validate_schema() must exit 60 when get_xsd_path() raises."""

    def test_xsd_not_found_exits_60_with_stderr(self, mhl_cli, tmp_path, monkeypatch):
        """When get_xsd_path raises FileNotFoundError, xsd-schema-check must
        exit 60 and write an error message to stderr."""

        mhl_file = tmp_path / "dummy.mhl"
        mhl_file.write_text('<?xml version="1.0" encoding="UTF-8"?>\n<hashlist version="1.1"/>\n')

        def _raise():
            raise FileNotFoundError("Could not locate MediaHashList_v1_1.xsd (tried /fake/path)")

        monkeypatch.setattr(core_verify, "get_xsd_path", _raise)

        rc, _, err = mhl_cli(["xsd-schema-check", str(mhl_file)])
        assert rc == 60
        assert "could not locate" in err.lower() or "mediahashlist" in err.lower()

    def test_validate_schema_oserror_exits_20(self, mhl_cli, tmp_path):
        """An OSError reading the MHL file (e.g. file disappears after the
        existence check) must produce exit 20 and a 'File Error' on stderr."""
        # We create the file, call xsd-schema-check with a path that will
        # cause lxml to raise OSError by giving it a directory path (lxml
        # can't parse a directory as XML).
        bogus = tmp_path / "not_a_file"
        bogus.mkdir()
        # Rename it to have a .mhl extension so verify's extension check passes.
        mhl_path = tmp_path / "broken.mhl"
        mhl_path.mkdir()  # a directory masquerading as a .mhl file
        rc, _, _err = mhl_cli(["xsd-schema-check", str(mhl_path)])
        # lxml raises OSError trying to open a directory; validate_schema → exit 20.
        assert rc in (20, 1)  # 1 if the dir check fires first


# ---------------------------------------------------------------------------
# TestGetXsdPathFallbackPaths
# ---------------------------------------------------------------------------


class TestGetXsdPathFallbackPaths:
    """get_xsd_path fallback: importlib.resources raises → local xsd/ sibling."""

    def test_falls_back_to_local_xsd_when_importlib_raises(self, tmp_path):
        """When importlib.resources.files raises ImportError, the local xsd/
        sibling is found and its path is returned.

        get_xsd_path lives in mhl_suite/classicmhl/verify.py, so the checkout fallback
        resolves xsd/ one level up from the module (parent.parent). We patch
        core_verify.__file__ to a 2-levels-deep path so tmp_path/xsd is the target.
        """

        xsd_dir = tmp_path / "xsd"
        xsd_dir.mkdir()
        xsd_file = xsd_dir / "MediaHashList_v1_1.xsd"
        xsd_file.write_text("<schema/>")

        with (
            patch.object(
                core_verify.importlib.resources,
                "files",
                side_effect=ImportError("no package"),
            ),
            patch.object(core_verify, "__file__", str(tmp_path / "classicmhl" / "verify.py")),
        ):
            result = core_verify.get_xsd_path()

        assert result == str(xsd_file)

    def test_falls_back_to_local_xsd_when_resource_is_not_a_file(self, tmp_path):
        """When files() succeeds but is_file() returns False (e.g. a namespace
        package without the XSD installed), the local xsd/ sibling is used."""

        xsd_dir = tmp_path / "xsd"
        xsd_dir.mkdir()
        xsd_file = xsd_dir / "MediaHashList_v1_1.xsd"
        xsd_file.write_text("<schema/>")

        fake_resource = MagicMock()
        fake_resource.is_file.return_value = False
        fake_pkg = MagicMock()
        fake_pkg.joinpath.return_value = fake_resource

        with (
            patch.object(core_verify.importlib.resources, "files", return_value=fake_pkg),
            patch.object(core_verify, "__file__", str(tmp_path / "classicmhl" / "verify.py")),
        ):
            result = core_verify.get_xsd_path()

        assert result == str(xsd_file)

    def test_raises_file_not_found_when_both_paths_absent(self, tmp_path):
        """FileNotFoundError is raised when neither the package resource nor the
        local xsd/ folder exists (tmp_path has no xsd/ subdirectory)."""

        with (
            patch.object(
                core_verify.importlib.resources,
                "files",
                side_effect=ImportError("no package"),
            ),
            patch.object(core_verify, "__file__", str(tmp_path / "classicmhl" / "verify.py")),
            pytest.raises(FileNotFoundError, match=r"MediaHashList_v1_1\.xsd"),
        ):
            core_verify.get_xsd_path()

    def test_verify_file_not_found_exits_1(self, mhl_cli, tmp_path):
        """verify on a nonexistent .mhl file must exit 1."""
        rc, _, err = mhl_cli(["verify", str(tmp_path / "ghost.mhl")])
        assert rc == 1
        assert "not found" in err.lower() or "error" in err.lower()

    def test_hash_element_without_file_child_is_skipped(self, mhl_cli, tmp_path):
        """A <hash> entry with no <file> child must be silently skipped (not crash)."""
        (tmp_path / "real.bin").write_bytes(b"data")
        root = etree.Element("hashlist", version="1.1")

        # Legit entry.
        h_good = etree.SubElement(root, "hash")
        etree.SubElement(h_good, "file").text = "real.bin"
        etree.SubElement(h_good, "size").text = "4"
        etree.SubElement(h_good, "lastmodificationdate").text = "2025-01-01T00:00:00Z"

        etree.SubElement(h_good, "md5").text = hashlib.md5(b"data").hexdigest()
        etree.SubElement(h_good, "hashdate").text = "2025-01-01T00:00:00Z"

        # Malformed entry: no <file> child at all.
        h_bad = etree.SubElement(root, "hash")
        etree.SubElement(h_bad, "md5").text = "deadbeef" * 4

        mhl = tmp_path / "partial.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, _out, _err = mhl_cli(["verify", str(mhl)])
        # The legit file verifies; the malformed entry is silently skipped.
        assert rc == 0

    def test_hash_element_with_no_supported_algorithm_tag(self, mhl_cli, tmp_path):
        """A <hash> whose only child tags are unrecognised must produce the
        'no supported hash found' mismatch (exit 40)."""
        (tmp_path / "x.bin").write_bytes(b"x")
        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = "x.bin"
        etree.SubElement(h, "size").text = "1"
        etree.SubElement(h, "lastmodificationdate").text = "2025-01-01T00:00:00Z"
        etree.SubElement(h, "blake3").text = "0" * 64  # not a computable hash tag
        etree.SubElement(h, "hashdate").text = "2025-01-01T00:00:00Z"
        mhl = tmp_path / "unsupported.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, out, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 40
        assert "no supported hash found" in out

    def test_null_tag_present_file_passes_with_size_only_notice(self, mhl_cli, tmp_path):
        """A <null> entry for a file that exists passes (exit 0) and, even without
        -v, prints the size-only notice — there are no per-file [OK] lines."""
        (tmp_path / "x.bin").write_bytes(b"x")
        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = "x.bin"
        etree.SubElement(h, "size").text = "1"
        etree.SubElement(h, "lastmodificationdate").text = "2025-01-01T00:00:00Z"
        etree.SubElement(h, "null")
        etree.SubElement(h, "hashdate").text = "2025-01-01T00:00:00Z"
        mhl = tmp_path / "null_present.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, out, _err = mhl_cli(["verify", str(mhl)])
        assert rc == 0
        assert "Verified with size-only checks (hashes missing from the manifest)." in out
        assert "[OK]" not in out  # no per-file lines without -v

    def test_null_tag_present_file_verbose_shows_ok(self, mhl_cli, tmp_path):
        """A <null> entry for a file that exists must print 'OK:' in verbose mode."""
        (tmp_path / "x.bin").write_bytes(b"x")
        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = "x.bin"
        etree.SubElement(h, "size").text = "1"
        etree.SubElement(h, "lastmodificationdate").text = "2025-01-01T00:00:00Z"
        etree.SubElement(h, "null")
        etree.SubElement(h, "hashdate").text = "2025-01-01T00:00:00Z"
        mhl = tmp_path / "null_verbose.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, out, _ = mhl_cli(["verify", "-v", str(mhl)])
        assert rc == 0
        assert "[OK] x.bin  size: 1 (size-only check - no hash stored)" in out
        assert "Verified with size-only checks (hashes missing from the manifest)." in out

    def test_null_tag_without_size_reports_existence_only(self, mhl_cli, tmp_path):
        """A <null> entry that records no <size> passed on existence alone — nothing
        about its size was checked, so the report line must not quote one."""
        (tmp_path / "x.bin").write_bytes(b"xxxx")
        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = "x.bin"
        etree.SubElement(h, "lastmodificationdate").text = "2025-01-01T00:00:00Z"
        etree.SubElement(h, "null")
        mhl = tmp_path / "null_no_size.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, out, _ = mhl_cli(["verify", "-v", str(mhl)])
        assert rc == 0
        assert "[OK] x.bin  (existence-only check — no hash or size stored)" in out
        assert "size:" not in out
        assert "Verified with existence-only checks (hashes and sizes missing from the manifest)." in out
        assert "size-only" not in out

    def test_null_tag_missing_file_reports_error(self, mhl_cli, tmp_path):
        """A <null> entry for a file that does NOT exist must exit 30."""
        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = "ghost.bin"
        etree.SubElement(h, "size").text = "0"
        etree.SubElement(h, "lastmodificationdate").text = "2025-01-01T00:00:00Z"
        etree.SubElement(h, "null")
        etree.SubElement(h, "hashdate").text = "2025-01-01T00:00:00Z"
        mhl = tmp_path / "null_missing.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, out, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 30
        assert "[ERROR] missing file: ghost.bin" in out

    def test_null_tag_size_mismatch_reports_error(self, mhl_cli, tmp_path):
        """A <null> entry whose file exists but whose size differs from the
        manifest <size> must fail with a size mismatch (exit 40).

        The v1.1 schema defines <null> as "no hash, only use file size
        verification", so a truncated/corrupted file must not pass on
        existence alone.
        """
        (tmp_path / "x.bin").write_bytes(b"xxxx")  # 4 bytes on disk
        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = "x.bin"
        etree.SubElement(h, "size").text = "1"  # manifest claims 1 byte
        etree.SubElement(h, "lastmodificationdate").text = "2025-01-01T00:00:00Z"
        etree.SubElement(h, "null")
        etree.SubElement(h, "hashdate").text = "2025-01-01T00:00:00Z"
        mhl = tmp_path / "null_size_mismatch.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, out, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 40
        assert "[ERROR] size mismatch: x.bin" in out

    def test_mixed_null_and_hash_manifest_shows_partial_notice(self, mhl_cli, tmp_path):
        """A manifest mixing a hashed entry and a <null> entry prints the partial
        size-only notice (not the all-size-only one)."""
        (tmp_path / "a.bin").write_bytes(b"hello")
        (tmp_path / "b.bin").write_bytes(b"world")
        root = etree.Element("hashlist", version="1.1")
        ha = etree.SubElement(root, "hash")
        etree.SubElement(ha, "file").text = "a.bin"
        etree.SubElement(ha, "size").text = "5"
        etree.SubElement(ha, "lastmodificationdate").text = "2025-01-01T00:00:00Z"
        etree.SubElement(ha, "xxhash64be").text = xxhash.xxh64(b"hello").hexdigest()
        etree.SubElement(ha, "hashdate").text = "2025-01-01T00:00:00Z"
        hb = etree.SubElement(root, "hash")
        etree.SubElement(hb, "file").text = "b.bin"
        etree.SubElement(hb, "size").text = "5"
        etree.SubElement(hb, "lastmodificationdate").text = "2025-01-01T00:00:00Z"
        etree.SubElement(hb, "null")
        etree.SubElement(hb, "hashdate").text = "2025-01-01T00:00:00Z"
        mhl = tmp_path / "mixed.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, out, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 0
        assert "Partially verified with size-only checks (some hashes missing from the manifest)." in out
        assert "(hashes missing from the manifest)" not in out  # not the all-null notice

    def test_mixed_size_only_and_existence_only_notice_names_both(self, mhl_cli, tmp_path):
        """A manifest with one <null>+<size> entry and one <null> entry lacking <size>
        names both check kinds in the all-null notice."""
        (tmp_path / "a.bin").write_bytes(b"hello")
        (tmp_path / "b.bin").write_bytes(b"world")
        root = etree.Element("hashlist", version="1.1")
        ha = etree.SubElement(root, "hash")
        etree.SubElement(ha, "file").text = "a.bin"
        etree.SubElement(ha, "size").text = "5"
        etree.SubElement(ha, "lastmodificationdate").text = "2025-01-01T00:00:00Z"
        etree.SubElement(ha, "null")
        hb = etree.SubElement(root, "hash")
        etree.SubElement(hb, "file").text = "b.bin"  # no <size>: existence-only
        etree.SubElement(hb, "lastmodificationdate").text = "2025-01-01T00:00:00Z"
        etree.SubElement(hb, "null")
        mhl = tmp_path / "mixed_null.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, out, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 0
        assert (
            "Verified with size-only and existence-only checks (hashes and some sizes missing from the manifest)."
            in out
        )

    def test_hashed_manifest_has_no_size_only_notice(self, mhl_cli, tmp_path):
        """A normal hash-verified manifest prints no size-only notice."""
        make_tree(tmp_path, {"a.bin": b"hello"})
        mhl = seal_helper(mhl_cli, tmp_path, algo="md5")
        rc, out, _ = mhl_cli(["verify", "-v", str(mhl)])
        assert rc == 0
        assert "size-only" not in out
        assert "No hashes stored" not in out

    def test_uncomputable_hash_tag_is_ignored(self, mhl_cli, tmp_path):
        """A hash we can't recompute (e.g. xxhash128) is treated like any unknown
        algorithm: ignored entirely. An entry whose only hash is uncomputable reports
        'no supported hash found' (exit 40), not a special 'cannot verify'."""
        (tmp_path / "x.bin").write_bytes(b"x")
        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = "x.bin"
        etree.SubElement(h, "size").text = "1"
        etree.SubElement(h, "lastmodificationdate").text = "2025-01-01T00:00:00Z"
        etree.SubElement(h, "xxhash128").text = "0" * 32
        etree.SubElement(h, "hashdate").text = "2025-01-01T00:00:00Z"
        mhl = tmp_path / "xxhash128.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, out, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 40
        assert "no supported hash found" in out

    def test_uncomputable_hash_tag_falls_back_to_computable_sibling(self, mhl_cli, tmp_path):
        """When an entry carries both an uncomputable hash and a computable one, the
        uncomputable tag is skipped and the computable hash is used (verifies clean)."""
        content = b"payload"
        (tmp_path / "x.bin").write_bytes(content)
        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = "x.bin"
        etree.SubElement(h, "size").text = str(len(content))
        etree.SubElement(h, "xxhash128").text = "0" * 32  # ignored
        etree.SubElement(h, "md5").text = hashlib.md5(content).hexdigest()
        mhl = tmp_path / "mixed.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        assert mhl_cli(["verify", str(mhl)])[0] == 0

    def test_uncomputable_hash_tag_falls_back_to_null(self, mhl_cli, tmp_path):
        """An uncomputable hash alongside <null> falls back to the size-only check."""
        content = b"payload"
        (tmp_path / "x.bin").write_bytes(content)
        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = "x.bin"
        etree.SubElement(h, "size").text = str(len(content))
        etree.SubElement(h, "xxhash128").text = "0" * 32  # ignored
        etree.SubElement(h, "null")
        mhl = tmp_path / "null_fallback.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        assert mhl_cli(["verify", str(mhl)])[0] == 0


# ---------------------------------------------------------------------------
# TestWalkEdgeCases
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="chmod-based permission tests are not applicable on Windows",
)
class TestWalkEdgeCases:
    """Exercises the two OSError-swallowing branches in _iter_files_for_seal."""

    @pytest.mark.skipif(
        getattr(os, "getuid", lambda: 1)() == 0,
        reason="root bypasses permission checks",
    )
    def test_unreadable_subdir_is_skipped_with_warning(self, mhl_cli, tmp_path):
        """A subdirectory that cannot be scanned (mode 000) is skipped, but the
        seal must surface a WARNING (always, not just under -v) — a dropped
        directory means its files are absent from the manifest. The seal still
        succeeds and includes the files that ARE accessible."""
        make_tree(
            tmp_path,
            {
                "accessible.bin": b"yes",
                "locked/secret.bin": b"no",
            },
        )
        locked = tmp_path / "locked"
        locked.chmod(0o000)
        try:
            rc, _, err = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
            assert rc == 0
            mhl = next(tmp_path.glob("*.mhl"))
            text = mhl.read_text()
            assert "accessible.bin" in text
            assert "secret.bin" not in text
            # Surfaced even without -v.
            assert "WARNING" in err
            assert "locked" in err
        finally:
            locked.chmod(0o755)  # restore so tmp_path cleanup can proceed


# ---------------------------------------------------------------------------
# TestSymlinks
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="symlinks require elevated privileges on Windows",
)
class TestSymlinks:
    """Symlink handling for both seal and verify.

    seal() excludes symlinks entirely (follow_symlinks=False on both is_dir and
    is_file), making directory-cycle traversal impossible by exclusion. verify()
    follows symlinks when named in a third-party manifest, hashing their targets.

    Protection layers pinned here so a future refactor cannot silently remove
    the follow_symlinks=False calls without a test failure.
    """

    def test_symlink_to_parent_is_excluded_from_seal(self, mhl_cli, tmp_path):
        """A symlink pointing back to its own parent directory must be silently
        excluded from the manifest — not descended into, not hashed."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "real.bin").write_bytes(b"data")
        loop = pkg / "loop"
        try:
            loop.symlink_to(pkg)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks not supported on this filesystem")

        rc, _, _ = mhl_cli(["seal", str(pkg), "-a", "md5"])
        assert rc == 0
        text = next(pkg.glob("*.mhl")).read_text()
        # Only the real file is sealed; the symlink is excluded entirely.
        assert "real.bin" in text
        assert "loop" not in text
        assert text.count("<hash>") == 1

    def test_mutual_symlinks_are_excluded_from_seal(self, mhl_cli, tmp_path):
        """Two symlinks pointing at each other must both be silently excluded —
        neither causes infinite descent, neither appears in the manifest."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        (pkg / "real.bin").write_bytes(b"data")
        a = pkg / "a.bin"
        b = pkg / "b.bin"
        try:
            a.symlink_to(b)
            b.symlink_to(a)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks not supported on this filesystem")

        rc, _, _ = mhl_cli(["seal", str(pkg), "-a", "md5"])
        assert rc == 0
        text = next(pkg.glob("*.mhl")).read_text()
        # Only the real file is sealed; both symlinks are excluded entirely.
        assert "real.bin" in text
        assert "a.bin" not in text
        assert "b.bin" not in text
        assert text.count("<hash>") == 1

    def test_symlink_to_file_inside_tree_verifies_correctly(self, mhl_cli, tmp_path):
        """verify follows a symlink that resolves inside the tree and hashes its
        target. A correct digest → exit 0."""

        pkg = tmp_path / "pkg"
        pkg.mkdir()
        real = pkg / "real.bin"
        real.write_bytes(b"payload")
        link = pkg / "link.bin"
        try:
            link.symlink_to(real)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks not supported on this filesystem")

        correct_md5 = hashlib.md5(b"payload").hexdigest()
        mhl = make_mhl(
            pkg,
            [
                {"file": "link.bin", "size": "7", "md5": correct_md5},
            ],
        )

        rc, out, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 0, f"unexpected output: {out}"

    def test_symlink_to_file_inside_tree_detects_mismatch(self, mhl_cli, tmp_path):
        """A wrong digest for a symlink target is detected and reported as a
        hash mismatch → exit 40."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        real = pkg / "real.bin"
        real.write_bytes(b"payload")
        link = pkg / "link.bin"
        try:
            link.symlink_to(real)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks not supported on this filesystem")

        mhl = make_mhl(
            pkg,
            [
                {"file": "link.bin", "size": "7", "md5": "0" * 32},
            ],
        )

        rc, out, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 40
        assert "hash mismatch" in out

    def test_mutual_symlinks_in_manifest_report_missing(self, mhl_cli, tmp_path):
        """A manifest naming mutually-pointing symlinks (a → b, b → a) must
        not loop. os.path.exists() follows the chain and returns False when it
        cannot resolve — the existence check fires before get_hash is ever
        called, so both entries are reported as missing files → exit 30."""
        pkg = tmp_path / "pkg"
        pkg.mkdir()
        a = pkg / "a.bin"
        b = pkg / "b.bin"
        try:
            a.symlink_to(b)
            b.symlink_to(a)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks not supported on this filesystem")

        mhl = make_mhl(
            pkg,
            [
                {"file": "a.bin", "size": "0", "md5": "0" * 32},
                {"file": "b.bin", "size": "0", "md5": "0" * 32},
            ],
        )

        rc, out, _ = mhl_cli(["verify", str(mhl)])
        # os.path.exists() returns False for unresolvable symlink chains;
        # both entries hit the missing-file branch before get_hash is called.
        assert rc == 30
        assert "missing file: a.bin" in out
        assert "missing file: b.bin" in out


# ---------------------------------------------------------------------------
# TestAdversarialXML
# ---------------------------------------------------------------------------


class TestAdversarialXML:
    """Adversarial and malformed XML inputs must never crash the tool.

    Covers XXE injection (lxml rejects external entities as XMLSyntaxError →
    exit 20) and structural anomalies (Comment/PI nodes with callable .tag
    attributes that would break naive tag-name lookups).
    """

    def test_xxe_entity_payload_exits_20(self, mhl_cli, tmp_path):
        """A manifest containing an XXE <!ENTITY> payload must exit 20 (malformed XML)
        and must never exfiltrate file content via entity expansion.

        lxml's default parser does not resolve external entities; it raises
        XMLSyntaxError instead. simple_mhl.verify() already maps that to exit 20.
        This test pins that behaviour as a regression guard — if the parser is
        ever reconfigured to resolve entities, this test will fail loudly.
        """
        xxe_payload = (
            '<?xml version="1.0"?>\n'
            "<!DOCTYPE foo [\n"
            '  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
            "]>\n"
            '<hashlist version="1.1">'
            "<hash><file>&xxe;</file><md5>" + "0" * 32 + "</md5></hash>"
            "</hashlist>"
        )
        mhl = tmp_path / "xxe.mhl"
        mhl.write_text(xxe_payload, encoding="utf-8")

        rc, out, err = mhl_cli(["verify", str(mhl)])
        assert rc == 20, f"Expected exit 20 for XXE payload, got {rc}"
        # No file content must leak into stdout or stderr.
        for stream in (out, err):
            assert "root:" not in stream, "Potential XXE exfiltration detected in output"
            assert "/bin/" not in stream, "Potential XXE exfiltration detected in output"

    def test_comment_and_pi_nodes_inside_hash_do_not_crash(self, mhl_cli, tmp_path):
        """lxml Comment and ProcessingInstruction nodes carry a callable (not a string)
        as their .tag attribute. simple_mhl._localname() used to call .rpartition()
        on it, triggering an AttributeError crash.

        The fix: _localname() returns '' for non-string tags, making them invisible
        to the hash-tag recognition test.
        """
        (tmp_path / "target.bin").write_bytes(b"data")

        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = "target.bin"
        # Inject adversarial non-element nodes directly inside the <hash> element.
        h.append(etree.Comment("Adversarial comment insertion"))
        h.append(etree.PI("xml-stylesheet", 'href="style.css"'))
        # A real md5 tag follows — the tool must still find it.

        digest = hashlib.md5(b"data").hexdigest()
        etree.SubElement(h, "md5").text = digest

        mhl = tmp_path / "anomaly.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, _, _ = mhl_cli(["verify", str(mhl)])
        # The real md5 tag follows the Comment/PI; the tool must find it and verify.
        assert rc == 0, f"Expected exit 0 after skipping Comment/PI nodes, got {rc}"

    def test_comment_only_hash_reports_no_supported_hash(self, mhl_cli, tmp_path):
        """A <hash> containing only Comment/PI nodes (no algorithm tag) must be
        reported as 'no supported hash found' (exit 40), not crash.
        """
        (tmp_path / "x.bin").write_bytes(b"x")

        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = "x.bin"
        h.append(etree.Comment("no real hash here"))

        mhl = tmp_path / "comment_only.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, out, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 40
        assert "no supported hash found" in out


# ---------------------------------------------------------------------------
# TestTOCTOURaceCondition
# ---------------------------------------------------------------------------


class TestTOCTOURaceCondition:
    """Files deleted between os.path.exists() and the next filesystem call must be handled gracefully.

    There are two distinct race windows in verify():

      1. exists() -> getsize(): covered by test_file_vanishes_between_exists_and_getsize.
         Requires a manifest <size> element; the OSError is caught by the size
         pre-check handler and reported as 'missing file' (exit 30).

      2. getsize() -> hash read: covered by test_file_deleted_before_hash_read.
         Requires NO <size> element so the size block is skipped entirely; the
         OSError is caught by the get_hashes handler and reported as 'cannot verify'
         (exit 40).

    Both handlers must produce a structured error message, not an unhandled exception.
    """

    def test_file_vanishes_between_exists_and_getsize(self, mhl_cli, tmp_path, monkeypatch):
        """Race window 1: file disappears after exists() but before getsize().

        The size pre-check's OSError handler (lines 549-555 of simple_mhl.py) must
        catch this and report 'missing file' (exit 30), not propagate the exception.

        Manifest includes a <size> element so the size pre-check block is entered.
        os.path.getsize is patched to raise OSError for the target file only.
        """
        mhl = make_mhl_with_size(tmp_path, "vanishing.bin", b"data")

        real_getsize = os.path.getsize

        def _getsize_raises(path):
            if str(path).endswith("vanishing.bin"):
                raise OSError("simulated vanish during getsize")
            return real_getsize(path)

        monkeypatch.setattr(simple_mhl.os.path, "getsize", _getsize_raises)

        rc, out, _ = mhl_cli(["verify", str(mhl)])

        assert rc == 30, f"Expected exit 30 (missing file), got {rc}"
        assert "[ERROR] missing file: vanishing.bin" in out

    def test_file_deleted_before_hash_read(self, mhl_cli, tmp_path, monkeypatch):
        """Race window 2: file disappears after getsize() but before the hash read opens it.

        verify() hashes through get_hashes (one read pass for one-or-many formats);
        its OSError handler must catch this and report 'cannot verify' (exit 40),
        not propagate the exception.

        Manifest has NO <size> element so the size pre-check is skipped and the race
        happens at the hash read as intended. get_hashes is patched to delete the
        file then attempt the real open, which raises OSError.
        """
        target = tmp_path / "vanishing.bin"
        target.write_bytes(b"data")

        real_get_hashes = simple_mhl.get_hashes

        def _get_hashes_after_delete(filepath, factories):
            target.unlink(missing_ok=True)
            return real_get_hashes(filepath, factories)

        monkeypatch.setattr(core_hashing, "get_hashes", _get_hashes_after_delete)

        # No <size> element — size pre-check block is not entered.
        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = "vanishing.bin"
        etree.SubElement(h, "md5").text = "0" * 32
        mhl = tmp_path / "race.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, out, _ = mhl_cli(["verify", str(mhl)])

        assert rc == 40, f"Expected exit 40 (cannot verify), got {rc}"
        assert "[ERROR] cannot verify vanishing.bin" in out


# ---------------------------------------------------------------------------
# TestRobustness
# ---------------------------------------------------------------------------


class TestRobustness:
    """The tool must never crash or regress on unusual inputs.

    Covers mutation-based fuzz resilience (random byte-level corruption of valid
    manifests must always produce a defined exit code) and memory behaviour
    (verify() must use iterparse, not parse, to keep peak memory bounded for
    large manifests tracking hundreds of thousands of frames).
    """

    def test_verify_pure_garbage_bytes_exits_cleanly(self, mhl_cli, tmp_path):
        """A file filled with random bytes must produce a defined exit code, never a traceback."""

        fuzzed = tmp_path / "garbage.mhl"
        fuzzed.write_bytes(os.urandom(4096))

        rc, _, _ = mhl_cli(["verify", str(fuzzed)])
        assert rc in (0, 1, 20, 30, 40, 70), f"Unexpected exit code {rc} on pure garbage input"

    def test_verify_mutation_fuzz_loop(self, mhl_cli, tmp_path):
        """Apply sequential random byte-level mutations to a valid manifest and
        assert the tool always exits with a defined code — never crashes.

        20 iterations is enough to exercise truncation, bit-flip, null-injection,
        and garbage-insertion without making the test suite noticeably slow.
        """

        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = "sample.bin"
        etree.SubElement(h, "md5").text = "0" * 32
        baseline = etree.tostring(root, xml_declaration=True, encoding="UTF-8")

        def mutate(content: bytes) -> bytes:
            if not content:
                return b""
            stream = bytearray(content)
            strategy = random.choice(["flip_bit", "truncate", "insert_garbage", "inject_null"])
            if strategy == "flip_bit":
                stream[random.randint(0, len(stream) - 1)] ^= random.randint(1, 255)
            elif strategy == "truncate" and len(stream) > 2:
                start = random.randint(0, len(stream) - 2)
                del stream[start : random.randint(start + 1, len(stream))]
            elif strategy == "insert_garbage":
                idx = random.randint(0, len(stream))
                stream[idx:idx] = os.urandom(random.randint(1, 50))
            elif strategy == "inject_null":
                stream[random.randint(0, len(stream) - 1)] = 0
            return bytes(stream)

        random.seed(42)  # fixed seed for reproducibility
        for i in range(20):
            mutated = mutate(baseline)
            manifest = tmp_path / f"mutated_{i}.mhl"
            manifest.write_bytes(mutated)
            rc, _, _ = mhl_cli(["verify", str(manifest)])
            assert rc in (0, 1, 20, 30, 40, 70), f"Unexpected exit code {rc} on mutation iteration {i}"

    def test_large_manifest_uses_iterparse_not_parse(self, mhl_cli, tmp_path, monkeypatch):
        """Confirm verify() calls etree.iterparse() rather than etree.parse().

        etree.parse() loads the full XML DOM into memory — for a 100MB manifest
        tracking hundreds of thousands of DPX/EXR frames that means 300-500MB of
        RAM. etree.iterparse() yields one <hash> at a time and frees it
        immediately, keeping peak memory proportional to one element, not the
        full document.

        This test is implementation-level: it directly asserts the streaming
        path is taken so that a future refactor cannot silently regress to DOM
        loading without a test failure.
        """
        parse_calls: list[str] = []
        iterparse_calls: list[str] = []

        real_iterparse = etree.iterparse

        def spy_parse(path, *args, **kwargs):
            parse_calls.append(str(path))
            raise AssertionError(
                "verify() called etree.parse() — this loads the full DOM into "
                "memory. Use etree.iterparse() to keep memory bounded."
            )

        def spy_iterparse(path, *args, **kwargs):
            iterparse_calls.append(str(path))
            return real_iterparse(path, *args, **kwargs)

        monkeypatch.setattr(simple_mhl.etree, "parse", spy_parse)
        monkeypatch.setattr(simple_mhl.etree, "iterparse", spy_iterparse)

        # Minimal manifest — just enough to exercise the parse path.
        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = "frame.dpx"
        etree.SubElement(h, "md5").text = "d41d8cd98f00b204e9800998ecf8427e"
        mhl = tmp_path / "test.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        mhl_cli(["verify", str(mhl)])

        assert not parse_calls, "etree.parse() was called — DOM loading detected"
        assert iterparse_calls, "etree.iterparse() was never called"


# ---------------------------------------------------------------------------
# TestSchemaShapedClassicMhlFuzz
# ---------------------------------------------------------------------------

# Schema-shaped value fuzzing — complements TestRobustness, which mutates bytes
# and therefore mostly yields *malformed* XML. Here we build *well-formed*
# manifests that follow the MediaHashList_v1_1.xsd element structure but inject
# adversarial values into the typed leaf fields the schema defines:
#   * <size>            (xs:positiveInteger)
#   * the hash digests  (md5/sha1: fixed-length hexBinary; xxhash: bounded int)
#   * the version attr  (versionType: decimal, 1 fraction digit, >= 0)
# This models the realistic threat: a user hand-edits a schema-valid manifest
# and inadvertently introduces wrong values, invalid characters, or encoding
# artifacts (NBSP, zero-width spaces, BOM, homoglyphs, full-width digits…).
# These inputs parse cleanly and so reach the value-handling code paths that
# byte-level corruption never gets to.

_FUZZ_VERSIONS = ["1.1", "1.0", "2.0", "0", "-1", "1.11", "", "abc", "1e5", "99.9"]
_FUZZ_SIZES = [
    "0",
    "-1",
    "1",
    "12345",
    "9" * 40,
    "1.5",
    "",
    "   10   ",
    "007",
    "0x1F",
    "1e3",
    "NaN",
    "abc",
    "+5",
    "  ",
    "१२३",
    "٢٣",
]
_CLASSIC_HASH_TAGS = ["md5", "sha1", "xxhash", "xxhash64", "xxhash64be", "null"]
# Digest pool weighted toward "user tampered the hash" mistakes: wrong length,
# non-hex, mixed case, and - crucially - invalid-character / encoding artifacts
# a copy-paste or a re-save-in-another-editor injects. The odd-character values
# are written as escapes (not literal glyphs) so the source stays reviewable and
# free of ambiguous Unicode, while the runtime strings carry the real bytes.
_FUZZ_DIGESTS = [
    "",
    "0" * 32,
    "0" * 40,
    "deadbeefdeadbeef",
    "DEADBEEFDEADBEEF",
    "g" * 32,
    "12345",
    "9999999999",
    "z",
    "   abc   ",
    "../etc",
    "\u00a0deadbeefdeadbeef",  # leading no-break space
    "deadbeef\u200bdeadbeef",  # embedded zero-width space
    "deadbeefdeadbeef\ufeff",  # trailing BOM / ZW no-break space
    "d\u0435\u0430db\u0435\u0435f",  # Cyrillic homoglyphs that look ASCII
    "\uff44\uff45\uff41\uff44",  # full-width latin "dead"
    "\U0001d589\U0001d58a\U0001d586\U0001d589",  # mathematical fraktur "dead" (astral)
    "rose\u0301rose\u0301",  # combining acute accents
    "deadbeef\ndeadbeef",  # embedded newline
]
_FUZZ_FILES = [
    "a.bin",
    "",
    "über.mov",
    "a b.txt",
    "name&<>'\".bin",
    "💾.mov",
    "x" * 250,
    "./rel",
    "CON",
    "a/b/c.mxf",
]


def _build_classic_fuzz_manifest(rng: random.Random) -> bytes:
    """Build a well-formed classic-MHL manifest whose leaf values are drawn from
    the adversarial pools above. Structure follows the XSD; only values vary.

    Built with lxml so the document is always well-formed and correctly escaped
    — the fuzzing targets the tool's value handling, not the XML serializer.
    """
    root = etree.Element("hashlist", version=rng.choice(_FUZZ_VERSIONS))
    for _ in range(rng.randint(1, 4)):
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = rng.choice(_FUZZ_FILES) or None
        etree.SubElement(h, "size").text = rng.choice(_FUZZ_SIZES)
        etree.SubElement(h, "lastmodificationdate").text = "2026-01-01T00:00:00Z"
        # The XSD permits one-or-more hash children (xs:choice, unbounded).
        for _ in range(rng.randint(1, 2)):
            tag = rng.choice(_CLASSIC_HASH_TAGS)
            etree.SubElement(h, tag).text = "" if tag == "null" else rng.choice(_FUZZ_DIGESTS)
        etree.SubElement(h, "hashdate").text = "2026-01-01T00:00:00Z"
    return etree.tostring(root, xml_declaration=True, encoding="UTF-8")


class TestSchemaShapedClassicMhlFuzz:
    """Well-formed, XSD-shaped manifests with adversarial leaf values must always
    yield a defined exit code — never an uncaught exception. A fixed seed keeps
    failures reproducible. Complements TestRobustness's byte-mutation fuzz."""

    def test_verify_on_schema_shaped_values(self, mhl_cli, tmp_path):
        """verify must return one of its documented codes for any schema-shaped
        manifest, whatever junk lives in the typed value fields. The referenced
        files don't exist, so this exercises XML parsing, the version attribute,
        path resolution and the missing-file path. (The size pre-check and digest
        comparison sit *after* the existence check, so they are covered by the
        existing-file tests below, not here.)"""
        rng = random.Random(1234)
        for i in range(80):
            mhl = tmp_path / f"fuzz_{i}.mhl"
            mhl.write_bytes(_build_classic_fuzz_manifest(rng))
            rc, _, _ = mhl_cli(["verify", str(mhl)])
            assert rc in {0, 1, 20, 30, 40, 70}, f"verify exit {rc} on fuzz iteration {i}"

    def test_verify_tampered_size_on_existing_files(self, mhl_cli, tmp_path):
        """Model a user editing the <size> of an entry whose file exists and whose
        digest is correct: verify gets *past* the missing-file check and actually
        runs the size pre-check. A malformed or mismatched size must be reported
        (40); a coincidentally-correct one falls through to the matching hash and
        passes (0). Never a crash, whatever odd characters or magnitudes the size
        carries — so the outcome here is driven purely by the size field."""
        rng = random.Random(24680)
        for i in range(80):
            content = bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 32)))
            data_file = tmp_path / f"clip_{i}.bin"
            data_file.write_bytes(content)

            root = etree.Element("hashlist", version="1.1")
            h = etree.SubElement(root, "hash")
            etree.SubElement(h, "file").text = data_file.name
            etree.SubElement(h, "size").text = rng.choice(_FUZZ_SIZES)  # tampered size
            etree.SubElement(h, "lastmodificationdate").text = "2026-01-01T00:00:00Z"
            etree.SubElement(h, "md5").text = hashlib.md5(content).hexdigest()  # correct digest
            etree.SubElement(h, "hashdate").text = "2026-01-01T00:00:00Z"

            mhl = tmp_path / f"sizefuzz_{i}.mhl"
            etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")
            rc, _, _ = mhl_cli(["verify", str(mhl)])
            assert rc in {0, 40}, f"verify exit {rc} on tampered-size iteration {i}"

    def test_verify_tampered_digest_on_existing_files(self, mhl_cli, tmp_path):
        """Model a user editing the digest of an entry whose file exists with the
        recorded size: verify gets *past* the existence and size pre-checks and
        actually reaches digest comparison. Whatever invalid characters or
        encoding the tampered digest carries, verify must report a clean result
        (0 if it happens to match, 40 mismatch / cannot-verify) — never crash."""
        rng = random.Random(31337)
        for i in range(80):
            content = bytes(rng.randint(0, 255) for _ in range(rng.randint(1, 32)))
            data_file = tmp_path / f"clip_{i}.bin"
            data_file.write_bytes(content)

            root = etree.Element("hashlist", version="1.1")
            h = etree.SubElement(root, "hash")
            etree.SubElement(h, "file").text = data_file.name
            etree.SubElement(h, "size").text = str(len(content))  # correct size → reaches hash step
            etree.SubElement(h, "lastmodificationdate").text = "2026-01-01T00:00:00Z"
            tag = rng.choice([t for t in _CLASSIC_HASH_TAGS if t != "null"])
            etree.SubElement(h, tag).text = rng.choice(_FUZZ_DIGESTS)
            etree.SubElement(h, "hashdate").text = "2026-01-01T00:00:00Z"

            mhl = tmp_path / f"tampered_{i}.mhl"
            etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")
            rc, _, _ = mhl_cli(["verify", str(mhl)])
            assert rc in {0, 40}, f"verify exit {rc} on tampered-digest iteration {i}"

    def test_xsd_schema_check_on_schema_shaped_values(self, mhl_cli, tmp_path):
        """xsd-schema-check must return one of its documented codes (0 valid,
        10 schema-invalid, 20 parse/file error, 60 xsd missing) — never crash."""
        rng = random.Random(5678)
        for i in range(80):
            mhl = tmp_path / f"fuzz_{i}.mhl"
            mhl.write_bytes(_build_classic_fuzz_manifest(rng))
            rc, _, _ = mhl_cli(["xsd-schema-check", str(mhl)])
            assert rc in {0, 10, 20, 60}, f"xsd-schema-check exit {rc} on fuzz iteration {i}"


# ---------------------------------------------------------------------------
# TestSmartDispatch
# ---------------------------------------------------------------------------


class TestSmartDispatch:
    """Bare path arguments are dispatched to the correct subcommand.

    simple-mhl <directory>   →  simple-mhl seal <directory>
    simple-mhl <file>.mhl    →  simple-mhl verify <file>.mhl
    """

    def test_bare_directory_dispatches_to_seal(self, mhl_cli, tmp_path):
        """Passing only a directory path (no subcommand) should seal it.

        The smart-dispatch logic in main() inspects sys.argv[1], detects an
        existing directory, and injects the 'seal' subcommand before argparse
        sees the arguments.  The result must be identical to calling
        'simple-mhl seal <dir>' explicitly.
        """
        make_tree(tmp_path, {"clip.bin": b"data"})

        # Invoke with just the directory — no explicit 'seal' subcommand.
        rc, _, _ = mhl_cli([str(tmp_path)])

        assert rc == 0, f"Expected exit 0 from implicit seal, got {rc}"
        mhls = list(tmp_path.glob("*.mhl"))
        assert len(mhls) == 1, "Expected exactly one .mhl file to be created"

    def test_bare_directory_dispatch_produces_valid_manifest(self, mhl_cli, tmp_path):
        """The manifest produced by implicit seal must be verifiable.

        Ensures dispatch injects the right subcommand *and* that all normal
        seal arguments (default algorithm, etc.) are preserved.
        """
        make_tree(tmp_path, {"a.bin": b"hello", "sub/b.bin": b"world"})
        mhl_cli([str(tmp_path)])
        mhl = next(tmp_path.glob("*.mhl"))

        rc, _, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 0, "Manifest produced by implicit seal did not verify clean"

    def test_bare_mhl_path_dispatches_to_verify(self, mhl_cli, tmp_path):
        """Passing only a .mhl path (no subcommand) should verify it.

        The smart-dispatch logic detects a .mhl extension and injects the
        'verify' subcommand.  A clean manifest must exit 0.
        """
        make_tree(tmp_path, {"a.bin": b"data"})
        mhl = seal_helper(mhl_cli, tmp_path)

        # Invoke with just the .mhl path — no explicit 'verify' subcommand.
        rc, _, _ = mhl_cli([str(mhl)])

        assert rc == 0, f"Expected exit 0 from implicit verify of clean manifest, got {rc}"

    def test_bare_mhl_path_dispatch_reports_corruption(self, mhl_cli, tmp_path):
        """Implicit verify must surface errors just as explicit verify does.

        Corrupting a file after sealing then invoking via bare .mhl path must
        produce exit 40 and the expected ERROR line — confirming dispatch
        reaches the real verify() code path, not a stub.
        """
        make_tree(tmp_path, {"a.bin": b"original"})
        mhl = seal_helper(mhl_cli, tmp_path)
        # Write same-length replacement so size pre-check passes and the hash
        # check is what catches the corruption — confirming the full verify
        # code path is exercised by implicit dispatch.
        (tmp_path / "a.bin").write_bytes(b"ORIGINAL")  # 8 bytes == len("original")

        rc, out, _ = mhl_cli([str(mhl)])

        assert rc == 40, f"Expected exit 40 from implicit verify of corrupt file, got {rc}"
        assert "[ERROR] hash mismatch: a.bin" in out

    def test_explicit_subcommand_not_intercepted(self, mhl_cli, tmp_path):
        """An explicit 'seal' or 'verify' subcommand must pass through unchanged.

        Regression guard: the dispatch block must only fire when the first
        token is NOT already a recognised subcommand.
        """
        make_tree(tmp_path, {"a.bin": b"x"})
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        assert rc == 0

        mhl = next(tmp_path.glob("*.mhl"))
        rc, _, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 0

    def test_bare_non_mhl_file_falls_through_to_argparse_error(self, mhl_cli, tmp_path):
        """A bare path that is neither a directory nor a .mhl file must fall
        through the dispatch block unmodified and let argparse reject it.

        The path is passed as the first argument with no subcommand, so it
        lands in argparse as an unrecognised subcommand → exit 2.
        This covers the fall-through branch (673→679) in main().
        """
        plain = tmp_path / "plain_text_file.txt"
        plain.write_text("data")

        rc, _, err = mhl_cli([str(plain)])

        assert rc == 2, f"Expected exit 2 from argparse, got {rc}"
        # argparse writes usage/error to stderr for unrecognised subcommands.
        assert err.strip() != "", "Expected argparse error on stderr, got silence"


class TestAlgorithmHelpHint:
    """'-h <algo>' is a common slip for '-a <algo>' and gets a pointing hint.

    '-h' is argparse's help flag (consumes no value), so the mistake would
    otherwise silently print help and ignore the algorithm/path.
    """

    def test_hint_points_to_algorithm_flag_then_shows_help(self, mhl_cli, tmp_path):
        rc, out, err = mhl_cli(["seal", "-h", "xxhash", str(tmp_path)])

        # Exit 2 (usage error)
        assert rc == 2
        # Hint on stderr, naming the exact flag the user meant.
        assert "Did you mean '-a xxhash' (-a / --algorithm)?" in err
        # The subcommand's normal help still prints (on stdout).
        assert "--algorithm" in out

    def test_verify_all_is_recognised_as_an_algorithm_value(self, mhl_cli):
        # 'all' is a valid verify selection, so 'verify -h all' gets the hint too.
        rc, _, err = mhl_cli(["verify", "-h", "all"])

        assert rc == 2
        assert "Did you mean '-a all' (-a / --algorithm)?" in err

    def test_seal_does_not_treat_all_as_an_algorithm(self, mhl_cli):
        # 'all' is verify-only; for seal, '-h all' is just plain help, no hint.
        rc, _, err = mhl_cli(["seal", "-h", "all"])

        assert rc == 0
        assert "Did you mean" not in err

    def test_bare_help_flag_still_shows_help_unchanged(self, mhl_cli):
        # '-h' with no algorithm after it is ordinary help — no hint.
        rc, out, err = mhl_cli(["seal", "-h"])

        assert rc == 0
        assert "Did you mean" not in err
        assert "--algorithm" in out


# ---------------------------------------------------------------------------
# TestSizePreCheck
# ---------------------------------------------------------------------------


class TestSizePreCheck:
    """File size is checked before hash computation during verify.

    The size pre-check is a fast, cheap guard: a stat() call that can rule
    out corruption without reading the entire file.  These tests confirm:

      * A single size-mismatched file is caught and reported.
      * The check fires *before* get_hash() is called (get_hash is not
        invoked when the size already proves the file is wrong).
      * A malformed (non-decimal) <size> field is flagged as corruption
        rather than silently skipped.
      * Even if a hash digest happens to match (forced via monkeypatch), a
        size discrepancy is still reported — size wins over hash agreement.
    """

    def test_size_mismatch_is_caught(self, mhl_cli, tmp_path):
        """A file whose on-disk size differs from the manifest <size> exits 40.

        Mechanism: we write the file with content 'hello' (5 bytes) but record
        size=9999 in the manifest, then verify.  The size pre-check must catch
        this without needing to hash the file.
        """
        mhl = make_mhl_with_size(tmp_path, "clip.bin", b"hello", size_override="9999")

        rc, out, _ = mhl_cli(["verify", str(mhl)])

        assert rc == 40, f"Expected exit 40 for size mismatch, got {rc}"
        assert "clip.bin" in out, "Affected filename must appear in output"
        # Accept either 'size mismatch' or 'malformed size' phrasing — both
        # indicate the size check fired before hashing.
        assert "size" in out.lower(), f"Expected a size-related error message, got: {out!r}"

    def test_size_mismatch_skips_hash_computation(self, mhl_cli, tmp_path, monkeypatch):
        """get_hashes() must NOT be called when the size pre-check already fails.

        A size mismatch is a definitive failure signal.  Hashing afterwards wastes
        I/O on a file that is already known to be wrong. verify() hashes through
        get_hashes (one read pass for one-or-many formats), so the spy watches that
        to confirm hashing is never reached.
        """
        get_hashes_calls: list[str] = []
        real_get_hashes = simple_mhl.get_hashes

        def spy_get_hashes(filepath, factories):
            get_hashes_calls.append(filepath)
            return real_get_hashes(filepath, factories)

        monkeypatch.setattr(core_hashing, "get_hashes", spy_get_hashes)

        mhl = make_mhl_with_size(tmp_path, "clip.bin", b"hello", size_override="9999")

        rc, _, _ = mhl_cli(["verify", str(mhl)])

        assert rc == 40, f"Expected exit 40, got {rc}"
        assert get_hashes_calls == [], (
            f"get_hashes() was called {len(get_hashes_calls)} time(s) despite size mismatch — "
            "the pre-check must short-circuit before hashing"
        )

    def test_malformed_size_field_is_flagged(self, mhl_cli, tmp_path):
        """A <size> containing non-decimal characters must be flagged as corrupt.

        Non-decimal Unicode digits (e.g. superscript '2\xb246896176' as seen in
        real-world corrupted MHL files) are rejected by isdecimal().  The tool
        must report this as a manifest error, not silently skip the check.
        """
        # Embed a superscript-two (U+00B2) mid-string — exactly the pattern
        # seen in the BGR2_20260426 fixture that triggered this requirement.
        mhl = make_mhl_with_size(tmp_path, "clip.bin", b"hello", size_override="2\xb246896176")

        rc, out, _ = mhl_cli(["verify", str(mhl)])

        assert rc == 40, f"Expected exit 40 for malformed size field, got {rc}"
        assert "clip.bin" in out
        assert "malformed size" in out.lower(), f"Expected 'malformed size' in output, got: {out!r}"

    def test_size_mismatch_caught_even_when_hash_matches(self, mhl_cli, tmp_path, monkeypatch):
        """A size discrepancy must be reported even if the hash digest matches.

        xxhash64 is non-cryptographic and constructing a real same-digest
        collision for two files of different lengths is impractical without
        specialised tooling.  Instead we monkeypatch get_hashes() to return the
        *correct* digest for the on-disk file regardless, then verify that the
        size check still fires before hashing is reached.

        This is the adversarially interesting case: a tool that only checks the
        hash would silently pass a file whose size is wrong (e.g. a truncated
        file that happens to share its hash with another file).  The size check
        must take priority.
        """
        content = b"A" * 1024
        correct_digest = xxhash.xxh64(content).hexdigest()

        # Record the correct digest but a wrong size.
        mhl = make_mhl_with_size(tmp_path, "clip.bin", content, size_override="9999")

        # Ensure get_hashes would return the correct digest if ever called,
        # so the only thing that can trigger the failure is the size check.
        def always_correct_hash(filepath, factories):
            return [correct_digest for _ in factories]

        monkeypatch.setattr(core_hashing, "get_hashes", always_correct_hash)

        rc, out, _ = mhl_cli(["verify", str(mhl)])

        assert rc == 40, f"Expected exit 40: size mismatch must be caught even when hash matches, got {rc}"
        assert "clip.bin" in out
        assert "size" in out.lower(), f"Expected a size-related error message, got: {out!r}"

    def test_correct_size_proceeds_to_hash_check(self, mhl_cli, tmp_path):
        """When size matches, verify must still check the hash.

        Regression guard: the size pre-check must not short-circuit a clean
        file.  A file with a matching size but a wrong hash must still exit 40.
        """
        content = b"original"
        mhl = make_mhl_with_size(tmp_path, "clip.bin", content)

        # Overwrite with same-size content that has a different hash.
        (tmp_path / "clip.bin").write_bytes(b"ORIGINAL")  # same 8 bytes, different content

        rc, out, _ = mhl_cli(["verify", str(mhl)])

        assert rc == 40, f"Expected exit 40 for hash mismatch after size matches, got {rc}"
        assert "hash mismatch" in out.lower()


# ---------------------------------------------------------------------------
# TestUnicodeNormalization
# ---------------------------------------------------------------------------


class TestUnicodeNormalization:
    """NFC normalization of accented filenames at seal and verify time.

    macOS HFS+/APFS returns filenames in NFD (decomposed) form — e.g. the
    single codepoint é (U+00E9) is decomposed to e (U+0065) + combining acute
    (U+0301).  Linux ext4 does byte-exact filename matching, so an NFD path
    from the manifest would silently fail os.path.exists() against an NFC file
    on disk.

    simple_mhl reconciles normalization forms at two points:
      1. seal — rel_path_posix is normalized to NFC before writing the <file>
                element, so manifests are written in canonical NFC.
      2. verify — unicodepaths.resolve_on_disk() matches the manifest path against real
                  directory entries across normalization forms (literal bytes
                  first, NFC-keyed index as fallback) so it finds the file
                  whatever form it is stored in, without assuming the
                  filesystem normalizes for us.

    These tests construct NFD filenames explicitly so the behaviour is
    deterministic regardless of what the host OS normalizes at mkdir/write time.
    """

    # NFD forms used across tests:
    #   NFC: "Ré.txt"  = R + U+00E9 (precomposed é)
    #   NFD: "Ré.txt"  = R + e + U+0301 (combining acute)
    _NFC_NAME = "R\u00e9.txt"  # R + precomposed é
    _NFD_NAME = "Re\u0301.txt"  # R + e + combining acute

    def test_seal_writes_nfc_for_nfd_filesystem_path(self, mhl_cli, tmp_path, monkeypatch):
        """seal() must write NFC <file> entries even when the filesystem returns NFD paths.

        We write the file under its NFD name (so get_hash can open it on any OS,
        since the path we hand to seal must actually exist on disk) and patch
        _iter_files_for_seal to yield that NFD path — simulating what macOS
        HFS+/APFS returns from rglob.  The manifest must contain the NFC form.

        On macOS, HFS+/APFS treats NFC and NFD as the same file, so both names
        resolve to the same inode.  On Linux ext4, filenames are byte-exact, so
        we must create the file with the NFD name to allow get_hash to open it.
        Either way, the assertion is the same: the manifest entry must be NFC.
        """

        # Create the file with the NFD name — openable on all platforms.
        nfd_path = tmp_path / self._NFD_NAME
        nfd_path.write_bytes(b"data")

        real_iter = simple_mhl._iter_files_for_seal

        def nfd_iter(root, mhl_path, on_skip=None):
            for p, stat_result in real_iter(root, mhl_path, on_skip=on_skip):
                # Yield the path as-is; real_iter already found the NFD file.
                # Normalize to NFD explicitly in case the OS returned NFC
                # (e.g. on a case-insensitive macOS volume that normalizes on
                # readback), ensuring the test exercises the NFC fix on all OSes.
                nfd_str = unicodedata.normalize("NFD", str(p))
                yield Path(nfd_str), stat_result

        monkeypatch.setattr(core_seal, "_iter_files_for_seal", nfd_iter)

        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        assert rc == 0

        mhl = next(tmp_path.glob("*.mhl"))
        text = mhl.read_text(encoding="utf-8")
        # The <file> element must contain the NFC form regardless of what was
        # on disk or what the iterator yielded.
        assert self._NFC_NAME in text, (
            f"Expected NFC name {self._NFC_NAME!r} in manifest. "
            f"Manifest snippet: {text[text.find('<file>') : text.find('</file>') + 7]!r}"
        )
        # The NFD byte sequence must not appear in the raw manifest bytes.
        assert self._NFD_NAME.encode("utf-8") not in mhl.read_bytes(), (
            "NFD byte sequence found in manifest — NFC normalization did not fire"
        )

    def test_seal_nfc_is_idempotent_for_already_nfc_paths(self, mhl_cli, tmp_path):
        """NFC normalization of an already-NFC path must produce the same result.

        Regression guard: applying NFC to a path that is already NFC must not
        corrupt the filename or produce a different string.
        """
        nfc_path = tmp_path / self._NFC_NAME
        nfc_path.write_bytes(b"data")

        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        assert rc == 0

        text = next(tmp_path.glob("*.mhl")).read_text(encoding="utf-8")
        assert self._NFC_NAME in text

    def test_verify_nfc_manifest_finds_nfc_file(self, mhl_cli, tmp_path):
        """verify() must find a file when both the manifest and disk use NFC.

        This is the baseline happy path for NFC filenames — seal then verify
        on the same OS must always work.
        """
        make_tree(tmp_path, {self._NFC_NAME: b"data"})
        mhl = seal_helper(mhl_cli, tmp_path)

        rc, _, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 0

    def test_verify_normalizes_nfd_manifest_path_to_find_nfc_file(self, mhl_cli, tmp_path):
        """verify() must find an NFC file on disk even when the manifest contains an NFD path.

        This is the cross-platform scenario: manifest sealed on macOS (NFD paths)
        verified on Linux (NFC files, byte-exact matching). We construct the
        manifest by hand with an NFD <file> entry pointing at an NFC file on disk.
        """

        # Create the file with an NFC name.
        nfc_path = tmp_path / self._NFC_NAME
        nfc_path.write_bytes(b"data")
        digest = simple_mhl.get_hash(str(nfc_path), "md5")

        # Write a manifest with the NFD form of the same name.
        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = self._NFD_NAME  # NFD — simulates macOS seal
        etree.SubElement(h, "size").text = str(len(b"data"))
        etree.SubElement(h, "lastmodificationdate").text = "2026-01-01T00:00:00Z"
        etree.SubElement(h, "md5").text = digest
        etree.SubElement(h, "hashdate").text = "2026-01-01T00:00:00Z"
        mhl = tmp_path / "test.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, out, _ = mhl_cli(["verify", str(mhl)])

        assert rc == 0, f"verify() failed to find NFC file via NFD manifest path. Exit {rc}, output: {out!r}"

    def test_verify_nfd_manifest_path_correct_hash_passes(self, mhl_cli, tmp_path):
        """Complement to the above: NFD manifest + correct digest = clean verify.

        Confirms the normalization does not break the hash check that follows.
        """

        nfc_path = tmp_path / self._NFC_NAME
        content = b"accented content"
        nfc_path.write_bytes(content)
        digest = simple_mhl.get_hash(str(nfc_path), "md5")

        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = self._NFD_NAME
        etree.SubElement(h, "size").text = str(len(content))
        etree.SubElement(h, "lastmodificationdate").text = "2026-01-01T00:00:00Z"
        etree.SubElement(h, "md5").text = digest
        etree.SubElement(h, "hashdate").text = "2026-01-01T00:00:00Z"
        mhl = tmp_path / "test.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, _, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 0

    def test_verify_nfd_manifest_path_wrong_hash_still_fails(self, mhl_cli, tmp_path):
        """NFD normalization must not suppress a genuine hash mismatch.

        Regression guard: the normalization step must not interfere with the
        hash check. A correct NFC path resolution followed by a wrong digest
        must still exit 40.
        """
        nfc_path = tmp_path / self._NFC_NAME
        nfc_path.write_bytes(b"original")

        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = self._NFD_NAME
        etree.SubElement(h, "size").text = str(len(b"original"))
        etree.SubElement(h, "lastmodificationdate").text = "2026-01-01T00:00:00Z"
        etree.SubElement(h, "md5").text = "0" * 32  # wrong digest
        etree.SubElement(h, "hashdate").text = "2026-01-01T00:00:00Z"
        mhl = tmp_path / "test.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, out, _ = mhl_cli(["verify", str(mhl)])

        assert rc == 40
        assert "hash mismatch" in out.lower()

    def test_verify_nfc_manifest_finds_nfd_file_on_disk(self, mhl_cli, tmp_path):
        """Scenario 3 (end-to-end): manifest path is NFC, the file on disk is NFD.

        Mirror of test_verify_normalizes_nfd_manifest_path_to_find_nfc_file.
        On a normalization-*sensitive* filesystem (ext4/exFAT/NTFS — e.g. Linux
        CI) the literal NFC lookup misses and resolution scans the directory and
        matches on NFC; on an *insensitive* volume (APFS/HFS+ — e.g. macOS dev)
        the literal lookup already succeeds. Either way verify must find and
        check the file, so this passes regardless of host filesystem.
        """
        nfd_path = tmp_path / self._NFD_NAME
        content = b"data"
        nfd_path.write_bytes(content)
        digest = simple_mhl.get_hash(str(nfd_path), "md5")

        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = self._NFC_NAME  # NFC manifest path
        etree.SubElement(h, "size").text = str(len(content))
        etree.SubElement(h, "lastmodificationdate").text = "2026-01-01T00:00:00Z"
        etree.SubElement(h, "md5").text = digest
        etree.SubElement(h, "hashdate").text = "2026-01-01T00:00:00Z"
        mhl = tmp_path / "test.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, out, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 0, f"verify failed to resolve NFC manifest to NFD disk file: {rc}, {out!r}"


# ---------------------------------------------------------------------------
# unicodepaths.resolve_on_disk — normalization-insensitive path resolution
# ---------------------------------------------------------------------------


class _FakeEntry:
    """Minimal stand-in for os.DirEntry — only .name is read by the resolver."""

    def __init__(self, name: str) -> None:
        self.name = name


def _sensitive_fs(existing: set[str]):
    """Build (lexists, scandir) callables modelling a normalization-sensitive,
    byte-exact filesystem (exFAT/ext4/NTFS) from a set of absolute paths.

    lexists is exact-string membership, so an NFC name and its NFD equivalent
    are distinct entries (the behaviour that cannot be reproduced on the APFS
    host). scandir returns the immediate children of a path and raises OSError
    when the path has none (modelling a file or a missing directory).
    """

    def lexists(p: str) -> bool:
        return p in existing

    def scandir(d: str):
        prefix = d.rstrip(os.sep) + os.sep
        names: list[str] = []
        for p in existing:
            if p.startswith(prefix):
                name = p[len(prefix) :].split(os.sep, 1)[0]
                if name and name not in names:
                    names.append(name)
        if not names:
            raise OSError(20, "Not a directory", d)
        return [_FakeEntry(n) for n in names]

    return lexists, scandir


class TestResolveOnDisk:
    """Unit tests for unicodepaths.resolve_on_disk against a simulated
    normalization-sensitive filesystem.

    The host filesystem on dev machines (APFS) is normalization-*insensitive*
    and cannot host coexisting NFC + NFD entries, so the sensitive-FS behaviour
    — the entire reason the resolver exists — must be exercised with patched
    lexists/scandir rather than real files.
    """

    _BASE = os.path.join(os.sep, "vol")
    _NFC = "ros\u00e9"  # rosé: c a f + precomposed é (U+00E9)
    _NFD = "rose\u0301"  # rosé: c a f e + combining acute (U+0301); same NFC key

    def _patch(self, monkeypatch, existing):
        lexists, scandir = _sensitive_fs(set(existing))
        monkeypatch.setattr(os.path, "lexists", lexists)
        monkeypatch.setattr(os, "scandir", scandir)

    def test_fast_path_literal_hit_does_not_scandir(self, monkeypatch):
        """When the literal path exists, resolution returns it without scanning
        — the common case, and the only correct choice when forms coexist."""
        nfc_file = os.path.join(self._BASE, self._NFC, "text.txt")
        existing = {self._BASE, os.path.join(self._BASE, self._NFC), nfc_file}
        lexists, real_scandir = _sensitive_fs(existing)
        calls: list[str] = []
        monkeypatch.setattr(os.path, "lexists", lexists)
        monkeypatch.setattr(os, "scandir", lambda d: calls.append(d) or real_scandir(d))

        result = unicodepaths.resolve_on_disk(self._BASE, os.path.join(self._NFC, "text.txt"), {})
        assert result == nfc_file
        assert calls == []  # never scanned

    def test_scenario3_nfc_query_resolves_to_nfd_on_disk(self, monkeypatch):
        """Scenario 3: NFC manifest path, NFD name on a sensitive filesystem.
        The literal NFC lookup misses; the NFC-keyed index resolves the real
        NFD entry."""
        nfd_file = os.path.join(self._BASE, self._NFD, "text.txt")
        self._patch(
            monkeypatch,
            {self._BASE, os.path.join(self._BASE, self._NFD), nfd_file},
        )
        result = unicodepaths.resolve_on_disk(self._BASE, os.path.join(self._NFC, "text.txt"), {})
        assert result == nfd_file

    def test_scenario2_coexisting_forms_resolve_distinctly(self, monkeypatch):
        """Scenario 2: NFC and NFD rosé/ both exist (sensitive FS). Each query
        resolves to its own distinct directory via the literal fast path — the
        two forms never collapse onto one."""
        nfc_file = os.path.join(self._BASE, self._NFC, "text.txt")
        nfd_file = os.path.join(self._BASE, self._NFD, "text.txt")
        self._patch(
            monkeypatch,
            {
                self._BASE,
                os.path.join(self._BASE, self._NFC),
                nfc_file,
                os.path.join(self._BASE, self._NFD),
                nfd_file,
            },
        )
        assert unicodepaths.resolve_on_disk(self._BASE, os.path.join(self._NFC, "text.txt"), {}) == nfc_file
        assert unicodepaths.resolve_on_disk(self._BASE, os.path.join(self._NFD, "text.txt"), {}) == nfd_file

    def test_intermediate_directory_normalization_mismatch(self, monkeypatch):
        """Normalization can differ on a non-leaf component: an ASCII parent, an
        NFD middle directory on disk addressed by an NFC manifest path, then an
        ASCII leaf. The resolver must reconcile the middle component."""
        real_file = os.path.join(self._BASE, "sub", self._NFD, "text.txt")
        self._patch(
            monkeypatch,
            {
                self._BASE,
                os.path.join(self._BASE, "sub"),
                os.path.join(self._BASE, "sub", self._NFD),
                real_file,
            },
        )
        result = unicodepaths.resolve_on_disk(self._BASE, os.path.join("sub", self._NFC, "text.txt"), {})
        assert result == real_file

    def test_genuinely_missing_returns_none(self, monkeypatch):
        """A name that matches in no normalization form resolves to None."""
        self._patch(monkeypatch, {self._BASE, os.path.join(self._BASE, "other.txt")})
        assert unicodepaths.resolve_on_disk(self._BASE, "ghost.txt", {}) is None

    def test_unreadable_directory_returns_none(self, monkeypatch):
        """When an intermediate component is not a scannable directory, scandir
        raises OSError and resolution returns None (treated as missing)."""
        # 'sub' exists as a leaf (file), so scandir(base/sub) raises OSError.
        self._patch(monkeypatch, {self._BASE, os.path.join(self._BASE, "sub")})
        assert unicodepaths.resolve_on_disk(self._BASE, os.path.join("sub", "child.txt"), {}) is None

    def test_empty_and_curdir_components_are_skipped(self, monkeypatch):
        """Leading './' and doubled separators yield empty / os.curdir path
        components, which must be skipped without affecting resolution."""
        leaf = os.path.join(self._BASE, "text.txt")
        self._patch(monkeypatch, {self._BASE, leaf})
        # rel_path like "./text.txt" → split gives [os.curdir, "text.txt"].
        rel = os.curdir + os.sep + "text.txt"
        assert unicodepaths.resolve_on_disk(self._BASE, rel, {}) == leaf

    def test_dir_index_caches_scandir_per_directory(self, monkeypatch):
        """Two files in the same NFD directory, addressed via NFC, must scan
        that directory only once (cached in dir_index across resolutions)."""
        f1 = os.path.join(self._BASE, self._NFD, "a.txt")
        f2 = os.path.join(self._BASE, self._NFD, "b.txt")
        existing = {self._BASE, os.path.join(self._BASE, self._NFD), f1, f2}
        lexists, real_scandir = _sensitive_fs(existing)
        calls: list[str] = []
        monkeypatch.setattr(os.path, "lexists", lexists)
        monkeypatch.setattr(os, "scandir", lambda d: calls.append(d) or real_scandir(d))

        index: dict[str, dict[str, str]] = {}
        r1 = unicodepaths.resolve_on_disk(self._BASE, os.path.join(self._NFC, "a.txt"), index)
        r2 = unicodepaths.resolve_on_disk(self._BASE, os.path.join(self._NFC, "b.txt"), index)
        assert r1 == f1
        assert r2 == f2
        assert calls == [self._BASE]  # scanned once; leaves hit the literal fast path


# ---------------------------------------------------------------------------
# "did you mean" hint for typed CLI paths with a normalization mismatch
# ---------------------------------------------------------------------------


def _patch_sensitive(monkeypatch, files, dirs):
    """Patch exists/isdir/lexists/scandir to model a normalization-sensitive,
    byte-exact filesystem from explicit file and directory path sets."""
    files = set(files)
    dirs = set(dirs)
    all_paths = files | dirs
    lexists, scandir = _sensitive_fs(all_paths)
    monkeypatch.setattr(os.path, "lexists", lexists)
    monkeypatch.setattr(os, "scandir", scandir)
    monkeypatch.setattr(os.path, "exists", lambda p: p in all_paths)
    monkeypatch.setattr(os.path, "isdir", lambda p: p in dirs)
    # The fabricated paths are already absolute and drive-less; keep abspath an
    # identity so it doesn't prepend the current drive on Windows (D:\vol\...)
    # and stop matching the fake filesystem's \vol\... entries.
    monkeypatch.setattr(os.path, "abspath", lambda p: p)


class TestNormalizationVariantHint:
    """The typed CLI path (verify's .mhl, seal's root) is left to the OS, but a
    not-found error suggests a real on-disk path that differs only in Unicode
    normalization. Simulated on a sensitive filesystem (the only place the
    mismatch is observable)."""

    _VOL = os.path.join(os.sep, "vol")
    _NFC = "ros\u00e9"  # rosé: precomposed é (U+00E9)
    _NFD = "rose\u0301"  # rosé: e + combining acute (U+0301); same NFC key

    def test_variant_helper_finds_differently_normalized_path(self, monkeypatch):
        nfd_mhl = os.path.join(self._VOL, self._NFD, "m.mhl")
        _patch_sensitive(
            monkeypatch,
            files={nfd_mhl},
            dirs={os.sep, self._VOL, os.path.join(self._VOL, self._NFD)},
        )
        typed = os.path.join(self._VOL, self._NFC, "m.mhl")  # NFC, not on disk
        assert unicodepaths.normalization_variant_on_disk(typed) == nfd_mhl

    def test_variant_helper_returns_none_for_genuine_typo(self, monkeypatch):
        _patch_sensitive(
            monkeypatch,
            files={os.path.join(self._VOL, "real.mhl")},
            dirs={os.sep, self._VOL},
        )
        assert unicodepaths.normalization_variant_on_disk(os.path.join(self._VOL, "ghost.mhl")) is None

    def test_variant_helper_returns_none_when_path_exists_as_typed(self, monkeypatch):
        typed = os.path.join(self._VOL, "m.mhl")
        _patch_sensitive(monkeypatch, files={typed}, dirs={os.sep, self._VOL})
        assert unicodepaths.normalization_variant_on_disk(typed) is None

    def test_root_only_path_returns_none(self):
        """A bare root (no path tail) leaves nothing to resolve, so the helper
        returns None before touching the filesystem."""
        assert unicodepaths.normalization_variant_on_disk(os.sep) is None

    def test_verify_not_found_suggests_variant(self, monkeypatch, capsys):
        nfd_mhl = os.path.join(self._VOL, self._NFD, "m.mhl")
        _patch_sensitive(
            monkeypatch,
            files={nfd_mhl},
            dirs={os.sep, self._VOL, os.path.join(self._VOL, self._NFD)},
        )
        typed = os.path.join(self._VOL, self._NFC, "m.mhl")
        with pytest.raises(SystemExit) as exc:
            simple_mhl._validate_mhl_path(typed)
        assert exc.value.code == 1
        err = capsys.readouterr().err
        assert "did you mean" in err
        assert nfd_mhl in err

    def test_verify_not_found_no_variant_is_plain_error(self, monkeypatch, capsys):
        _patch_sensitive(
            monkeypatch,
            files={os.path.join(self._VOL, "real.mhl")},
            dirs={os.sep, self._VOL},
        )
        with pytest.raises(SystemExit) as exc:
            simple_mhl._validate_mhl_path(os.path.join(self._VOL, "ghost.mhl"))
        assert exc.value.code == 1
        err = capsys.readouterr().err
        assert "not found" in err
        assert "did you mean" not in err

    def test_seal_not_a_directory_suggests_variant(self, monkeypatch, capsys):
        nfd_dir = os.path.join(self._VOL, self._NFD)
        _patch_sensitive(
            monkeypatch,
            files=set(),
            dirs={os.sep, self._VOL, nfd_dir},
        )
        typed = os.path.join(self._VOL, self._NFC)  # NFC dir, not on disk
        with pytest.raises(SystemExit) as exc:
            simple_mhl.seal(typed, ["md5"])
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "did you mean" in err
        assert nfd_dir in err


# ---------------------------------------------------------------------------
# hostinfo.friendly_hostname — shared host identity helper
# ---------------------------------------------------------------------------


class TestFriendlyHostname:
    """friendly_hostname prefers the macOS ComputerName, with fallbacks. Shared
    by simple_mhl (manifest <hostname>) and mhlver (report Host field)."""

    def test_macos_uses_computer_name(self, monkeypatch):
        """On macOS the user-facing ComputerName from scutil is preferred over
        the bare network hostname."""
        monkeypatch.setattr(hostinfo.sys, "platform", "darwin")
        completed = hostinfo.subprocess.CompletedProcess(
            args=[], returncode=0, stdout="Luis's MacBook Pro\n", stderr=""
        )
        monkeypatch.setattr(hostinfo.subprocess, "run", lambda *a, **kw: completed)
        assert hostinfo.friendly_hostname() == "Luis's MacBook Pro"

    def test_macos_falls_back_to_node_when_scutil_fails(self, monkeypatch):
        """If scutil is missing or errors, fall back to platform.node()."""
        monkeypatch.setattr(hostinfo.sys, "platform", "darwin")
        monkeypatch.setattr(hostinfo.subprocess, "run", lambda *a, **kw: (_ for _ in ()).throw(OSError()))
        monkeypatch.setattr(hostinfo.platform, "node", lambda: "fallback-host")
        assert hostinfo.friendly_hostname() == "fallback-host"

    def test_non_macos_uses_node(self, monkeypatch):
        """Off macOS, platform.node() is used directly (FQDN preserved)."""
        monkeypatch.setattr(hostinfo.sys, "platform", "linux")
        monkeypatch.setattr(hostinfo.platform, "node", lambda: "nas01.studio.local")
        assert hostinfo.friendly_hostname() == "nas01.studio.local"

    def test_empty_node_falls_back_to_unknown(self, monkeypatch):
        """A blank platform.node() (minimal containers) yields a stable label."""
        monkeypatch.setattr(hostinfo.sys, "platform", "linux")
        monkeypatch.setattr(hostinfo.platform, "node", lambda: "")
        assert hostinfo.friendly_hostname() == "unknown"

    def test_scutil_decoded_as_utf8_regardless_of_locale(self, monkeypatch):
        """scutil output must be decoded as UTF-8, not via the (possibly ASCII)
        locale — otherwise a ComputerName with a curly apostrophe, accent, or
        emoji would raise UnicodeDecodeError under LANG=C. A non-ASCII name
        must round-trip intact."""
        captured: dict = {}

        def fake_run(*a, **kw):
            captured.update(kw)
            return hostinfo.subprocess.CompletedProcess(
                args=[], returncode=0, stdout="Jos\u00e9\u2019s iMac \U0001f3ac\n", stderr=""
            )

        monkeypatch.setattr(hostinfo.sys, "platform", "darwin")
        monkeypatch.setattr(hostinfo.subprocess, "run", fake_run)
        assert hostinfo.friendly_hostname() == "Jos\u00e9\u2019s iMac \U0001f3ac"
        assert captured.get("encoding") == "utf-8"
        assert captured.get("errors") == "replace"

    def test_creatorinfo_uses_friendly_hostname(self, monkeypatch):
        """The manifest's creatorinfo <hostname> is sourced from the shared
        helper, not the bare network hostname."""
        monkeypatch.setattr(core_seal, "friendly_hostname", lambda: "Luis's MacBook Pro")
        doc = etree.Element("hashlist", version="1.1")
        info = simple_mhl._build_creatorinfo(doc, "simple-mhl test", "2026-01-01T00:00:00Z")
        assert info.findtext("hostname") == "Luis's MacBook Pro"


# ---------------------------------------------------------------------------
# TestAdaptiveHashing — locks the auto-concurrency decisions and invariants
# ---------------------------------------------------------------------------


class TestAdaptiveHashing:
    """Behaviour of _hash_files_auto / _probe_read_bw / _hash_batch.

    These pin the *decisions* (sequential vs parallel-N vs demotion) and the
    output invariant, never the throughput numbers (which are hardware-bound).
    The disk/hash measurements are mocked so the tests are deterministic on any
    machine — including the all-important guarantee that concurrency never
    changes the manifest.
    """

    @staticmethod
    def _make_files(tmp_path, count, algo="md5"):
        paths, sizes = [], []
        for i in range(count):
            p = tmp_path / f"f{i:04d}.bin"
            p.write_bytes(bytes([i % 256]) * (1000 + i))  # distinct content & size
            paths.append(str(p))
            sizes.append(p.stat().st_size)
        ref = [simple_mhl.get_hash(p, algo) for p in paths]  # pure-sequential reference
        return paths, sizes, ref

    def _force(self, monkeypatch, *, read_bw, hash_bw, cpu=8, min_bytes=0, recheck=8 * 1024**3):
        monkeypatch.setattr(core_hashing, "_AUTO_MIN_BYTES", min_bytes)
        monkeypatch.setattr(core_hashing, "_AUTO_RECHECK_BYTES", recheck)
        monkeypatch.setattr(core_hashing, "_calibrate_hash_bw", lambda algo: hash_bw)
        # seal calibrates all formats combined via _calibrate_hash_bw_multi.
        monkeypatch.setattr(core_hashing, "_calibrate_hash_bw_multi", lambda factories: hash_bw)
        monkeypatch.setattr(core_hashing, "_probe_read_bw", lambda paths: read_bw)
        monkeypatch.setattr(simple_mhl.os, "cpu_count", lambda: cpu)

    def _spy_batch(self, monkeypatch):
        calls: list[int] = []
        real = core_hashing._hash_batch

        def spy(jobs, workers):
            calls.append(workers)
            return real(jobs, workers)

        monkeypatch.setattr(core_hashing, "_hash_batch", spy)
        return calls

    # --- output invariance: the manifest must be identical on every path -----

    def test_output_identical_parallel_branch(self, tmp_path, monkeypatch):
        paths, sizes, ref = self._make_files(tmp_path, 30)
        self._force(monkeypatch, read_bw=4000, hash_bw=1000)
        assert [d for d, _hashdate in simple_mhl._hash_files_auto(paths, sizes, ["md5"])] == [[r] for r in ref]

    def test_output_identical_demotion_branch(self, tmp_path, monkeypatch):
        paths, sizes, ref = self._make_files(tmp_path, 30)
        # hash_bw huge => every window's measured rate < hash_bw => demote; a
        # tiny recheck window makes demotion leave a real sequential remainder.
        self._force(monkeypatch, read_bw=1e30, hash_bw=1e18, recheck=1)
        assert [d for d, _hashdate in simple_mhl._hash_files_auto(paths, sizes, ["md5"])] == [[r] for r in ref]

    def test_output_identical_sequential_gate(self, tmp_path, monkeypatch):
        paths, sizes, ref = self._make_files(tmp_path, 30)
        self._force(monkeypatch, read_bw=100, hash_bw=1000)  # disk-bound
        assert [d for d, _hashdate in simple_mhl._hash_files_auto(paths, sizes, ["md5"])] == [[r] for r in ref]

    # --- decisions -----------------------------------------------------------

    def test_disk_bound_never_parallelises(self, tmp_path, monkeypatch):
        """read_bw below the threshold (HDD / fast hash) must stay sequential —
        the branch that protects spinning disks from seek-thrash."""
        paths, sizes, _ = self._make_files(tmp_path, 10)
        self._force(monkeypatch, read_bw=100, hash_bw=1000)
        calls = self._spy_batch(monkeypatch)
        list(simple_mhl._hash_files_auto(paths, sizes, ["md5"]))
        assert all(w <= 1 for w in calls), f"disk-bound must not issue a concurrent batch, saw {calls}"

    def test_parallel_worker_count_from_bandwidth(self, tmp_path, monkeypatch):
        """workers ~= round(read_bw / hash_bw)."""
        paths, sizes, _ = self._make_files(tmp_path, 10)
        self._force(monkeypatch, read_bw=4000, hash_bw=1000, cpu=8)
        calls = self._spy_batch(monkeypatch)
        list(simple_mhl._hash_files_auto(paths, sizes, ["md5"]))
        assert calls, "expected a concurrent batch to run"
        assert max(calls) == 4, f"expected 4 workers, saw {calls}"

    def test_worker_count_clamped_to_cores(self, tmp_path, monkeypatch):
        paths, sizes, _ = self._make_files(tmp_path, 10)
        self._force(monkeypatch, read_bw=100_000, hash_bw=1000, cpu=4)  # wants 100, capped to cores
        calls = self._spy_batch(monkeypatch)
        list(simple_mhl._hash_files_auto(paths, sizes, ["md5"]))
        assert calls, "expected a concurrent batch to run"
        assert max(calls) == 4

    def test_small_job_skips_probe(self, tmp_path, monkeypatch):
        paths, sizes, ref = self._make_files(tmp_path, 5)
        monkeypatch.setattr(core_hashing, "_AUTO_MIN_BYTES", 10 * 1024**3)  # larger than the job
        probed: list[int] = []
        monkeypatch.setattr(core_hashing, "_probe_read_bw", lambda p: probed.append(1) or 1.0)
        assert [d for d, _hashdate in simple_mhl._hash_files_auto(paths, sizes, ["md5"])] == [[r] for r in ref]
        assert probed == [], "a sub-threshold job must not probe the disk"

    def test_single_file_skips_probe(self, tmp_path, monkeypatch):
        paths, sizes, ref = self._make_files(tmp_path, 1)
        monkeypatch.setattr(core_hashing, "_AUTO_MIN_BYTES", 0)
        probed: list[int] = []
        monkeypatch.setattr(core_hashing, "_probe_read_bw", lambda p: probed.append(1) or 9e9)
        assert [d for d, _hashdate in simple_mhl._hash_files_auto(paths, sizes, ["md5"])] == [[r] for r in ref]
        assert probed == [], "nothing to parallelise across a single file"

    # --- helpers -------------------------------------------------------------

    def test_hash_batch_preserves_order(self, tmp_path):
        paths, _, ref = self._make_files(tmp_path, 20)
        jobs: list[Callable[[], str]] = [(lambda p=p: simple_mhl.get_hash(p, "md5")) for p in paths]
        assert simple_mhl._hash_batch(jobs, 4) == ref

    def test_hash_batch_runs_jobs_concurrently_in_order(self, tmp_path, monkeypatch):
        """_hash_batch runs each job callable and returns results in input order;
        jobs resolve get_hash via the module global so monkeypatches intercept."""
        paths, _, _ = self._make_files(tmp_path, 6)
        monkeypatch.setattr(core_hashing, "get_hash", lambda p, a: "STUB")
        jobs: list[Callable[[], str]] = [(lambda p=p: core_hashing.get_hash(p, "md5")) for p in paths]
        assert core_hashing._hash_batch(jobs, 3) == ["STUB"] * 6

    def test_probe_read_bw_skips_unreadable(self, tmp_path, monkeypatch):
        good = tmp_path / "g.bin"
        good.write_bytes(b"x" * 4096)
        monkeypatch.setattr(core_hashing, "_AUTO_PROBE_BYTES", 1)
        monkeypatch.setattr(core_hashing, "_AUTO_PROBE_SECONDS", 0.0)
        bw = simple_mhl._probe_read_bw([str(tmp_path / "missing.bin"), str(good)])
        assert bw > 0  # unreadable path skipped without error, good file measured

    def test_carries_well_formed_per_file_hashdate(self, tmp_path):
        """Each file comes back paired with a UTC ISO-8601 hashdate captured by the
        hashing worker (precise even in parallel windows), not stamped at emit."""
        paths, sizes, ref = self._make_files(tmp_path, 3)
        out = list(simple_mhl._hash_files_auto(paths, sizes, ["md5"]))
        assert [d for d, _ in out] == [[r] for r in ref]
        for _digests, hashdate in out:
            datetime.strptime(hashdate, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)

    def test_calibrate_hash_bw_is_positive_and_finite(self):
        """The real in-RAM calibration (mocked everywhere else) returns a usable
        bytes/sec figure for every writable algorithm."""
        for algo in ("md5", "xxhash"):
            bw = simple_mhl._calibrate_hash_bw(algo)
            assert 0 < bw < float("inf")


# ---------------------------------------------------------------------------
# TestSealConcurrency — seal self-tunes; no operator knob
# ---------------------------------------------------------------------------


class TestSealConcurrency:
    """Seal always self-tunes — there is no operator knob. The adaptive path must
    still produce correct digests, and the default must actually probe."""

    @staticmethod
    def _force_parallel(monkeypatch):
        monkeypatch.setattr(core_hashing, "_AUTO_MIN_BYTES", 0)
        monkeypatch.setattr(simple_mhl.os, "cpu_count", lambda: 8)
        monkeypatch.setattr(core_hashing, "_calibrate_hash_bw", lambda a: 1000.0)
        monkeypatch.setattr(core_hashing, "_calibrate_hash_bw_multi", lambda f: 1000.0)
        monkeypatch.setattr(core_hashing, "_probe_read_bw", lambda p: 8000.0)  # read >> hash ⇒ parallel

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
        monkeypatch.setattr(core_hashing, "_calibrate_hash_bw", lambda a: 1000.0)
        monkeypatch.setattr(core_hashing, "_calibrate_hash_bw_multi", lambda f: 1000.0)
        probed: list[int] = []
        monkeypatch.setattr(core_hashing, "_probe_read_bw", lambda p: probed.append(1) or 100.0)  # disk-bound
        simple_mhl.seal(str(tmp_path), ["md5"], verbose=False)
        assert probed == [1], "the default must probe the disk to decide"


# ---------------------------------------------------------------------------
# TestVerifyConcurrency — verify defers hashing to the shared adaptive controller
# ---------------------------------------------------------------------------


class TestVerifyConcurrency:
    """Concurrency must never change verify's verdict, exit code, or output —
    only its speed. The deferred-hash restructure must also keep the
    size-precheck-before-hash contract (covered separately) intact."""

    @staticmethod
    def _build_manifest(tmp_path, n=8):
        files = {f"f{i:03d}.bin": bytes([i % 256]) * (2000 + i) for i in range(n)}
        make_tree(tmp_path, files)
        root = etree.Element("hashlist", version="1.1")
        for name in sorted(files):
            content = files[name]
            h = etree.SubElement(root, "hash")
            etree.SubElement(h, "file").text = name
            etree.SubElement(h, "size").text = str(len(content))
            etree.SubElement(h, "lastmodificationdate").text = "2026-01-01T00:00:00Z"
            etree.SubElement(h, "md5").text = hashlib.md5(content).hexdigest()
            etree.SubElement(h, "hashdate").text = "2026-01-01T00:00:00Z"
        mhl = tmp_path / "m.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")
        return mhl, files

    def _force_parallel(self, monkeypatch):
        monkeypatch.setattr(core_hashing, "_AUTO_MIN_BYTES", 0)
        monkeypatch.setattr(simple_mhl.os, "cpu_count", lambda: 8)
        monkeypatch.setattr(core_hashing, "_calibrate_hash_bw", lambda a: 1000.0)
        monkeypatch.setattr(core_hashing, "_probe_read_bw", lambda p: 8000.0)  # read >> hash ⇒ parallel
        monkeypatch.setattr(core_hashing, "_AUTO_RECHECK_BYTES", 4096)  # several windows over tiny files

    def test_parallel_matches_sequential_clean(self, mhl_cli, tmp_path, monkeypatch):
        mhl, _ = self._build_manifest(tmp_path)
        # Reference run first: a tiny manifest stays under the auto threshold ⇒
        # sequential. Then force parallel and require identical output.
        rc_seq, out_seq, _ = mhl_cli(["verify", str(mhl), "-v"])
        self._force_parallel(monkeypatch)
        rc_par, out_par, _ = mhl_cli(["verify", str(mhl), "-v"])
        assert rc_seq == 0
        assert rc_par == rc_seq
        assert out_par == out_seq  # identical [OK] lines, same order

    def test_parallel_matches_sequential_with_failures(self, mhl_cli, tmp_path, monkeypatch):
        mhl, files = self._build_manifest(tmp_path)
        # hash mismatch (same length, different content) + a missing file
        (tmp_path / "f002.bin").write_bytes(b"Z" * len(files["f002.bin"]))
        (tmp_path / "f005.bin").unlink()
        rc_seq, out_seq, _ = mhl_cli(["verify", str(mhl), "-v"])  # sequential reference
        self._force_parallel(monkeypatch)
        rc_par, out_par, _ = mhl_cli(["verify", str(mhl), "-v"])
        assert rc_seq == 70  # both missing and mismatch
        assert rc_par == rc_seq
        assert out_par == out_seq  # same buckets, same order


# ---------------------------------------------------------------------------
# TestVerifyManifestOutcomes — the structured contract mhlver's report consumes
# ---------------------------------------------------------------------------


class TestVerifyManifestOutcomes:
    """verify_manifest emits structured FileOutcomes — status, detail, and the
    weak-check flags — that mhlver maps straight onto its report (no text parse).
    These pin that contract directly, replacing the old mhlver output-parser tests."""

    @staticmethod
    def _write(tmp_path, entries):
        """entries: list of (file_text, {child_tag: text}); returns the .mhl path."""
        root = etree.Element("hashlist", version="1.1")
        for file_text, fields in entries:
            h = etree.SubElement(root, "hash")
            etree.SubElement(h, "file").text = file_text
            for tag, text in fields.items():
                etree.SubElement(h, tag).text = text
        mhl = tmp_path / "m.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")
        return mhl

    def test_hash_mismatch_detail_is_full_fidelity(self, tmp_path):
        (tmp_path / "f.bin").write_bytes(b"actual content")  # 14 bytes
        mhl = self._write(tmp_path, [("f.bin", {"size": "14", "md5": "0" * 32})])
        report = core_verify.verify_manifest(str(mhl))
        assert report.code == 40
        (e,) = report.entries
        assert e.status == "mismatch"
        assert e.detail.startswith("hash mismatch: calc md5: ")
        assert "stored md5: " + "0" * 32 in e.detail

    def test_missing_file(self, tmp_path):
        mhl = self._write(tmp_path, [("ghost.bin", {"size": "3", "md5": "0" * 32})])
        report = core_verify.verify_manifest(str(mhl))
        assert report.code == 30
        (e,) = report.entries
        assert e.status == "missing"

    def test_blocked_traversal_is_error(self, tmp_path):
        mhl = self._write(tmp_path, [("../escape.bin", {"size": "3", "md5": "0" * 32})])
        (e,) = core_verify.verify_manifest(str(mhl)).entries
        assert e.status == "error"
        assert e.detail == "blocked traversal attempt"

    def test_size_only_without_recorded_size_is_error(self, tmp_path):
        (tmp_path / "f.bin").write_bytes(b"xx")
        mhl = self._write(tmp_path, [("f.bin", {"md5": "0" * 32})])  # no <size>
        (e,) = core_verify.verify_manifest(str(mhl), size_only=True).entries
        assert e.status == "error"
        assert e.detail == "no size recorded"

    def test_requested_hash_not_stored_is_error(self, tmp_path):
        (tmp_path / "f.bin").write_bytes(b"xx")
        mhl = self._write(tmp_path, [("f.bin", {"size": "2", "md5": hashlib.md5(b"xx").hexdigest()})])
        (e,) = core_verify.verify_manifest(str(mhl), algorithm=["sha1"]).entries
        assert e.status == "error"
        assert e.detail == "requested hash sha1 not stored"

    def test_null_entries_set_size_only_and_existence_only(self, tmp_path):
        (tmp_path / "s.bin").write_bytes(b"abcd")
        (tmp_path / "e.bin").write_bytes(b"z")
        mhl = self._write(tmp_path, [("s.bin", {"size": "4", "null": ""}), ("e.bin", {"null": ""})])
        report = core_verify.verify_manifest(str(mhl))
        assert report.code == 0
        by_path = {e.path: e for e in report.entries}
        assert by_path["s.bin"].size_only is True
        assert by_path["e.bin"].existence_only is True
        assert report.notices  # the "Verified with … checks" notice fired

    def test_malformed_xml_sets_code_20(self, tmp_path):
        mhl = tmp_path / "bad.mhl"
        mhl.write_text("<hashlist><hash><file>x</file>")  # truncated
        report = core_verify.verify_manifest(str(mhl))
        assert report.code == 20
        assert report.malformed is True
        assert report.entries == []
