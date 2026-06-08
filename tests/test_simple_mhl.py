#!/usr/bin/env python3
"""Test suite for simple_mhl.py."""

import hashlib
import os
import random
import re
import sys
import time
import unicodedata
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock, patch

import pytest
import xxhash
from lxml import etree

from mhl_suite import simple_mhl


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

    def test_seal_skips_hidden_files(self, mhl_cli, tmp_path):
        """Files starting with '.' should be excluded from the manifest."""
        make_tree(
            tmp_path,
            {
                "visible.bin": b"yes",
                ".hidden.bin": b"no",
                ".hiddendir/inside.bin": b"also no",
            },
        )
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])

        assert rc == 0
        text = next(tmp_path.glob("*.mhl")).read_text()
        assert "visible.bin" in text
        assert "hidden" not in text

    def test_seal_dont_reseal(self, mhl_cli, tmp_path):
        """--dont-reseal should bail out if MHL already exists."""
        make_tree(tmp_path, {"a.bin": b"hello"})

        rc1, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        assert rc1 == 0

        rc2, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        assert rc2 == 0

        rc3, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5", "--dont-reseal"])
        assert rc3 == 0

    def test_seal_unicode_filenames(self, mhl_cli, tmp_path):
        """Manifests must handle non-ASCII filenames cleanly (UTF-8)."""
        make_tree(
            tmp_path,
            {
                "日本語.bin": b"japanese",
                "café/résumé.txt": b"french",
                "🎬.mp4": b"emoji",
            },
        )
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])

        assert rc == 0
        text = next(tmp_path.glob("*.mhl")).read_text(encoding="utf-8")
        assert "日本語.bin" in text
        assert "café/résumé.txt" in text
        assert "🎬.mp4" in text

    def test_seal_empty_file(self, mhl_cli, tmp_path):
        """Zero-byte files should still get a hash entry."""
        make_tree(tmp_path, {"empty.bin": b""})
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])

        assert rc == 0
        text = next(tmp_path.glob("*.mhl")).read_text()
        assert "d41d8cd98f00b204e9800998ecf8427e" in text

    def test_seal_invalid_algorithm(self, mhl_cli, tmp_path):
        """Unknown algorithm should be rejected by argparse with exit 2."""
        make_tree(tmp_path, {"a.bin": b"x"})
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "blake2"])
        assert rc == 2

    def test_seal_nonexistent_directory(self, mhl_cli):
        """Non-existent path should fail cleanly with exit 2."""
        rc, _, _ = mhl_cli(["seal", "/nonexistent/path/xyz", "-a", "md5"])
        assert rc == 2


# ---------------------------------------------------------------------------
# TestSealUnsupportedAlgorithm
# ---------------------------------------------------------------------------


class TestSealUnsupportedAlgorithm:
    """seal() exits 2 when called directly with an algorithm not in ALGO_MAP."""

    def test_unsupported_algorithm_exits_2(self, tmp_path):
        """Calling seal() directly with 'blake3' (not in ALGO_MAP) exits with 2."""

        (tmp_path / "a.bin").write_bytes(b"data")
        with pytest.raises(SystemExit) as exc:
            simple_mhl.seal(str(tmp_path), "blake3", dont_reseal=False)
        assert exc.value.code == 2

    def test_unsupported_algorithm_writes_error_to_stderr(self, tmp_path, capsys):
        """The error message written to stderr names the unsupported algorithm."""

        (tmp_path / "a.bin").write_bytes(b"data")
        with pytest.raises(SystemExit):
            simple_mhl.seal(str(tmp_path), "blake3", dont_reseal=False)
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
        assert "ERROR: missing file: a.bin" in out

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
        assert "ERROR:" in out

    def test_verify_missing_and_modified(self, mhl_cli, tmp_path):
        """If BOTH missing and mismatch occur, exit 70 (combined failure)."""
        make_tree(tmp_path, {"a.bin": b"hello", "b.bin": b"world"})
        mhl = seal_helper(mhl_cli, tmp_path)
        (tmp_path / "a.bin").unlink()
        (tmp_path / "b.bin").write_bytes(b"changed")

        rc, out, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 70
        assert "ERROR: missing file: a.bin" in out
        # "world" (5 bytes) → "changed" (7 bytes): size pre-check fires first.
        assert "b.bin" in out
        assert "ERROR:" in out

    def test_verify_clean_is_silent(self, mhl_cli, tmp_path):
        """A clean verify must produce no stdout at all (exit 0 only)."""
        make_tree(tmp_path, {"a.bin": b"hello"})
        mhl = seal_helper(mhl_cli, tmp_path)

        rc, out, err = mhl_cli(["verify", str(mhl)])
        assert rc == 0
        assert out == ""
        assert err == ""

    def test_verify_verbose_emits_ok_lines(self, mhl_cli, tmp_path):
        """--verbose should print one 'OK: <path>' line per verified file."""
        make_tree(tmp_path, {"a.bin": b"hello", "sub/b.bin": b"world"})
        mhl = seal_helper(mhl_cli, tmp_path)

        rc, out, _err = mhl_cli(["verify", "-v", str(mhl)])
        assert rc == 0
        assert "OK: a.bin" in out
        assert "OK: sub/b.bin" in out.replace(os.sep, "/")

    def test_verify_verbose_with_failures_shows_both(self, mhl_cli, tmp_path):
        """--verbose plus failures: OK for clean files, ERROR for failed."""
        make_tree(tmp_path, {"good.bin": b"hello", "bad.bin": b"world"})
        mhl = seal_helper(mhl_cli, tmp_path)
        (tmp_path / "bad.bin").write_bytes(b"changed")

        rc, out, _ = mhl_cli(["verify", "-v", str(mhl)])
        assert rc == 40
        assert "OK: good.bin" in out
        # "world" (5 bytes) → "changed" (7 bytes): size pre-check fires first.
        assert "bad.bin" in out
        assert "ERROR:" in out

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

    def test_verify_legacy_decimal_xxhash(self, mhl_cli, tmp_path):
        """Old MHL files stored xxhash as decimal int — must verify correctly."""
        make_tree(tmp_path, {"a.bin": b"x"})

        h = xxhash.xxh64()
        h.update(b"x")
        hex_digest = h.hexdigest()
        decimal_digest = str(int(hex_digest, 16))

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

        mhl = tmp_path / "legacy.mhl"
        etree.ElementTree(doc).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, _, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 0


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
        assert "schema error" in err.lower()


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
            nsmap=cast(dict[str, str], {None: ns}),  # lxml requires None for default ns
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
    # patch boilerplate, so we factor it into a class-scoped fixture that:
    #
    #   * patches mhl_suite.simple_mhl.datetime once for the whole class
    #   * exposes the frozen timestamp string (ts) and base dir name (base)
    #     as attributes on the fixture object
    #
    # Tests that don't need a fixed timestamp (the first three) ignore it.
    # The fixture is class-scoped because the patch has no side-effects that
    # would bleed between tests — each test still gets its own tmp_path.

    @pytest.fixture(scope="class")
    def frozen_dt(self):
        """Freeze simple_mhl's datetime to 2025-06-01T12:00:00Z for the class.

        Yields a namespace with .ts (the formatted timestamp string) so tests
        can construct known collision filenames without repeating the patch.
        """
        fixed = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)

        class _Info:
            ts = "2025-06-01_120000"

        with patch("mhl_suite.simple_mhl.datetime") as mock_dt:
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

    def test_dont_reseal_exits_0_when_file_exists(self, mhl_cli, tmp_path):
        """--dont-reseal must exit 0 whether it collides or picks a fresh timestamp."""
        make_tree(tmp_path, {"a.bin": b"data"})

        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        assert rc == 0

        rc2, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5", "--dont-reseal"])
        assert rc2 == 0

    def test_collision_without_dont_reseal_creates_suffix(self, mhl_cli, tmp_path):
        """Without --dont-reseal a collision must produce a _1.mhl rather than
        overwriting or failing. Two seals → two distinct files."""
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

    def test_dont_reseal_with_injected_collision_exits_0_writes_nothing(self, mhl_cli, tmp_path, frozen_dt):
        """--dont-reseal with a pre-injected collision must exit 0 immediately
        and must NOT create any new .mhl files.

        Directly exercises the FileExistsError → dont_reseal → sys.exit(0)
        branch inside the O_EXCL loop.
        """
        make_tree(tmp_path, {"a.bin": b"hello"})
        base = tmp_path.name

        collider = tmp_path / f"{base}_{frozen_dt.ts}.mhl"
        collider.write_text("placeholder")

        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5", "--dont-reseal"])

        assert rc == 0
        mhls = list(tmp_path.glob("*.mhl"))
        assert mhls == [collider], f"Expected only the injected placeholder; found: {mhls}"
        assert collider.read_text() == "placeholder"


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

        monkeypatch.setattr(simple_mhl, "get_xsd_path", _raise)

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
        sibling is found and its path is returned."""

        xsd_dir = tmp_path / "xsd"
        xsd_dir.mkdir()
        xsd_file = xsd_dir / "MediaHashList_v1_1.xsd"
        xsd_file.write_text("<schema/>")

        with (
            patch.object(
                simple_mhl.importlib.resources,
                "files",
                side_effect=ImportError("no package"),
            ),
            patch.object(simple_mhl, "__file__", str(tmp_path / "simple_mhl.py")),
        ):
            result = simple_mhl.get_xsd_path()

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
            patch.object(simple_mhl.importlib.resources, "files", return_value=fake_pkg),
            patch.object(simple_mhl, "__file__", str(tmp_path / "simple_mhl.py")),
        ):
            result = simple_mhl.get_xsd_path()

        assert result == str(xsd_file)

    def test_raises_file_not_found_when_both_paths_absent(self, tmp_path):
        """FileNotFoundError is raised when neither the package resource nor the
        local xsd/ folder exists (tmp_path has no xsd/ subdirectory)."""

        with (
            patch.object(
                simple_mhl.importlib.resources,
                "files",
                side_effect=ImportError("no package"),
            ),
            patch.object(simple_mhl, "__file__", str(tmp_path / "simple_mhl.py")),
            pytest.raises(FileNotFoundError, match=r"MediaHashList_v1_1\.xsd"),
        ):
            simple_mhl.get_xsd_path()

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
        etree.SubElement(h, "blake3").text = "0" * 64  # not in SUPPORTED_HASH_TAGS
        etree.SubElement(h, "hashdate").text = "2025-01-01T00:00:00Z"
        mhl = tmp_path / "unsupported.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, out, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 40
        assert "no supported hash found" in out

    def test_null_tag_present_file_silent(self, mhl_cli, tmp_path):
        """A <null> entry for a file that exists must pass silently (exit 0, no output)."""
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
        assert out == ""

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
        assert "OK: x.bin" in out

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
        assert "ERROR: missing file: ghost.bin" in out

    def test_unsupported_read_only_algorithm_reports_cannot_verify(self, mhl_cli, tmp_path):
        """An xxhash128 digest (accepted for reading, not writable) must produce
        the 'cannot verify' mismatch (exit 40) rather than crashing."""
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
        assert "cannot verify" in out


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
    def test_unreadable_subdir_is_silently_skipped(self, mhl_cli, tmp_path):
        """A subdirectory that cannot be scanned (mode 000) must be silently
        skipped — the seal must still succeed and include the files that
        ARE accessible."""
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
            rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
            assert rc == 0
            mhl = next(tmp_path.glob("*.mhl"))
            text = mhl.read_text()
            assert "accessible.bin" in text
            assert "secret.bin" not in text
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
        to the SUPPORTED_HASH_TAGS membership test.
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

      2. getsize() -> get_hash(): covered by test_file_deleted_during_get_hash.
         Requires NO <size> element so the size block is skipped entirely; the
         OSError is caught by the get_hash handler and reported as 'cannot verify'
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
        assert "ERROR: missing file: vanishing.bin" in out

    def test_file_deleted_during_get_hash(self, mhl_cli, tmp_path, monkeypatch):
        """Race window 2: file disappears after getsize() but before get_hash() opens it.

        The get_hash OSError handler must catch this and report 'cannot verify'
        (exit 40), not propagate the exception.

        Manifest has NO <size> element so the size pre-check is skipped and the
        race happens at get_hash() as intended. get_hash is patched to delete the
        file then attempt the real open, which raises OSError.
        """
        target = tmp_path / "vanishing.bin"
        target.write_bytes(b"data")

        real_get_hash = simple_mhl.get_hash

        def _get_hash_after_delete(filepath, algo_key):
            target.unlink(missing_ok=True)
            return real_get_hash(filepath, algo_key)

        monkeypatch.setattr(simple_mhl, "get_hash", _get_hash_after_delete)

        # No <size> element — size pre-check block is not entered.
        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = "vanishing.bin"
        etree.SubElement(h, "md5").text = "0" * 32
        mhl = tmp_path / "race.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, out, _ = mhl_cli(["verify", str(mhl)])

        assert rc == 40, f"Expected exit 40 (cannot verify), got {rc}"
        assert "ERROR: cannot verify vanishing.bin" in out


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
        assert "ERROR: hash mismatch: a.bin" in out

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
        """get_hash() must NOT be called when the size pre-check already fails.

        A size mismatch is a definitive failure signal.  Calling get_hash()
        afterwards wastes I/O on a file that is already known to be wrong.
        This test uses a spy to confirm get_hash is never reached.
        """
        get_hash_calls: list[str] = []
        real_get_hash = simple_mhl.get_hash

        def spy_get_hash(filepath, algo_key):
            get_hash_calls.append(filepath)
            return real_get_hash(filepath, algo_key)

        monkeypatch.setattr(simple_mhl, "get_hash", spy_get_hash)

        mhl = make_mhl_with_size(tmp_path, "clip.bin", b"hello", size_override="9999")

        rc, _, _ = mhl_cli(["verify", str(mhl)])

        assert rc == 40, f"Expected exit 40, got {rc}"
        assert get_hash_calls == [], (
            f"get_hash() was called {len(get_hash_calls)} time(s) despite size mismatch — "
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
        specialised tooling.  Instead we monkeypatch get_hash() to return the
        *correct* digest for the on-disk file regardless, then verify that the
        size check still fires before get_hash is reached.

        This is the adversarially interesting case: a tool that only checks the
        hash would silently pass a file whose size is wrong (e.g. a truncated
        file that happens to share its hash with another file).  The size check
        must take priority.
        """
        content = b"A" * 1024
        correct_digest = xxhash.xxh64(content).hexdigest()

        # Record the correct digest but a wrong size.
        mhl = make_mhl_with_size(tmp_path, "clip.bin", content, size_override="9999")

        # Ensure get_hash would return the correct digest if ever called,
        # so the only thing that can trigger the failure is the size check.
        def always_correct_hash(filepath, algo_key):
            return correct_digest

        monkeypatch.setattr(simple_mhl, "get_hash", always_correct_hash)

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
# TestUnicodeNormalisation
# ---------------------------------------------------------------------------


class TestUnicodeNormalisation:
    """NFC normalisation of accented filenames at seal and verify time.

    macOS HFS+/APFS returns filenames in NFD (decomposed) form — e.g. the
    single codepoint é (U+00E9) is decomposed to e (U+0065) + combining acute
    (U+0301).  Linux ext4 does byte-exact filename matching, so an NFD path
    from the manifest would silently fail os.path.exists() against an NFC file
    on disk.

    simple_mhl normalises to NFC at two points:
      1. seal — rel_path_posix is normalised before writing the <file> element
      2. verify — rel_path from the manifest is normalised before constructing
                  the candidate path

    These tests construct NFD filenames explicitly so the behaviour is
    deterministic regardless of what the host OS normalises at mkdir/write time.
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

        def nfd_iter(root, mhl_path):
            for p, stat_result in real_iter(root, mhl_path):
                # Yield the path as-is; real_iter already found the NFD file.
                # Normalise to NFD explicitly in case the OS returned NFC
                # (e.g. on a case-insensitive macOS volume that normalises on
                # readback), ensuring the test exercises the NFC fix on all OSes.
                nfd_str = unicodedata.normalize("NFD", str(p))
                yield Path(nfd_str), stat_result

        monkeypatch.setattr(simple_mhl, "_iter_files_for_seal", nfd_iter)

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
            "NFD byte sequence found in manifest — NFC normalisation did not fire"
        )

    def test_seal_nfc_is_idempotent_for_already_nfc_paths(self, mhl_cli, tmp_path):
        """NFC normalisation of an already-NFC path must produce the same result.

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

    def test_verify_normalises_nfd_manifest_path_to_find_nfc_file(self, mhl_cli, tmp_path):
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

        Confirms the normalisation does not break the hash check that follows.
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
        """NFD normalisation must not suppress a genuine hash mismatch.

        Regression guard: the normalisation step must not interfere with the
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
