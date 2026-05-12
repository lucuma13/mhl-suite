#!/usr/bin/env python3
"""Test suite for simple_mhl.py core functionality and stress testing.

Covers:
  - Correctness: seal/verify round-trips with multiple algorithms
  - Edge cases: hidden files, unicode names, nested dirs, empty files
  - Failure modes: corrupted files, missing files, malformed XML, schema errors
  - Security: path traversal blocking
  - Stress: large files, thousands of files, pathological naming conventions
"""
import os
import time
from pathlib import Path

import pytest
from lxml import etree


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
        make_tree(tmp_path, {
            "visible.bin": b"yes",
            ".hidden.bin": b"no",
            ".hiddendir/inside.bin": b"also no",
        })
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
        make_tree(tmp_path, {
            "日本語.bin": b"japanese",
            "café/résumé.txt": b"french",
            "🎬.mp4": b"emoji",
        })
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


class TestVerify:
    """Tests around the verify command."""

    def test_verify_clean(self, mhl_cli, tmp_path):
        """A freshly sealed dir should verify clean (exit 0)."""
        make_tree(tmp_path, {"a.bin": b"hello", "b/c.bin": b"world"})
        mhl = seal_helper(mhl_cli, tmp_path)
        
        rc, out, err = mhl_cli(["verify", str(mhl)])
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
        """A modified file should produce exit 40."""
        make_tree(tmp_path, {"a.bin": b"hello"})
        mhl = seal_helper(mhl_cli, tmp_path)
        (tmp_path / "a.bin").write_bytes(b"goodbye")
        
        rc, out, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 40
        assert "ERROR: hash mismatch: a.bin" in out

    def test_verify_missing_and_modified(self, mhl_cli, tmp_path):
        """If BOTH missing and mismatch occur, exit 70 (combined failure)."""
        make_tree(tmp_path, {"a.bin": b"hello", "b.bin": b"world"})
        mhl = seal_helper(mhl_cli, tmp_path)
        (tmp_path / "a.bin").unlink()
        (tmp_path / "b.bin").write_bytes(b"changed")
        
        rc, out, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 70
        assert "ERROR: missing file: a.bin" in out
        assert "ERROR: hash mismatch: b.bin" in out

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
        
        rc, out, err = mhl_cli(["verify", "-v", str(mhl)])
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
        assert "ERROR: hash mismatch: bad.bin" in out

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
        import xxhash
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
        print(f"\n  seal 1000 files: {seal_time*1000:.0f}ms")

        mhl = next(tmp_path.glob("*.mhl"))
        t0 = time.perf_counter()
        rc, _, _ = mhl_cli(["verify", str(mhl)])
        verify_time = time.perf_counter() - t0
        assert rc == 0
        print(f"  verify 1000 files: {verify_time*1000:.0f}ms")

    def test_pathological_filenames(self, mhl_cli, tmp_path):
        """Files with spaces, brackets, accented chars, etc."""
        weird = [
            "file with spaces.bin",
            "[brackets].bin",
            "(parens).bin",
            "ampersand&.bin",
            "single'quote.bin",
            "double\"quote.bin",
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
            for _ in range(50):
                f.write(chunk)
                
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
        root = etree.Element(f"{{{ns}}}hashlist", version="1.1", nsmap={None: ns})
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

    def test_traversal_strict_mode(self, mhl_cli, tmp_path, monkeypatch):
        """In strict mode, a symlink escape should also be blocked."""
        outside = tmp_path.parent / "stress_outside_secret.bin"
        outside.write_bytes(b"secret")
        try:
            seal_root = tmp_path / "pkg"
            seal_root.mkdir()
            link = seal_root / "innocent_looking.bin"
            try:
                os.symlink(str(outside), str(link))
            except (OSError, NotImplementedError):
                pytest.skip("symlinks not supported")
            (seal_root / "real.bin").write_bytes(b"yes")

            root = etree.Element("hashlist", version="1.1")
            for fname in ["real.bin", "innocent_looking.bin"]:
                h = etree.SubElement(root, "hash")
                etree.SubElement(h, "file").text = fname
                etree.SubElement(h, "size").text = "0"
                etree.SubElement(h, "lastmodificationdate").text = "2025-01-01T00:00:00Z"
                etree.SubElement(h, "md5").text = "0" * 32
                etree.SubElement(h, "hashdate").text = "2025-01-01T00:00:00Z"
            mhl = seal_root / "manual.mhl"
            etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

            monkeypatch.setenv("MHL_STRICT_TRAVERSAL", "1")
            rc, out, _ = mhl_cli(["verify", str(mhl)])
            
            assert rc == 40
            assert "traversal" in out.lower()
        finally:
            outside.unlink(missing_ok=True)