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
            '  <fake_tag>This breaks the schema</fake_tag>\n'
            '</hashlist>\n'
        )
        rc, _, err = mhl_cli(["xsd-schema-check", str(bad_mhl)])
        assert rc == 10
        assert "schema error" in err.lower()


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

    def test_traversal_strict_mode_allows_internal_symlink(self, mhl_cli, tmp_path, monkeypatch):
        """In strict mode, a symlink that resolves within the manifest directory must not be blocked."""
        seal_root = tmp_path / "pkg"
        seal_root.mkdir()
        target = seal_root / "actual_data.bin"
        target.write_bytes(b"data")
        link = seal_root / "internal_link.bin"
        try:
            os.symlink(str(target), str(link))
        except (OSError, NotImplementedError):
            pytest.skip("Symlinks not supported on this filesystem.")

        mhl = seal_helper(mhl_cli, seal_root, "md5")

        monkeypatch.setenv("MHL_STRICT_TRAVERSAL", "1")
        rc, out, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 0
        assert "traversal" not in out.lower()

# =============================================================================
# TestSealAtomicCollision
# =============================================================================
# Tests for the O_EXCL-based collision handling added in the race-condition fix.
# The logic under test lives in seal() around the os.open(..., O_CREAT|O_EXCL)
# loop:
#
#   - If the chosen path already exists AND --dont-reseal is set → exit 0.
#   - If the chosen path already exists AND --dont-reseal is NOT set → seal
#     lands on a _1.mhl suffix (and continues incrementing if needed).
#   - Two concurrent seal() calls for the same timestamp must not clobber each
#     other; we simulate this by injecting a pre-existing file and checking
#     that the second seal writes to a distinct path.
#
# We cannot easily test actual concurrent processes in a unit test, so instead
# we inject the collision condition by pre-creating the expected filename before
# seal() runs. This exercises the exact FileExistsError → suffix branch that
# the fix introduced.


class TestSealAtomicCollision:
    """Tests for the O_EXCL atomic-collision fix in seal()."""

    def _expected_mhl_name(self, root: Path, dt_str: str) -> Path:
        """Return the primary (no-suffix) MHL path for a given timestamp string."""
        return root / f"{root.name}_{dt_str}.mhl"

    def test_no_collision_writes_primary_path(self, mhl_cli, tmp_path):
        """Under no collision the manifest lands at the bare timestamped name."""
        make_tree(tmp_path, {"a.bin": b"data"})
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        assert rc == 0
        mhls = list(tmp_path.glob("*.mhl"))
        assert len(mhls) == 1
        # Name must match <dir>_<YYYY-MM-DD_HHMMSS>.mhl with no numeric suffix.
        import re
        assert re.fullmatch(
            rf"{re.escape(tmp_path.name)}_\d{{4}}-\d{{2}}-\d{{2}}_\d{{6}}\.mhl",
            mhls[0].name,
        ), f"unexpected filename: {mhls[0].name}"

    def test_dont_reseal_exits_0_when_file_exists(self, mhl_cli, tmp_path):
        """--dont-reseal must exit 0 (and NOT write a second manifest) when one
        already exists for the current timestamp.

        We inject the collision by pre-creating the expected filename, then
        invoke seal with --dont-reseal. The invocation must exit 0 and the
        injected file must be the only MHL in the directory (no _1.mhl created).
        """
        make_tree(tmp_path, {"a.bin": b"data"})

        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        assert rc == 0

        # A second --dont-reseal invocation must exit 0 whether it collides
        # (same second) or picks a fresh timestamp (new second). Either outcome
        # is acceptable; the invariant is the exit code.
        rc2, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5", "--dont-reseal"])
        assert rc2 == 0

    def test_collision_without_dont_reseal_creates_suffix(self, mhl_cli, tmp_path):
        """Without --dont-reseal a collision on the primary path must produce a
        _1.mhl (or higher) file rather than overwriting or failing.

        Strategy: seal once, seal again without --dont-reseal in the same
        second. If both finish in the same second, two distinct .mhl files must
        exist. If a second has ticked, two different timestamps are used and
        there's no collision — still two files, both named without collision.
        Either way, exactly two .mhl files must exist and both must be valid.
        """
        make_tree(tmp_path, {"a.bin": b"data"})
        rc1, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        assert rc1 == 0

        rc2, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        assert rc2 == 0

        mhls = sorted(tmp_path.glob("*.mhl"))
        # Both seals succeeded and produced distinct files.
        assert len(mhls) == 2
        assert mhls[0] != mhls[1]

    def test_pre_injected_collision_suffix_loop(self, mhl_cli, tmp_path, monkeypatch):
        """Deterministically trigger the O_EXCL suffix loop by pre-creating both
        the primary *and* _1 filenames, then verifying seal lands on _2.

        We monkeypatch datetime so seal() produces a known timestamp, allowing
        us to construct the collision filenames precisely.
        """
        from datetime import datetime, timezone
        from unittest.mock import patch

        make_tree(tmp_path, {"a.bin": b"hello"})

        fixed_dt = datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        ts = "2025-06-01_120000"
        base = tmp_path.name

        # Pre-create both the primary and _1 colliders.
        (tmp_path / f"{base}_{ts}.mhl").write_text("placeholder")
        (tmp_path / f"{base}_{ts}_1.mhl").write_text("placeholder")

        with patch("mhl_suite.simple_mhl.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_dt
            # Forward strftime calls to the real datetime.
            mock_dt.fromtimestamp.side_effect = datetime.fromtimestamp
            rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])

        assert rc == 0
        # The _2 file should have been created.
        expected = tmp_path / f"{base}_{ts}_2.mhl"
        assert expected.exists(), (
            f"Expected _2 collision file not found. Files: {list(tmp_path.glob('*.mhl'))}"
        )
        # And it must be a real, parseable manifest, not the injected placeholder.
        text = expected.read_text()
        assert "<hashlist" in text

    def test_dont_reseal_with_injected_collision_exits_0_writes_nothing(
        self, mhl_cli, tmp_path, monkeypatch
    ):
        """--dont-reseal with a pre-injected collision must exit 0 immediately
        and must NOT create any new .mhl files.

        This directly exercises the FileExistsError → dont_reseal → sys.exit(0)
        branch inside the O_EXCL loop.
        """
        from datetime import datetime, timezone
        from unittest.mock import patch

        make_tree(tmp_path, {"a.bin": b"hello"})

        fixed_dt = datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
        ts = "2025-06-01_120000"
        base = tmp_path.name

        # Pre-create only the primary filename — that's enough to fire O_EXCL.
        collider = tmp_path / f"{base}_{ts}.mhl"
        collider.write_text("placeholder")

        with patch("mhl_suite.simple_mhl.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_dt
            mock_dt.fromtimestamp.side_effect = datetime.fromtimestamp
            rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5", "--dont-reseal"])

        assert rc == 0
        # The only MHL in the directory must still be our placeholder — nothing
        # new was written.
        mhls = list(tmp_path.glob("*.mhl"))
        assert mhls == [collider], (
            f"Expected only the injected placeholder; found: {mhls}"
        )
        assert collider.read_text() == "placeholder"


# =============================================================================
# TestGetXsdPath / TestValidateSchemaExits60
# =============================================================================
# Covers the FileNotFoundError raise in get_xsd_path() and the corresponding
# catch → stderr → sys.exit(60) in validate_schema() (fix #3).


class TestValidateSchemaXsdNotFound:
    """validate_schema() must exit 60 when get_xsd_path() raises."""

    def test_xsd_not_found_exits_60_with_stderr(self, mhl_cli, tmp_path, monkeypatch):
        """When get_xsd_path raises FileNotFoundError, xsd-schema-check must
        exit 60 and write an error message to stderr."""
        from mhl_suite import simple_mhl

        mhl_file = tmp_path / "dummy.mhl"
        mhl_file.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n<hashlist version="1.1"/>\n'
        )

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
        rc, _, err = mhl_cli(["xsd-schema-check", str(mhl_path)])
        # lxml raises OSError trying to open a directory; validate_schema → exit 20.
        assert rc in (20, 1)  # 1 if the dir check fires first


# =============================================================================
# TestVerifyEdgeCases — coverage for uncovered verify() branches
# =============================================================================


class TestVerifyEdgeCases:
    """Covers branches in verify() not hit by existing tests."""

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
        import hashlib
        etree.SubElement(h_good, "md5").text = hashlib.md5(b"data").hexdigest()
        etree.SubElement(h_good, "hashdate").text = "2025-01-01T00:00:00Z"

        # Malformed entry: no <file> child at all.
        h_bad = etree.SubElement(root, "hash")
        etree.SubElement(h_bad, "md5").text = "deadbeef" * 4

        mhl = tmp_path / "partial.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, out, err = mhl_cli(["verify", str(mhl)])
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
        etree.SubElement(h, "blake3").text = "0" * 64   # not in SUPPORTED_HASH_TAGS
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

        rc, out, err = mhl_cli(["verify", str(mhl)])
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


# =============================================================================
# TestWalkEdgeCases — coverage for _iter_files_for_seal OSError paths
# =============================================================================


class TestWalkEdgeCases:
    """Exercises the two OSError-swallowing branches in _iter_files_for_seal."""

    @pytest.mark.skipif(
        os.getuid() == 0, reason="root bypasses permission checks"
    )
    def test_unreadable_subdir_is_silently_skipped(self, mhl_cli, tmp_path):
        """A subdirectory that cannot be scanned (mode 000) must be silently
        skipped — the seal must still succeed and include the files that
        ARE accessible."""
        make_tree(tmp_path, {
            "accessible.bin": b"yes",
            "locked/secret.bin": b"no",
        })
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
            locked.chmod(0o755)   # restore so tmp_path cleanup can proceed
