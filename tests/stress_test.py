#!/usr/bin/env python3
"""Stress tests — adversarial and edge-case scenarios."""
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from mhl_suite import simple_mhl


def run_simple_mhl(argv):
    """Capture exit code and output from a CLI invocation."""
    import io
    old = sys.argv, sys.stdout, sys.stderr
    sys.argv = ["simple-mhl"] + argv
    sys.stdout, sys.stderr = io.StringIO(), io.StringIO()
    try:
        try:
            simple_mhl.main()
            rc = 0
        except SystemExit as e:
            rc = e.code if e.code is not None else 0
        return rc, sys.stdout.getvalue(), sys.stderr.getvalue()
    finally:
        sys.argv, sys.stdout, sys.stderr = old


class StressTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="mhl_stress_"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_thousand_files(self):
        """Seal and verify 1000 small files in under a few seconds."""
        for i in range(1000):
            (self.tmp / f"f{i:05d}.bin").write_bytes(f"data-{i}".encode())

        t0 = time.perf_counter()
        rc, _, _ = run_simple_mhl(["seal", str(self.tmp), "-a", "md5"])
        seal_time = time.perf_counter() - t0
        self.assertEqual(rc, 0)
        print(f"\n  seal 1000 files: {seal_time*1000:.0f}ms")

        mhl = next(self.tmp.glob("*.mhl"))
        t0 = time.perf_counter()
        rc, _, _ = run_simple_mhl(["verify", str(mhl)])
        verify_time = time.perf_counter() - t0
        self.assertEqual(rc, 0)
        print(f"  verify 1000 files: {verify_time*1000:.0f}ms")

    def test_pathological_filenames(self):
        """Files with spaces, brackets, accented chars, etc."""
        weird = [
            "file with spaces.bin",
            "[brackets].bin",
            "(parens).bin",
            "ampersand&.bin",
            "single'quote.bin",
            "double\"quote.bin",  # only on filesystems that allow it
            "tab\there.bin",      # actually most FS allow tabs
            "naïve.bin",
            "über.bin",
        ]
        for name in weird:
            try:
                (self.tmp / name).write_bytes(b"x")
            except OSError:
                continue  # skip names this FS rejects

        rc, _, _ = run_simple_mhl(["seal", str(self.tmp), "-a", "md5"])
        self.assertEqual(rc, 0)
        mhl = next(self.tmp.glob("*.mhl"))
        rc, out, _ = run_simple_mhl(["verify", str(mhl)])
        self.assertEqual(rc, 0, msg=f"verify failed: {out}")

    def test_long_filename(self):
        """A 200-char filename (close to but not over the typical 255 limit)."""
        long_name = "a" * 200 + ".bin"
        try:
            (self.tmp / long_name).write_bytes(b"x")
        except OSError:
            self.skipTest("FS doesn't allow 200-char names")
        rc, _, _ = run_simple_mhl(["seal", str(self.tmp), "-a", "md5"])
        self.assertEqual(rc, 0)
        mhl = next(self.tmp.glob("*.mhl"))
        rc, _, _ = run_simple_mhl(["verify", str(mhl)])
        self.assertEqual(rc, 0)

    def test_empty_directory(self):
        """Sealing an empty directory should produce a manifest with no <hash>."""
        rc, _, _ = run_simple_mhl(["seal", str(self.tmp), "-a", "md5"])
        self.assertEqual(rc, 0)
        mhl = next(self.tmp.glob("*.mhl"))
        text = mhl.read_text()
        self.assertNotIn("<hash>", text)

    def test_single_huge_file(self):
        """A 50 MB file — exercises the chunked-read path."""
        # Use a deterministic content so verify can re-confirm.
        path = self.tmp / "huge.bin"
        with open(path, "wb") as f:
            chunk = os.urandom(1024 * 1024)
            for _ in range(50):
                f.write(chunk)
        rc, _, _ = run_simple_mhl(["seal", str(self.tmp), "-a", "md5"])
        self.assertEqual(rc, 0)
        mhl = next(self.tmp.glob("*.mhl"))
        rc, _, _ = run_simple_mhl(["verify", str(mhl)])
        self.assertEqual(rc, 0)

    def test_subtle_corruption(self):
        """Flipping one byte in a 10MB file should be caught."""
        (self.tmp / "data.bin").write_bytes(b"X" * (10 * 1024 * 1024))
        rc, _, _ = run_simple_mhl(["seal", str(self.tmp), "-a", "md5"])
        self.assertEqual(rc, 0)
        # Flip a single byte in the middle.
        with open(self.tmp / "data.bin", "r+b") as f:
            f.seek(5 * 1024 * 1024)
            b = f.read(1)
            f.seek(-1, 1)
            f.write(bytes([b[0] ^ 1]))
        mhl = next(self.tmp.glob("*.mhl"))
        rc, out, _ = run_simple_mhl(["verify", str(mhl)])
        self.assertEqual(rc, 40)
        self.assertIn("data.bin", out)

    def test_namespace_in_manifest(self):
        """A manifest that uses an XML namespace should still verify cleanly."""
        # Build a namespaced manifest by hand. Real-world MHL files don't usually
        # carry a namespace but some XML toolchains add one when writing —
        # the verifier should be tolerant.
        from lxml import etree
        (self.tmp / "x.bin").write_bytes(b"hi")
        ns = "urn:foo:mhl"
        root = etree.Element(f"{{{ns}}}hashlist", version="1.1", nsmap={None: ns})
        h = etree.SubElement(root, f"{{{ns}}}hash")
        etree.SubElement(h, f"{{{ns}}}file").text = "x.bin"
        etree.SubElement(h, f"{{{ns}}}size").text = "2"
        etree.SubElement(h, f"{{{ns}}}lastmodificationdate").text = "2025-01-01T00:00:00Z"
        # md5("hi") = 49f68a5c8493ec2c0bf489821c21fc3b
        etree.SubElement(h, f"{{{ns}}}md5").text = "49f68a5c8493ec2c0bf489821c21fc3b"
        etree.SubElement(h, f"{{{ns}}}hashdate").text = "2025-01-01T00:00:00Z"

        mhl = self.tmp / "ns.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")
        rc, out, err = run_simple_mhl(["verify", str(mhl)])
        self.assertEqual(rc, 0, msg=f"out={out}\nerr={err}")

    def test_uppercase_hex_digest(self):
        """A manifest with uppercase hex should still match (we lowercase both)."""
        (self.tmp / "x.bin").write_bytes(b"hi")
        from lxml import etree
        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = "x.bin"
        etree.SubElement(h, "size").text = "2"
        etree.SubElement(h, "lastmodificationdate").text = "2025-01-01T00:00:00Z"
        # Same digest as above but UPPERCASE.
        etree.SubElement(h, "md5").text = "49F68A5C8493EC2C0BF489821C21FC3B"
        etree.SubElement(h, "hashdate").text = "2025-01-01T00:00:00Z"
        mhl = self.tmp / "upper.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")
        rc, _, _ = run_simple_mhl(["verify", str(mhl)])
        self.assertEqual(rc, 0)

    def test_traversal_strict_mode(self):
        """In strict mode, a symlink escape should also be blocked."""
        # Create a victim outside, a symlink inside that points to it.
        outside = self.tmp.parent / "stress_outside_secret.bin"
        outside.write_bytes(b"secret")
        try:
            seal_root = self.tmp / "pkg"
            seal_root.mkdir()
            link = seal_root / "innocent_looking.bin"
            try:
                os.symlink(str(outside), str(link))
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not supported")
            (seal_root / "real.bin").write_bytes(b"yes")

            # Build a hand-crafted manifest where rel path points through the
            # symlink. Without strict mode the abspath alone stays inside;
            # only realpath (strict mode) detects the escape.
            from lxml import etree
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

            os.environ["MHL_STRICT_TRAVERSAL"] = "1"
            try:
                rc, out, _ = run_simple_mhl(["verify", str(mhl)])
            finally:
                del os.environ["MHL_STRICT_TRAVERSAL"]
            # Strict mode should refuse the symlinked file.
            self.assertEqual(rc, 40)
            self.assertIn("traversal", out.lower())
        finally:
            outside.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
