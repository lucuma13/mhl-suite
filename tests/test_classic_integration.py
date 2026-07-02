"""Adversarial, stress, symlink, TOCTOU and fuzz tests for classicmhl seal/verify."""

import hashlib
import os
import random
import sys
import time
from typing import cast

import pytest
from lxml import etree

from mhl_suite import hashing as core_hashing
from mhl_suite.cli import simple_mhl

from .helpers import (
    make_mhl,
    make_mhl_with_size,
    make_tree,
)


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
        assert rc == 11
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
        """
        A subdirectory that cannot be scanned (mode 000) is skipped, but the seal must surface a WARNING (always, not
        just under -v) — a dropped directory means its files are absent from the manifest. The seal still succeeds and
        includes the files that ARE accessible.
        """
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


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="symlinks require elevated privileges on Windows",
)
class TestSymlinks:
    """
    Symlink handling for both seal and verify.

    seal() excludes symlinks entirely (follow_symlinks=False on both is_dir and is_file), making directory-cycle
    traversal impossible by exclusion. verify() follows symlinks when named in a third-party manifest, hashing their
    targets.

    Protection layers pinned here so a future refactor cannot silently remove the follow_symlinks=False calls without a
    test failure.
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
        """
        Two symlinks pointing at each other must both be silently excluded — neither causes infinite descent, neither
        appears in the manifest.
        """
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
        """verify follows a symlink that resolves inside the tree and hashes its target."""

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
        """A wrong digest for a symlink target is detected and reported as a hash mismatch → exit 40."""
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
        assert rc == 11
        assert "hash mismatch" in out

    def test_mutual_symlinks_in_manifest_report_missing(self, mhl_cli, tmp_path):
        """
        A manifest naming mutually-pointing symlinks (a → b, b → a) must not loop. os.path.exists() follows the chain
        and returns False when it cannot resolve — the existence check fires before get_hash is ever called, so both
        entries are reported as missing files → exit 10.
        """
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
        # os.path.exists() returns False for unresolvable symlink chains; both entries hit the missing-file branch
        # before get_hash is called.
        assert rc == 10
        assert "missing file: a.bin" in out
        assert "missing file: b.bin" in out


class TestAdversarialXML:
    """Adversarial and malformed XML inputs must never crash the tool.

    Covers XXE injection (lxml rejects external entities as XMLSyntaxError → exit 40) and structural anomalies
    (Comment/PI nodes with callable .tag attributes that would break naive tag-name lookups).
    """

    def test_xxe_entity_payload_exits_40(self, mhl_cli, tmp_path):
        """
        A manifest containing an XXE <!ENTITY> payload must exit 40 (malformed XML) and must never exfiltrate file
        content via entity expansion.

        lxml's default parser does not resolve external entities; it raises XMLSyntaxError instead. simple_mhl.verify()
        already maps that to exit 40. This test pins that behaviour as a regression guard — if the parser is ever
        reconfigured to resolve entities, this test will fail loudly.
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
        assert rc == 40, f"Expected exit 40 for XXE payload, got {rc}"
        # No file content must leak into stdout or stderr.
        for stream in (out, err):
            assert "root:" not in stream, "Potential XXE exfiltration detected in output"
            assert "/bin/" not in stream, "Potential XXE exfiltration detected in output"

    def test_comment_and_pi_nodes_inside_hash_do_not_crash(self, mhl_cli, tmp_path):
        """
        lxml Comment and ProcessingInstruction nodes carry a callable (not a string) as their .tag attribute.
        simple_mhl._localname() used to call .rpartition() on it, triggering an AttributeError crash.

        The fix: _localname() returns '' for non-string tags, making them invisible to the hash-tag recognition test.
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
        """
        A <hash> containing only Comment/PI nodes (no algorithm tag) must be reported as 'no supported hash found' (exit
        40), not crash.
        """
        (tmp_path / "x.bin").write_bytes(b"x")

        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = "x.bin"
        h.append(etree.Comment("no real hash here"))

        mhl = tmp_path / "comment_only.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, out, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 11
        assert "no supported hash found" in out


class TestTOCTOURaceCondition:
    """
    Files deleted between os.path.exists() and the next filesystem call must be handled gracefully.

    There are two distinct race windows in verify():

      1. exists() -> getsize(): covered by test_file_vanishes_between_exists_and_getsize. Requires a manifest <size>
         element; the OSError is caught by the size pre-check handler and reported as 'missing file' (exit 10).

      2. getsize() -> hash read: covered by test_file_deleted_before_hash_read. Requires NO <size> element so the size
         block is skipped entirely; the OSError is caught by the get_hashes handler and reported as 'cannot verify'
         (exit 40).

    Both handlers must produce a structured error message, not an unhandled exception.
    """

    def test_file_vanishes_between_exists_and_getsize(self, mhl_cli, tmp_path, monkeypatch):
        """
        Race window 1: file disappears after exists() but before getsize().

        The size pre-check's OSError handler (lines 549-555 of simple_mhl.py) must catch this and report 'missing file'
        (exit 10), not propagate the exception.

        Manifest includes a <size> element so the size pre-check block is entered. os.path.getsize is patched to raise
        OSError for the target file only.
        """
        mhl = make_mhl_with_size(tmp_path, "vanishing.bin", b"data")

        real_getsize = os.path.getsize

        def _getsize_raises(path):
            if str(path).endswith("vanishing.bin"):
                raise OSError("simulated vanish during getsize")
            return real_getsize(path)

        monkeypatch.setattr(simple_mhl.os.path, "getsize", _getsize_raises)

        rc, out, _ = mhl_cli(["verify", str(mhl)])

        assert rc == 10, f"Expected exit 10 (missing file), got {rc}"
        assert "[ERROR] missing file: vanishing.bin" in out

    def test_file_deleted_before_hash_read(self, mhl_cli, tmp_path, monkeypatch):
        """
        Race window 2: file disappears after getsize() but before the hash read opens it.

        verify() hashes through get_hashes (one read pass for one-or-many formats); its OSError handler must catch this
        and report 'cannot verify' (exit 40), not propagate the exception.

        Manifest has NO <size> element so the size pre-check is skipped and the race happens at the hash read as
        intended. get_hashes is patched to delete the file then attempt the real open, which raises OSError.
        """
        target = tmp_path / "vanishing.bin"
        target.write_bytes(b"data")

        real_get_hashes = simple_mhl.get_hashes

        def _get_hashes_after_delete(filepath, factories, on_progress=None):
            target.unlink(missing_ok=True)
            return real_get_hashes(filepath, factories, on_progress=on_progress)

        monkeypatch.setattr(core_hashing, "get_hashes", _get_hashes_after_delete)

        # No <size> element — size pre-check block is not entered.
        root = etree.Element("hashlist", version="1.1")
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = "vanishing.bin"
        etree.SubElement(h, "md5").text = "0" * 32
        mhl = tmp_path / "race.mhl"
        etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")

        rc, out, _ = mhl_cli(["verify", str(mhl)])

        assert rc == 11, f"Expected exit 11 (cannot verify), got {rc}"
        assert "[ERROR] cannot verify vanishing.bin" in out


class TestRobustness:
    """
    The tool must never crash or regress on unusual inputs.

    Covers mutation-based fuzz resilience (random byte-level corruption of valid manifests must always produce a defined
    exit code) and memory behaviour (verify() must use iterparse, not parse, to keep peak memory bounded for large
    manifests tracking hundreds of thousands of frames).
    """

    def test_verify_pure_garbage_bytes_exits_cleanly(self, mhl_cli, tmp_path):
        """A file filled with random bytes must produce a defined exit code, never a traceback."""

        fuzzed = tmp_path / "garbage.mhl"
        fuzzed.write_bytes(os.urandom(4096))

        rc, _, _ = mhl_cli(["verify", str(fuzzed)])
        assert rc in (0, 1, 10, 11, 13, 40, 41), f"Unexpected exit code {rc} on pure garbage input"

    def test_verify_mutation_fuzz_loop(self, mhl_cli, tmp_path):
        """
        Apply sequential random byte-level mutations to a valid manifest and assert the tool always exits with a defined
        code — never crashes.

        20 iterations is enough to exercise truncation, bit-flip, null-injection, and garbage-insertion without making
        the test suite noticeably slow.
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
            assert rc in (0, 1, 10, 11, 13, 40, 41), f"Unexpected exit code {rc} on mutation iteration {i}"

    def test_large_manifest_uses_iterparse_not_parse(self, mhl_cli, tmp_path, monkeypatch):
        """
        Confirm verify() calls etree.iterparse() rather than etree.parse().

        etree.parse() loads the full XML DOM into memory — for a 100MB manifest tracking hundreds of thousands of
        DPX/EXR frames that means 300-500MB of RAM. etree.iterparse() yields one <hash> at a time and frees it
        immediately, keeping peak memory proportional to one element, not the full document.

        This test is implementation-level: it directly asserts the streaming path is taken so that a future refactor
        cannot silently regress to DOM loading without a test failure.
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
    """
    Build a well-formed classic-MHL manifest whose leaf values are drawn from the adversarial pools above. Structure
    follows the XSD; only values vary.

    Built with lxml so the document is always well-formed and correctly escaped — the fuzzing targets the tool's value
    handling, not the XML serializer.
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
    """
    Well-formed, XSD-shaped manifests with adversarial leaf values must always yield a defined exit code — never an
    uncaught exception. A fixed seed keeps failures reproducible. Complements TestRobustness's byte-mutation fuzz."""

    def test_verify_on_schema_shaped_values(self, mhl_cli, tmp_path):
        """
        verify must return one of its documented codes for any schema-shaped manifest, whatever junk lives in the typed
        value fields. The referenced files don't exist, so this exercises XML parsing, the version attribute, path
        resolution and the missing-file path. (The size pre-check and digest comparison sit *after* the existence check,
        so they are covered by the existing-file tests below, not here.)"""
        rng = random.Random(1234)
        for i in range(80):
            mhl = tmp_path / f"fuzz_{i}.mhl"
            mhl.write_bytes(_build_classic_fuzz_manifest(rng))
            rc, _, _ = mhl_cli(["verify", str(mhl)])
            assert rc in {0, 1, 10, 11, 13, 40, 41}, f"verify exit {rc} on fuzz iteration {i}"

    def test_verify_tampered_size_on_existing_files(self, mhl_cli, tmp_path):
        """
        Model a user editing the <size> of an entry whose file exists and whose digest is correct: verify gets *past*
        the missing-file check and actually runs the size pre-check. A malformed or mismatched size must be reported
        (40); a coincidentally-correct one falls through to the matching hash and passes (0). Never a crash, whatever
        odd characters or magnitudes the size carries — so the outcome here is driven purely by the size field."""
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
            assert rc in {0, 11}, f"verify exit {rc} on tampered-size iteration {i}"

    def test_verify_tampered_digest_on_existing_files(self, mhl_cli, tmp_path):
        """
        Model a user editing the digest of an entry whose file exists with the recorded size: verify gets *past* the
        existence and size pre-checks and actually reaches digest comparison. Whatever invalid characters or encoding
        the tampered digest carries, verify must report a clean result (0 if it happens to match, 40 mismatch /
        cannot-verify) — never crash."""
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
            assert rc in {0, 11}, f"verify exit {rc} on tampered-digest iteration {i}"

    def test_xsd_schema_check_on_schema_shaped_values(self, mhl_cli, tmp_path):
        """xsd-schema-check must return one of its documented codes (0 valid,
        41 schema-invalid, 40 parse/file error, 1 error (xsd missing)) — never crash."""
        rng = random.Random(5678)
        for i in range(80):
            mhl = tmp_path / f"fuzz_{i}.mhl"
            mhl.write_bytes(_build_classic_fuzz_manifest(rng))
            rc, _, _ = mhl_cli(["xsd-schema-check", str(mhl)])
            assert rc in {0, 1, 40, 41}, f"xsd-schema-check exit {rc} on fuzz iteration {i}"
