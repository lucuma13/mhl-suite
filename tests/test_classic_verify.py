"""
Tests for classic_verify: structured verify_classic outcomes plus CLI-level
verify behaviour. Schema validation lives in test_xsd_check, the shared
result model and renderer in test_verify.
"""

import hashlib
import os
import sys
from pathlib import Path

import pytest
import xxhash
from lxml import etree

from mhl_suite import classic_seal as core_seal
from mhl_suite import classic_verify, hashing
from mhl_suite.cli import simple_mhl
from mhl_suite.verify import ErrorKind

from .helpers import make_mhl_with_size, make_multi_hash_mhl, make_tree, seal_helper


class TestVerify:
    """Tests around the verify command."""

    def test_verify_missing_and_modified(self, mhl_cli, tmp_path):
        """If BOTH missing and mismatch occur, mismatch wins: exit 11. Both still show in the output."""
        make_tree(tmp_path, {"a.bin": b"hello", "b.bin": b"world"})
        mhl = seal_helper(mhl_cli, tmp_path)
        (tmp_path / "a.bin").unlink()
        (tmp_path / "b.bin").write_bytes(b"changed")

        rc, out, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 11
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
        file, naming the algorithm actually checked and its digest. Umbrella for verify's verbose *success* output —
        extend this rather than adding a sibling per detail (failure output lives in its own scenario tests)."""
        make_tree(tmp_path, {"a.bin": b"hello", "sub/b.bin": b"world"})
        mhl = seal_helper(mhl_cli, tmp_path, algo="md5")

        rc, out, _err = mhl_cli(["verify", "-v", str(mhl)])
        assert rc == 0
        assert f"[OK] a.bin  md5: {hashlib.md5(b'hello').hexdigest()}" in out
        # The terminal is the one place we render the native separator. Assert os.sep so the conversion (simple_mhl →
        # to_terminal_sep) stays locked in.
        assert f"[OK] sub{os.sep}b.bin" in out

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
        assert rc == 11
        assert "[OK] good.bin" in out
        # "world" (5 bytes) → "changed" (7 bytes): size pre-check fires first.
        assert "bad.bin" in out
        assert "[ERROR]" in out

    def test_verify_verbose_mismatch_output(self, mhl_cli, tmp_path):
        """Umbrella for verify's verbose *failure* output. A same-size content
        change passes the size pre-check and reaches the hash comparison, so --verbose prints the calc/stored hash
        detail line."""
        make_tree(tmp_path, {"a.bin": b"world"})
        mhl = seal_helper(mhl_cli, tmp_path)
        # Same byte length (5) so the size pre-check passes and the hash differs.
        (tmp_path / "a.bin").write_bytes(b"wXrld")

        rc, out, _ = mhl_cli(["verify", "-v", str(mhl)])
        assert rc == 11
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
        """A file whose byte-length no longer matches <size> is a size mismatch (exit 13)."""
        make_tree(tmp_path, {"a.bin": b"hello"})
        mhl = seal_helper(mhl_cli, tmp_path)
        (tmp_path / "a.bin").write_bytes(b"hello world")

        rc, out, _ = mhl_cli(["verify", "--size-only", str(mhl)])
        assert rc == 13
        assert "[ERROR] size mismatch: a.bin" in out

    def test_size_only_missing_file(self, mhl_cli, tmp_path):
        """A deleted file is reported missing (exit 10) in size-only mode too."""
        make_tree(tmp_path, {"a.bin": b"hello"})
        mhl = seal_helper(mhl_cli, tmp_path)
        (tmp_path / "a.bin").unlink()

        rc, out, _ = mhl_cli(["verify", "-S", str(mhl)])
        assert rc == 10
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
        assert rc == 13
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
        an OS-junk entry must still be skipped silently (no callback invoked, no crash) and excluded, while a hidden
        user file IS yielded."""
        make_tree(tmp_path, {"visible.bin": b"x", ".hidden.bin": b"y", ".DS_Store": b"junk"})
        mhl_path = str(tmp_path / "out.mhl")
        yielded = sorted(os.path.basename(p) for p, _ in core_seal._iter_files_for_seal(str(tmp_path), mhl_path))
        assert yielded == [".hidden.bin", "visible.bin"]

    @pytest.mark.skipif(sys.platform == "win32", reason="os.mkfifo is POSIX-only")
    def test_iter_files_without_on_skip_skips_non_regular(self, tmp_path):
        """A non-regular file (FIFO) must be skipped silently when on_skip=None."""
        make_tree(tmp_path, {"visible.bin": b"x"})
        os.mkfifo(tmp_path / "pipe")
        mhl_path = str(tmp_path / "out.mhl")
        yielded = [os.path.basename(p) for p, _ in core_seal._iter_files_for_seal(str(tmp_path), mhl_path)]
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

        Its <hash> entries use <path> not <file>, so the v1 verify loop would skip them all and falsely exit 0 — this
        guards that regression.
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
        """Malformed XML should produce exit 40."""
        bad = tmp_path / "bad.mhl"
        bad.write_text("<not valid xml")
        rc, _, _ = mhl_cli(["verify", str(bad)])
        assert rc == 40

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
            assert rc == 11
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


class TestVerifyClassicBadAlgorithm:
    """verify_classic rejects an unsupported -a selection with ValueError, whether
    it arrives as a single name or inside an explicit tag list."""

    def _mhl(self, tmp_path):
        return make_multi_hash_mhl(tmp_path, "a.bin", b"hello", {"md5": hashlib.md5(b"hello").hexdigest()})

    def test_single_name_not_in_algo_map(self, tmp_path):
        with pytest.raises(ValueError, match="unsupported algorithm 'blake2'"):
            classic_verify.verify_classic(str(self._mhl(tmp_path)), algorithm="blake2")

    def test_tag_list_with_unknown_tag(self, tmp_path):
        with pytest.raises(ValueError, match="unsupported algorithm 'blake2be'"):
            classic_verify.verify_classic(str(self._mhl(tmp_path)), algorithm=["blake2be"])

    def test_single_name_in_algo_map_resolves_to_its_tag(self, tmp_path):
        """A bare valid algorithm string (not a list) is accepted and canonicalised
        to its manifest tag, verifying cleanly when the digest matches."""
        report = classic_verify.verify_classic(str(self._mhl(tmp_path)), algorithm="md5")
        assert report.code == 0


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
            assert mhl_cli(["verify", str(mhl)])[0] == 11

    def test_xxhash64be_rejects_little_endian_value(self, mhl_cli, tmp_path):
        """xxhash64be is strict big-endian: the little-endian form must NOT verify."""
        content = b"strict big endian"
        be = xxhash.xxh64(content).hexdigest()
        le = _le_hex(xxhash.xxh64(content).intdigest(), 8)
        assert le != be  # palindromic digest would be astronomically unlikely
        mhl = make_multi_hash_mhl(tmp_path, "a.bin", content, {"xxhash64be": le})
        assert mhl_cli(["verify", str(mhl)])[0] == 11


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
        assert mhl_cli(["verify", str(mhl)])[0] == 11


class TestSizePreCheck:
    """File size is checked before hash computation during verify.

    The size pre-check is a fast, cheap guard: a stat() call that can rule out corruption without reading the entire
    file.  These tests confirm:

      * A single size-mismatched file is caught and reported.
      * The check fires *before* get_hash() is called (get_hash is not invoked when the size already proves the file is
        wrong).
      * A malformed (non-decimal) <size> field is flagged as corruption rather than silently skipped.
      * Even if a hash digest happens to match (forced via monkeypatch), a size discrepancy is still reported — size
        wins over hash agreement.
    """

    def test_size_mismatch_is_caught(self, mhl_cli, tmp_path):
        """A file whose on-disk size differs from the manifest <size> exits 11.

        Mechanism: we write the file with content 'hello' (5 bytes) but record size=9999 in the manifest, then verify.
        The size pre-check must catch this without needing to hash the file.
        """
        mhl = make_mhl_with_size(tmp_path, "clip.bin", b"hello", size_override="9999")

        rc, out, _ = mhl_cli(["verify", str(mhl)])

        assert rc == 11, f"Expected exit 11 for size mismatch, got {rc}"
        assert "clip.bin" in out, "Affected filename must appear in output"
        # Accept either 'size mismatch' or 'malformed size' phrasing — both indicate the size check fired before
        # hashing.
        assert "size" in out.lower(), f"Expected a size-related error message, got: {out!r}"

    def test_size_mismatch_skips_hash_computation(self, mhl_cli, tmp_path, monkeypatch):
        """get_hashes() must NOT be called when the size pre-check already fails.

        A size mismatch is a definitive failure signal.  Hashing afterwards wastes I/O on a file that is already known
        to be wrong. verify() hashes through get_hashes (one read pass for one-or-many formats), so the spy watches that
        to confirm hashing is never reached.
        """
        get_hashes_calls: list[str] = []
        real_get_hashes = hashing.get_hashes

        def spy_get_hashes(filepath, factories, on_progress=None):
            get_hashes_calls.append(filepath)
            return real_get_hashes(filepath, factories, on_progress=on_progress)

        monkeypatch.setattr(hashing, "get_hashes", spy_get_hashes)

        mhl = make_mhl_with_size(tmp_path, "clip.bin", b"hello", size_override="9999")

        rc, _, _ = mhl_cli(["verify", str(mhl)])

        assert rc == 11, f"Expected exit 11, got {rc}"
        assert get_hashes_calls == [], (
            f"get_hashes() was called {len(get_hashes_calls)} time(s) despite size mismatch — "
            "the pre-check must short-circuit before hashing"
        )

    def test_malformed_size_field_is_flagged(self, mhl_cli, tmp_path):
        """A <size> containing non-decimal characters must be flagged as corrupt.

        Non-decimal Unicode digits (e.g. superscript '2\xb246896176' as seen in real-world corrupted MHL files) are
        rejected by isdecimal().  The tool must report this as a manifest error, not silently skip the check.
        """
        # Embed a superscript-two (U+00B2) mid-string — exactly the pattern seen in the BGR2_20260426 fixture that
        # triggered this requirement.
        mhl = make_mhl_with_size(tmp_path, "clip.bin", b"hello", size_override="2\xb246896176")

        rc, out, _ = mhl_cli(["verify", str(mhl)])

        assert rc == 11, f"Expected exit 11 for malformed size field, got {rc}"
        assert "clip.bin" in out
        assert "malformed size" in out.lower(), f"Expected 'malformed size' in output, got: {out!r}"

    def test_size_mismatch_caught_even_when_hash_matches(self, mhl_cli, tmp_path, monkeypatch):
        """A size discrepancy must be reported even if the hash digest matches.

        xxhash64 is non-cryptographic and constructing a real same-digest collision for two files of different lengths
        is impractical without specialised tooling.  Instead we monkeypatch get_hashes() to return the *correct* digest
        for the on-disk file regardless, then verify that the size check still fires before hashing is reached.

        This is the adversarially interesting case: a tool that only checks the hash would silently pass a file whose
        size is wrong (e.g. a truncated file that happens to share its hash with another file).  The size check must
        take priority.
        """
        content = b"A" * 1024
        correct_digest = xxhash.xxh64(content).hexdigest()

        # Record the correct digest but a wrong size.
        mhl = make_mhl_with_size(tmp_path, "clip.bin", content, size_override="9999")

        # Ensure get_hashes would return the correct digest if ever called, so the only thing that can trigger the
        # failure is the size check.
        def always_correct_hash(filepath, factories, on_progress=None):
            return [correct_digest for _ in factories]

        monkeypatch.setattr(hashing, "get_hashes", always_correct_hash)

        rc, out, _ = mhl_cli(["verify", str(mhl)])

        assert rc == 11, f"Expected exit 11: size mismatch must be caught even when hash matches, got {rc}"
        assert "clip.bin" in out
        assert "size" in out.lower(), f"Expected a size-related error message, got: {out!r}"

    def test_correct_size_proceeds_to_hash_check(self, mhl_cli, tmp_path):
        """When size matches, verify must still check the hash.

        Regression guard: the size pre-check must not short-circuit a clean file.  A file with a matching size but a
        wrong hash must still exit 11.
        """
        content = b"original"
        mhl = make_mhl_with_size(tmp_path, "clip.bin", content)

        # Overwrite with same-size content that has a different hash.
        (tmp_path / "clip.bin").write_bytes(b"ORIGINAL")  # same 8 bytes, different content

        rc, out, _ = mhl_cli(["verify", str(mhl)])

        assert rc == 11, f"Expected exit 11 for hash mismatch after size matches, got {rc}"
        assert "hash mismatch" in out.lower()


class TestVerifyConcurrency:
    """Concurrency must never change verify's verdict, exit code, or output —
    only its speed. The deferred-hash restructure must also keep the size-precheck-before-hash contract (covered
    separately) intact."""

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
        monkeypatch.setattr(hashing, "_AUTO_MIN_BYTES", 0)
        monkeypatch.setattr(hashing, "_AUTO_WARMUP_SECONDS", 0.0)
        monkeypatch.setattr(hashing, "_AUTO_PROBE_MIN_BYTES", 0)
        monkeypatch.setattr(simple_mhl.os, "cpu_count", lambda: 8)
        monkeypatch.setattr(hashing, "calibrate_hash_bandwidth", lambda f: 1000.0)
        monkeypatch.setattr(hashing, "_warmup_seq_bw", lambda nbytes, elapsed: 1000.0)
        monkeypatch.setattr(hashing, "_probe_read_bw_multi", lambda slots, n: 8000.0)  # aggregate >> seq ⇒ parallel
        monkeypatch.setattr(hashing, "_AUTO_RECHECK_BYTES", 4096)  # several windows over tiny files

    def test_parallel_matches_sequential_clean(self, mhl_cli, tmp_path, monkeypatch):
        mhl, _ = self._build_manifest(tmp_path)
        # Reference run first: a tiny manifest stays under the auto threshold ⇒ sequential. Then force parallel and
        # require identical output.
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
        assert rc_seq == 11  # mismatch wins over missing
        assert rc_par == rc_seq
        assert out_par == out_seq  # same buckets, same order


class TestVerifyManifestOutcomes:
    """verify_classic emits structured VerifyEntries — status, detail, and the
    weak-check flags — that mhlver maps straight onto its report (no text parse). These pin that contract directly,
    replacing the old mhlver output-parser tests."""

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

    def test_hash_mismatch_carries_full_comparison(self, tmp_path):
        (tmp_path / "f.bin").write_bytes(b"actual content")  # 14 bytes
        mhl = self._write(tmp_path, [("f.bin", {"size": "14", "md5": "0" * 32})])
        report = classic_verify.verify_classic(str(mhl))
        assert report.code == 11
        (e,) = report.entries
        assert e.status == "mismatch"
        assert e.hash_mismatch
        (cmp_,) = e.hashes
        assert cmp_.tag == "md5"
        assert cmp_.expected == "0" * 32
        assert cmp_.computed == hashlib.md5(b"actual content").hexdigest()
        assert cmp_.ok is False

    def test_missing_file(self, tmp_path):
        mhl = self._write(tmp_path, [("ghost.bin", {"size": "3", "md5": "0" * 32})])
        report = classic_verify.verify_classic(str(mhl))
        assert report.code == 10
        (e,) = report.entries
        assert e.status == "missing"

    def test_blocked_traversal_is_error(self, tmp_path):
        mhl = self._write(tmp_path, [("../escape.bin", {"size": "3", "md5": "0" * 32})])
        (e,) = classic_verify.verify_classic(str(mhl)).entries
        assert e.status == "error"
        assert e.error == ErrorKind.TRAVERSAL

    def test_size_only_without_recorded_size_is_error(self, tmp_path):
        (tmp_path / "f.bin").write_bytes(b"xx")
        mhl = self._write(tmp_path, [("f.bin", {"md5": "0" * 32})])  # no <size>
        (e,) = classic_verify.verify_classic(str(mhl), size_only=True).entries
        assert e.status == "error"
        assert e.error == ErrorKind.NO_SIZE

    def test_requested_hash_not_stored_is_error(self, tmp_path):
        (tmp_path / "f.bin").write_bytes(b"xx")
        mhl = self._write(tmp_path, [("f.bin", {"size": "2", "md5": hashlib.md5(b"xx").hexdigest()})])
        (e,) = classic_verify.verify_classic(str(mhl), algorithm=["sha1"]).entries
        assert e.status == "error"
        assert e.error == ErrorKind.HASH_NOT_STORED
        assert e.detail == "sha1"

    def test_null_entries_set_size_only_and_existence_only(self, tmp_path):
        (tmp_path / "s.bin").write_bytes(b"abcd")
        (tmp_path / "e.bin").write_bytes(b"z")
        mhl = self._write(tmp_path, [("s.bin", {"size": "4", "null": ""}), ("e.bin", {"null": ""})])
        report = classic_verify.verify_classic(str(mhl))
        assert report.code == 0
        by_path = {e.path: e for e in report.entries}
        assert by_path["s.bin"].size_only is True
        assert by_path["e.bin"].existence_only is True
        assert report.notices  # the "Verified with … checks" notice fired

    def test_malformed_xml_sets_code_40(self, tmp_path):
        mhl = tmp_path / "bad.mhl"
        mhl.write_text("<hashlist><hash><file>x</file>")  # truncated
        report = classic_verify.verify_classic(str(mhl))
        assert report.code == 40
        assert report.malformed is True
        assert report.entries == []


class TestVerifyNullAndHashEdgeCases:
    """Null-tag, hash-element, and uncomputable-hash edge cases for classic_verify.

    Relocated from a misnamed grab-bag (TestGetXsdPathFallbackPaths) in the old schema test file — these exercise
    verify, not XSD path resolution."""

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
        assert rc == 11
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
        """A <null> entry for a file that does NOT exist must exit 10."""
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
        assert rc == 10
        assert "[ERROR] missing file: ghost.bin" in out

    def test_null_tag_size_mismatch_reports_error(self, mhl_cli, tmp_path):
        """A <null> entry whose file exists but whose size differs from the
        manifest <size> must fail with a size mismatch (exit 13).

        The v1.1 schema defines <null> as "no hash, only use file size verification", so a truncated/corrupted file must
        not pass on existence alone.
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
        assert rc == 11
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
        algorithm: ignored entirely. An entry whose only hash is uncomputable reports 'no supported hash found' (exit
        40), not a special 'cannot verify'."""
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
        assert rc == 11
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
