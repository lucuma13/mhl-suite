"""
CLI behaviour for simple-mhl: smart dispatch, help hints, Unicode-normalization
wiring, and the algorithm parsing/selection that drives seal/verify hash-format
handling.
"""

import argparse
import hashlib
import os
import unicodedata
from pathlib import Path

import pytest
import xxhash
from lxml import etree

from mhl_suite import classic_seal as core_seal
from mhl_suite import osutils
from mhl_suite.algorithms import get_hash
from mhl_suite.classic_seal import SealError
from mhl_suite.cli import simple_mhl
from mhl_suite.verify import VERIFY_ALL

from .helpers import (
    _sensitive_fs,
    make_multi_hash_mhl,
    make_tree,
    seal_helper,
)


class TestSmartDispatch:
    """Bare path arguments are dispatched to the correct subcommand.

    simple-mhl <directory>   →  simple-mhl seal <directory>
    simple-mhl <file>.mhl    →  simple-mhl verify <file>.mhl
    """

    def test_bare_directory_dispatches_to_seal(self, mhl_cli, tmp_path):
        """
        Passing only a directory path (no subcommand) should seal it.

        The smart-dispatch logic in main() inspects sys.argv[1], detects an
        existing directory, and injects the 'seal' subcommand before argparse
        sees the arguments.  The result must be identical to calling 'simple-mhl
        seal <dir>' explicitly.
        """
        make_tree(tmp_path, {"clip.bin": b"data"})

        # Invoke with just the directory — no explicit 'seal' subcommand.
        rc, _, _ = mhl_cli([str(tmp_path)])

        assert rc == 0, f"Expected exit 0 from implicit seal, got {rc}"
        mhls = list(tmp_path.glob("*.mhl"))
        assert len(mhls) == 1, "Expected exactly one .mhl file to be created"

    def test_bare_directory_dispatch_produces_valid_manifest(self, mhl_cli, tmp_path):
        """
        The manifest produced by implicit seal must be verifiable.

        Ensures dispatch injects the right subcommand *and* that all normal seal
        arguments (default algorithm, etc.) are preserved.
        """
        make_tree(tmp_path, {"a.bin": b"hello", "sub/b.bin": b"world"})
        mhl_cli([str(tmp_path)])
        mhl = next(tmp_path.glob("*.mhl"))

        rc, _, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 0, "Manifest produced by implicit seal did not verify clean"

    def test_bare_mhl_path_dispatches_to_verify(self, mhl_cli, tmp_path):
        """
        Passing only a .mhl path (no subcommand) should verify it.

        The smart-dispatch logic detects a .mhl extension and injects the
        'verify' subcommand.  A clean manifest must exit 0.
        """
        make_tree(tmp_path, {"a.bin": b"data"})
        mhl = seal_helper(mhl_cli, tmp_path)

        # Invoke with just the .mhl path — no explicit 'verify' subcommand.
        rc, _, _ = mhl_cli([str(mhl)])

        assert rc == 0, f"Expected exit 0 from implicit verify of clean manifest, got {rc}"

    def test_bare_mhl_path_dispatch_reports_corruption(self, mhl_cli, tmp_path):
        """
        Implicit verify must surface errors just as explicit verify does.

        Corrupting a file after sealing then invoking via bare .mhl path must
        produce exit 40 and the expected ERROR line — confirming dispatch
        reaches the real verify() code path, not a stub.
        """
        make_tree(tmp_path, {"a.bin": b"original"})
        mhl = seal_helper(mhl_cli, tmp_path)
        # Write same-length replacement so size pre-check passes and the hash
        # check is what catches the corruption — confirming the full verify code
        # path is exercised by implicit dispatch.
        (tmp_path / "a.bin").write_bytes(b"ORIGINAL")  # 8 bytes == len("original")

        rc, out, _ = mhl_cli([str(mhl)])

        assert rc == 11, f"Expected exit 11 from implicit verify of corrupt file, got {rc}"
        assert "[ERROR] hash mismatch: a.bin" in out

    def test_explicit_subcommand_not_intercepted(self, mhl_cli, tmp_path):
        """
        An explicit 'seal' or 'verify' subcommand must pass through unchanged.

        Regression guard: the dispatch block must only fire when the first token
        is NOT already a recognised subcommand.
        """
        make_tree(tmp_path, {"a.bin": b"x"})
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        assert rc == 0

        mhl = next(tmp_path.glob("*.mhl"))
        rc, _, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 0

    def test_bare_non_mhl_file_falls_through_to_argparse_error(self, mhl_cli, tmp_path):
        """
        A bare path that is neither a directory nor a .mhl file must fall
        through the dispatch block unmodified and let argparse reject it.

        The path is passed as the first argument with no subcommand, so it lands
        in argparse as an unrecognised subcommand → exit 2. This covers the
        fall-through branch (673→679) in main().
        """
        plain = tmp_path / "plain_text_file.txt"
        plain.write_text("data")

        rc, _, err = mhl_cli([str(plain)])

        assert rc == 2, f"Expected exit 2 from argparse, got {rc}"
        # argparse writes usage/error to stderr for unrecognised subcommands.
        assert err.strip() != "", "Expected argparse error on stderr, got silence"


class TestAlgorithmHelpHint:
    """
    '-h <algo>' is a common slip for '-a <algo>' and gets a pointing hint.

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

    def test_help_before_any_subcommand_gets_no_hint(self, mhl_cli):
        # '-h' with no seal/verify subcommand preceding it (e.g. top-level help)
        # is ordinary help — the hint only fires for a seal/verify slip.
        rc, _, err = mhl_cli(["-h", "xxhash"])

        assert rc == 0
        assert "Did you mean" not in err


class TestUnicodeNormalization:
    """
    Unicode normalization of accented filenames at seal and verify time.

    macOS HFS+ returns filenames in a frozen modified NFD form — e.g. the single
    codepoint é (U+00E9) is decomposed to e (U+0065) + combining acute (U+0301).
    Linux ext4 does byte-exact filename matching, so an NFD path from the
    manifest would silently fail os.path.exists() against an NFC file on disk.

    simple_mhl handles normalization forms at two points:
      1. seal   — <file> records the walk's bytes verbatim. Byte-exact
                  verifiers match manifest paths against readdir output
                  literally, so any rewriting at seal time breaks them;
                  normalizing verifiers accept either form.
      2. verify — osutils.resolve_on_disk() matches the manifest path against
                  real directory entries across normalization forms (literal
                  bytes first, NFC-keyed index as fallback) so it finds the file
                  whatever form it is stored in, without assuming the filesystem
                  normalizes for us — refusing the fallback when several
                  coexisting entries share one NFC identity.

    These tests construct NFD filenames explicitly so the behaviour is
    deterministic regardless of what the host OS normalizes at mkdir/write time.
    """

    # NFD forms used across tests:
    #   NFC: "Ré.txt"  = R + U+00E9 (precomposed é)
    #   NFD: "Ré.txt"  = R + e + U+0301 (combining acute)
    _NFC_NAME = "R\u00e9.txt"  # R + precomposed é
    _NFD_NAME = "Re\u0301.txt"  # R + e + combining acute

    def test_seal_writes_walked_nfd_path_verbatim(self, mhl_cli, tmp_path, monkeypatch):
        """
        seal() must write the walk's bytes verbatim: an NFD path from the
        filesystem lands in <file> as NFD.

        Byte-exact verifiers (ascmhl reference implementation, SealVerify,
        MediaVerify) match manifest paths against readdir output literally —
        rewriting the form at seal time makes every accented name fail in those
        tools, while normalizing verifiers (ours, Offshoot, TrueCheck) accept
        either form.

        We write the file under its NFD name (so get_hash can open it on any OS,
        since the path we hand to seal must actually exist on disk) and patch
        _iter_files_for_seal to yield that NFD path — simulating what macOS HFS+
        returns.  The manifest must contain the NFD form, untouched.
        """

        # Create the file with the NFD name — openable on all platforms.
        nfd_path = tmp_path / self._NFD_NAME
        nfd_path.write_bytes(b"data")

        real_iter = core_seal._iter_files_for_seal

        def nfd_iter(root, mhl_path, on_skip=None):
            for p, stat_result in real_iter(root, mhl_path, on_skip=on_skip):
                # Force the NFD spelling in case the OS returned NFC (e.g. on a
                # normalization-insensitive macOS volume), so the test exercises
                # the verbatim contract on all OSes.
                nfd_str = unicodedata.normalize("NFD", str(p))
                yield Path(nfd_str), stat_result

        monkeypatch.setattr(core_seal, "_iter_files_for_seal", nfd_iter)

        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        assert rc == 0

        mhl = next(tmp_path.glob("*.mhl"))
        text = mhl.read_text(encoding="utf-8")
        # The <file> element must carry the walked NFD bytes, not a rewrite.
        assert self._NFD_NAME in text, (
            f"Expected walked NFD name {self._NFD_NAME!r} in manifest. "
            f"Manifest snippet: {text[text.find('<file>') : text.find('</file>') + 7]!r}"
        )
        # The NFC byte sequence must not appear in the raw manifest bytes.
        assert self._NFC_NAME.encode("utf-8") not in mhl.read_bytes(), (
            "NFC byte sequence found in manifest — seal rewrote the walked form"
        )

    def test_seal_writes_walked_nfc_path_verbatim(self, mhl_cli, tmp_path, monkeypatch):
        """
        An NFC name walks through seal untouched — verbatim in both directions.
        """
        nfc_path = tmp_path / self._NFC_NAME
        nfc_path.write_bytes(b"data")

        real_iter = core_seal._iter_files_for_seal

        def nfc_iter(root, mhl_path, on_skip=None):
            for p, stat_result in real_iter(root, mhl_path, on_skip=on_skip):
                yield Path(unicodedata.normalize("NFC", str(p))), stat_result

        monkeypatch.setattr(core_seal, "_iter_files_for_seal", nfc_iter)

        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        assert rc == 0

        mhl = next(tmp_path.glob("*.mhl"))
        assert self._NFC_NAME in mhl.read_text(encoding="utf-8")
        assert self._NFD_NAME.encode("utf-8") not in mhl.read_bytes()

    def test_verify_nfc_manifest_finds_nfc_file(self, mhl_cli, tmp_path):
        """
        verify() must find a file when both the manifest and disk use NFC.

        This is the baseline happy path for NFC filenames — seal then verify on
        the same OS must always work.
        """
        make_tree(tmp_path, {self._NFC_NAME: b"data"})
        mhl = seal_helper(mhl_cli, tmp_path)

        rc, _, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 0

    def test_verify_normalizes_nfd_manifest_path_to_find_nfc_file(self, mhl_cli, tmp_path):
        """
        verify() must find an NFC file on disk even when the manifest contains
        an NFD path.

        This is the cross-platform scenario: manifest sealed on macOS (NFD
        paths) verified on Linux (NFC files, byte-exact matching). We construct
        the manifest by hand with an NFD <file> entry pointing at an NFC file on
        disk.
        """

        # Create the file with an NFC name.
        nfc_path = tmp_path / self._NFC_NAME
        nfc_path.write_bytes(b"data")
        digest = get_hash(str(nfc_path), "md5")

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
        """
        Complement to the above: NFD manifest + correct digest = clean verify.

        Confirms the normalization does not break the hash check that follows.
        """

        nfc_path = tmp_path / self._NFC_NAME
        content = b"accented content"
        nfc_path.write_bytes(content)
        digest = get_hash(str(nfc_path), "md5")

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
        """
        NFD normalization must not suppress a genuine hash mismatch.

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

        assert rc == 11
        assert "hash mismatch" in out.lower()

    def test_verify_nfc_manifest_finds_nfd_file_on_disk(self, mhl_cli, tmp_path):
        """
        Scenario 3 (end-to-end): manifest path is NFC, the file on disk is NFD.

        Mirror of test_verify_normalizes_nfd_manifest_path_to_find_nfc_file. On
        a normalization-*sensitive* filesystem (ext4/exFAT/NTFS — e.g. Linux CI)
        the literal NFC lookup misses and resolution scans the directory and
        matches on NFC; on an *insensitive* volume (APFS/HFS+ — e.g. macOS dev)
        the literal lookup already succeeds. Either way verify must find and
        check the file, so this passes regardless of host filesystem.
        """
        nfd_path = tmp_path / self._NFD_NAME
        content = b"data"
        nfd_path.write_bytes(content)
        digest = get_hash(str(nfd_path), "md5")

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


def _patch_sensitive(monkeypatch, files, dirs):
    """
    Patch exists/isdir/lexists/scandir to model a normalization-sensitive,
    byte-exact filesystem from explicit file and directory path sets.
    """
    files = set(files)
    dirs = set(dirs)
    all_paths = files | dirs
    lexists, scandir = _sensitive_fs(all_paths)
    monkeypatch.setattr(os.path, "lexists", lexists)
    monkeypatch.setattr(os, "scandir", scandir)
    monkeypatch.setattr(os.path, "exists", lambda p: p in all_paths)
    monkeypatch.setattr(os.path, "isdir", lambda p: p in dirs)
    # The fabricated paths are already absolute and drive-less; keep abspath an identity so it doesn't prepend the
    # current drive on Windows (D:\vol\...) and stop matching the fake filesystem's \vol\... entries.
    monkeypatch.setattr(os.path, "abspath", lambda p: p)


class TestNormalizationVariantHint:
    """
    The typed CLI path (verify's .mhl, seal's root) is left to the OS, but a
    not-found error suggests a real on-disk path that differs only in Unicode
    normalization. Simulated on a sensitive filesystem (the only place the
    mismatch is observable).
    """

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
        assert osutils.normalization_variant_on_disk(typed) == nfd_mhl

    def test_variant_helper_returns_none_for_genuine_typo(self, monkeypatch):
        _patch_sensitive(
            monkeypatch,
            files={os.path.join(self._VOL, "real.mhl")},
            dirs={os.sep, self._VOL},
        )
        assert osutils.normalization_variant_on_disk(os.path.join(self._VOL, "ghost.mhl")) is None

    def test_variant_helper_returns_none_when_path_exists_as_typed(self, monkeypatch):
        typed = os.path.join(self._VOL, "m.mhl")
        _patch_sensitive(monkeypatch, files={typed}, dirs={os.sep, self._VOL})
        assert osutils.normalization_variant_on_disk(typed) is None

    def test_root_only_path_returns_none(self):
        """A bare root (no path tail) leaves nothing to resolve, so the helper
        returns None before touching the filesystem."""
        assert osutils.normalization_variant_on_disk(os.sep) is None

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
        with pytest.raises(SealError) as exc:
            simple_mhl.seal_classic(typed, ["md5"])
        assert "did you mean" in str(exc.value)
        assert nfd_dir in str(exc.value)


class TestVerifyAlgorithmSelection:
    """
    verify defaults to the fastest recorded hash (xxhash > md5 > sha1); -a
    overrides.
    """

    def test_default_uses_xxhash_when_md5_is_wrong(self, mhl_cli, tmp_path):
        """md5 deliberately wrong but xxhash correct → default (xxhash) passes."""
        content = b"hello"
        mhl = make_multi_hash_mhl(
            tmp_path, "a.bin", content, {"md5": "0" * 32, "xxhash64be": xxhash.xxh64(content).hexdigest()}
        )
        rc, _, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 0

    def test_default_picks_xxhash_even_when_listed_last(self, mhl_cli, tmp_path):
        """
        md5 correct but xxhash (last element) wrong → default chooses xxhash and
        fails, proving selection is by speed, not document order.
        """
        content = b"hello"
        mhl = make_multi_hash_mhl(
            tmp_path, "a.bin", content, {"md5": hashlib.md5(content).hexdigest(), "xxhash64be": "00" * 8}
        )
        rc, out, _ = mhl_cli(["verify", str(mhl)])
        assert rc == 11
        assert "hash mismatch" in out

    def test_override_md5_passes_when_md5_correct(self, mhl_cli, tmp_path):
        """Same manifest where xxhash is wrong but md5 is right: -a md5
        passes."""
        content = b"hello"
        mhl = make_multi_hash_mhl(
            tmp_path, "a.bin", content, {"md5": hashlib.md5(content).hexdigest(), "xxhash64be": "00" * 8}
        )
        rc, _, _ = mhl_cli(["verify", str(mhl), "-a", "md5"])
        assert rc == 0

    def test_override_md5_detects_corrupt_md5(self, mhl_cli, tmp_path):
        """
        -a md5 forces md5 even though the correct xxhash would pass by default.
        """
        content = b"hello"
        mhl = make_multi_hash_mhl(
            tmp_path, "a.bin", content, {"md5": "0" * 32, "xxhash64be": xxhash.xxh64(content).hexdigest()}
        )
        rc, _, _ = mhl_cli(["verify", str(mhl), "-a", "md5"])
        assert rc == 11

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
        assert rc == 11
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
        """
        -a all checks ALL recorded hashes, so one wrong stored digest fails the
        entry even when the fastest (default) hash matches. Verbose marks per
        format which matched and which didn't.
        """
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
        assert rc == 11
        assert "hash mismatch: clip.bin" in out
        assert "sha1 MISMATCH" in out
        assert "md5 OK" in out
        assert "xxhash64be OK" in out

    def test_comma_list_checks_each_selected_hash_order_independent(self, mhl_cli, tmp_path):
        """
        -a md5,sha1 verifies exactly those two; the unrequested xxhash is
        skipped, and requested order doesn't change the result (output stays in
        manifest order).
        """
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
        """
        Requesting tags the entry doesn't record fails it, naming each missing
        one; the list is sorted so the message is stable regardless of requested
        order.
        """
        content = b"hello"
        mhl = make_multi_hash_mhl(tmp_path, "a.bin", content, {"xxhash64be": xxhash.xxh64(content).hexdigest()})
        rc, out, _ = mhl_cli(["verify", "-a", "sha1,md5", str(mhl)])
        assert rc == 11
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
        assert rc == 11
        assert "sha1 MISMATCH" in out


class TestCombineAlgorithms:
    """Merging repeated -a occurrences (argparse action="append" shapes)."""

    def test_seal_none_defaults_to_xxh64(self):
        assert simple_mhl.combine_seal_algorithms(None) == ["xxh64"]
        assert simple_mhl.classic_seal_tag("xxh64") == "xxhash64be"

    def test_seal_flattens_and_dedups_across_flags(self):
        assert simple_mhl.combine_seal_algorithms([["md5"], ["sha1"], ["md5"]]) == ["md5", "sha1"]

    def test_verify_none_means_fastest(self):
        assert simple_mhl.combine_verify_algorithms(None) is None

    def test_verify_flattens_and_dedups_in_order(self):
        assert simple_mhl.combine_verify_algorithms([["md5"], ["sha1"], ["md5"]]) == ["md5", "sha1"]

    def test_verify_all_supersedes(self):
        assert simple_mhl.combine_verify_algorithms([["md5"], "all"]) == VERIFY_ALL


class TestSealSizeOnlyFlag:
    """`seal -S` is an alias for `seal -a null` (record sizes, no digest)."""

    def test_size_only_records_null_no_digest(self, mhl_cli, tmp_path):
        make_tree(tmp_path, {"a.txt": b"hello"})
        rc, _, _ = mhl_cli(["seal", "-S", str(tmp_path)])
        assert rc == 0
        mhl = next(tmp_path.glob("*.mhl"))
        xml = mhl.read_text()
        assert "<null>" in xml
        assert "<size>5</size>" in xml
        assert "xxhash" not in xml
        assert "<md5>" not in xml

    def test_size_only_resolves_to_same_algorithms_as_a_null(self):
        # -S injects a [["null"]] group; parsing `-a null` yields the same list,
        # so both drive the seal engine with exactly ["null"].
        assert simple_mhl.combine_seal_algorithms([["null"]]) == simple_mhl.combine_seal_algorithms(
            [simple_mhl.parse_algorithms("null")]
        )

    def test_size_only_combined_with_real_algorithm_errors(self, mhl_cli, tmp_path):
        make_tree(tmp_path, {"a.txt": b"hello"})
        rc, _, err = mhl_cli(["seal", "-S", "-a", "md5", str(tmp_path)])
        assert rc == 2
        assert "'null' cannot be combined" in err


class TestParseVerifyAlgorithms:
    """
    The verify -a comma-list parser (accepts the 'all' keyword, dedups by tag).
    """

    def test_all_keyword_supersedes(self):
        assert simple_mhl.parse_verify_algorithms("md5,all") is VERIFY_ALL

    def test_dedup_by_tag_first_wins(self):
        # xxhash and xxh64 both canonicalise to xxhash64be; only the first survives.
        assert simple_mhl.parse_verify_algorithms("xxhash,xxh64") == ["xxhash64be"]

    def test_empty_raises(self):
        with pytest.raises(argparse.ArgumentTypeError):
            simple_mhl.parse_verify_algorithms(" , ")

    def test_unknown_raises(self):
        with pytest.raises(argparse.ArgumentTypeError):
            simple_mhl.parse_verify_algorithms("blake2")


class TestVerifyWrapperBadAlgorithm:
    """verify() maps a verify_classic ValueError (bad algorithm) to exit 2."""

    def test_unsupported_algorithm_exits_2(self, tmp_path, capsys):
        mhl = make_multi_hash_mhl(tmp_path, "a.bin", b"hello", {"md5": "0" * 32})
        with pytest.raises(SystemExit) as exc:
            simple_mhl.verify(str(mhl), algorithm="blake2")
        assert exc.value.code == 2
        assert "unsupported algorithm" in capsys.readouterr().err


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


class TestVerifyAfterFormDrift:
    """
    A sealed name whose normalization form drifts on disk (HFS+ round-trip,
    normalizing copy tool) still verifies via the gated NFC-equivalence fallback
    — simulated with an in-place rename to the equivalent byte form. Names are
    explicit escapes: a source literal's byte form is host-dependent.
    """

    _NFC = "ros\u00e9.txt"
    _NFD = "rose\u0301.txt"

    def test_verify_passes_after_normalization_drift(self, mhl_cli, tmp_path):
        (tmp_path / self._NFC).write_bytes(b"payload")
        (tmp_path / "plain.txt").write_bytes(b"control")
        rc, _, _ = mhl_cli(["seal", str(tmp_path), "-a", "md5"])
        assert rc == 0

        os.rename(tmp_path / self._NFC, tmp_path / self._NFD)
        if self._NFD not in os.listdir(tmp_path):
            pytest.skip("host filesystem does not preserve the renamed normalization form")

        mhl = next(tmp_path.glob("*.mhl"))
        rc, _, err = mhl_cli(["verify", str(mhl)])
        assert (rc, err) == (0, "")
