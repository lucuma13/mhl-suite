"""
Tests for mhl_suite.osutils — friendly_hostname, supports_color and resolve_on_disk.

The CLI wiring that consumes the resolver (the "did you mean" not-found hint)
lives with the CLI tests; the resolver tests here pin it against a simulated
normalization-sensitive filesystem.
"""

import os
import unicodedata

import pytest

from mhl_suite import classic_seal as core_seal
from mhl_suite import osutils

from .helpers import _sensitive_fs


class TestFriendlyHostname:
    """
    friendly_hostname prefers the macOS ComputerName, with fallbacks. Shared by
    simple_mhl (manifest <hostname>) and mhlver (report Host field).
    """

    def test_macos_uses_computer_name(self, monkeypatch):
        """On macOS the user-facing ComputerName from scutil is preferred over
        the bare network hostname."""
        monkeypatch.setattr(osutils.sys, "platform", "darwin")
        completed = osutils.subprocess.CompletedProcess(args=[], returncode=0, stdout="Luis's MacBook Pro\n", stderr="")
        monkeypatch.setattr(osutils.subprocess, "run", lambda *a, **kw: completed)
        assert osutils.friendly_hostname() == "Luis's MacBook Pro"

    def test_macos_falls_back_to_node_when_scutil_fails(self, monkeypatch):
        """If scutil is missing or errors, fall back to platform.node()."""
        monkeypatch.setattr(osutils.sys, "platform", "darwin")
        monkeypatch.setattr(osutils.subprocess, "run", lambda *a, **kw: (_ for _ in ()).throw(OSError()))
        monkeypatch.setattr(osutils.platform, "node", lambda: "fallback-host")
        assert osutils.friendly_hostname() == "fallback-host"

    def test_macos_blank_computer_name_falls_back_to_node(self, monkeypatch):
        """An empty ComputerName (scutil succeeds but the value is unset) is
        ignored, falling through to platform.node() rather than returning ''."""
        monkeypatch.setattr(osutils.sys, "platform", "darwin")
        completed = osutils.subprocess.CompletedProcess(args=[], returncode=0, stdout="\n", stderr="")
        monkeypatch.setattr(osutils.subprocess, "run", lambda *a, **kw: completed)
        monkeypatch.setattr(osutils.platform, "node", lambda: "fallback-host")
        assert osutils.friendly_hostname() == "fallback-host"

    def test_non_macos_uses_node(self, monkeypatch):
        """Off macOS, platform.node() is used directly (FQDN preserved)."""
        monkeypatch.setattr(osutils.sys, "platform", "linux")
        monkeypatch.setattr(osutils.platform, "node", lambda: "nas01.studio.local")
        assert osutils.friendly_hostname() == "nas01.studio.local"

    def test_empty_node_falls_back_to_unknown(self, monkeypatch):
        """A blank platform.node() (minimal containers) yields a stable label."""
        monkeypatch.setattr(osutils.sys, "platform", "linux")
        monkeypatch.setattr(osutils.platform, "node", lambda: "")
        assert osutils.friendly_hostname() == "unknown"

    def test_scutil_decoded_as_utf8_regardless_of_locale(self, monkeypatch):
        """
        scutil output must be decoded as UTF-8, not via the (possibly ASCII)
        locale — otherwise a ComputerName with a curly apostrophe, accent, or
        emoji would raise UnicodeDecodeError under LANG=C. A non-ASCII name must
        round-trip intact.
        """
        captured: dict = {}

        def fake_run(*a, **kw):
            captured.update(kw)
            return osutils.subprocess.CompletedProcess(
                args=[], returncode=0, stdout="Jos\u00e9\u2019s iMac \U0001f3ac\n", stderr=""
            )

        monkeypatch.setattr(osutils.sys, "platform", "darwin")
        monkeypatch.setattr(osutils.subprocess, "run", fake_run)
        assert osutils.friendly_hostname() == "Jos\u00e9\u2019s iMac \U0001f3ac"
        assert captured.get("encoding") == "utf-8"
        assert captured.get("errors") == "replace"

    def test_creatorinfo_uses_friendly_hostname(self, monkeypatch):
        """
        The manifest's creatorinfo <hostname> is sourced from the shared helper,
        not the bare network hostname.
        """
        monkeypatch.setattr(core_seal, "friendly_hostname", lambda: "Luis's MacBook Pro")
        info = core_seal._creatorinfo_element("simple-mhl test", "2026-01-01T00:00:00Z")
        assert info.findtext("hostname") == "Luis's MacBook Pro"


class TestToTerminalSep:
    """
    to_terminal_sep renders the canonical forward-slash path with the platform
    separator — the one place we leave the forward-slash form. Both CLIs route
    terminal output through it, so the same manifest shows the same separators
    whichever tool verified it.
    """

    def test_forward_slashes_become_native_separator(self, monkeypatch):
        """
        On Windows, forward slashes are rewritten to backward slashes for
        display.
        """
        monkeypatch.setattr(osutils.os, "sep", "\\")
        assert osutils.to_terminal_sep("[OK] sub/b.bin") == "[OK] sub\\b.bin"

    def test_noop_where_separator_is_already_slash(self, monkeypatch):
        """Where os.sep is already '/', the text is returned unchanged."""
        monkeypatch.setattr(osutils.os, "sep", "/")
        assert osutils.to_terminal_sep("[OK] sub/b.bin") == "[OK] sub/b.bin"


class FakeStream:
    """A TerminalStream double: a TTY or not, with an optionally exploding isatty."""

    def __init__(self, *, tty: bool = True, isatty_raises: bool = False):
        self._tty = tty
        self._isatty_raises = isatty_raises

    def isatty(self) -> bool:
        if self._isatty_raises:
            raise ValueError("I/O operation on closed file")
        return self._tty

    def fileno(self) -> int:
        return 1


class TestSupportsColor:
    """
    supports_color decides whether ANSI codes reach a stream. It is the suite's
    single answer to that question, so a piped run stays free of escape
    sequences and the operator's NO_COLOR / FORCE_COLOR is honoured everywhere.
    """

    @pytest.mark.parametrize(
        ("env", "tty", "expected"),
        [
            ({}, True, True),
            ({}, False, False),
            ({"NO_COLOR": "1"}, True, False),
            ({"FORCE_COLOR": "1"}, False, True),
            ({"NO_COLOR": "1", "FORCE_COLOR": "1"}, True, False),  # NO_COLOR wins
            ({"NO_COLOR": ""}, True, True),  # the convention: only a non-empty value counts
        ],
    )
    def test_follows_no_color_and_force_color(self, monkeypatch, env, tty, expected):
        """
        no-color.org: NO_COLOR disables, FORCE_COLOR forces, otherwise the TTY
        decides.
        """
        for var in ("NO_COLOR", "FORCE_COLOR"):
            monkeypatch.delenv(var, raising=False)
        for var, value in env.items():
            monkeypatch.setenv(var, value)
        monkeypatch.setattr(osutils, "_enable_ansi", lambda stream: True)
        assert osutils.supports_color(FakeStream(tty=tty)) is expected

    def test_false_when_ansi_cannot_be_enabled(self, monkeypatch):
        """
        A TTY that will not take VT processing (an old Windows console) stays
        monochrome.
        """
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        monkeypatch.setattr(osutils, "_enable_ansi", lambda stream: False)
        assert osutils.supports_color(FakeStream(tty=True)) is False

    def test_false_when_isatty_raises(self, monkeypatch):
        """A closed or replaced stream must not take the caller down with it."""
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        assert osutils.supports_color(FakeStream(isatty_raises=True)) is False


class TestResolveOnDisk:
    """
    Unit tests for osutils.resolve_on_disk against a simulated
    normalization-sensitive filesystem.

    The host filesystem on dev machines (APFS) is normalization-*insensitive*
    and cannot host coexisting NFC + NFD entries, so the sensitive-FS behaviour
    — the entire reason the resolver exists — must be exercised with patched
    lexists/scandir rather than real files.
    """

    _BASE = os.path.join(os.sep, "vol")
    # Computed (not literal) so the distinct byte sequences survive any
    # source-file Unicode normalization: same NFC key, different on-disk forms.
    _NFC = unicodedata.normalize("NFC", "rosé")  # precomposed é (U+00E9)
    _NFD = unicodedata.normalize("NFD", "rosé")  # decomposed e + combining acute (U+0301)

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

        result = osutils.resolve_on_disk(self._BASE, os.path.join(self._NFC, "text.txt"), {})
        assert result == nfc_file
        assert calls == []  # never scanned

    def test_scenario3_nfc_query_resolves_to_nfd_on_disk(self, monkeypatch):
        """
        Scenario 3: NFC manifest path, NFD name on a sensitive filesystem. The
        literal NFC lookup misses; the NFC-keyed index resolves the real NFD
        entry.
        """
        nfd_file = os.path.join(self._BASE, self._NFD, "text.txt")
        self._patch(
            monkeypatch,
            {self._BASE, os.path.join(self._BASE, self._NFD), nfd_file},
        )
        result = osutils.resolve_on_disk(self._BASE, os.path.join(self._NFC, "text.txt"), {})
        assert result == nfd_file

    def test_scenario2_coexisting_forms_resolve_distinctly(self, monkeypatch):
        """
        Scenario 2: NFC and NFD rosé/ both exist (sensitive FS). Each query
        resolves to its own distinct directory via the literal fast path — the
        two forms never collapse onto one.
        """
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
        assert osutils.resolve_on_disk(self._BASE, os.path.join(self._NFC, "text.txt"), {}) == nfc_file
        assert osutils.resolve_on_disk(self._BASE, os.path.join(self._NFD, "text.txt"), {}) == nfd_file

    def test_intermediate_directory_normalization_mismatch(self, monkeypatch):
        """
        Normalization can differ on a non-leaf component: an ASCII parent, an
        NFD middle directory on disk addressed by an NFC manifest path, then an
        ASCII leaf. The resolver must reconcile the middle component.
        """
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
        result = osutils.resolve_on_disk(self._BASE, os.path.join("sub", self._NFC, "text.txt"), {})
        assert result == real_file

    def test_genuinely_missing_returns_none(self, monkeypatch):
        """A name that matches in no normalization form resolves to None."""
        self._patch(monkeypatch, {self._BASE, os.path.join(self._BASE, "other.txt")})
        assert osutils.resolve_on_disk(self._BASE, "ghost.txt", {}) is None

    def test_unreadable_directory_returns_none(self, monkeypatch):
        """
        When an intermediate component is not a scannable directory, scandir
        raises OSError and resolution returns None (treated as missing).
        """
        # 'sub' exists as a leaf (file), so scandir(base/sub) raises OSError.
        self._patch(monkeypatch, {self._BASE, os.path.join(self._BASE, "sub")})
        assert osutils.resolve_on_disk(self._BASE, os.path.join("sub", "child.txt"), {}) is None

    def test_empty_and_curdir_components_are_skipped(self, monkeypatch):
        """
        Leading './' and doubled separators yield empty / os.curdir path
        components, which must be skipped without affecting resolution.
        """
        leaf = os.path.join(self._BASE, "text.txt")
        self._patch(monkeypatch, {self._BASE, leaf})
        # rel_path like "./text.txt" → split gives [os.curdir, "text.txt"].
        rel = os.curdir + os.sep + "text.txt"
        assert osutils.resolve_on_disk(self._BASE, rel, {}) == leaf

    def test_dir_index_caches_scandir_per_directory(self, monkeypatch):
        """
        Two files in the same NFD directory, addressed via NFC, must scan that
        directory only once (cached in dir_index across resolutions).
        """
        f1 = os.path.join(self._BASE, self._NFD, "a.txt")
        f2 = os.path.join(self._BASE, self._NFD, "b.txt")
        existing = {self._BASE, os.path.join(self._BASE, self._NFD), f1, f2}
        lexists, real_scandir = _sensitive_fs(existing)
        calls: list[str] = []
        monkeypatch.setattr(os.path, "lexists", lexists)
        monkeypatch.setattr(os, "scandir", lambda d: calls.append(d) or real_scandir(d))

        index: dict[str, dict[str, str | None]] = {}
        r1 = osutils.resolve_on_disk(self._BASE, os.path.join(self._NFC, "a.txt"), index)
        r2 = osutils.resolve_on_disk(self._BASE, os.path.join(self._NFC, "b.txt"), index)
        assert r1 == f1
        assert r2 == f2
        assert calls == [self._BASE]  # scanned once; leaves hit the literal fast path

    def test_ambiguous_coexisting_equivalents_refuse_fallback(self, monkeypatch):
        """
        Two coexisting entries share one NFC identity — A+overring (U+00C5) and
        the Angstrom sign (U+212B), both NFC-normalizing to U+00C5. A third
        spelling of that identity must resolve to None: either pick would be a
        guess, and reporting the queried byte form as missing is a plain fact.
        Each coexisting form still resolves to itself via the literal path.
        """
        nfd_name = "A\u030a.txt"  # A + combining ring
        angstrom_name = "\u212b.txt"  # angstrom singleton
        nfc_query = "\u00c5.txt"  # precomposed Å — on disk in no form
        nfd_file = os.path.join(self._BASE, nfd_name)
        angstrom_file = os.path.join(self._BASE, angstrom_name)
        self._patch(monkeypatch, {self._BASE, nfd_file, angstrom_file})

        assert osutils.resolve_on_disk(self._BASE, nfc_query, {}) is None
        assert osutils.resolve_on_disk(self._BASE, nfd_name, {}) == nfd_file
        assert osutils.resolve_on_disk(self._BASE, angstrom_name, {}) == angstrom_file

    def test_allow_fallback_false_restricts_to_literal_bytes(self, monkeypatch):
        """
        allow_fallback=False (the record side of the lookup is ambiguous — two
        manifest records sharing one identity) must skip the equivalence scan
        entirely and miss, while the default still resolves the same query.
        """
        nfd_file = os.path.join(self._BASE, self._NFD, "text.txt")
        self._patch(monkeypatch, {self._BASE, os.path.join(self._BASE, self._NFD), nfd_file})
        rel = os.path.join(self._NFC, "text.txt")

        assert osutils.resolve_on_disk(self._BASE, rel, {}, allow_fallback=False) is None
        assert osutils.resolve_on_disk(self._BASE, rel, {}) == nfd_file


class TestSealContext:
    """
    seal_context gathers the OS/volume facts a seal records for name-form
    provenance. Platform probes are best effort — assertions here stay to
    what must hold on any supported host, plus unit tests of the macOS
    mount-table parse against canned output.
    """

    def test_host_facts_present_and_lowercase_filesystem(self, tmp_path):
        context = osutils.seal_context(str(tmp_path))
        assert context.get("os")
        assert context.get("kernel")
        # The filesystem probe works on every platform we ship for; the field
        # is normalized to lowercase (statfs and Windows disagree on casing).
        assert context.get("filesystem")
        assert context["filesystem"] == context["filesystem"].lower()

    def test_unresolvable_path_still_reports_host(self):
        context = osutils.seal_context(os.path.join(os.sep, "definitely", "not", "a", "path"))
        assert context.get("os")
        assert context.get("kernel")
        assert "filesystem" not in context

    def test_fskit_mount_detected_from_mount_table(self, monkeypatch):
        table = (
            "/dev/disk3s5 on /System/Volumes/Data (apfs, local, journaled, nobrowse)\n"
            "/dev/disk6s1 on /Volumes/CARD (exfat, local, nodev, nosuid, noatime, fskit, mounted by tash)\n"
        )
        monkeypatch.setattr(osutils, "_mount_table", lambda: table)
        assert osutils._is_fskit_mount("/Volumes/CARD") is True
        assert osutils._is_fskit_mount("/System/Volumes/Data") is False
        assert osutils._is_fskit_mount("/Volumes/ELSEWHERE") is False

    def test_fskit_flag_requires_exact_option_not_substring(self, monkeypatch):
        """A volume named like the flag must not trip the option match."""
        table = "/dev/disk9s1 on /Volumes/X (exfat, local, fskitten, mounted by tash)\n"
        monkeypatch.setattr(osutils, "_mount_table", lambda: table)
        assert osutils._is_fskit_mount("/Volumes/X") is False


class TestCollidingIdentityGroups:
    """
    colliding_identity_groups — the seal-time guard's core: names one NFC
    identity cannot tell apart must group together; everything else must not.
    Names are built from explicit escapes: a source-file literal's byte form is
    whatever the editor emitted, which is exactly the bug class under test.
    """

    _NFC = "ros\u00e9.txt"
    _NFD = "rose\u0301.txt"

    def test_equivalent_forms_group(self):
        groups = osutils.colliding_identity_groups([self._NFC, "plain.txt", self._NFD])
        assert groups == [[self._NFC, self._NFD]]

    def test_three_equivalent_spellings_one_group(self):
        """
        Precomposed Å, decomposed A+ring, and the U+212B singleton all share the
        identity U+00C5 — one group of three.
        """
        forms = ["\u00c5.txt", "A\u030a.txt", "\u212b.txt"]
        assert osutils.colliding_identity_groups(forms) == [forms]

    def test_byte_identical_duplicates_group(self):
        """
        A damaged exFAT directory can list one name twice — the same bytes twice
        is a collision too (one entry's data is unreachable).
        """
        assert osutils.colliding_identity_groups(["x.txt", "x.txt"]) == [["x.txt", "x.txt"]]

    def test_distinct_names_no_groups(self):
        assert osutils.colliding_identity_groups(["a.txt", "b.txt", self._NFC]) == []

    def test_collision_in_directory_component_groups_full_paths(self):
        """
        The identity is the whole relative path — equivalent directory spellings
        with the same leaf collide as full paths.
        """
        p1 = "ros\u00e9/clip.mov"
        p2 = "rose\u0301/clip.mov"
        assert osutils.colliding_identity_groups([p1, p2, "ros\u00e9/other.mov"]) == [[p1, p2]]
