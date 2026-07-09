"""
Tests for mhl_suite.osutils — friendly_hostname and resolve_on_disk.

The CLI wiring that consumes the resolver (the "did you mean" not-found hint)
lives with the CLI tests; the resolver tests here pin it against a simulated
normalization-sensitive filesystem.
"""

import os
import unicodedata

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
        """scutil output must be decoded as UTF-8, not via the (possibly ASCII)
        locale — otherwise a ComputerName with a curly apostrophe, accent, or
        emoji would raise UnicodeDecodeError under LANG=C. A non-ASCII name
        must round-trip intact."""
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
        """On Windows, forward slashes are rewritten to backward slashes for display."""
        monkeypatch.setattr(osutils.os, "sep", "\\")
        assert osutils.to_terminal_sep("[OK] sub/b.bin") == "[OK] sub\\b.bin"

    def test_noop_where_separator_is_already_slash(self, monkeypatch):
        """Where os.sep is already '/', the text is returned unchanged."""
        monkeypatch.setattr(osutils.os, "sep", "/")
        assert osutils.to_terminal_sep("[OK] sub/b.bin") == "[OK] sub/b.bin"


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
        """When an intermediate component is not a scannable directory, scandir
        raises OSError and resolution returns None (treated as missing)."""
        # 'sub' exists as a leaf (file), so scandir(base/sub) raises OSError.
        self._patch(monkeypatch, {self._BASE, os.path.join(self._BASE, "sub")})
        assert osutils.resolve_on_disk(self._BASE, os.path.join("sub", "child.txt"), {}) is None

    def test_empty_and_curdir_components_are_skipped(self, monkeypatch):
        """Leading './' and doubled separators yield empty / os.curdir path
        components, which must be skipped without affecting resolution."""
        leaf = os.path.join(self._BASE, "text.txt")
        self._patch(monkeypatch, {self._BASE, leaf})
        # rel_path like "./text.txt" → split gives [os.curdir, "text.txt"].
        rel = os.curdir + os.sep + "text.txt"
        assert osutils.resolve_on_disk(self._BASE, rel, {}) == leaf

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
        r1 = osutils.resolve_on_disk(self._BASE, os.path.join(self._NFC, "a.txt"), index)
        r2 = osutils.resolve_on_disk(self._BASE, os.path.join(self._NFC, "b.txt"), index)
        assert r1 == f1
        assert r2 == f2
        assert calls == [self._BASE]  # scanned once; leaves hit the literal fast path
