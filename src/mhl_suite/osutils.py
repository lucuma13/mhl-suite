"""
Cross-platform OS / filesystem helpers.

Portable wrappers over platform-specific quirks, shared by both simple_mhl
(classic MHL verify/seal) and mhlver (the orchestrator) so the two tools cannot
drift. Not part of the public API — the public surface of mhl-suite is the
simple-mhl and mhlver CLIs.

Two concerns live here:
  * Host identity — friendly_hostname(): the human-facing machine name.
  * Unicode path resolution — resolve_on_disk() /
    normalization_variant_on_disk(): reconciling NFC/NFD filenames across
    normalization-sensitive filesystems.
  * Terminal display — to_terminal_sep(): the one place manifest paths are
    rendered with the platform separator.
"""

import os
import platform
import subprocess
import sys
import unicodedata

# -----------------------------------------------------------------------------
# Terminal display
#
# Internally every path is the canonical forward-slash form. The terminal is the
# one place we show the operator their platform's native separator. Shared by
# both CLIs so the same manifest verified either way shows the same separators.
# -----------------------------------------------------------------------------


def to_terminal_sep(text: str) -> str:
    """Convert forward slashes to the platform separator for terminal display; a no-op where os.sep is already '/'."""
    return text.replace("/", os.sep) if os.sep != "/" else text


# -----------------------------------------------------------------------------
# Host identity
#
# Shared by simple_mhl (the <hostname> in a manifest's creatorinfo block) and
# mhlver (the Host field in a verification report). Kept in one place so the two
# tools report the same machine name and cannot drift.
# -----------------------------------------------------------------------------


def friendly_hostname() -> str:
    """
    The human-facing machine name, matching what other media tools (e.g. ShotPut
    Pro) record. On macOS that's the 'ComputerName' from System Settings
    ("Luis's MacBook Pro"), not the network hostname platform.node() returns
    ("Mac"). Falls back to platform.node() off macOS or if the lookup fails for
    any reason.
    """
    if sys.platform == "darwin":
        try:
            # scutil emits UTF-8 from the dynamic store regardless of locale.
            # Decode it as such (not via the locale, which is ASCII under LANG=C
            # — common in cron/SSH) so a ComputerName with a curly apostrophe,
            # accent, or emoji can't raise UnicodeDecodeError.
            name = subprocess.run(
                ["/usr/sbin/scutil", "--get", "ComputerName"],
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=5,
                check=True,
            ).stdout.strip()
            if name:
                return name
        except (OSError, subprocess.SubprocessError):
            pass
    return platform.node() or "unknown"


# -----------------------------------------------------------------------------
# Filesystem path resolution across Unicode normalization forms
#
# Background: filesystems disagree on Unicode normalization. HFS+ forces a
# decomposed (NFD-ish) form; APFS/NTFS-upcase are normalization-*insensitive*
# but byte-preserving; exFAT/ext4 (default)/NTFS are normalization-*sensitive*,
# so "rosé"-NFC and "rosé"-NFD are distinct entries. A path that visually
# matches may therefore fail a byte-exact lookup. These helpers match on NFC
# while only ever opening names that actually exist on disk.
# -----------------------------------------------------------------------------


def resolve_on_disk(base: str, rel_path: str, dir_index: dict[str, dict[str, str]]) -> str | None:
    """
    Resolve a manifest-relative path to its real on-disk path, matching across
    Unicode normalization forms.

    Walks ``rel_path`` one component at a time from ``base``. Each component is
    tried as literal bytes first — the common case, and the only correct choice
    when several normalization forms coexist on a normalization-*sensitive*
    filesystem (exFAT/ext4/NTFS), where ``rosé``-NFC and ``rosé``-NFD are
    distinct entries. On a literal miss we scan the directory once and match the
    component's NFC form against the NFC form of each real entry, so a name
    stored in a different form (e.g. an NFD name from an HFS+ round-trip, looked
    up from an NFC manifest) still resolves. Returns the real absolute path, or
    ``None`` if any component is genuinely absent.

    ``dir_index`` caches each scanned directory as ``{ NFC(name): real_name }``
    so a manifest with many files in one folder scans that folder only once. It
    is passed in (not module-global) so each ``verify()`` call sees a fresh view
    of the filesystem rather than a stale listing from a previous run.
    """
    current = base
    for comp in rel_path.split(os.sep):
        if not comp or comp == os.curdir:
            continue
        literal = os.path.join(current, comp)
        if os.path.lexists(literal):
            current = literal  # fast path: exact bytes exist on disk
            continue
        index = dir_index.get(current)
        if index is None:
            try:
                index = {unicodedata.normalize("NFC", entry.name): entry.name for entry in os.scandir(current)}
            except OSError:
                return None  # current dir unreadable/absent → file is missing
            dir_index[current] = index
        real = index.get(unicodedata.normalize("NFC", comp))
        if real is None:
            return None  # no entry matches in any normalization form
        current = os.path.join(current, real)
    return current


def normalization_variant_on_disk(path: str) -> str | None:
    """
    If ``path`` does not exist as typed but a Unicode-normalization variant of
    it does, return that real on-disk path; otherwise None.

    Used purely to add a "did you mean" hint to not-found errors for paths a
    user types on the command line (e.g. the .mhl for verify, the root dir for
    seal, or the target for mhlver). It never changes what a command operates on
    — unlike a manifest's internal <file> entries (a portable artifact authored
    elsewhere, which we actively reconcile), the typed path is a local,
    interactive reference, so we leave matching to the OS and only *suggest* the
    real spelling. This keeps behaviour aligned with cat/cp/ls instead of
    silently resolving a path they cannot open.
    """
    abspath = os.path.abspath(path)
    drive, tail = os.path.splitdrive(abspath)
    rel = tail.lstrip(os.sep)
    if not rel:
        return None
    resolved = resolve_on_disk(drive + os.sep, rel, {})
    return resolved if resolved is not None and resolved != abspath else None
