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
    rendered with the platform separator; supports_color(): whether ANSI colour
    should be written to a given stream.
"""

import os
import platform
import subprocess
import sys
import unicodedata
from typing import Protocol

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


# Windows console handle IDs, keyed by the POSIX fd the stream wraps.
_STD_HANDLE_BY_FD = {1: -11, 2: -12}  # STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
_ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004


class TerminalStream(Protocol):
    """
    Structural type for the stream the colour check inspects.

    Typing against the two methods actually called, rather than the concrete
    TextIO, keeps the annotation honest about what is required and lets test
    doubles conform without an Any escape hatch. sys.stdout / sys.stderr satisfy
    it as they are.
    """

    def isatty(self) -> bool: ...

    def fileno(self) -> int: ...


def _enable_ansi(stream: TerminalStream) -> bool:
    """Enable ANSI escape processing for `stream` on Windows 10+; a no-op on Unix.

    Flips ENABLE_VIRTUAL_TERMINAL_PROCESSING on the stream's console handle so
    VT-aware terminals render colour rather than echoing the escape sequences.
    Returns True when ANSI is usable: always on Unix; on Windows only if the
    stream is one of the two standard handles and the console mode call succeeds.
    """
    if os.name != "nt":
        return True
    try:
        import ctypes  # noqa: PLC0415 — Windows-only import, skipped entirely on Unix

        handle_id = _STD_HANDLE_BY_FD.get(stream.fileno())
        if handle_id is None:
            return False
        kernel32 = ctypes.windll.kernel32  # windll is Windows-only
        handle = kernel32.GetStdHandle(handle_id)
        mode = ctypes.c_ulong()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        kernel32.SetConsoleMode(handle, mode.value | _ENABLE_VIRTUAL_TERMINAL_PROCESSING)
        return True
    except (AttributeError, OSError, ValueError):  # no console attached, missing DLL, detached stream
        return False


def supports_color(stream: TerminalStream) -> bool:
    """True when ANSI colour should be written to `stream`.

    Follows the NO_COLOR / FORCE_COLOR conventions (https://no-color.org): a
    non-empty NO_COLOR disables colour, else a non-empty FORCE_COLOR forces it,
    else colour is used when the stream is a TTY and ANSI is available. Only a
    non-empty value counts, so NO_COLOR="" leaves the decision to the TTY check.

    Evaluated per call rather than cached at import so the environment is read
    at the point of output, which also keeps it patchable from tests.
    """
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return stream.isatty() and _enable_ansi(stream)
    except Exception:  # noqa: BLE001 — the stream may be closed or replaced; stay monochrome
        return False


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
