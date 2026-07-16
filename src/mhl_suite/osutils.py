"""
Cross-platform OS / filesystem helpers.

Portable wrappers over platform-specific quirks, shared by both simple_mhl
(classic MHL verify/seal) and mhlver (the orchestrator) so the two tools cannot
drift. Not part of the public API — the public surface of mhl-suite is the
simple-mhl and mhlver CLIs.

The concerns that live here:
  * Host identity — friendly_hostname(): the human-facing machine name.
  * Seal context — seal_context(): the OS and source-volume facts a seal
    records into its manifest (name-form provenance).
  * Unicode path resolution — resolve_on_disk() /
    normalization_variant_on_disk() / colliding_identity_groups(): reconciling
    NFC/NFD filenames across normalization-sensitive filesystems.
  * Terminal display — to_terminal_sep(): the one place manifest paths are
    rendered with the platform separator; supports_color(): whether ANSI colour
    should be written to a given stream.
"""

import functools
import os
import platform
import subprocess
import sys
import unicodedata
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Iterable

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
# Seal context
#
# OS and source-volume facts a seal records alongside its hashes. The recorded
# byte form of a filename is only as meaningful as the filesystem that reported
# it — e.g. the macOS 26 FSKit exFAT driver reports composable names (é-class)
# in its own decomposed dialect whichever form is on disk, though singleton
# codepoints such as U+212B pass through verbatim, while ext4 reports literal
# disk bytes — so the manifest carries where its paths came from. Best effort
# throughout: a field that cannot be determined is omitted, and nothing here
# may abort a seal.
# -----------------------------------------------------------------------------


def seal_context(path: str) -> dict[str, str]:
    """
    The seal-context fields for the volume holding `path`, in recording order:
    'os' (marketing name and version), 'kernel' (uname system + release),
    'filesystem' (the volume's filesystem type as mounted, lowercase — the
    protocol name for network/shared mounts, e.g. "smbfs"), and on macOS
    'driver' ("fskit" when the volume is mounted through an FSKit module —
    the driver generation is part of name provenance, since each ships its
    own Unicode handling).

    Classic seals flatten this into the creatorinfo <log> line; ASC-MHL seals
    record it as a namespaced element in the hashlist <metadata> slot.
    """
    context: dict[str, str] = {}
    system = platform.system()
    if system == "Darwin":
        context["os"] = f"macOS {platform.mac_ver()[0]}".strip()
    elif system == "Windows":
        context["os"] = f"Windows {platform.release()}".strip()
    elif system == "Linux":
        try:
            context["os"] = platform.freedesktop_os_release().get("PRETTY_NAME") or "Linux"
        except OSError:
            context["os"] = "Linux"
    elif system:
        context["os"] = system
    if system:
        context["kernel"] = f"{system} {platform.release()}".strip()
    filesystem, mount_point = _volume_filesystem(path)
    if filesystem:
        context["filesystem"] = filesystem.lower()
    if sys.platform == "darwin" and mount_point and _is_fskit_mount(mount_point):
        context["driver"] = "fskit"
    return context


def _volume_filesystem(path: str) -> "tuple[str | None, str | None]":
    """(filesystem type, mount point) of the volume holding `path`, best effort."""
    try:
        if sys.platform == "darwin":
            return _statfs_typename_darwin(path)
        if os.name == "nt":
            return _volume_info_windows(path)
        if sys.platform.startswith("linux"):
            return _proc_mounts_linux(path)
    except (OSError, ValueError, AttributeError):
        pass
    return None, None


def _statfs_typename_darwin(path: str) -> "tuple[str | None, str | None]":
    """f_fstypename and f_mntonname from statfs(2) — the API `mount` itself uses."""
    import ctypes  # noqa: PLC0415 — platform-specific, imported only on the branch that needs it

    class Statfs(ctypes.Structure):
        # struct statfs, sys/mount.h (64-bit inode layout, the only one on
        # current macOS; MFSTYPENAMELEN=16, MAXPATHLEN=1024).
        _fields_ = [
            ("f_bsize", ctypes.c_uint32),
            ("f_iosize", ctypes.c_int32),
            ("f_blocks", ctypes.c_uint64),
            ("f_bfree", ctypes.c_uint64),
            ("f_bavail", ctypes.c_uint64),
            ("f_files", ctypes.c_uint64),
            ("f_ffree", ctypes.c_uint64),
            ("f_fsid", ctypes.c_int32 * 2),
            ("f_owner", ctypes.c_uint32),
            ("f_type", ctypes.c_uint32),
            ("f_flags", ctypes.c_uint32),
            ("f_fssubtype", ctypes.c_uint32),
            ("f_fstypename", ctypes.c_char * 16),
            ("f_mntonname", ctypes.c_char * 1024),
            ("f_mntfromname", ctypes.c_char * 1024),
            ("f_flags_ext", ctypes.c_uint32),
            ("f_reserved", ctypes.c_uint32 * 7),
        ]

    libc = ctypes.CDLL(None, use_errno=True)
    # x86_64 exposes the 64-bit-inode variant under a decorated symbol;
    # arm64 has only the plain name.
    statfs = getattr(libc, "statfs$INODE64", None) or libc.statfs
    buf = Statfs()
    if statfs(os.fsencode(os.path.abspath(path)), ctypes.byref(buf)) != 0:
        return None, None
    return buf.f_fstypename.decode("ascii", "replace") or None, os.fsdecode(buf.f_mntonname) or None


def _proc_mounts_linux(path: str) -> "tuple[str | None, str | None]":
    """Filesystem type from /proc/self/mounts, by longest mount-point prefix."""
    real = os.path.realpath(path)
    best_mount, best_type = "", None
    with open("/proc/self/mounts", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                _device, mount, fstype = line.split()[:3]
            except ValueError:
                continue
            # The kernel octal-escapes whitespace and backslashes in mount points.
            mount = mount.replace("\\040", " ").replace("\\011", "\t").replace("\\134", "\\")
            if (real == mount or real.startswith(mount.rstrip("/") + "/")) and len(mount) > len(best_mount):
                best_mount, best_type = mount, fstype
    return best_type, best_mount or None


def _volume_info_windows(path: str) -> "tuple[str | None, str | None]":
    """Filesystem name from GetVolumeInformationW on the path's volume root."""
    if os.name != "nt":  # caller-checked; repeated here so windll narrows
        return None, None
    import ctypes  # noqa: PLC0415 — platform-specific, imported only on the branch that needs it

    kernel32 = ctypes.windll.kernel32  # windll is Windows-only
    root = ctypes.create_unicode_buffer(261)
    if not kernel32.GetVolumePathNameW(os.path.abspath(path), root, 261):
        return None, None
    name = ctypes.create_unicode_buffer(64)
    if not kernel32.GetVolumeInformationW(root, None, 0, None, None, None, name, 64):
        return None, root.value or None
    return name.value or None, root.value or None


def _is_fskit_mount(mount_point: str) -> bool:
    """
    True when the macOS mount table lists the volume with the `fskit` option —
    e.g. `/dev/disk6s1 on /Volumes/CARD (exfat, local, ..., fskit, mounted by
    tash)`. The distinction matters for name provenance: the FSKit and kext
    generations of the same filesystem driver render Unicode names differently.
    """
    marker = f" on {mount_point} ("
    for line in _mount_table().splitlines():
        if marker in line:
            options = line.rsplit("(", 1)[-1].rstrip(")")
            return "fskit" in {opt.strip() for opt in options.split(",")}
    return False


def _mount_table() -> str:
    """The `mount` listing, fetched once per process (see _cached_mount_table)."""
    return _cached_mount_table()


@functools.lru_cache(maxsize=1)
def _cached_mount_table() -> str:
    try:
        return subprocess.run(
            ["/sbin/mount"],
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=True,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


# -----------------------------------------------------------------------------
# Filesystem path resolution across Unicode normalization forms
#
# Background: filesystems disagree on Unicode normalization. HFS+ forces a
# decomposed (NFD-ish) form; APFS/NTFS-upcase are normalization-*insensitive*
# but byte-preserving; exFAT/ext4 (default)/NTFS are normalization-*sensitive*,
# so "rosé"-NFC and "rosé"-NFD are distinct entries. A path that visually
# matches may therefore fail a byte-exact lookup. These helpers match on NFC
# while only ever opening names that actually exist on disk — and only when the
# match is unambiguous: if several coexisting entries share one NFC identity, no
# fallback is attempted, because any pick would be a guess.
# -----------------------------------------------------------------------------


def colliding_identity_groups(rel_paths: "Iterable[str]") -> "list[list[str]]":
    """
    Groups of paths that share one NFC canonical identity — names that a
    normalization-insensitive filesystem (or any normalizing tool) cannot tell
    apart. Such pairs coexist only on normalization-sensitive volumes; sealing
    them would record entries that verify cannot unambiguously match back to
    disk, and that silently merge or overwrite on the first copy to APFS/HFS+. A
    group can also be two byte-identical paths: a damaged exFAT directory can
    list one name twice, in which case one of the two entries' data is
    unreachable. Sealers abort when any group has more than one member.
    """
    by_identity: dict[str, list[str]] = {}
    for rel in rel_paths:
        by_identity.setdefault(unicodedata.normalize("NFC", rel), []).append(rel)
    return [group for group in by_identity.values() if len(group) > 1]


def resolve_on_disk(
    base: str,
    rel_path: str,
    dir_index: "dict[str, dict[str, str | None]]",
    allow_fallback: bool = True,
) -> str | None:
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

    The fallback fires only when it cannot guess wrong. If two real entries in
    one directory share an NFC identity, that identity maps to ``None`` in the
    index and never matches — reporting the byte form as missing is a plain
    fact, silently picking one of two equivalent entries is not. Callers pass
    ``allow_fallback=False`` when the *looked-up* side is equally ambiguous
    (two manifest records sharing one identity), which restricts resolution to
    literal bytes for every component.

    ``dir_index`` caches each scanned directory as ``{ NFC(name): real_name }``
    (``None`` marking ambiguous identities) so a manifest with many files in
    one folder scans that folder only once. It is passed in (not module-global)
    so each ``verify()`` call sees a fresh view of the filesystem rather than a
    stale listing from a previous run.
    """
    current = base
    for comp in rel_path.split(os.sep):
        if not comp or comp == os.curdir:
            continue
        literal = os.path.join(current, comp)
        if os.path.lexists(literal):
            current = literal  # fast path: exact bytes exist on disk
            continue
        if not allow_fallback:
            return None  # byte-exact resolution only
        index = dir_index.get(current)
        if index is None:
            index = {}
            try:
                for entry in os.scandir(current):
                    key = unicodedata.normalize("NFC", entry.name)
                    index[key] = None if key in index else entry.name
            except OSError:
                return None  # current dir unreadable/absent → file is missing
            dir_index[current] = index
        real = index.get(unicodedata.normalize("NFC", comp))
        if real is None:
            return None  # absent, or ambiguous across coexisting forms
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
