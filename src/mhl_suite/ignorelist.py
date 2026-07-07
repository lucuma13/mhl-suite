"""
OS-junk ignore list.

The set of OS-generated names that should never be sealed in a manifest.

These files/dirs are rewritten by the system on its own (Finder, Spotlight, Time
Machine, Windows Explorer) or back the filesystem itself. Hashing them would
make a later `verify` fail with spurious mismatches and "new file" reports every
time the OS touches them.

Matched case-sensitively against the exact-name set, or by prefix — the OS
always writes these names with fixed casing, so an exact match can never drop a
user file that differs only in case. Two macOS names carry a trailing carriage
return as a literal byte in the on-disk name — the custom-folder "Icon\\r" and
the HFS+ private hard-link directory — so they appear here with that '\\r'.
"""

OS_JUNK_NAMES = frozenset(
    {
        # Per-folder cruft (can appear anywhere)
        ".DS_Store",
        ".localized",
        ".AppleDouble",  # Netatalk/AFP resource-fork store (NAS shares)
        ".LSOverride",
        "Icon\r",  # Finder custom-folder icon; note the trailing CR
        "Thumbs.db",  # Windows
        # Volume-root items (appear when sealing a whole drive)
        ".DocumentRevisions-V100",
        ".fseventsd",
        ".Spotlight-V100",
        ".TemporaryItems",
        ".Trashes",
        ".VolumeIcon.icns",
        ".com.apple.timemachine.donotpresent",
        ".com.apple.timemachine.supported",
        ".PKInstallSandboxManager",
        ".PKInstallSandboxManager-SystemSoftware",
        ".hotfiles.btree",
        ".vol",
        ".file",
        "lost+found",
        ".HFS+ Private Directory Data\r",  # HFS+ hard-link backing dir; note the CR
    }
)

# macOS '._' AppleDouble resource forks (._MyClip.mov mirror the real name) and
# the boot '.disk_label' / '.disk_label_2x' images — matched by prefix.
OS_JUNK_PREFIXES = ("._", ".disk_label")


def is_os_junk(name: str) -> bool:
    """True if `name` is OS-generated metadata that should never be sealed."""
    return name.startswith(OS_JUNK_PREFIXES) or name in OS_JUNK_NAMES
