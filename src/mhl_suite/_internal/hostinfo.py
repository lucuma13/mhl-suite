# -----------------------------------------------------------------------------
# Host identity.
#
# Shared internal helper used by both simple_mhl (the <hostname> in a manifest's
# creatorinfo block) and mhlver (the Host field in a verification report). Kept
# in one place so the two tools report the same machine name and cannot drift.
# Not part of the public API.
# -----------------------------------------------------------------------------

import platform
import subprocess
import sys


def friendly_hostname() -> str:
    """The human-facing machine name, matching what other media tools (e.g.
    ShotPut Pro) record. On macOS that's the 'ComputerName' from System
    Settings ("Luis's MacBook Pro"), not the network hostname platform.node()
    returns ("Mac"). Falls back to platform.node() off macOS or if the lookup
    fails for any reason.
    """
    if sys.platform == "darwin":
        try:
            # scutil emits UTF-8 from the dynamic store regardless of locale.
            # Decode it as such (not via the locale, which is ASCII under
            # LANG=C — common in cron/SSH) so a ComputerName with a curly
            # apostrophe, accent, or emoji can't raise UnicodeDecodeError.
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
