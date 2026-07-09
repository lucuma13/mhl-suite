"""Portable PyPI update checker.

It checks PyPI for a newer release of the package and prints an upgrade
hint to stderr:

    Update available! Run: uv tool upgrade <package_name>

Features:
  - one-call CLI integration: hang the console-script entry point on
    ``run_with_update_check(package, version, run)``
  - the upgrade command is inferred from where the package lives on disk
    (uv tool, pipx, Homebrew, uv-managed or plain venv), defaulting to
    ``uv tool upgrade`` when unrecognized; pass ``upgrade_command`` to
    override
  - never crashes or slows down the host CLI: every failure is silent,
    and the network fetch runs in a daemon thread that is simply
    abandoned if it hasn't finished by the time notify() returns
  - at most one PyPI request per ``check_interval`` (result cached
    private-to-the-user in the platform cache dir; another fetch happens
    only once it expires)
  - the fetch identifies its sender, requests a gzip body, and caps the
    response size (raw and decompressed) against hostile/broken servers
  - hints only appear on interactive runs (stderr is a tty)
  - colour follows the NO_COLOR / FORCE_COLOR conventions (no-color.org)
  - opt out with <PACKAGE>_NO_UPDATE_CHECK=1, NO_UPDATE_CHECK=1, or in CI

"""
# Copyright (c) 2026 Luis Gómez Gutiérrez. License: MIT.

import itertools
import json
import os
import re
import sys
import threading
import time
import urllib.parse
import urllib.request
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

from packaging.version import InvalidVersion, Version

_DAY_SECONDS = 24 * 60 * 60.0

# Caps how much of a PyPI response is read (and decompressed) — a hostile or
# broken response must not balloon memory inside the host CLI. Must stay above
# the largest real PyPI JSON payload (a few MiB for huge packages).
_MAX_RESPONSE_BYTES = 16 * 1024 * 1024

_T = TypeVar("_T")


def _parse_version(version: str) -> Version | None:
    """Parse *version* per PEP 440, or None if it isn't a valid version.

    None means "cannot compare, stay quiet" — e.g. "unknown" from a dev
    install with no package metadata.
    """
    try:
        return Version(version)
    except InvalidVersion:
        return None


def _is_newer(latest: str, current: str) -> bool:
    """True if ``latest`` is a strictly higher release than ``current``.

    Full PEP 440 comparison. An unparsable version on either
    side yields False — a wrong hint is worse than no hint.
    """
    latest_v, current_v = _parse_version(latest), _parse_version(current)
    if latest_v is None or current_v is None:
        return False
    return latest_v > current_v


def _stderr_is_interactive() -> bool:
    """True when stderr is a terminal a human is looking at.

    Module-level so tests (and embedders) can override it — patching
    ``sys.stderr.isatty`` directly is unreliable under pytest's capture.
    """
    try:
        return sys.stderr.isatty()
    except Exception:  # noqa: BLE001 — stderr may be closed or replaced; stay quiet
        return False


ORANGE = "\033[38;5;208m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _enable_ansi_on_stderr() -> bool:
    """Enable ANSI escape processing for stderr on Windows 10+; no-op on Unix.

    Flips ``ENABLE_VIRTUAL_TERMINAL_PROCESSING`` on the stderr handle so
    VT-aware terminals render colour. Returns True when ANSI is usable
    (always on Unix; on Windows only if the console mode call succeeds).
    """
    if os.name != "nt":
        return True
    try:
        import ctypes  # noqa: PLC0415 — Windows-only import, skipped entirely on Unix

        kernel32 = ctypes.windll.kernel32  # windll is Windows-only
        handle = kernel32.GetStdHandle(-12)  # STD_ERROR_HANDLE
        mode = ctypes.c_ulong()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        return True
    except (AttributeError, OSError):  # no console attached, missing DLL, etc. — just skip colour
        return False


def _stderr_supports_color() -> bool:
    """True when ANSI colour should be used on stderr.

    Follows the NO_COLOR / FORCE_COLOR conventions (https://no-color.org): a
    non-empty NO_COLOR disables colour, else a non-empty FORCE_COLOR forces
    it, else colour is used when stderr is a TTY and ANSI is available.
    """
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        return sys.stderr.isatty() and _enable_ansi_on_stderr()
    except Exception:  # noqa: BLE001 — stderr may be closed or replaced; stay monochrome
        return False


def _gunzip_capped(data: bytes) -> bytes:
    """Decompress a gzip body, refusing to expand past _MAX_RESPONSE_BYTES.

    gzip shrinks the transfer but not the decompressed payload this guards, so
    a small hostile body ("gzip bomb") must not be allowed to blow up memory.
    Raises on oversized or malformed input; _fetch treats any raise as
    "no result".
    """
    decompressor = zlib.decompressobj(wbits=zlib.MAX_WBITS | 16)  # | 16 selects the gzip format
    result = decompressor.decompress(data, _MAX_RESPONSE_BYTES + 1)
    if len(result) > _MAX_RESPONSE_BYTES or decompressor.unconsumed_tail:
        msg = "decompressed response exceeded the maximum allowed size"
        raise ValueError(msg)
    return result


def _default_cache_dir() -> Path:
    """Per-user cache directory, following each platform's convention."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    elif sys.platform == "darwin":
        base = str(Path.home() / "Library" / "Caches")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or str(Path.home() / ".cache")
    return Path(base)


def _detect_upgrade_command(package: str, module_path: Path | None = None, sys_prefix: str | None = None) -> str:
    """Best-effort guess at the upgrade command for this installation.

    Each installer keeps its environments in a recognizable place, so the
    on-disk location of this very file gives away who installed it:

        uv tool    .../uv/tools/<package>/...
        pipx       .../pipx/venvs/<package>/...
        Homebrew   <prefix>/Cellar/<formula>/...

    Failing that, ``pyvenv.cfg`` tells uv-managed venvs (``uv pip``) apart
    from plain ones (``pip``), and anything unrecognized falls back to
    ``uv tool upgrade`` — the recommended way to install in the first place.
    """
    try:
        parts = (module_path or Path(__file__)).resolve().parts
    except Exception:  # noqa: BLE001 — frozen/odd interpreters; fall through to the pip default
        parts = ()
    if "Cellar" in parts:
        return f"brew upgrade {package}"
    neighbours = set(itertools.pairwise(parts))
    if ("uv", "tools") in neighbours:
        return f"uv tool upgrade {package}"
    if ("pipx", "venvs") in neighbours:
        return f"pipx upgrade {package}"
    try:
        cfg = (Path(sys_prefix or sys.prefix) / "pyvenv.cfg").read_text(encoding="utf-8")
    except Exception:  # noqa: BLE001 — no readable pyvenv.cfg means "not a venv at all"
        cfg = None
    if cfg is not None:
        if any(line.partition("=")[0].strip() == "uv" for line in cfg.splitlines()):
            return f"uv pip install --upgrade {package}"
        return f"pip install --upgrade {package}"
    return f"uv tool upgrade {package}"


class UpdateNotifier:
    """Checks PyPI for a newer release and prints an upgrade hint.

    Parameters
    ----------
    package         : PyPI distribution name
    current_version : the running version (e.g. importlib.metadata.version(...))
    upgrade_command : shown in the hint; default: inferred from the install
                      location (uv tool / pipx / Homebrew / uv venv / pip)
    check_interval  : seconds between PyPI requests (default: one day)
    cache_dir       : where the check result is cached (default: a
                      per-package subdir of the platform cache dir)
    """

    def __init__(
        self,
        package: str,
        current_version: str,
        upgrade_command: str | None = None,
        check_interval: float = _DAY_SECONDS,
        cache_dir: Path | None = None,
    ) -> None:
        self.package = package
        self.current_version = current_version
        self.upgrade_command = upgrade_command or _detect_upgrade_command(package)
        self.check_interval = check_interval
        self._cache_path = (cache_dir or _default_cache_dir() / package) / "update-check.json"
        self._latest: str | None = None
        self._thread: threading.Thread | None = None

    # --- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        """Begin the check. Instant: either reads a fresh cache or spawns a thread."""
        if not self._enabled():
            return
        cached = self._read_cache()
        if cached is not None:
            self._latest = cached
            return
        self._thread = threading.Thread(target=self._fetch, daemon=True, name=f"{self.package}-update-check")
        self._thread.start()

    def notify(self, timeout: float = 0.25) -> None:
        """Print the upgrade hint to stderr if a newer release is known.

        Waits at most ``timeout`` seconds for an in-flight fetch — long
        enough for a warm connection, short enough to be imperceptible.
        A fetch that misses the window still lands in the cache for the
        next run (unless the process exits first, which is also fine).
        """
        if self._thread is not None:
            self._thread.join(timeout)
        if self._latest is not None and _is_newer(self._latest, self.current_version):
            if _stderr_supports_color():
                # BOLD stacks on ORANGE, so the command renders bold orange.
                message = f"{ORANGE}Update available! Run: {BOLD}{self.upgrade_command}{RESET}"
            else:
                message = f"Update available! Run: {self.upgrade_command}"
            print(message, file=sys.stderr)

    # --- internals ---------------------------------------------------------

    def _enabled(self) -> bool:
        env_prefix = re.sub(r"[^A-Z0-9]", "_", self.package.upper())
        opt_outs = (f"{env_prefix}_NO_UPDATE_CHECK", "NO_UPDATE_CHECK", "CI")
        # Any non-empty value opts out — including "0" and "false" — matching
        # how CI-style flags are conventionally treated.
        if any(os.environ.get(var) for var in opt_outs):
            return False
        if _parse_version(self.current_version) is None:  # dev install / unknown version
            return False
        return _stderr_is_interactive()

    def _fetch(self) -> None:
        """Ask PyPI for the latest version; cache it. Runs in the daemon thread.

        The request identifies its sender (PyPI operators prefer meaningful
        User-Agents) and asks for a gzip body. Both the raw read and the decompression are
        capped at _MAX_RESPONSE_BYTES; an oversized response is simply discarded.
        """
        try:
            url = f"https://pypi.org/pypi/{urllib.parse.quote(self.package, safe='')}/json"
            request = urllib.request.Request(  # noqa: S310 — fixed https URL
                url,
                headers={
                    "Accept": "application/json",
                    "Accept-Encoding": "gzip",
                    "User-Agent": f"{self.package}/{self.current_version} (update-check)",
                },
            )
            with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310 — fixed https URL
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(raw) > _MAX_RESPONSE_BYTES:
                    return
                if response.headers.get("Content-Encoding") == "gzip":
                    raw = _gunzip_capped(raw)
            info = json.loads(raw)
            self._latest = str(info["info"]["version"])
            self._write_cache(self._latest)
        except Exception:  # noqa: BLE001, S110 — update hints must never break the host CLI
            pass

    def _read_cache(self) -> str | None:
        """Return the cached latest version, or None if absent/stale/corrupt."""
        try:
            raw = json.loads(self._cache_path.read_text(encoding="utf-8"))
            if time.time() - float(raw["checked_at"]) < self.check_interval:
                return str(raw["latest"])
        except Exception:  # noqa: BLE001, S110 — a bad cache means "check again", nothing more
            pass
        return None

    def _write_cache(self, latest: str) -> None:
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            payload = json.dumps({"latest": latest, "checked_at": time.time()})
            # Write-then-rename so a concurrent reader never sees a torn file.
            tmp = self._cache_path.with_suffix(f".tmp.{os.getpid()}")
            tmp.write_text(payload, encoding="utf-8")
            tmp.chmod(0o600)
            tmp.replace(self._cache_path)
        except Exception:  # noqa: BLE001, S110 — caching is best-effort
            pass


def run_with_update_check(package: str, current_version: str, run: Callable[[], _T]) -> _T:
    """Run a CLI body inside the update check — the one-line entry-point hook.

    ::

        def main() -> None:
            run_with_update_check("my-package", __version__, _main)

    start() returns instantly (cache read or a daemon-thread fetch that runs
    while ``run`` does the real work); notify() prints the upgrade hint on
    every exit path — ``run``'s return value, SystemExit, and any other
    exception all pass straight through.
    """
    notifier = UpdateNotifier(package, current_version)
    notifier.start()
    try:
        return run()
    finally:
        notifier.notify()


if __name__ == "__main__":  # pragma: no cover — manual smoke test
    if len(sys.argv) < 2:  # noqa: PLR2004 — argv position, not magic
        sys.exit(f"usage: python {Path(__file__).name} <package> [current_version]")
    _package = sys.argv[1]
    _current = sys.argv[2] if len(sys.argv) > 2 else "0.0.1"  # noqa: PLR2004 — argv position, not magic
    _notifier = UpdateNotifier(_package, _current, check_interval=0)
    _notifier.start()
    _notifier.notify(timeout=10)
