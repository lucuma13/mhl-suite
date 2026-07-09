"""Tests for the PyPI update-notice helper."""

import gzip
import importlib
import importlib.metadata
import io
import json
import re
import sys
import time
import tomllib
import urllib.request
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from packaging.version import Version

# Fully portable: the distribution name is read from the project's pyproject.toml
# (two levels up from this file), so this suite drops into any project unchanged.
PACKAGE = tomllib.loads((Path(__file__).resolve().parents[1] / "pyproject.toml").read_text())["project"]["name"]

# Everything else is derived: the import name per the packaging convention
# (dist name with '-' → '_'), the installed version and the console-script
# entry points from the package metadata.
MODULE = PACKAGE.replace("-", "_")
VERSION = importlib.metadata.version(PACKAGE)
CONSOLE_SCRIPTS = sorted(
    (ep for ep in importlib.metadata.distribution(PACKAGE).entry_points if ep.group == "console_scripts"),
    key=lambda ep: ep.name,
)

update_checker = importlib.import_module(f"{MODULE}.update_checker")
UpdateNotifier = update_checker.UpdateNotifier
run_with_update_check = update_checker.run_with_update_check
_detect_upgrade_command = update_checker._detect_upgrade_command
_is_newer = update_checker._is_newer
_parse_version = update_checker._parse_version

# Derived, mirroring update_checker._enabled()'s env-var derivation.
ENV_PREFIX = re.sub(r"[^A-Z0-9]", "_", PACKAGE.upper())
OPT_OUT_VARS = ("CI", "NO_UPDATE_CHECK", f"{ENV_PREFIX}_NO_UPDATE_CHECK")
UPGRADE_COMMAND = f"uv tool upgrade {PACKAGE}"


# ===========================================================================
# Helpers / fixtures
# ===========================================================================


@pytest.fixture
def enabled_env(monkeypatch):
    """Make the notifier believe it's an interactive, non-CI run."""
    for var in OPT_OUT_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setattr(update_checker, "_stderr_is_interactive", lambda: True)


class FakeResponse(io.BytesIO):
    """A urlopen() response double: a readable body plus response headers."""

    def __init__(self, body: bytes, headers: dict | None = None):
        super().__init__(body)
        self.headers = headers or {}


def fake_pypi(monkeypatch, version: str, *, gzipped: bool = False, body: bytes | None = None):
    """Replace urllib.request.urlopen with a canned PyPI JSON response.

    Captures the request's URL and headers for assertions. `gzipped` serves
    the body gzip-encoded (with the matching response header); `body`
    overrides the payload entirely (still gzipped when requested).
    """
    payload = body if body is not None else json.dumps({"info": {"version": version}}).encode()
    headers = {"Content-Encoding": "gzip"} if gzipped else {}
    wire_body = gzip.compress(payload) if gzipped else payload
    captured = SimpleNamespace(url=None, request_headers=None)

    def fake_urlopen(request, timeout=None):
        captured.url = request.full_url
        captured.request_headers = dict(request.header_items())
        return FakeResponse(wire_body, headers)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return captured


def write_cache(path: Path, latest: str, age_seconds: float = 0.0) -> None:
    path.write_text(json.dumps({"latest": latest, "checked_at": time.time() - age_seconds}))


# ===========================================================================
# Version parsing / comparison
# ===========================================================================


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("2.3.1", Version("2.3.1")),
        ("2.3.1rc1", Version("2.3.1rc1")),  # pre-release preserved (PEP 440)
        ("10", Version("10")),
        (" 1.2 ", Version("1.2")),  # surrounding whitespace tolerated
        ("v1.2", Version("1.2")),  # PEP 440 allows a leading 'v'
        ("unknown", None),
        ("", None),
    ],
)
def test_parse_version(version, expected):
    assert _parse_version(version) == expected


@pytest.mark.parametrize(
    ("latest", "current", "newer"),
    [
        ("2.3.0", "2.2.1", True),
        ("2.10.0", "2.9.9", True),  # numeric, not lexicographic
        ("2.2.0.1", "2.2", True),  # longer release ordered correctly
        ("2.2.1", "2.2.1rc1", True),  # a final release is newer than its own rc
        ("2.2.1", "2.2.1", False),
        ("2.2", "2.2.0", False),  # equal under PEP 440
        ("2.2.1", "2.3.0", False),  # local version ahead of PyPI
        ("2.2.1rc1", "2.2.1", False),  # an rc is not newer than the final
        ("unknown", "2.2.1", False),
        ("2.3.0", "unknown", False),
    ],
)
def test_is_newer(latest, current, newer):
    assert _is_newer(latest, current) is newer


# ===========================================================================
# Opt-outs
# ===========================================================================


@pytest.mark.parametrize("var", OPT_OUT_VARS)
def test_disabled_by_env_var(enabled_env, monkeypatch, tmp_path, var):
    monkeypatch.setenv(var, "1")
    notifier = UpdateNotifier(PACKAGE, "1.0", cache_dir=tmp_path)
    assert not notifier._enabled()


def test_disabled_for_unparsable_version(enabled_env, tmp_path):
    notifier = UpdateNotifier(PACKAGE, "unknown", cache_dir=tmp_path)
    assert not notifier._enabled()


def test_disabled_when_stderr_not_a_tty(enabled_env, monkeypatch, tmp_path):
    monkeypatch.setattr(update_checker, "_stderr_is_interactive", lambda: False)
    notifier = UpdateNotifier(PACKAGE, "1.0", cache_dir=tmp_path)
    assert not notifier._enabled()


def test_disabled_start_does_nothing(enabled_env, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("CI", "true")

    def boom(*args, **kwargs):
        raise AssertionError("network must not be touched when disabled")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    notifier = UpdateNotifier(PACKAGE, "0.1", cache_dir=tmp_path)
    notifier.start()
    notifier.notify()
    assert capsys.readouterr().err == ""


# ===========================================================================
# Cache behaviour
# ===========================================================================


def test_fresh_cache_skips_network(enabled_env, monkeypatch, tmp_path, capsys):
    def boom(*args, **kwargs):
        raise AssertionError("network must not be touched with a fresh cache")

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    notifier = UpdateNotifier(PACKAGE, "1.0", upgrade_command=UPGRADE_COMMAND, cache_dir=tmp_path)
    write_cache(notifier._cache_path, "2.0")

    notifier.start()
    notifier.notify()
    assert f"Update available! Run: {UPGRADE_COMMAND}" in capsys.readouterr().err


def test_stale_cache_triggers_fetch_and_rewrite(enabled_env, monkeypatch, tmp_path, capsys):
    fake_pypi(monkeypatch, "3.0")
    notifier = UpdateNotifier(PACKAGE, "1.0", cache_dir=tmp_path)
    write_cache(notifier._cache_path, "2.0", age_seconds=2 * 24 * 3600)

    notifier.start()
    notifier.notify(timeout=5)
    assert "Update available!" in capsys.readouterr().err
    assert json.loads(notifier._cache_path.read_text())["latest"] == "3.0"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_cache_file_is_private(enabled_env, monkeypatch, tmp_path):
    """The cache reveals which tools the user runs, so it is written 0o600."""
    fake_pypi(monkeypatch, "3.0")
    notifier = UpdateNotifier(PACKAGE, "1.0", cache_dir=tmp_path)

    notifier.start()
    notifier.notify(timeout=5)
    assert notifier._cache_path.stat().st_mode & 0o777 == 0o600


def test_corrupt_cache_is_ignored(enabled_env, monkeypatch, tmp_path, capsys):
    fake_pypi(monkeypatch, "3.0")
    notifier = UpdateNotifier(PACKAGE, "1.0", cache_dir=tmp_path)
    notifier._cache_path.write_text("{not json")

    notifier.start()
    notifier.notify(timeout=5)
    assert "Update available!" in capsys.readouterr().err


# ===========================================================================
# Fetch / notify
# ===========================================================================


def test_fetch_queries_pypi_and_notifies(enabled_env, monkeypatch, tmp_path, capsys):
    fake = fake_pypi(monkeypatch, "9.9.9")
    notifier = UpdateNotifier(PACKAGE, "1.0", upgrade_command=UPGRADE_COMMAND, cache_dir=tmp_path)

    notifier.start()
    notifier.notify(timeout=5)
    assert fake.url == f"https://pypi.org/pypi/{PACKAGE}/json"
    assert f"Update available! Run: {UPGRADE_COMMAND}" in capsys.readouterr().err


def test_fetch_quotes_package_name_and_identifies_itself(enabled_env, monkeypatch, tmp_path):
    """The package name is URL-quoted and the request carries an identifiable
    User-Agent plus a gzip Accept-Encoding (urllib doesn't negotiate it)."""
    fake = fake_pypi(monkeypatch, "2.0")
    notifier = UpdateNotifier("odd/name", "1.0", upgrade_command="x", cache_dir=tmp_path)

    notifier.start()
    notifier.notify(timeout=5)
    assert fake.url == "https://pypi.org/pypi/odd%2Fname/json"
    # urllib normalizes header names to Capitalized-lowercase form.
    assert fake.request_headers["User-agent"] == "odd/name/1.0 (update-check)"
    assert fake.request_headers["Accept-encoding"] == "gzip"


def test_gzipped_response_is_decompressed(enabled_env, monkeypatch, tmp_path, capsys):
    fake_pypi(monkeypatch, "3.0", gzipped=True)
    notifier = UpdateNotifier(PACKAGE, "1.0", cache_dir=tmp_path)

    notifier.start()
    notifier.notify(timeout=5)
    assert "Update available!" in capsys.readouterr().err


@pytest.mark.parametrize("gzipped", [False, True], ids=["raw", "gzip-bomb"])
def test_oversized_response_is_discarded(enabled_env, monkeypatch, tmp_path, capsys, gzipped):
    """A body over the cap — as transferred bytes or once decompressed — is
    dropped without a hint or a cache write."""
    monkeypatch.setattr(update_checker, "_MAX_RESPONSE_BYTES", 64)
    oversized = json.dumps({"info": {"version": "9.9"}, "pad": "x" * 100}).encode()
    fake_pypi(monkeypatch, "9.9", gzipped=gzipped, body=oversized)
    notifier = UpdateNotifier(PACKAGE, "1.0", cache_dir=tmp_path)

    notifier.start()
    notifier.notify(timeout=5)
    assert capsys.readouterr().err == ""
    assert not notifier._cache_path.exists()


def test_no_hint_when_up_to_date(enabled_env, monkeypatch, tmp_path, capsys):
    fake_pypi(monkeypatch, "1.0")
    notifier = UpdateNotifier(PACKAGE, "1.0", cache_dir=tmp_path)

    notifier.start()
    notifier.notify(timeout=5)
    assert capsys.readouterr().err == ""


def test_network_failure_is_silent(enabled_env, monkeypatch, tmp_path, capsys):
    def offline(*args, **kwargs):
        raise OSError("no network")

    monkeypatch.setattr(urllib.request, "urlopen", offline)
    notifier = UpdateNotifier(PACKAGE, "1.0", cache_dir=tmp_path)

    notifier.start()
    notifier.notify(timeout=5)
    assert capsys.readouterr().err == ""
    assert not notifier._cache_path.exists()


def test_custom_upgrade_command(enabled_env, monkeypatch, tmp_path, capsys):
    # A deliberately different package name proves the custom command is honoured verbatim.
    fake_pypi(monkeypatch, "2.0")
    notifier = UpdateNotifier("other-pkg", "1.0", upgrade_command="pipx upgrade other-pkg", cache_dir=tmp_path)

    notifier.start()
    notifier.notify(timeout=5)
    assert "Run: pipx upgrade other-pkg" in capsys.readouterr().err


# ===========================================================================
# Colour
# ===========================================================================


def test_hint_is_coloured_when_stderr_supports_it(enabled_env, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(update_checker, "_stderr_supports_color", lambda: True)
    notifier = UpdateNotifier(PACKAGE, "1.0", upgrade_command=UPGRADE_COMMAND, cache_dir=tmp_path)
    write_cache(notifier._cache_path, "2.0")

    notifier.start()
    notifier.notify()
    err = capsys.readouterr().err
    assert err.startswith(update_checker.ORANGE)
    assert f"{update_checker.BOLD}{UPGRADE_COMMAND}" in err  # command itself is bold
    assert err.rstrip("\n").endswith(update_checker.RESET)


def test_hint_is_plain_when_stderr_lacks_colour(enabled_env, monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(update_checker, "_stderr_supports_color", lambda: False)
    notifier = UpdateNotifier(PACKAGE, "1.0", upgrade_command=UPGRADE_COMMAND, cache_dir=tmp_path)
    write_cache(notifier._cache_path, "2.0")

    notifier.start()
    notifier.notify()
    err = capsys.readouterr().err
    assert "\033[" not in err
    assert f"Update available! Run: {UPGRADE_COMMAND}" in err


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
def test_color_follows_no_color_and_force_color(monkeypatch, env, tty, expected):
    """https://no-color.org: NO_COLOR disables, FORCE_COLOR forces, otherwise
    the TTY decides."""
    for var in ("NO_COLOR", "FORCE_COLOR"):
        monkeypatch.delenv(var, raising=False)
    for var, value in env.items():
        monkeypatch.setenv(var, value)
    monkeypatch.setattr(update_checker.sys, "stderr", SimpleNamespace(isatty=lambda: tty))
    monkeypatch.setattr(update_checker, "_enable_ansi_on_stderr", lambda: True)
    assert update_checker._stderr_supports_color() is expected


# ===========================================================================
# Installer detection
# ===========================================================================


@pytest.mark.parametrize(
    ("module_path", "expected"),
    [
        (
            f"/Users/u/.local/share/uv/tools/{PACKAGE}/lib/python3.14/site-packages/{PACKAGE}/update_checker.py",
            f"uv tool upgrade {PACKAGE}",
        ),
        (
            f"/home/u/.local/pipx/venvs/{PACKAGE}/lib/python3.14/site-packages/{PACKAGE}/update_checker.py",
            f"pipx upgrade {PACKAGE}",
        ),
        (
            f"/opt/homebrew/Cellar/{PACKAGE}/2.3.0/libexec/lib/python3.14/site-packages/{PACKAGE}/update_checker.py",
            f"brew upgrade {PACKAGE}",
        ),
        (
            f"/home/linuxbrew/.linuxbrew/Cellar/{PACKAGE}/2.3.0/libexec/lib/python3.14/site-packages/{PACKAGE}/update_checker.py",
            f"brew upgrade {PACKAGE}",
        ),
        (
            # Nothing recognizable and no venv: recommend the default install method.
            f"/usr/lib/python3.14/site-packages/{PACKAGE}/update_checker.py",
            f"uv tool upgrade {PACKAGE}",
        ),
    ],
)
def test_detect_upgrade_command_from_install_path(tmp_path, module_path, expected):
    # tmp_path stands in for sys.prefix: no pyvenv.cfg there, so only the path decides.
    assert _detect_upgrade_command(PACKAGE, Path(module_path), sys_prefix=str(tmp_path)) == expected


def test_detect_upgrade_command_uv_venv(tmp_path):
    (tmp_path / "pyvenv.cfg").write_text("home = /usr/local/bin\nuv = 0.7.2\nversion_info = 3.14.0\n")
    module_path = tmp_path / "lib" / "python3.14" / "site-packages" / PACKAGE / "update_checker.py"
    assert (
        _detect_upgrade_command(PACKAGE, module_path, sys_prefix=str(tmp_path)) == f"uv pip install --upgrade {PACKAGE}"
    )


def test_detect_upgrade_command_plain_venv(tmp_path):
    (tmp_path / "pyvenv.cfg").write_text("home = /usr/local/bin\nversion = 3.14.0\n")
    module_path = tmp_path / "lib" / "python3.14" / "site-packages" / PACKAGE / "update_checker.py"
    assert _detect_upgrade_command(PACKAGE, module_path, sys_prefix=str(tmp_path)) == f"pip install --upgrade {PACKAGE}"


def test_detect_upgrade_command_path_beats_pyvenv_cfg(tmp_path):
    # uv tool environments are uv-stamped venvs too; the tool path must win.
    prefix = tmp_path / "uv" / "tools" / PACKAGE
    prefix.mkdir(parents=True)
    (prefix / "pyvenv.cfg").write_text("uv = 0.7.2\n")
    module_path = prefix / "lib" / "python3.14" / "site-packages" / PACKAGE / "update_checker.py"
    assert _detect_upgrade_command(PACKAGE, module_path, sys_prefix=str(prefix)) == f"uv tool upgrade {PACKAGE}"


def test_detect_upgrade_command_unresolvable_path_falls_back(tmp_path):
    """A frozen/odd interpreter where resolve() raises must not crash — with no
    readable pyvenv.cfg it lands on the default recommendation."""
    bad = MagicMock()
    bad.resolve.side_effect = OSError("frozen interpreter")
    assert _detect_upgrade_command(PACKAGE, bad, sys_prefix=str(tmp_path)) == f"uv tool upgrade {PACKAGE}"


# ===========================================================================
# Cache directory conventions
# ===========================================================================


class TestDefaultCacheDir:
    def test_darwin(self, monkeypatch):
        monkeypatch.setattr(update_checker.sys, "platform", "darwin")
        assert update_checker._default_cache_dir() == Path.home() / "Library" / "Caches"

    def test_win32_uses_localappdata(self, monkeypatch):
        monkeypatch.setattr(update_checker.sys, "platform", "win32")
        monkeypatch.setenv("LOCALAPPDATA", str(Path("/c/Users/u/AppData/Local")))
        assert update_checker._default_cache_dir() == Path("/c/Users/u/AppData/Local")

    def test_win32_without_localappdata(self, monkeypatch):
        monkeypatch.setattr(update_checker.sys, "platform", "win32")
        monkeypatch.delenv("LOCALAPPDATA", raising=False)
        assert update_checker._default_cache_dir() == Path.home() / "AppData" / "Local"

    def test_linux_uses_xdg_cache_home(self, monkeypatch):
        monkeypatch.setattr(update_checker.sys, "platform", "linux")
        monkeypatch.setenv("XDG_CACHE_HOME", str(Path("/custom/cache")))
        assert update_checker._default_cache_dir() == Path("/custom/cache")

    def test_linux_without_xdg_falls_back_to_dot_cache(self, monkeypatch):
        monkeypatch.setattr(update_checker.sys, "platform", "linux")
        monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
        assert update_checker._default_cache_dir() == Path.home() / ".cache"


# ===========================================================================
# Never breaks the host CLI — "stay quiet" guarantees
# ===========================================================================


class _BoomStderr:
    """A stderr whose isatty() blows up — models a closed/replaced stream."""

    def isatty(self):
        raise ValueError("I/O operation on closed file")


def test_stderr_is_interactive_false_when_isatty_raises(monkeypatch):
    monkeypatch.setattr(update_checker.sys, "stderr", _BoomStderr())
    assert update_checker._stderr_is_interactive() is False


def test_stderr_supports_color_false_when_isatty_raises(monkeypatch):
    monkeypatch.setattr(update_checker.sys, "stderr", _BoomStderr())
    assert update_checker._stderr_supports_color() is False


# ===========================================================================
# CLI wiring — run_with_update_check and the console-script entry points
# ===========================================================================


@pytest.fixture
def notifier_events(monkeypatch):
    """Swap UpdateNotifier for a recorder; returns the event list."""
    events = []

    class FakeNotifier:
        def __init__(self, package, version):
            events.append(f"init {package} {version}")

        def start(self):
            events.append("start")

        def notify(self):
            events.append("notify")

    monkeypatch.setattr(update_checker, "UpdateNotifier", FakeNotifier)
    return events


def test_run_with_update_check_wraps_the_body(notifier_events):
    """The check starts before the body and the body's return value passes through."""
    result = run_with_update_check(PACKAGE, "1.0", lambda: notifier_events.append("run") or 42)
    assert result == 42
    assert notifier_events == [f"init {PACKAGE} 1.0", "start", "run", "notify"]


def test_run_with_update_check_notifies_on_every_exit_path(notifier_events):
    """SystemExit from the body still notifies and propagates unchanged."""

    def body():
        raise SystemExit(3)

    with pytest.raises(SystemExit) as excinfo:
        run_with_update_check(PACKAGE, "1.0", body)
    assert excinfo.value.code == 3
    assert notifier_events == [f"init {PACKAGE} 1.0", "start", "notify"]


@pytest.mark.parametrize("script", CONSOLE_SCRIPTS, ids=[ep.name for ep in CONSOLE_SCRIPTS])
def test_console_scripts_run_inside_the_update_check(monkeypatch, script):
    """Every console script hangs its body on run_with_update_check, passing
    the distribution name (what to ask PyPI about) and the installed version."""
    cli = importlib.import_module(script.module)
    entry = script.load()
    calls = []
    monkeypatch.setattr(cli, "run_with_update_check", lambda *args: calls.append(args))

    entry()
    ((package, version, run),) = calls
    assert package == PACKAGE
    assert version == VERSION
    assert callable(run)


def test_write_cache_failure_is_silent(enabled_env, monkeypatch, tmp_path):
    """A read-only cache dir must not raise — caching is best-effort."""

    def boom(*args, **kwargs):
        raise OSError("read-only filesystem")

    monkeypatch.setattr(update_checker.Path, "mkdir", boom)
    notifier = UpdateNotifier(PACKAGE, "1.0", cache_dir=tmp_path)
    notifier._write_cache("2.0")  # must not raise
    assert not notifier._cache_path.exists()
