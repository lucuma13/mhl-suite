"""
Package-wide fixtures shared across the test suite.

The two CLI entry points are driven in-process: each fixture swaps sys.argv /
sys.stdout / sys.stderr, calls main(), catches SystemExit, and returns
(exit_code, stdout, stderr). Lifted here from the old monolithic CLI test files
so every test module inherits them without re-defining.
"""

import io
import sys

import pytest

from mhl_suite.cli import advanced_mhl, mhlver, simple_mhl

from .helpers import make_package


@pytest.fixture(autouse=True)
def _no_update_check(monkeypatch):
    """Keep the CLIs' PyPI update check inert for every test (no network, no
    real cache-dir writes). test_update_checker's enabled_env fixture deletes
    the variable again for the tests that exercise the checker itself."""
    monkeypatch.setenv("NO_UPDATE_CHECK", "1")


@pytest.fixture
def mhl_cli():
    """Execute simple_mhl in-process and capture (exit_code, stdout, stderr)."""

    def _run(argv):
        str_argv = [str(arg) for arg in argv]
        old_argv, old_stdout, old_stderr = sys.argv, sys.stdout, sys.stderr
        sys.argv = ["simple-mhl", *str_argv]
        out, err = io.StringIO(), io.StringIO()
        sys.stdout, sys.stderr = out, err
        try:
            exit_code = 0
            try:
                simple_mhl.main()
            except SystemExit as e:
                exit_code = e.code if e.code is not None else 0
            return exit_code, out.getvalue(), err.getvalue()
        finally:
            sys.argv, sys.stdout, sys.stderr = old_argv, old_stdout, old_stderr

    return _run


@pytest.fixture
def ascmhl_cli():
    """Execute advanced_mhl in-process and capture (exit_code, stdout, stderr)."""

    def _run(argv):
        str_argv = [str(arg) for arg in argv]
        old_argv, old_stdout, old_stderr = sys.argv, sys.stdout, sys.stderr
        sys.argv = ["advanced-mhl", *str_argv]
        out, err = io.StringIO(), io.StringIO()
        sys.stdout, sys.stderr = out, err
        try:
            exit_code = 0
            try:
                advanced_mhl.main()
            except SystemExit as e:
                exit_code = e.code if e.code is not None else 0
            return exit_code, out.getvalue(), err.getvalue()
        finally:
            sys.argv, sys.stdout, sys.stderr = old_argv, old_stdout, old_stderr

    return _run


@pytest.fixture
def mhlver_cli():
    """Execute mhlver in-process and capture (exit_code, stdout, stderr)."""

    def _run_main(argv):
        str_argv = [str(a) for a in argv]
        old_argv, old_out, old_err = sys.argv, sys.stdout, sys.stderr
        sys.argv = ["mhlver", *str_argv]
        out, err = io.StringIO(), io.StringIO()
        sys.stdout, sys.stderr = out, err
        exit_code = 0
        try:
            try:
                mhlver.main()
            except SystemExit as e:
                exit_code = e.code if e.code is not None else 0
        finally:
            sys.argv, sys.stdout, sys.stderr = old_argv, old_out, old_err
        return exit_code, out.getvalue(), err.getvalue()

    return _run_main


@pytest.fixture
def package(tmp_path):
    """A sealed, clean ASC-MHL package with a couple of files."""
    return make_package(tmp_path / "pkg", {"top.txt": b"hello\n", "A/a1.txt": b"aaa\n", "A/a2.txt": b"bbb\n"})
