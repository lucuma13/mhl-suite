"""Provide shared fixtures and configuration for the MHL test suite.

Define common testing utilities, such as the mhl_cli fixture, to ensure
consistent command-line execution and state isolation across all modules.
"""

import io
import pytest
import sys
from mhl_suite import simple_mhl


@pytest.fixture
def mhl_cli():
    """Fixture to execute simple_mhl in-process and capture results."""
    def _run(argv):
        # Convert Path objects to strings to prevent sys.argv type errors
        str_argv = [str(arg) for arg in argv]
        
        old_argv, old_stdout, old_stderr = sys.argv, sys.stdout, sys.stderr
        sys.argv = ["simple-mhl"] + str_argv
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