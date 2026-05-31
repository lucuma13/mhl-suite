"""Provide shared fixtures and configuration for the MHL test suite.

Define common testing utilities, such as the mhl_cli fixture, to ensure
consistent command-line execution and state isolation across all modules.
"""

import io
import pytest
import sys
from pathlib import Path
from mhl_suite import simple_mhl

# ---------------------------------------------------------------------------
# ASC-MHL XML helpers
# ---------------------------------------------------------------------------

_MHL_TMPL = """\
<?xml version="1.0" encoding="UTF-8"?>
<hashlist version="2.0" xmlns="urn:ASC:MHL:v2.0">
  <hashes>
{entries}  </hashes>
</hashlist>"""

_HASH_ENTRY = """\
    <hash>
      <path size="{size}">{path}</path>
      <xxh64 action="{action}" hashdate="2026-05-30T12:00:00+00:00">{digest}</xxh64>
    </hash>
"""

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def write_mhl():
    """Factory fixture that writes a minimal ASC-MHL 2.0 generation file.

    Usage::

        def test_something(tmp_path, write_mhl):
            ascdir = tmp_path / "ascmhl"
            ascdir.mkdir()
            write_mhl(ascdir, "0001.mhl", [
                {"path": "clip.mov", "size": "1000000",
                 "action": "original", "digest": "aabbccdd"},
            ])

    Each entry dict must contain ``path``, ``size``, ``action``, and
    ``digest``.  Returns the :class:`~pathlib.Path` of the written file.
    """

    def _write(ascdir: Path, name: str, entries: list[dict]) -> Path:
        body = "".join(_HASH_ENTRY.format(**e) for e in entries)
        mhl = ascdir / name
        mhl.write_text(_MHL_TMPL.format(entries=body))
        return mhl

    return _write


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
