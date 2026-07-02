"""The shared verify-result contract (mhl_suite.verify_results).

VerifyReport is the single type both dialects return; `ok` is its only derived
behaviour (exit code 0). These pin it, independent of either engine.
"""

import pytest

from mhl_suite.verify_results import VerifyEntry, VerifyReport


def _report(kinds, *, code=0, malformed=False):
    """A VerifyReport whose entries carry the given per-file status strings."""
    entries = [VerifyEntry(path=f"f{i}", status=s) for i, s in enumerate(kinds)]
    return VerifyReport(entries=entries, code=code, malformed=malformed)


class TestOk:
    """`ok` is purely a code==0 predicate, regardless of entries."""

    def test_clean_report_is_ok(self):
        assert VerifyReport(code=0).ok is True

    @pytest.mark.parametrize("code", [10, 11, 13, 40, 41])
    def test_any_nonzero_code_is_not_ok(self, code):
        assert VerifyReport(code=code).ok is False

    def test_ok_ignores_entries(self):
        # code is the source of truth: a stray entry doesn't flip `ok`.
        assert _report(["ok"], code=0).ok is True


class TestVerifyEntryDefaults:
    """VerifyEntry is a formatting-free carrier with size/existence flags off by default."""

    def test_defaults(self):
        e = VerifyEntry(path="clip.mov", status="ok")
        assert e.detail == ""
        assert e.size_only is False
        assert e.existence_only is False
        assert e.line == ""
        assert e.detail_line == ""
