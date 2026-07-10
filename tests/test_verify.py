"""
The shared verify core (mhl_suite.verify): its semantic result model and its
renderer.

VerifyReport is the single type both dialects return; the first tests pin its
derived behaviour (`ok`, the mismatch predicates), independent of either
engine. render_verify_lines is the only place [OK]/[ERROR] terminal text is
built; the render tests pin that a semantic VerifyReport reproduces the terminal
form in both quiet and verbose modes. The engine (verify_records) is exercised
through the dialect drivers in test_classic_verify / test_ascmhl_history.
"""

import pytest

from mhl_suite.verify import HashComparison, Status, VerifyEntry, VerifyReport, render_verify_lines


def _report(kinds, *, code=0, malformed=False):
    """A VerifyReport whose entries carry the given per-file statuses."""
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


class TestVerifyEntrySemantics:
    """
    VerifyEntry is a formatting-free semantic carrier: no pre-rendered terminal
    text, flags off by default, and mismatch kinds derived from the recorded
    comparisons rather than stored labels.
    """

    def test_defaults(self):
        e = VerifyEntry(path="clip.mov", status=Status.OK)
        assert e.detail == ""
        assert e.size_only is False
        assert e.existence_only is False
        assert e.hashes == []
        assert e.error is None
        assert e.recorded_size is None
        assert e.actual_size is None

    def test_hash_mismatch_derived_from_comparisons(self):
        ok = HashComparison(tag="md5", expected="aa", computed="aa", ok=True)
        bad = HashComparison(tag="md5", expected="aa", computed="bb", ok=False)
        assert VerifyEntry(path="f", status=Status.MISMATCH, hashes=[ok, bad]).hash_mismatch is True
        assert VerifyEntry(path="f", status=Status.OK, hashes=[ok]).hash_mismatch is False

    def test_size_mismatch_requires_both_sizes(self):
        assert VerifyEntry(path="f", status=Status.MISMATCH, recorded_size=10, actual_size=9).size_mismatch is True
        assert VerifyEntry(path="f", status=Status.OK, recorded_size=10, actual_size=10).size_mismatch is False
        assert VerifyEntry(path="f", status=Status.OK, recorded_size=None, actual_size=9).size_mismatch is False


class TestRenderMismatchVerboseDetail:
    """render_verify_lines emits a mismatch entry's verbose continuation
    derived from its semantic comparison fields, and suppresses it without -v."""

    def test_mismatch_detail_line_shown_only_when_verbose(self):
        report = VerifyReport(
            entries=[
                VerifyEntry(
                    path="a.bin",
                    status=Status.MISMATCH,
                    hashes=[HashComparison(tag="md5", expected="aa", computed="bb", ok=False)],
                )
            ],
            code=11,
        )
        verbose = render_verify_lines(report, verbose=True)
        assert "[ERROR] hash mismatch: a.bin" in verbose
        assert "        (calc md5: bb | stored md5: aa)" in verbose
        # Without -v the continuation is suppressed.
        plain = render_verify_lines(report, verbose=False)
        assert "(calc" not in "\n".join(plain)


class TestRenderLines:
    """render_verify_lines reproduces the terminal text from a semantic VerifyReport."""

    def _report(self):
        return VerifyReport(
            notices=["Verified with size-only checks"],
            entries=[
                VerifyEntry(
                    path="ok.txt",
                    status=Status.OK,
                    hashes=[HashComparison(tag="xxh64", expected="a" * 16, computed="a" * 16, ok=True)],
                ),
                VerifyEntry(path="bad.txt", status=Status.MISMATCH, recorded_size=4, actual_size=9),
            ],
        )

    def test_quiet_shows_notices_and_failures_only(self):
        lines = render_verify_lines(self._report(), verbose=False)
        assert lines == ["Verified with size-only checks", "[ERROR] size mismatch: bad.txt"]

    def test_verbose_adds_ok_lines_and_detail_continuation(self):
        lines = render_verify_lines(self._report(), verbose=True)
        assert lines == [
            "Verified with size-only checks",
            f"[OK] ok.txt  xxh64: {'a' * 16}",
            "[ERROR] size mismatch: bad.txt",
            "        (calc size: 9 | stored size: 4)",
        ]
