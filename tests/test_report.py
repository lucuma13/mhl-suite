"""
mhlver's report model and renderer (mhl_suite.report).

_render_report and _format_file_result are pure functions writing to a buffer,
and ManifestResult/FileResult are the model they render. The mhlver CLI run
tests only feed the renderer empty/all-OK results, so the per-status summaries,
the Details section, the Issues roll-up, and the size-only/existence-only
verdict downgrades are exercised here against hand-built ManifestResults.
"""

import io
from pathlib import Path

from mhl_suite import report


class TestManifestResultCounts:
    """
    The n_* convenience properties on ManifestResult tally file_results by
    status; verify each counts only its own status.
    """

    def test_counts_by_status(self):
        mr = report.ManifestResult(
            manifest_path=Path("m.mhl"),
            manifest_status="failed",
            file_results=[
                report.FileResult(path="a", status="ok"),
                report.FileResult(path="b", status="ok"),
                report.FileResult(path="c", status="missing"),
                report.FileResult(path="d", status="mismatch"),
                report.FileResult(path="e", status="new"),
                report.FileResult(path="f", status="error"),
            ],
        )
        assert mr.n_ok == 2
        assert mr.n_missing == 1
        assert mr.n_mismatch == 1
        assert mr.n_new == 1
        assert mr.n_error == 1
        assert mr.n_files == 6

    def test_empty_results_are_all_zero(self):
        mr = report.ManifestResult(manifest_path=Path("m.mhl"), manifest_status="ok")
        assert (mr.n_ok, mr.n_missing, mr.n_mismatch, mr.n_new, mr.n_error, mr.n_files) == (0, 0, 0, 0, 0, 0)


class TestRenderReportDetails:
    """
    _render_report is a pure fn writing to a file handle. The TestRun cases only
    feed it empty/all-OK results, leaving the per-status summary appends, the
    Details section, and the manifest-error line uncovered. Here we feed it
    populated ManifestResults to exercise those branches.
    """

    def _render(self, manifest_results, exit_status):
        buf = io.StringIO()
        now = report.datetime.now()
        report._render_report(buf, Path("/src"), now, now, manifest_results, exit_status)
        return buf.getvalue()

    def test_summary_lists_each_nonzero_status(self):
        """
        A manifest with one of every failing status produces a summary line
        naming missing / mismatch / error / new counts.
        """
        mr = report.ManifestResult(
            manifest_path=Path("m.mhl"),
            manifest_status="failed",
            file_results=[
                report.FileResult(path="ok.mxf", status="ok"),
                report.FileResult(path="gone.mxf", status="missing"),
                report.FileResult(path="bad.mxf", status="mismatch"),
                report.FileResult(path="boom.mxf", status="error", detail="boom"),
                report.FileResult(path="extra.mxf", status="new"),
            ],
        )
        out = self._render([mr], exit_status=40)

        assert "❌ FAILED" in out
        assert "1 missing" in out
        assert "1 mismatch" in out
        assert "1 error" in out
        assert "1 new (untracked)" in out
        # Manifest section is rendered for a non-empty result set (singular
        # header for a single manifest).
        assert "Manifest\n" in out
        assert "📄 m.mhl" in out
        # Per-file lines come from _format_file_result.
        assert "gone.mxf" in out
        assert "extra.mxf" in out

    def test_summary_all_size_only_verdict(self):
        """
        All-size-only: the global summary is downgraded to a warning while the
        per-manifest line keeps the plain ✅ VERIFIED prefix.
        """
        mr = report.ManifestResult(
            manifest_path=Path("m.mhl"),
            manifest_status="ok",
            file_results=[
                report.FileResult(path="a.mxf", status="ok", size_only=True),
                report.FileResult(path="b.mxf", status="ok", size_only=True),
            ],
        )
        out = self._render([mr], exit_status=0)
        assert "⚠️ VERIFIED WITH WARNINGS (SIZE-ONLY CHECKS)" in out  # global summary
        assert "✅ VERIFIED (SIZE-ONLY CHECKS)" in out  # per-manifest, unchanged
        assert "PARTIAL" not in out

    def test_summary_partial_size_only_verdict(self):
        """
        Partial size-only: global downgraded to a warning, per-manifest stays
        plain.
        """
        mr = report.ManifestResult(
            manifest_path=Path("m.mhl"),
            manifest_status="ok",
            file_results=[
                report.FileResult(path="a.mxf", status="ok"),
                report.FileResult(path="b.mxf", status="ok", size_only=True),
            ],
        )
        out = self._render([mr], exit_status=0)
        assert "⚠️ VERIFIED WITH WARNINGS (SOME SIZE-ONLY CHECKS)" in out  # global
        assert "✅ VERIFIED (SOME SIZE-ONLY CHECKS)" in out  # per-manifest

    def test_summary_no_size_only_is_plain_verified(self):
        """A fully hash-verified manifest keeps the plain VERIFIED verdict."""
        mr = report.ManifestResult(
            manifest_path=Path("m.mhl"),
            manifest_status="ok",
            file_results=[report.FileResult(path="a.mxf", status="ok")],
        )
        out = self._render([mr], exit_status=0)
        assert "✅ VERIFIED" in out
        assert "SIZE-ONLY" not in out

    def test_summary_existence_only_verdict_is_labelled_distinctly(self):
        """
        An existence-only entry (null, no <size>) downgrades the global verdict
        to a warning and is labelled EXISTENCE-ONLY — never SIZE-ONLY, since no
        size was checked.
        """
        mr = report.ManifestResult(
            manifest_path=Path("m.mhl"),
            manifest_status="ok",
            file_results=[
                report.FileResult(path="a.mxf", status="ok"),
                report.FileResult(path="b.mxf", status="ok", existence_only=True),
            ],
        )
        out = self._render([mr], exit_status=0)
        assert "⚠️ VERIFIED WITH WARNINGS (SOME EXISTENCE-ONLY CHECKS)" in out  # global
        assert "✅ VERIFIED (SOME EXISTENCE-ONLY CHECKS)" in out  # per-manifest
        assert "SIZE-ONLY" not in out

    def test_summary_mixed_size_and_existence_only_names_both(self):
        """
        When a run mixes size-only and existence-only entries, the verdict names
        both.
        """
        mr = report.ManifestResult(
            manifest_path=Path("m.mhl"),
            manifest_status="ok",
            file_results=[
                report.FileResult(path="a.mxf", status="ok", size_only=True),
                report.FileResult(path="b.mxf", status="ok", existence_only=True),
            ],
        )
        out = self._render([mr], exit_status=0)
        assert "⚠️ VERIFIED WITH WARNINGS (SIZE-ONLY AND EXISTENCE-ONLY CHECKS)" in out

    def test_manifest_level_error_renders_error_line(self):
        """
        A manifest whose own status is 'error' prints the manifest error and
        skips per-file rendering.
        """
        mr = report.ManifestResult(
            manifest_path=Path("broken.mhl"),
            manifest_status="error",
            manifest_error="could not read manifest",
        )
        out = self._render([mr], exit_status=40)
        assert "📄 broken.mhl" in out
        assert "could not read manifest" in out

    def test_manifest_error_falls_back_to_default_text(self):
        """
        When manifest_status is 'error' but no message was attached, a generic
        label is printed instead.
        """
        mr = report.ManifestResult(
            manifest_path=Path("broken.mhl"),
            manifest_status="error",
            manifest_error="",
        )
        out = self._render([mr], exit_status=40)
        assert "manifest-level error" in out

    def test_header_carries_provenance_fields(self):
        """
        The header records tool, host, user, source, and the start/finish window
        that anchor a fixity record for archival.
        """
        out = self._render([], exit_status=0)
        for label in ("Tool:", "Host:", "User:", "Source:", "Started:", "Finished:"):
            assert label in out

    def test_operator_falls_back_when_lookup_fails(self, monkeypatch):
        """
        Environments that can't resolve a username must not crash the report.
        """
        monkeypatch.setattr("getpass.getuser", lambda: (_ for _ in ()).throw(OSError()))
        out = self._render([], exit_status=0)
        assert "User:       unknown" in out

    def test_issues_section_collects_non_ok_across_manifests(self):
        """
        The Issues section surfaces every non-OK entry — including new/untracked
        warnings and manifest-level errors — pulled above the per-manifest
        Manifests section.
        """
        good = report.ManifestResult(
            manifest_path=Path("good.mhl"),
            manifest_status="ok",
            file_results=[report.FileResult(path="ok.mxf", status="ok")],
        )
        bad = report.ManifestResult(
            manifest_path=Path("bad.mhl"),
            manifest_status="failed",
            file_results=[
                report.FileResult(path="bad.mxf", status="mismatch"),
                report.FileResult(path="extra.mxf", status="new"),
            ],
        )
        broken = report.ManifestResult(
            manifest_path=Path("broken.mhl"),
            manifest_status="error",
            manifest_error="parse failed",
        )
        out = self._render([good, bad, broken], exit_status=40)
        issues = out.split("Issues", 1)[1].split("Manifests", 1)[0]
        assert "bad.mxf" in issues
        assert "extra.mxf" in issues  # new/untracked included
        assert "parse failed" in issues  # manifest-level error included
        assert "ok.mxf" not in issues  # clean entries stay out

    def test_issues_section_omitted_when_all_ok(self):
        """No Issues heading when every file passed."""
        mr = report.ManifestResult(
            manifest_path=Path("m.mhl"),
            manifest_status="ok",
            file_results=[report.FileResult(path="ok.mxf", status="ok")],
        )
        out = self._render([mr], exit_status=0)
        assert "Issues" not in out

    def test_per_manifest_sub_summary_line(self):
        """
        Each manifest header is followed by its own verdict line; new/untracked
        is a warning and does not flip the manifest to FAILED.
        """
        mr = report.ManifestResult(
            manifest_path=Path("m.mhl"),
            manifest_status="ok",
            file_results=[
                report.FileResult(path="ok.mxf", status="ok"),
                report.FileResult(path="extra.mxf", status="new"),
            ],
        )
        details = self._render([mr], exit_status=0).split("Manifest\n", 1)[1]
        assert "📄 m.mhl" in details
        assert "✅ VERIFIED | 2 files | 1 verified | 1 new (untracked)" in details


class TestFormatFileResult:
    """_format_file_result is a pure status→string mapper; cover every arm."""

    def test_ok(self):
        out = report._format_file_result(report.FileResult(path="f.mxf", status="ok"))
        assert "✓" in out
        assert "f.mxf" in out

    def test_missing(self):
        out = report._format_file_result(report.FileResult(path="f.mxf", status="missing"))
        assert "missing" in out
        assert "f.mxf" in out

    def test_mismatch_with_verbose_detail_splits_label_and_parenthetical(self):
        fr = report.FileResult(path="f.mxf", status="mismatch", detail="hash mismatch: calc a | stored b")
        out = report._format_file_result(fr)
        assert "hash mismatch: f.mxf" in out
        assert "(calc a | stored b)" in out

    def test_mismatch_without_detail_uses_fallback(self):
        fr = report.FileResult(path="f.mxf", status="mismatch", detail="size mismatch")
        out = report._format_file_result(fr)
        assert "size mismatch: f.mxf" in out
        assert "\n" not in out  # no parenthetical second line

    def test_new(self):
        out = report._format_file_result(report.FileResult(path="f.mxf", status="new"))
        assert "new (untracked)" in out
        assert "f.mxf" in out

    def test_error_with_detail(self):
        fr = report.FileResult(path="f.mxf", status="error", detail="boom")
        out = report._format_file_result(fr)
        assert "error" in out
        assert "f.mxf" in out
        assert "(boom)" in out

    def test_error_without_detail(self):
        out = report._format_file_result(report.FileResult(path="f.mxf", status="error"))
        assert "error" in out
        assert "f.mxf" in out
        assert "\n" not in out  # no detail line
