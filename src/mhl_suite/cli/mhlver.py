#!/usr/bin/env python3
# =============================================================================
# mhlver — One MHL tool to verify them all (CLI)
# =============================================================================
# Copyright (c) 2026 Luis Gómez Gutiérrez. Licensed MIT.
#
# The mhlver command: walk a path, verify every MHL manifest under it (classic
# and ASC-MHL alike), and report. The cross-dialect verification engine lives in
# mhl_suite.verifyall (the print-free orchestrator); this module is the terminal
# front end — argument parsing, the rich progress bar, colour output, and the
# report file. It drives verifyall.verify_item per manifest and renders each
# returned StatusLine to the terminal via _report_via_table.
#
# Exit code policy: the first non-zero backend exit code becomes mhlver's
# exit code, so an automation script gets a meaningful signal even when many
# rolls verify together.
# =============================================================================

import argparse
import importlib.metadata
import sys
from datetime import datetime
from pathlib import Path
from typing import Protocol, TextIO

from rich.console import Console, Group
from rich.live import Live
from rich.progress import BarColumn, Progress, TextColumn
from rich.text import Text

from mhl_suite._internal.unicodepaths import normalization_variant_on_disk
from mhl_suite.shared.report import (
    FileResult,  # noqa: F401 — re-exported for tests
    ManifestResult,
    _format_file_result,  # noqa: F401 — re-exported for tests
    _open_report,
    _render_report,
)
from mhl_suite.verifyall import StatusLine, _manifest_weights, _select_mhl_files, verify_item

# -----------------------------------------------------------------------------
# Version
# -----------------------------------------------------------------------------

try:
    __version__ = importlib.metadata.version("mhl-suite")
except importlib.metadata.PackageNotFoundError:  # pragma: no cover
    __version__ = "unknown"

# -----------------------------------------------------------------------------
# Terminal colours
# -----------------------------------------------------------------------------
# We deliberately suppress colour codes when stdout is not a TTY (e.g. piped
# into a log file); otherwise the report file gets littered with raw ANSI
# escape sequences. The check happens once at module load.

if sys.stdout.isatty():
    RED = "\033[0;31m"
    ORANGE = "\033[38;5;208m"
    GREEN = "\033[0;32m"
    RESET = "\033[0m"
else:
    RED = ORANGE = GREEN = RESET = ""


# -----------------------------------------------------------------------------
# Logging helpers
# -----------------------------------------------------------------------------
# When a rich Progress bar is active, bare print()/sys.stderr.write() calls
# would tear through the live display. Callers that hold a Progress instance
# pass its console here via the `console` parameter so all terminal output is
# routed through rich's rendering pipeline instead.


class _ConsoleLike(Protocol):
    """Structural type for the `console` argument threaded through this module.

    Output is routed through a rich Console when a progress bar is live, but the
    only method ever used is .print(). Typing against this minimal Protocol
    rather than the concrete rich Console keeps the annotation honest about what
    is required and lets the test doubles (e.g. FakeConsole) satisfy it without
    an `Any` escape hatch or a cast. markup/highlight are
    declared keyword-only so their call sites stay type-checked; msg is
    positional-only so a single-positional double like FakeConsole conforms.
    """

    def print(self, msg: object, /, *, markup: bool = ..., highlight: bool = ...) -> None: ...


def _log(
    msg: str,
    *,
    colour: str,
    stream: TextIO | None,
    console: "_ConsoleLike | None" = None,
) -> None:
    """Print to a stream with colour, or route through a rich Console.

    If `console` is a rich Console instance, output is routed through it so
    the live progress bar is not disrupted.
    """
    if console is not None:
        # markup=False: filenames contain bracket sequences (e.g. "[26_163234]")
        # that rich would misinterpret as markup tags, causing bold artefacts.
        # highlight=False: prevents rich auto-colouring numbers/paths.
        console.print(msg, markup=False, highlight=False)
    else:
        print(f"{colour}{msg}{RESET}", file=stream)


def log_success(
    msg: str,
    console: "_ConsoleLike | None" = None,
) -> None:
    _log(msg, colour="", stream=sys.stdout, console=console)


def log_warning(
    msg: str,
    console: "_ConsoleLike | None" = None,
) -> None:
    _log(msg, colour=ORANGE, stream=sys.stderr, console=console)


def log_error(
    msg: str,
    console: "_ConsoleLike | None" = None,
) -> None:
    _log(msg, colour=RED, stream=sys.stderr, console=console)


# Report data model (FileResult / ManifestResult) and the report renderer live
# in mhl_suite.shared.report; the names this module uses are imported up top.


def _emit_step_output(
    out: str,
    exit_code: int,
    *,
    show_on_terminal: bool,
    console: "_ConsoleLike | None" = None,
) -> None:
    """
    Write captured backend output to the terminal when show_on_terminal is True.

    The terminal-suppression flag exists to avoid duplicating mhlver's own
    status line. mhlver translates each exit code into a clear human-readable
    message via the dispatch tables; for many ascmhl errors the backend's
    raw output is a near-restatement of that translation, so showing it
    twice just clutters the operator's terminal.

    Callers pass show_on_terminal=True for simple-mhl (whose per-file
    output is structured complementary info we want operators to see) and
    for any backend invocation when --verbose was requested.

    Colour: red on failure, no colour on success. Verbose `OK:` lines
    shouldn't look like errors just because they go through this same path.
    """
    if not out:
        return
    if show_on_terminal:
        if exit_code != 0:
            _log(out, colour=RED, stream=sys.stderr, console=console)
        else:
            _log(out, colour="", stream=sys.stdout, console=console)


# -----------------------------------------------------------------------------
# Exit-code dispatch tables
# -----------------------------------------------------------------------------
# Both backends return structured exit codes. Rather than long if/elif chains,
# we map exit_code -> (template, severity) and dispatch through a small helper.
# severity is "success" / "warning" / "error" and selects the logger.
#
# Templates use {target} which we .format() with the manifest's name or its
# package directory depending on the action.


# --- simple-mhl (classic MHL) verify exit codes ------------------------------
# These are the codes simple_mhl.py returns. Exit 70 was added in v1.0.2 to
# distinguish "missing AND mismatch" from either failure alone.
#
# Wording note: the per-file detail (which files, what kind of failure)
# comes from simple-mhl itself, which prints structured `ERROR: <category>:
# <path>` lines that are self-explanatory standalone. mhlver therefore only
# needs to say "this manifest failed" — the lines below explain why. The
# exit code itself still encodes the precise failure category for tooling.
# --- ASC-MHL (2.0) verify exit codes ----------------------------------------
# These come from the vendored ascmhl/errors.py (each a click.ClickException
# subclass carrying an exit_code), surfaced in-process by mhl_suite.ascmhl.verify.
#
# As with the classic MHL table, mhlver gives a single short status line per
# manifest; the per-file detail (which file mismatched, which manifest is
# missing) comes from the structured VerifyReport, rendered by
# _render_ascmhl_lines. The exit code preserves the precise failure category.
def _log_by_severity(
    severity: str,
    msg: str,
    console: "_ConsoleLike | None" = None,
) -> None:
    """Dispatch a message to the right logger based on its severity label."""
    if severity == "success":
        log_success(msg, console=console)
    elif severity == "warning":
        log_warning(msg, console=console)
    else:  # "error"
        log_error(msg, console=console)


def _report_via_table(
    table: dict[int, tuple[str, str]],
    exit_code: int,
    target_label: str,
    output: str,
    *,
    show_backend_output: bool,
    show_status_on_terminal: bool = True,
    console: "_ConsoleLike | None" = None,
) -> None:
    """
    Look up exit_code in `table`, log the appropriate message, and emit any
    captured backend output. Falls back to a clearly-marked 'unexpected'
    message for codes not in the table — surfaces the raw exit code so the
    operator can investigate rather than silently treating it as success.

    `show_backend_output` controls whether the backend's captured stdout/
    stderr is replayed to the terminal.

    `show_status_on_terminal` suppresses the per-manifest status line on the
    terminal when a progress bar is active (the bar communicates progress
    visually; the status lines are noise). Errors and warnings are always
    shown regardless, since those need operator attention immediately.
    """
    template, severity = table.get(
        exit_code,
        (f"🚨 Unexpected backend exit {exit_code} for {{target}}", "warning"),
    )
    msg = template.format(target=target_label)
    if show_status_on_terminal or severity != "success":
        _log_by_severity(severity, msg, console=console)
    _emit_step_output(
        output,
        exit_code,
        show_on_terminal=show_backend_output,
        console=console,
    )


# -----------------------------------------------------------------------------
# Progress bar helpers
# -----------------------------------------------------------------------------


# Hash element local-names simple-mhl can recompute (mirrors ALGO_MAP keys in
# simple_mhl). An entry whose only hash child is <null> — or which records no
# computable hash — is verified by size/existence alone and reads zero bytes,
# so its <size> must not weight the byte-based progress total.
def _render_status(sl: StatusLine, console: "_ConsoleLike | None" = None) -> None:
    """Render one orchestrator StatusLine to the terminal — the `emit` sink that
    verifyall.verify_item calls per manifest, routed through _report_via_table so
    the message colour and backend output match the rest of mhlver's output."""
    _report_via_table(
        sl.table,
        sl.code,
        sl.label,
        sl.output,
        show_backend_output=True,
        console=console,
    )


def _build_live() -> "tuple[Live, Progress, Text, Console]":
    """
    Construct a rich Live display for two-line progress output:

    We use Live + Group(Text, Progress) rather than two Progress tasks because
    rich renders all columns on every task row — there is no per-task column
    visibility. This approach keeps the label line completely clean (no bar
    artefacts) and the bar line completely clean (no spinner).
    """
    stdout_console = Console(file=sys.stdout, force_terminal=True)

    label = Text()
    label.append("🔎 Verifying… ", style="bold")
    label.append("scanning…", style="dim")

    # Bar columns: fill bar + percentage + manifest count.
    # Count is stored in task.fields["done"] and task.fields["total_n"]
    # and updated by the _run loop each iteration.
    progress = Progress(
        BarColumn(
            bar_width=None,
            complete_style="green",
            finished_style="green",
        ),
        TextColumn("{task.percentage:>3.0f}%"),
        TextColumn("({task.fields[done]}/{task.fields[total_n]} manifests)"),
        console=stdout_console,
        transient=False,
    )

    live = Live(
        Group(label, progress),
        console=stdout_console,
        refresh_per_second=20,
        transient=True,
    )
    return live, progress, label, stdout_console


# -----------------------------------------------------------------------------
# CLI entry point
# -----------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="mhlver",
        description="One tool to verify them all: find and verify MHL files or directories.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument(
        "-r",
        "--report",
        action="store_true",
        help="export a verification report to the target directory",
    )
    parser.add_argument(
        "-S",
        "--size-only",
        action="store_true",
        help="check file sizes only (skip hashing)",
    )
    parser.add_argument(
        "-s",
        "--xsd-schema-check",
        action="store_true",
        help="validate XML Schema Definition",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print invoked commands and per-file status",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument(
        "path",
        nargs="?",
        default=".",
        help="path to MHL file or directory (default: current directory)",
    )

    args = parser.parse_args()
    src = Path(args.path).resolve()

    if not src.exists():
        msg = "Argument should be a file or directory that exists in the filesystem"
        # On a normalization-sensitive filesystem the typed path may differ from
        # the on-disk name only in Unicode form; suggest the real spelling rather
        # than silently failing.
        variant = normalization_variant_on_disk(str(src))
        if variant is not None:
            msg += f"\n  A path with a different Unicode normalization exists — did you mean:\n    {variant}"
        log_error(msg)
        sys.exit(2)

    # -s (schema-check) and -S (size-only) are mutually exclusive modes
    if args.xsd_schema_check and args.size_only:
        msg = "Error: the XSD schema check (-s) and the size-only check (-S) cannot be executed together"
        log_error(msg)
        sys.exit(2)

    # Verification reports are meaningless with -s (schema-check) mode
    if args.xsd_schema_check and args.report:
        print("\nDid you mean 'mhlver -S -r'?\n")
        msg = "Error: reports (-r) for XSD schema checks (-s) are not supported"
        log_error(msg)
        sys.exit(2)

    # Write a report only if requested *and* at least one manifest was found.
    # Verify first, then open the file — opening it up front would leave an
    # empty log behind when a directory turns up no MHL files.
    if args.report:
        started_at = datetime.now().astimezone()
        exit_status, manifest_results, found = _run(src, args.verbose, args.xsd_schema_check, args.size_only)
        finished_at = datetime.now().astimezone()
        if found:
            with _open_report(src) as (rf, rp):
                _render_report(rf, src, started_at, finished_at, manifest_results, exit_status)
            print(f"report saved to: {rp}")
    else:
        exit_status, _, _ = _run(src, args.verbose, args.xsd_schema_check, args.size_only)

    sys.exit(exit_status)


def _verify_dir_with_progress(
    mhl_files: "list[Path]",
    weights: "dict[Path, int]",
    verbose: bool,
    schema: bool,
    size_only: bool,
) -> "tuple[int, list[ManifestResult], Console]":
    """
    Verify each manifest in `mhl_files` with a live rich progress bar.

    Returns (exit_status, manifest_results, console). exit_status follows the
    first-non-zero rule (see _run); console is the stdout-bound rich Console
    that callers reuse for the post-scan summary line so it lands below the bar.
    """
    exit_status = 0
    manifest_results: list[ManifestResult] = []

    live, progress, label, stdout_console = _build_live()
    total_n = len(mhl_files)
    total_bytes = sum(weights.values())
    bar_task = progress.add_task(" ", total=total_bytes, done=0, total_n=total_n)
    # Both backends now verify in-process and report byte progress via on_bytes,
    # so the rich Live display (auto-refreshing on its own timer, see _build_live)
    # animates the bar without any manual poll/refresh thread.
    with live:
        con = stdout_console
        for i, f in enumerate(mhl_files):
            label.plain = ""
            label.append("🔎 Verifying… ", style="bold")
            label.append(f.name, style="cyan")
            # Both backends report bytes per hashed file via on_bytes, so the bar
            # advances live within a manifest instead of jumping once at the end.
            # We track what was advanced and top up the remainder afterwards so the
            # manifest still contributes exactly its weight (covering size-only and
            # directory/<null> entries that read no media bytes).
            advanced_box: list[int] = [0]

            def _advance(n: int, box: list[int] = advanced_box) -> None:
                progress.advance(bar_task, n)
                box[0] += n

            code, mr = verify_item(
                f,
                verbose,
                schema,
                size_only,
                emit=lambda sl: _render_status(sl, con),
                on_bytes=_advance,
            )
            if mr is not None:
                manifest_results.append(mr)
            progress.advance(bar_task, max(0, weights[f] - advanced_box[0]))
            progress.update(bar_task, done=i + 1)
            if exit_status == 0:
                exit_status = code
        label.plain = ""
        label.append("🔎 Verifying… ", style="bold")
        label.append("done", style="green")

    return exit_status, manifest_results, stdout_console


def _run(src: Path, verbose: bool, schema: bool, size_only: bool = False) -> "tuple[int, list[ManifestResult], bool]":
    """
    Execute the verification pass on `src`.

    Returns (exit_status, manifest_results, found).

    exit_status: 0 if every MHL verified, otherwise the first non-zero code
    encountered in walk order. The first-non-zero rule gives automation a
    stable, non-zero signal on any failure without attempting to rank severity
    across independent manifests.

    manifest_results: collected per-manifest outcomes used to render the
    structured report when --report is active. Always populated regardless of
    whether --report was requested (cheap to collect, free to discard).

    found: True if at least one manifest was located to verify. False only
    when a directory scan turns up no MHL files (or src is neither file nor
    directory). manifest_results can't stand in for this: schema-check mode
    produces no per-manifest result even when manifests were found, so the
    report decision needs an explicit signal.

    Note: because the exit code is the *first* failure rather than the
    *worst*, a later more-severe failure (e.g. exit 40 hash mismatch) can
    be masked by an earlier milder one (e.g. exit 30 missing file). The
    per-manifest status lines printed to the terminal always show the full
    picture; the exit code is intentionally coarse.

    When rich is available and stderr is a TTY, a progress bar is shown for
    directory scans (single-file invocations are fast enough to not need one).
    All terminal output produced during verification — per-manifest status
    lines, backend ERROR: lines, verbose OK: lines — is routed through the
    rich Console so the live bar is not disrupted. The bar stays on screen
    after completion (transient=False); the summary line prints below it.
    """
    exit_status = 0
    manifest_results: list[ManifestResult] = []
    found = False

    if src.is_file():
        found = True
        code, mr = verify_item(src, verbose, schema, size_only, emit=_render_status)
        exit_status = code
        if mr is not None:
            manifest_results.append(mr)
        console = None

    elif src.is_dir():
        mhl_files = _select_mhl_files(src)
        found = bool(mhl_files)
        if not mhl_files:
            log_warning(f"No MHL files found under {src}")

        use_progress = sys.stdout.isatty() and len(mhl_files) > 0

        if use_progress:
            # Pre-read byte weights for accurate ETA (XML parse only, no
            # hashing). Classic MHL requires a <size> on every entry
            # (MediaHashList_v1_1.xsd), so a zero weight there means a
            # genuinely malformed manifest. ASC-MHL's size is an optional
            # path/@size attribute (ASCMHL.xsd) and is absent by design on
            # <directoryhash> entries, so a low/zero weight can be legitimate —
            # never an error, just a less precise ETA. Verify, not this
            # pre-read, is the source of truth; the weight only paces the bar.
            weights = _manifest_weights(mhl_files, size_only)
            exit_status, manifest_results, console = _verify_dir_with_progress(
                mhl_files, weights, verbose, schema, size_only
            )
        else:
            for f in mhl_files:
                code, mr = verify_item(f, verbose, schema, size_only, emit=_render_status)
                if mr is not None:
                    manifest_results.append(mr)
                if exit_status == 0:
                    exit_status = code
            console = None

    else:
        console = None

    # With no manifests found, the "No MHL files found" warning already stands
    # on its own — there's nothing to declare verified or failed.
    if not found:
        pass
    elif exit_status == 0:
        # Flag when any manifest relied on non-hash checks (<null>) — the ✨ becomes a
        # ⚠️ warning and the qualifier is appended.
        has_size_only = any(mr.n_size_only for mr in manifest_results)
        has_existence_only = any(mr.n_existence_only for mr in manifest_results)
        kinds = [k for k, present in (("size-only", has_size_only), ("existence-only", has_existence_only)) if present]
        emoji = "⚠️" if kinds else "✨️"
        suffix = f" (some of them with {' and '.join(kinds)} checks)." if kinds else "."
        log_success(
            f"{emoji} All MHL manifests have been successfully verified{suffix}",
            console=console,
        )
    else:
        log_error(
            "❌ Verification failed for some of the MHL files. See details above.",
            console=console,
        )
    return exit_status, manifest_results, found


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
