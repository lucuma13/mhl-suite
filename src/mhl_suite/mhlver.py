#!/usr/bin/env python3
# =============================================================================
# mhlver — One MHL tool to verify them all
# =============================================================================
# Copyright (c) 2026 Luis Gómez Gutiérrez. Licensed MIT.
#
# mhlver walks a path looking for MHL manifests and verifies each one by
# delegating to the right backend:
#
#     classic MHL (1.x)  -> shells out to `simple-mhl verify`
#     ASC-MHL  (2.0)    -> shells out to `ascmhl-debug verify`
#
# It detects ASC-MHL packages by the conventional `ascmhl/` folder containing
# the manifest. Each backend's exit code is translated into a human-readable
# status line via dispatch tables (see _CLASSICMHL_RESULTS, _ASCMHL_VERIFY_RESULTS).
#
# Exit code policy: the first non-zero backend exit code becomes mhlver's
# exit code, so an automation script gets a meaningful signal even when many
# rolls verify together.
# =============================================================================

import argparse
import importlib.metadata
import re
import shutil
import subprocess
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol, TextIO

from lxml import etree
from rich.console import Console, Group
from rich.live import Live
from rich.progress import BarColumn, Progress, TextColumn
from rich.text import Text

from mhl_suite._internal.unicodepaths import normalization_variant_on_disk

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


def _log(
    msg: str,
    *,
    colour: str,
    stream: TextIO | None,
    console: Any = None,  # noqa: ANN401 — duck-typed: accepts Console or test doubles
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
    console: Any = None,  # noqa: ANN401 — duck-typed: accepts Console or test doubles
) -> None:
    _log(msg, colour="", stream=sys.stdout, console=console)


def log_warning(
    msg: str,
    console: Any = None,  # noqa: ANN401 — duck-typed: accepts Console or test doubles
) -> None:
    _log(msg, colour=ORANGE, stream=sys.stderr, console=console)


def log_error(
    msg: str,
    console: Any = None,  # noqa: ANN401 — duck-typed: accepts Console or test doubles
) -> None:
    _log(msg, colour=RED, stream=sys.stderr, console=console)


# -----------------------------------------------------------------------------
# Command resolution
# -----------------------------------------------------------------------------


def get_command_path(cmd_name: str) -> str | None:
    """
    Find a command in the active venv first, falling back to the system PATH.

    When mhlver is installed via `pip install` into a venv, the helper
    binaries (simple-mhl, ascmhl-debug) live in the same venv's bin/.
    We check there first so that a venv-installed mhlver doesn't accidentally
    invoke a globally-installed simple-mhl that might be a different version.
    """
    venv_bin = Path(sys.prefix) / ("Scripts" if sys.platform == "win32" else "bin")
    candidate = venv_bin / cmd_name
    if candidate.exists():
        return str(candidate)
    return shutil.which(cmd_name)


# -----------------------------------------------------------------------------
# Subprocess helper
# -----------------------------------------------------------------------------


@dataclass
class StepResult:
    """Outcome of a single subprocess invocation."""

    exit_code: int
    output: str  # stdout + stderr combined and stripped


# -----------------------------------------------------------------------------
# Report data model
# -----------------------------------------------------------------------------
# FileResult and ManifestResult are populated by parsing backend output when
# --report is requested. They are kept entirely separate from the terminal
# output path so that the existing streaming log behaviour is not affected.
#
# status values:
#   "ok"        — file verified successfully
#   "missing"   — file not found on disk
#   "mismatch"  — hash (or size) does not match the manifest
#   "new"       — file found on disk but not recorded in ASC-MHL history
#   "error"     — any other per-file problem (traversal block, bad algo, etc.)
#
# manifest_status values:
#   "ok"        — all files verified
#   "failed"    — one or more per-file failures
#   "error"     — manifest-level failure (malformed XML, backend not found, etc.)


@dataclass
class FileResult:
    """Outcome for a single file entry within a manifest."""

    path: str  # relative path as recorded in the manifest
    status: str  # "ok" | "missing" | "mismatch" | "new" | "error"
    detail: str = ""  # extra info: mismatch hashes, error reason, etc.


@dataclass
class ManifestResult:
    """Collected results for one manifest file."""

    manifest_path: Path
    manifest_status: str  # "ok" | "failed" | "error"
    manifest_error: str = ""  # set when manifest_status == "error"
    file_results: list[FileResult] = field(default_factory=list)

    # Convenience counts — computed once after collection is complete.
    @property
    def n_ok(self) -> int:
        return sum(1 for r in self.file_results if r.status == "ok")

    @property
    def n_missing(self) -> int:
        return sum(1 for r in self.file_results if r.status == "missing")

    @property
    def n_mismatch(self) -> int:
        return sum(1 for r in self.file_results if r.status == "mismatch")

    @property
    def n_new(self) -> int:
        return sum(1 for r in self.file_results if r.status == "new")

    @property
    def n_error(self) -> int:
        return sum(1 for r in self.file_results if r.status == "error")

    @property
    def n_files(self) -> int:
        return len(self.file_results)


# --- Output parsers -----------------------------------------------------------
#
# Each parser turns raw backend stdout+stderr into a list[FileResult].
# Both parsers are intentionally defensive: unrecognised lines are silently
# skipped so that future backend output changes degrade gracefully rather
# than raising exceptions.

# simple-mhl verify -v line patterns (bracket format):
#   [OK] <path>
#   [ERROR] missing file: <path>
#   [ERROR] hash mismatch: <path>
#   [ERROR] hash mismatch: <path>          <- followed by indented detail line (verbose)
#           (calc <tag>: <hex> | stored <tag>: <hex>)
#   [ERROR] size mismatch: <path>
#           (calc size: <n> | stored size: <n>)  <- verbose only
#   [ERROR] malformed size field: <path>
#   [ERROR] no supported hash found: <path>
#   [ERROR] blocked traversal attempt: <path>
#   [ERROR] cannot verify <path>: <reason>

_CLASSICMHL_OK = re.compile(r"^\[OK\] (.+)$")
_CLASSICMHL_MISSING = re.compile(r"^\[ERROR\] missing file: (.+)$")
_CLASSICMHL_MISMATCH = re.compile(r"^\[ERROR\] (hash mismatch|size mismatch): (.+)$")
_CLASSICMHL_ERROR = re.compile(
    r"^\[ERROR\] (?:malformed size field|no supported hash found|blocked traversal attempt): (.+)$"
)
_CLASSICMHL_CANNOT_VERIFY = re.compile(r"^\[ERROR\] cannot verify (.+?): (.+)$")
_CLASSICMHL_DETAIL = re.compile(r"^\s+\((.+)\)$")  # indented detail line after a mismatch


def _parse_classicmhl_output(output: str) -> list[FileResult]:
    """Parse simple-mhl verify output into FileResult entries.

    Simple-mhl emits structured [OK] / [ERROR] lines. Verbose mode appends a
    second indented detail line for hash and size mismatches:

        [ERROR] hash mismatch: path/to/file.mxf
                (calc xxhash64be: abc… | stored xxhash64be: def…)

    The parser collects these pairs: when a mismatch line is seen, the next
    line is checked for a detail parenthetical and attached if found.
    All other detail is passed through verbatim from the bracket prefix onward.
    """
    lines = output.splitlines()
    results: list[FileResult] = []
    i = 0
    while i < len(lines):
        stripped = lines[i].strip()

        if m := _CLASSICMHL_OK.match(stripped):
            results.append(FileResult(path=m.group(1), status="ok"))

        elif m := _CLASSICMHL_MISSING.match(stripped):
            results.append(FileResult(path=m.group(1), status="missing"))

        elif m := _CLASSICMHL_MISMATCH.match(stripped):
            mtype = m.group(1)  # "hash mismatch" | "size mismatch"
            path = m.group(2)
            # Peek at next line for optional verbose detail.
            detail = mtype
            if i + 1 < len(lines) and (d := _CLASSICMHL_DETAIL.match(lines[i + 1])):
                detail = f"{mtype}: {d.group(1)}"
                i += 1  # consume the detail line
            results.append(FileResult(path=path, status="mismatch", detail=detail))

        elif m := _CLASSICMHL_ERROR.match(stripped):
            # Everything after "[ERROR] <category>: " is the path; the category
            # itself is the useful detail label.
            category = re.match(r"^\[ERROR\] (.+?): .+$", stripped)
            detail = category.group(1) if category else stripped
            results.append(FileResult(path=m.group(1), status="error", detail=detail))

        elif m := _CLASSICMHL_CANNOT_VERIFY.match(stripped):
            results.append(FileResult(path=m.group(1), status="error", detail=m.group(2)))

        i += 1
    return results


# ascmhl-debug verify -v line patterns:
#   verification (xxh64) of file <path>: OK
#   ERROR: hash mismatch        for <path> old xxh64: <hex>, new xxh64: <hex>
#   found new file <path>
#   ERROR: <N> missing file(s):          <- block header
#     <path>                             <- one or more indented paths follow
#   check folder at path: <path>         <- informational, skip
#   ignoring filepath <path>             <- informational, skip
#   Error: <message>                     <- manifest-level summary, skip

_ASCMHL_OK = re.compile(r"^verification \(.+?\) of file (.+): OK$")
_ASCMHL_MISMATCH = re.compile(r"^ERROR: hash mismatch\s+for (.+?) old (\S+): (\S+), new (\S+): (\S+)$")
_ASCMHL_NEW = re.compile(r"^found new file (.+)$")
_ASCMHL_MISSING_HEADER = re.compile(r"^ERROR: \d+ missing file\(s\):$")
_ASCMHL_MISSING_ENTRY = re.compile(r"^\s+(\S.+)$")  # indented path under missing header


def _parse_ascmhl_output(output: str) -> list[FileResult]:
    """Parse ascmhl-debug verify -v output into FileResult entries."""
    results: list[FileResult] = []
    in_missing_block = False

    for line in output.splitlines():
        # Missing block: header sets the flag; indented paths are consumed.
        if _ASCMHL_MISSING_HEADER.match(line.strip()):
            in_missing_block = True
            continue
        if in_missing_block:
            if m := _ASCMHL_MISSING_ENTRY.match(line):
                results.append(FileResult(path=m.group(1).strip(), status="missing"))
                continue
            # Any non-indented line ends the block.
            in_missing_block = False

        stripped = line.strip()
        if m := _ASCMHL_OK.match(stripped):
            results.append(FileResult(path=m.group(1), status="ok"))
        elif m := _ASCMHL_MISMATCH.match(stripped):
            # groups: path, old_algo, old_hex, new_algo, new_hex
            # ascmhl reports: old = stored (from manifest history), new = calculated
            algo = m.group(2)  # old and new algo should be the same
            detail = f"hash mismatch: calc {algo}: {m.group(5)} | stored {algo}: {m.group(3)}"
            results.append(FileResult(path=m.group(1), status="mismatch", detail=detail))
        elif m := _ASCMHL_NEW.match(stripped):
            results.append(FileResult(path=m.group(1), status="new"))
        # Informational lines (check folder, ignoring filepath, Error: …) are skipped.

    return results


class _PollEvent(Protocol):
    """Structural type for the on_poll argument accepted by _run_step.

    Only set() is called by the ticker thread, so any object that provides
    it satisfies the contract — threading.Event, a counting shim in tests,
    or any other compatible type.  Using a Protocol rather than the concrete
    threading.Event keeps the annotation honest and lets test doubles pass
    the type-checker without a cast.
    """

    def set(self) -> None: ...


def _run_step(
    cmd: list[str],
    cwd: Path | None = None,
    on_poll: "_PollEvent | None" = None,
) -> StepResult:
    """
    Run `cmd` and return its exit code plus combined stdout+stderr.

    We capture both streams together because either could carry diagnostic
    information from the backend; presenting them merged matches what an
    operator would see if they ran the command interactively.

    `cwd` is set when calling ascmhl-debug so it can find its bundled XSD
    files via relative paths. For simple-mhl we pass cwd=None since it
    locates its XSD via importlib.resources.

    `on_poll` is any object satisfying _PollEvent (typically a threading.Event)
    that is set() each time the ticker thread fires (every ~100 ms) while the
    subprocess is running. The progress bar uses this to animate.

    IMPORTANT — why we do NOT poll+wait before calling communicate():
    Popen with stdout=PIPE and stderr=PIPE gives the child two kernel pipe
    buffers (default 64 KB each on macOS/Linux). If the child writes more
    than that before the parent reads, the child blocks on its next write()
    and can never exit — while the parent's poll loop spins forever waiting
    for the child to exit. Classic deadlock.

    communicate() avoids this by draining both pipes concurrently with
    internal reader threads. We therefore call it immediately and drive
    on_poll ticks from a separate lightweight timer thread so the progress
    bar continues animating without touching the pipe-draining path.
    """
    proc = subprocess.Popen(
        cmd,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # Fire on_poll ticks from a background thread so the main thread can sit
    # in communicate() uninterrupted. The stop flag is a threading.Event
    # rather than a plain bool so the ticker sleeps efficiently (wait() with
    # a timeout) instead of busy-looping with time.sleep().
    stop_ticking = threading.Event()

    def _ticker() -> None:
        while not stop_ticking.is_set():
            if on_poll is not None:
                on_poll.set()
            stop_ticking.wait(timeout=0.1)

    ticker_thread: threading.Thread | None = None
    if on_poll is not None:
        ticker_thread = threading.Thread(target=_ticker, daemon=True)
        ticker_thread.start()

    try:
        stdout, stderr = proc.communicate()
    finally:
        stop_ticking.set()
        if ticker_thread is not None:
            ticker_thread.join()

    combined = ((stdout or "") + (stderr or "")).strip()
    return StepResult(exit_code=proc.returncode, output=combined)


def _emit_step_output(
    out: str,
    exit_code: int,
    *,
    show_on_terminal: bool,
    console: Any = None,  # noqa: ANN401 — duck-typed: accepts Console or test doubles
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
_CLASSICMHL_RESULTS: dict[int, tuple[str, str]] = {
    0: ("✅ MHL verified: {target}", "success"),
    1: (
        "🚨 Verification Error: {target} — file not found or invalid argument (not an MHL file).",
        "warning",
    ),
    10: ("⚠️ Schema non-compliant: {target}", "error"),
    20: ("🚨 Malformed XML: {target} cannot be parsed.", "warning"),
    30: ("❌ Verification failed: {target}", "error"),
    40: ("❌ Verification failed: {target}", "error"),
    70: ("❌ Verification failed: {target}", "error"),
    127: (
        "🚨 System error: 'simple-mhl' command not found. Ensure it is in your PATH.",
        "warning",
    ),
}

# Schema-check uses the same codes but with a different success message,
# plus exit 60 which is unique to schema-check (XSD not found on disk).
_CLASSICMHL_SCHEMA_RESULTS: dict[int, tuple[str, str]] = {
    **_CLASSICMHL_RESULTS,
    0: ("📝 MHL schema valid: {target}", "success"),
    60: (
        "🚨 Schema check unavailable: simple-mhl could not locate its bundled XSD file.",
        "warning",
    ),
}

# --- ascmhl-debug (ASC-MHL 2.0) verify exit codes ---------------------------
# These come from ascmhl/errors.py in the upstream Pomfort package. Each
# corresponds to a click.ClickException subclass.
#
# As with the classic MHL table, mhlver gives a single short status line per
# manifest. ascmhl-debug emits its own `logger.error(...)` lines describing
# what went wrong (which file mismatched, which manifest is missing, etc.);
# those lines are passed through to the terminal so the operator sees the
# detail. The exit code preserves the precise failure category for tooling.
_ASCMHL_VERIFY_RESULTS: dict[int, tuple[str, str]] = {
    0: ("✅ ASC-MHL verified: {target}", "success"),
    10: ("❌ ASC-MHL verification failed: {target}", "error"),
    11: ("❌ ASC-MHL verification failed: {target}", "error"),
    12: ("❌ ASC-MHL verification failed: {target}", "error"),
    20: ("❌ ASC-MHL verification failed: {target}", "error"),
    21: (
        "⚠️ ASC-MHL: new files found in {target} that are not recorded in history.",
        "error",
    ),
    30: ("❌ ASC-MHL verification failed: {target}", "error"),
    31: ("❌ ASC-MHL verification failed: {target}", "error"),
    32: ("❌ ASC-MHL verification failed: {target}", "error"),
    33: ("❌ ASC-MHL verification failed: {target}", "error"),
    127: (
        "🚨 System error: 'ascmhl-debug' command not found. Ensure it is in your PATH.",
        "warning",
    ),
}

# ASC-MHL xsd-schema-check uses VerificationFailedException (code 11) for
# schema-non-compliance, which deserves its own message distinct from the
# verify path's "hash mismatch" interpretation of the same code.
_ASCMHL_SCHEMA_RESULTS: dict[int, tuple[str, str]] = {
    0: ("📝 ASC-MHL schema valid: {target}", "success"),
    11: (
        "⚠️ ASC-MHL schema non-compliant: {target} does not match the ASC-MHL schema.",
        "error",
    ),
    127: (
        "🚨 System error: 'ascmhl-debug' command not found. Ensure it is in your PATH.",
        "warning",
    ),
}


def _log_by_severity(
    severity: str,
    msg: str,
    console: Any = None,  # noqa: ANN401 — duck-typed: accepts Console or test doubles
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
    console: Any = None,  # noqa: ANN401 — duck-typed: accepts Console or test doubles
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


def _verbose_announce(
    cmd: list[str],
    cwd: Path | None,
    verbose: bool,
    console: Any = None,  # noqa: ANN401 — duck-typed: accepts Console or test doubles
) -> None:
    """
    When --verbose, print the exact command (and cwd) that's about to run.

    Operators trying to reproduce a failure manually need the actual
    invocation, not a paraphrase. Showing this BEFORE the run also lets
    them see how far we got if the backend crashes mid-execution.
    """
    if not verbose:
        return
    rendered = " ".join(cmd)
    line = f"  ↪ running: {rendered}"
    if cwd is not None:
        line += f"  (cwd={cwd})"
    if console is not None:
        console.print(line)
    else:
        print(line, file=sys.stderr)


# -----------------------------------------------------------------------------
# verify_item — main per-MHL dispatcher
# -----------------------------------------------------------------------------


def verify_item(
    target: Path,
    verbose: bool,
    schema: bool,
    console: Any = None,  # noqa: ANN401 — duck-typed: accepts Console or test doubles
    progress_active: bool = False,
    poll_event: "threading.Event | None" = None,
) -> "tuple[int, ManifestResult | None]":
    """
    Verify a single MHL manifest, dispatching to the right backend.

    Detection rule: if any path component is exactly 'ascmhl' the manifest
    belongs to an ASC-MHL package; otherwise it's classic MHL. This matches
    the convention used by ascmhl-debug, where manifests live at
    `<root>/ascmhl/manifest.mhl`.

    `progress_active` suppresses per-manifest success lines on the terminal
    when a rich progress bar is already communicating progress visually.
    Errors and warnings are always shown.

    Returns (exit_code, ManifestResult | None). ManifestResult is None when
    schema-check mode is active (no per-file detail is available then).
    """
    if "ascmhl" in target.parts:
        return _verify_ascmhl(
            target,
            verbose,
            schema,
            console=console,
            progress_active=progress_active,
            poll_event=poll_event,
        )
    return _verify_classicmhl(
        target,
        verbose,
        schema,
        console=console,
        progress_active=progress_active,
        poll_event=poll_event,
    )


# --- Classic MHL (1.x) path ----------------------------------------------------


def _verify_classicmhl(
    target: Path,
    verbose: bool,
    schema: bool,
    console: Any = None,  # noqa: ANN401 — duck-typed: accepts Console or test doubles
    progress_active: bool = False,
    poll_event: "threading.Event | None" = None,
) -> "tuple[int, ManifestResult | None]":
    """Run simple-mhl against a classic MHL manifest and translate the result."""
    cmd_path = get_command_path("simple-mhl")
    if not cmd_path:
        # 127 is the conventional 'command not found' exit code; keep the
        # same so report-aggregation tooling can detect it consistently
        # across both backends.
        msg, sev = _CLASSICMHL_RESULTS[127]
        _log_by_severity(sev, msg, console=console)
        mr = ManifestResult(
            manifest_path=target,
            manifest_status="error",
            manifest_error=msg,
        )
        return 127, mr

    sub = "xsd-schema-check" if schema else "verify"
    cmd = [cmd_path, sub, str(target)]
    # Pass -v through to simple-mhl when in verbose mode (only for verify;
    # xsd-schema-check has no notion of per-file OK lines). simple-mhl will
    # then emit `OK: <path>` for every successfully verified file, which
    # mhlver's "always show classic MHL backend output" rule will surface.
    #
    # For report collection we always pass -v even when the user didn't ask
    # for it, so we can parse per-file OK lines. The extra output never
    # reaches the terminal (show_backend_output remains driven by verbose),
    # so the user experience is unchanged.
    cmd_for_report = cmd + (["-v"] if not verbose and not schema else [])
    if verbose and not schema:
        cmd.append("-v")
    _verbose_announce(cmd, cwd=None, verbose=verbose, console=console)

    # Run with -v for report collection; run the user-facing command for terminal.
    # When verbose is already set both are the same invocation, so we avoid
    # running the subprocess twice.
    if not verbose and not schema:
        # Run once with -v to get full per-file output for the report.
        step = _run_step(cmd_for_report, on_poll=poll_event)
        # Run again without -v for the terminal (silent on success as the user expects).
        step_terminal = _run_step(cmd, on_poll=poll_event)
    else:
        step = _run_step(cmd, on_poll=poll_event)
        step_terminal = step

    # simple-mhl is a tool we control. Its per-file output uses structured
    # `ERROR: <category>: <path>` and `OK: <path>` prefixes that stand
    # alone — they aren't restatements of mhlver's summary line. Always
    # show on terminal.
    table = _CLASSICMHL_SCHEMA_RESULTS if schema else _CLASSICMHL_RESULTS
    _report_via_table(
        table,
        step_terminal.exit_code,
        target.name,
        step_terminal.output,
        show_backend_output=True,
        show_status_on_terminal=not progress_active,
        console=console,
    )

    # Build ManifestResult from the -v output (not available for schema-check).
    if schema:
        return step.exit_code, None

    file_results = _parse_classicmhl_output(step.output)
    if step.exit_code == 0:
        mstatus = "ok"
    elif file_results:
        mstatus = "failed"
    else:
        mstatus = "error"
    template, _ = table.get(step.exit_code, ("Unexpected exit {code}", "warning"))
    merror = "" if mstatus != "error" else template.format(target=target.name)
    mr = ManifestResult(
        manifest_path=target,
        manifest_status=mstatus,
        manifest_error=merror,
        file_results=file_results,
    )
    return step.exit_code, mr


# --- ASC-MHL (2.0) path -------------------------------------------------------


def _verify_ascmhl(
    target: Path,
    verbose: bool,
    schema: bool,
    console: Any = None,  # noqa: ANN401 — duck-typed: accepts Console or test doubles
    progress_active: bool = False,
    poll_event: "threading.Event | None" = None,
) -> "tuple[int, ManifestResult | None]":
    """Run ascmhl-debug against an ASC-MHL manifest and translate the result."""
    cmd_path = get_command_path("ascmhl-debug")
    if not cmd_path:
        msg, sev = _ASCMHL_VERIFY_RESULTS[127]
        _log_by_severity(sev, msg, console=console)
        mr = ManifestResult(
            manifest_path=target,
            manifest_status="error",
            manifest_error=msg,
        )
        return 127, mr

    # ascmhl-debug expects to find its bundled XSDs via paths relative to
    # its working directory. Setting cwd to the directory containing this
    # script lets it locate them when the suite is installed alongside.
    # Path(__file__).resolve().parent is always valid — if it didn't exist,
    # Python would have failed to import this module.
    cwd = Path(__file__).resolve().parent

    if schema:
        code = _ascmhl_schema_check(
            target,
            cmd_path,
            cwd,
            verbose,
            console=console,
            progress_active=progress_active,
            poll_event=poll_event,
        )
        return code, None
    return _ascmhl_verify(
        target,
        cmd_path,
        cwd,
        verbose,
        console=console,
        progress_active=progress_active,
        poll_event=poll_event,
    )


def _ascmhl_schema_check(
    target: Path,
    cmd_path: str,
    cwd: Path | None,
    verbose: bool,
    console: Any = None,  # noqa: ANN401 — duck-typed: accepts Console or test doubles
    progress_active: bool = False,
    poll_event: "threading.Event | None" = None,
) -> int:
    """
    Schema-check both halves of an ASC-MHL package: the manifest itself
    and the sibling ascmhl_chain.xml directory file.

    Both checks always run; the worst exit code (preferring the manifest's)
    is returned so the caller has a single signal.

    Backend output is always shown — XSD validation errors from ascmhl
    typically include line numbers and structural detail that an operator
    needs to fix the manifest. Suppressing them would force the operator
    to re-run with -v, which defeats the purpose.
    """
    # Step 1: the .mhl manifest against the manifest schema.
    mhl_cmd = [cmd_path, "xsd-schema-check", str(target)]
    _verbose_announce(mhl_cmd, cwd, verbose, console=console)
    mhl_step = _run_step(mhl_cmd, cwd=cwd, on_poll=poll_event)
    _report_via_table(
        _ASCMHL_SCHEMA_RESULTS,
        mhl_step.exit_code,
        str(target),
        mhl_step.output,
        show_backend_output=True,
        show_status_on_terminal=not progress_active,
        console=console,
    )

    # Step 2: ascmhl_chain.xml against the directory schema
    chain_file = target.parent / "ascmhl_chain.xml"
    chain_cmd = [cmd_path, "xsd-schema-check", "--directory_file", str(chain_file)]
    _verbose_announce(chain_cmd, cwd, verbose, console=console)
    chain_step = _run_step(chain_cmd, cwd=cwd, on_poll=poll_event)
    _report_via_table(
        _ASCMHL_SCHEMA_RESULTS,
        chain_step.exit_code,
        str(chain_file),
        chain_step.output,
        show_backend_output=True,
        show_status_on_terminal=not progress_active,
        console=console,
    )

    # Manifest failure takes priority; otherwise the chain's code wins.
    return mhl_step.exit_code if mhl_step.exit_code != 0 else chain_step.exit_code


def _ascmhl_verify(
    target: Path,
    cmd_path: str,
    cwd: Path | None,
    verbose: bool,
    console: Any = None,  # noqa: ANN401 — duck-typed: accepts Console or test doubles
    progress_active: bool = False,
    poll_event: "threading.Event | None" = None,
) -> "tuple[int, ManifestResult]":
    """
    Run ascmhl-debug verify against the package directory.

    ASC-MHL convention: the manifest at <root>/ascmhl/manifest.mhl
    describes the contents of <root>. ascmhl-debug verify takes <root>
    as its argument, so we hand it the parent of the parent of the
    manifest path.

    The --verbose flag has two effects here:
      1. Adds -v to the ascmhl-debug invocation, which makes ascmhl emit
         per-file "verification of X: OK" lines via its own logger.
      2. Prints the exact command being run before invocation, useful
         when reproducing a failure manually.

    Backend output is ALWAYS shown on the terminal: ascmhl's logger.error
    lines are the per-file explanation that complements mhlver's short
    summary, much like simple-mhl's ERROR: prefixed lines do for classic MHL.

    For report collection we always pass -v to ascmhl-debug so we can
    parse the per-file OK lines, running a second quiet invocation for
    the user-facing terminal output when the user didn't request --verbose.
    """
    package_dir = target.parent.parent

    cmd = [cmd_path, "verify"]
    if verbose:
        cmd.append("-v")
    cmd.append(str(package_dir))

    cmd_verbose = [cmd_path, "verify", "-v", str(package_dir)]

    _verbose_announce(cmd, cwd, verbose, console=console)

    # Always run with -v for report collection.  When the user also asked
    # for --verbose both commands are identical and we avoid the extra run.
    if not verbose:
        step_verbose = _run_step(cmd_verbose, cwd=cwd, on_poll=poll_event)
        step_terminal = _run_step(cmd, cwd=cwd, on_poll=poll_event)
    else:
        step_verbose = _run_step(cmd, cwd=cwd, on_poll=poll_event)
        step_terminal = step_verbose

    _report_via_table(
        _ASCMHL_VERIFY_RESULTS,
        step_terminal.exit_code,
        str(package_dir),
        step_terminal.output,
        show_backend_output=True,
        show_status_on_terminal=not progress_active,
        console=console,
    )

    file_results = _parse_ascmhl_output(step_verbose.output)
    mstatus = "ok" if step_terminal.exit_code == 0 else "failed"
    mr = ManifestResult(
        manifest_path=target,
        manifest_status=mstatus,
        file_results=file_results,
    )
    return step_terminal.exit_code, mr


# -----------------------------------------------------------------------------
# Filesystem walking
# -----------------------------------------------------------------------------


def find_mhl_files(root: Path) -> Iterator[Path]:
    """
    Yield every .mhl file under `root`, case-insensitively, skipping
    macOS resource forks (filenames starting with '._').

    rglob's pattern syntax with character classes is the only portable way
    to do case-insensitive matching in pathlib without a fnmatch fallback.
    """
    for p in root.rglob("*.[mM][hH][lL]"):
        if not p.name.startswith("._"):
            yield p


def _select_mhl_files(root: Path) -> list[Path]:
    """
    Return a sorted list of MHL files to verify, deduplicating ASC-MHL
    packages (one MHL per package even if multiple .mhl files exist).

    An ASC-MHL package is identified by its `ascmhl/` folder. When that
    folder contains multiple manifests (one per generation, e.g. 0001.mhl,
    0002.mhl), running verify on any of them verifies the whole package,
    so we pick the lexicographically last one (latest generation) per
    package and skip the rest.

    Implementation: we iterate in sorted order and track the chosen manifest
    per package root in a dict. Because later entries in sorted order are
    lexicographically greater, the final value in the dict is always the
    latest generation — no list rebuild needed.
    """
    # Maps package_root -> the latest manifest seen so far for that package.
    # For classic MHL files (not inside an ascmhl/ folder) we use the file
    # path itself as its own key so they pass through unchanged.
    latest: dict[Path, Path] = {}

    for f in sorted(find_mhl_files(root)):
        key = f.parent.parent if f.parent.name == "ascmhl" else f  # ascmhl: pkg root; classic mhl: file itself
        latest[key] = f  # sorted order → last write wins

    # Re-sort the values to preserve the original output order (dict insertion
    # order is sorted-key order here, but an explicit sort is clearer).
    return sorted(latest.values())


# -----------------------------------------------------------------------------
# Progress bar helpers
# -----------------------------------------------------------------------------


def _mhl_total_bytes(mhl_file: Path) -> int:
    """
    Sum the <size> elements in a classic MHL 1.x manifest to get the total
    byte weight of the files it covers.

    Used to weight progress-bar units by actual data volume rather than
    manifest count, giving a more accurate ETA when manifests vary wildly
    in size (e.g. 500 GB camera originals vs 2 GB proxies).
    """

    try:
        tree = etree.parse(str(mhl_file))
        return sum(int(el.text) for el in tree.iterfind(".//{*}size") if el.text and el.text.strip().isdecimal())
    except (OSError, ValueError, etree.XMLSyntaxError):
        return 0


def _ascmhl_total_bytes(latest_mhl: Path) -> int:
    """
    Sum the ``size`` attributes on ``<path>`` elements across every .mhl
    generation file in an ASC-MHL package, counting each file path only once.

    Per the ASC-MHL 2.0 schema (ASCMHL.xsd), file sizes are stored as an
    attribute of the ``<path>`` element inside each ``<hash>`` record::

        <hash>
          <path size="1234567">relative/path/to/clip.mov</path>
          …
        </hash>

    ``latest_mhl`` is the lexicographically last generation file chosen by
    ``_select_mhl_files`` (e.g. ``ascmhl/0003.mhl``).  Because each
    generation only records *new or changed* files, summing only the latest
    generation would undercount the full corpus.  We therefore parse all
    ``.mhl`` files in the same ``ascmhl/`` directory in filename order
    (which matches the ``sequencenr`` order in ``ascmhl_chain.xml``).

    A verification pass re-records every file with ``action="verified"`` at
    the same size, so naively summing all generations double- (or triple-)
    counts files that appear in multiple passes.  We deduplicate by relative
    path: the first generation to record a path wins its size; later
    occurrences of the same path are skipped.
    """

    ascmhl_dir = latest_mhl.parent  # the ascmhl/ folder
    seen: set[str] = set()
    total = 0
    for mhl_path in sorted(ascmhl_dir.glob("*.mhl")):
        try:
            tree = etree.parse(str(mhl_path))
            for el in tree.iterfind(".//{*}path"):
                rel = (el.text or "").strip()
                if not rel or rel in seen:
                    continue
                size_str = el.get("size", "")
                if size_str.strip().isdecimal():
                    seen.add(rel)
                    total += int(size_str)
        except (OSError, ValueError, etree.XMLSyntaxError):
            pass  # skip unreadable generation files; others still count
    return total


def _build_live() -> "tuple[Live, Progress, Text, Console]":
    """
    Construct a rich Live display for two-line progress output:

      Line 1:  🔎 Verifying… XW001_2026-04-26.mhl        (plain Text, updated each manifest)
      Line 2:   ╸━━━━━━━━━  0% — ETA 0:03:32. Elapsed 0:00:25  (Progress bar)

    We use Live + Group(Text, Progress) rather than two Progress tasks because
    rich renders all columns on every task row — there is no per-task column
    visibility. This approach keeps the label line completely clean (no bar
    artefacts) and the bar line completely clean (no spinner).

    Colour design:
    - Bar filled green, track default dim.
    - Percentage white.
    - "ETA" / "Elapsed" labels dim; their values use rich's default (white).
    - Output on stdout with force_terminal=True for uv run compatibility.
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
# Report file
# -----------------------------------------------------------------------------


@contextmanager
def _open_report(src: Path) -> Iterator[tuple[TextIO, Path]]:
    """
    Open a timestamped report log next to `src` and yield (file, path).

    Context-manager form ensures the file is always closed and we don't
    have to thread try/finally through the main flow. The path is yielded
    so we can echo it on completion ("report saved to: ...").

    Unlike the old streaming approach, this file handle is only used by
    _render_report() which writes the complete structured report at the
    end of the verification run. Nothing is written here at open time.
    """
    report_dir = src if src.is_dir() else src.parent
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = report_dir / f"mhlver_report_{src.name}_{timestamp}.log"
    with open(report_path, "w", encoding="utf-8") as fh:
        yield fh, report_path


_W = 119  # total report width (matches the === / --- separator length)
_SEP_HEAVY = "=" * _W
_SEP_LIGHT = "-" * _W


def _render_report(
    fh: TextIO,
    src: Path,
    started_at: datetime,
    manifest_results: list[ManifestResult],
    exit_status: int,
) -> None:
    """
    Write the structured verification report to fh.
    """

    def line(s: str = "") -> None:
        fh.write(s + "\n")

    # ── Header ────────────────────────────────────────────────────────────────
    line(_SEP_HEAVY)
    line("MHL Verification Report")
    line(_SEP_HEAVY)
    line()

    date_str = started_at.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")

    line(f"Tool:       mhlver {__version__}")
    line(f"Date:       {date_str}")
    line(f"Source:     {src}")
    line()

    # ── Summary ───────────────────────────────────────────────────────────────
    line("Summary")
    line(_SEP_LIGHT)

    # Aggregate counts across all manifests.
    n_manifests = len(manifest_results)
    n_files = sum(mr.n_files for mr in manifest_results)
    n_ok = sum(mr.n_ok for mr in manifest_results)
    n_missing = sum(mr.n_missing for mr in manifest_results)
    n_mismatch = sum(mr.n_mismatch for mr in manifest_results)
    n_new = sum(mr.n_new for mr in manifest_results)
    n_error = sum(mr.n_error for mr in manifest_results)

    manifest_word = "manifest" if n_manifests == 1 else "manifests"
    file_word = "file" if n_files == 1 else "files"

    overall_ok = exit_status == 0
    status_icon = "✅ PASSED" if overall_ok else "❌ FAILED"

    parts = [
        f"{status_icon}",
        f"{n_manifests} {manifest_word}",
        f"{n_files} {file_word}",
        f"{n_ok} passed",
    ]
    if n_missing:
        parts.append(f"{n_missing} missing")
    if n_mismatch:
        parts.append(f"{n_mismatch} hash mismatch")
    if n_error:
        parts.append(f"{n_error} error")
    if n_new:
        parts.append(f"{n_new} new (untracked)")

    line(" | ".join(parts))
    line()

    # ── Details ───────────────────────────────────────────────────────────────
    if manifest_results:
        line("Details")
        line(_SEP_LIGHT)

    for mr in manifest_results:
        # Manifest header line — show the .mhl path (for classic MHL) or the
        # asc-mhl directory (for ASC-MHL)
        line(f"📄 {mr.manifest_path}")

        if mr.manifest_status == "error":
            line(f"    ✗ {mr.manifest_error or 'manifest-level error'}")
            continue

        for fr in mr.file_results:
            line(_format_file_result(fr))

    line(_SEP_HEAVY)


def _format_file_result(fr: "FileResult") -> str:
    """Return the report line(s) for a single FileResult (without trailing newline).

    Mismatch entries with detail render across two lines, using the label
    embedded in the detail string (e.g. "hash mismatch", "size mismatch"):

        ❌ hash mismatch: path/to/file.mxf
           (calc xxh64: abc123 | stored xxh64: def456)

        ❌ size mismatch: path/to/file.mxf
           (calc size: 122 | stored size: 4170)

    The detail string is "<label>: <parenthetical>" — split on the first ": "
    to derive the label. Without verbose detail it is just "<label>".
    """
    if fr.status == "ok":
        return f"    ✓ {fr.path}"
    if fr.status == "missing":
        return f"    ❌ missing: {fr.path}"
    if fr.status == "mismatch":
        if ": " in fr.detail:
            label, paren_content = fr.detail.split(": ", 1)
            return f"    ❌ {label}: {fr.path}\n       ({paren_content})"
        # Non-verbose fallback: detail is just "hash mismatch" or "size mismatch".
        return f"    ❌ {fr.detail}: {fr.path}"
    if fr.status == "new":
        return f"    ⚠️ new (untracked): {fr.path}"
    # "error"
    if fr.detail:
        return f"    🚨 error: {fr.path}\n       ({fr.detail})"
    return f"    🚨 error: {fr.path}"


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
        help="export a report log to the target directory",
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
        # than silently failing. Matches simple-mhl's behaviour (shared helper).
        variant = normalization_variant_on_disk(str(src))
        if variant is not None:
            msg += f"\n  A path with a different Unicode normalization exists — did you mean:\n    {variant}"
        log_error(msg)
        sys.exit(2)

    # Open the report file if requested. Using a context manager means we
    # don't have to remember to close it on every exit path.
    if args.report:
        started_at = datetime.now()
        with _open_report(src) as (rf, rp):
            exit_status, manifest_results = _run(src, args.verbose, args.xsd_schema_check)
            _render_report(rf, src, started_at, manifest_results, exit_status)
        print(f"report saved to: {rp}")
    else:
        exit_status, _ = _run(src, args.verbose, args.xsd_schema_check)

    sys.exit(exit_status)


def _run(  # noqa: C901 — branches are independent cases, not nested complexity
    src: Path,
    verbose: bool,
    schema: bool,
) -> "tuple[int, list[ManifestResult]]":
    """
    Execute the verification pass on `src`.

    Returns (exit_status, manifest_results).

    exit_status: 0 if every MHL verified, otherwise the first non-zero code
    encountered in walk order. The first-non-zero rule gives automation a
    stable, non-zero signal on any failure without attempting to rank severity
    across independent manifests.

    manifest_results: collected per-manifest outcomes used to render the
    structured report when --report is active. Always populated regardless of
    whether --report was requested (cheap to collect, free to discard).

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

    if src.is_file():
        code, mr = verify_item(src, verbose, schema)
        exit_status = code
        if mr is not None:
            manifest_results.append(mr)
        console = None

    elif src.is_dir():
        mhl_files = _select_mhl_files(src)
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
            weights = {f: (_ascmhl_total_bytes(f) if "ascmhl" in f.parts else _mhl_total_bytes(f)) for f in mhl_files}

            live, progress, label, stdout_console = _build_live()
            total_n = len(mhl_files)
            total_bytes = sum(weights.values())
            bar_task = progress.add_task(" ", total=total_bytes, done=0, total_n=total_n)
            # poll_event is set() every ~100 ms while a subprocess runs,
            # causing the Live display to refresh and animate the bar.
            # stop_event is a separate signal used only to tell the refresh
            # thread to exit — keeping it distinct from poll_event avoids a
            # race where the thread clears the stop signal after it is set:
            #
            #   main: poll_event.set()        <- shutdown signal
            #   thread: poll_event.wait() returns
            #   thread: poll_event.clear()    <- signal gone, loop continues
            #   main: refresh_thread.join()   <- blocks forever
            #
            # With a dedicated stop_event that is never cleared, the thread
            # sees it reliably on the next loop iteration.
            poll_event = threading.Event()
            stop_event = threading.Event()

            def _refresh_on_poll() -> None:
                """Background thread: refresh Live display on each poll tick."""
                while not stop_event.is_set():
                    live.refresh()
                    poll_event.wait(timeout=0.1)
                    poll_event.clear()

            with live:
                con = stdout_console
                refresh_thread = threading.Thread(target=_refresh_on_poll, daemon=True)
                refresh_thread.start()
                for i, f in enumerate(mhl_files):
                    label.plain = ""
                    label.append("🔎 Verifying… ", style="bold")
                    label.append(f.name, style="cyan")
                    code, mr = verify_item(
                        f,
                        verbose,
                        schema,
                        console=con,
                        poll_event=poll_event,
                    )
                    if mr is not None:
                        manifest_results.append(mr)
                    progress.advance(bar_task, weights[f])
                    progress.update(bar_task, done=i + 1)
                    if exit_status == 0:
                        exit_status = code
                # Signal refresh thread to stop and wait for it to exit.
                stop_event.set()
                refresh_thread.join()
                label.plain = ""
                label.append("🔎 Verifying… ", style="bold")
                label.append("done", style="green")
            console = stdout_console
        else:
            for f in mhl_files:
                code, mr = verify_item(f, verbose, schema)
                if mr is not None:
                    manifest_results.append(mr)
                if exit_status == 0:
                    exit_status = code
            console = None

    else:
        console = None

    if exit_status == 0:
        log_success(
            "✨️ All MHL manifests have been successfully verified.",
            console=console,
        )
    else:
        log_error(
            "❌ Verification failed for some of the MHL files. See details above.",
            console=console,
        )
    return exit_status, manifest_results


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
