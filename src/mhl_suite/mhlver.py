#!/usr/bin/env python3
# =============================================================================
# mhlver — One MHL tool to verify them all
# =============================================================================
# Copyright (c) 2026 Luis Gómez Gutiérrez. Licensed MIT.
#
# mhlver walks a path looking for MHL manifests and verifies each one by
# delegating to the right backend:
#
#     legacy MHL (1.x)  -> shells out to `simple-mhl verify`
#     ASC-MHL  (2.0)    -> shells out to `ascmhl-debug verify`
#
# It detects ASC-MHL packages by the conventional `ascmhl/` folder containing
# the manifest. Each backend's exit code is translated into a human-readable
# status line via dispatch tables (see _LEGACY_RESULTS, _ASCMHL_VERIFY_RESULTS).
#
# Exit code policy: the first non-zero backend exit code becomes mhlver's
# exit code, so an automation script gets a meaningful signal even when many
# rolls verify together.
# =============================================================================

import argparse
import os
import shutil
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterator, TextIO


MHLVER_VERSION = "1.2.0"


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
# Each log function writes to the terminal AND to the optional report file.
# The report file gets timestamped lines (audit trail); the terminal gets the
# coloured form without timestamp clutter, since timestamps are visually
# noisy when a human is watching the output scroll past.

def _log(msg: str, *, colour: str, stream, report_file: TextIO | None) -> None:
    """Print to a stream (with colour) and mirror to report_file (without)."""
    print(f"{colour}{msg}{RESET}", file=stream)
    if report_file:
        timestamp = datetime.now().strftime("%Y.%m.%d-%H:%M:%S")
        report_file.write(f"[{timestamp}] {msg}\n")


def log_success(msg: str, report_file: TextIO | None = None) -> None:
    _log(msg, colour="", stream=sys.stdout, report_file=report_file)


def log_warning(msg: str, report_file: TextIO | None = None) -> None:
    _log(msg, colour=ORANGE, stream=sys.stderr, report_file=report_file)


def log_error(msg: str, report_file: TextIO | None = None) -> None:
    _log(msg, colour=RED, stream=sys.stderr, report_file=report_file)


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


def _run_step(cmd: list[str], cwd: Path | None = None) -> StepResult:
    """
    Run `cmd` and return its exit code plus combined stdout+stderr.

    We capture both streams together because either could carry diagnostic
    information from the backend; presenting them merged matches what an
    operator would see if they ran the command interactively.

    `cwd` is set when calling ascmhl-debug so it can find its bundled XSD
    files via relative paths. For simple-mhl we pass cwd=None since it
    locates its XSD via importlib.resources.
    """
    result = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    combined = ((result.stdout or "") + (result.stderr or "")).strip()
    return StepResult(exit_code=result.returncode, output=combined)


def _emit_step_output(
    out: str,
    exit_code: int,
    report_file: TextIO | None,
    *,
    show_on_terminal: bool,
) -> None:
    """
    Write captured backend output to the report file (always) and to the
    terminal (when show_on_terminal is True).

    The terminal-suppression flag exists to avoid duplicating mhlver's own
    status line. mhlver translates each exit code into a clear human-readable
    message via the dispatch tables; for many ascmhl errors the backend's
    raw output is a near-restatement of that translation, so showing it
    twice just clutters the operator's terminal. The full backend output
    always lands in the report file so an audit trail still exists.

    Callers pass show_on_terminal=True for simple-mhl (whose per-file
    output is structured complementary info we want operators to see) and
    for any backend invocation when --verbose was requested.

    Colour: red on failure, no colour on success. Verbose `OK:` lines
    shouldn't look like errors just because they go through this same path.
    """
    if not out:
        return
    # Report file: always preserve, regardless of terminal display choice.
    if report_file:
        report_file.write(out + "\n")
    # Terminal: shown when caller requests it; coloured only on failure.
    if show_on_terminal:
        if exit_code != 0:
            print(f"{RED}{out}{RESET}", file=sys.stderr)
        else:
            print(out)


# -----------------------------------------------------------------------------
# Exit-code dispatch tables
# -----------------------------------------------------------------------------
# Both backends return structured exit codes. Rather than long if/elif chains,
# we map exit_code -> (template, severity) and dispatch through a small helper.
# severity is "success" / "warning" / "error" and selects the logger.
#
# Templates use {target} which we .format() with the manifest's name or its
# package directory depending on the action.

# --- simple-mhl (legacy MHL) verify exit codes ------------------------------
# These are the codes simple_mhl.py returns. Exit 70 was added in v1.0.2 to
# distinguish "missing AND mismatch" from either failure alone.
#
# Wording note: the per-file detail (which files, what kind of failure)
# comes from simple-mhl itself, which prints structured `ERROR: <category>:
# <path>` lines that are self-explanatory standalone. mhlver therefore only
# needs to say "this manifest failed" — the lines below explain why. The
# exit code itself still encodes the precise failure category for tooling.
_LEGACY_RESULTS: dict[int, tuple[str, str]] = {
      0: ("✅ MHL verified: {target}",                                                              "success"),
     10: ("⚠️  Schema non-compliant: {target}",                                                     "error"),
     20: ("🚨 Malformed XML: {target} cannot be parsed.",                                           "warning"),
     30: ("❌ Verification failed: {target}",                                                       "error"),
     40: ("❌ Verification failed: {target}",                                                       "error"),
     70: ("❌ Verification failed: {target}",                                                       "error"),
    127: ("🚨 System error: 'simple-mhl' command not found. Ensure it is in your PATH.",            "warning"),
}

# Schema-check uses the same codes but with a different success message,
# plus exit 60 which is unique to schema-check (XSD not found on disk).
_LEGACY_SCHEMA_RESULTS: dict[int, tuple[str, str]] = {
    **_LEGACY_RESULTS,
    0:  ("📝 MHL schema valid: {target}",                                                                "success"),
    60: ("🚨 Schema check unavailable: simple-mhl could not locate its bundled XSD file.",               "warning"),
}

# --- ascmhl-debug (ASC-MHL 2.0) verify exit codes ---------------------------
# These come from ascmhl/errors.py in the upstream Pomfort package. Each
# corresponds to a click.ClickException subclass.
#
# As with the legacy table, mhlver gives a single short status line per
# manifest. ascmhl-debug emits its own `logger.error(...)` lines describing
# what went wrong (which file mismatched, which manifest is missing, etc.);
# those lines are passed through to the terminal so the operator sees the
# detail. The exit code preserves the precise failure category for tooling.
_ASCMHL_VERIFY_RESULTS: dict[int, tuple[str, str]] = {
      0: ("✅ ASC-MHL verified: {target}",                                                          "success"),
     10: ("❌ ASC-MHL verification failed: {target}",                                               "error"),
     11: ("❌ ASC-MHL verification failed: {target}",                                               "error"),
     12: ("❌ ASC-MHL verification failed: {target}",                                               "error"),
     20: ("❌ ASC-MHL verification failed: {target}",                                               "error"),
     21: ("⚠️  ASC-MHL: new files found in {target} that are not recorded in history.",             "error"),
     30: ("❌ ASC-MHL verification failed: {target}",                                               "error"),
     31: ("❌ ASC-MHL verification failed: {target}",                                               "error"),
     32: ("❌ ASC-MHL verification failed: {target}",                                               "error"),
     33: ("❌ ASC-MHL verification failed: {target}",                                               "error"),
    127: ("🚨 System error: 'ascmhl-debug' command not found. Ensure it is in your PATH.",          "warning"),
}

# ASC-MHL xsd-schema-check uses VerificationFailedException (code 11) for
# schema-non-compliance, which deserves its own message distinct from the
# verify path's "hash mismatch" interpretation of the same code.
_ASCMHL_SCHEMA_RESULTS: dict[int, tuple[str, str]] = {
      0: ("📝 ASC-MHL schema valid: {target}",                                                          "success"),
     11: ("⚠️  ASC-MHL schema non-compliant: {target} does not match the ASC-MHL schema.",              "error"),
    127: ("🚨 System error: 'ascmhl-debug' command not found. Ensure it is in your PATH.",              "warning"),
}


def _log_by_severity(severity: str, msg: str, report_file: TextIO | None) -> None:
    """Dispatch a message to the right logger based on its severity label."""
    if severity == "success":
        log_success(msg, report_file)
    elif severity == "warning":
        log_warning(msg, report_file)
    else:  # "error"
        log_error(msg, report_file)


def _report_via_table(
    table: dict[int, tuple[str, str]],
    exit_code: int,
    target_label: str,
    output: str,
    report_file: TextIO | None,
    *,
    show_backend_output: bool,
) -> None:
    """
    Look up exit_code in `table`, log the appropriate message, and emit any
    captured backend output. Falls back to a clearly-marked 'unexpected'
    message for codes not in the table — surfaces the raw exit code so the
    operator can investigate rather than silently treating it as success.

    `show_backend_output` controls whether the backend's captured stdout/
    stderr is replayed to the terminal. The report file always gets it.
    """
    template, severity = table.get(
        exit_code,
        (f"🚨 Unexpected backend exit {exit_code} for {{target}}", "warning"),
    )
    _log_by_severity(severity, template.format(target=target_label), report_file)
    _emit_step_output(output, exit_code, report_file, show_on_terminal=show_backend_output)


def _verbose_announce(
    cmd: list[str],
    cwd: Path | None,
    verbose: bool,
    report_file: TextIO | None,
) -> None:
    """
    When --verbose, print the exact command (and cwd) that's about to run.

    Operators trying to reproduce a failure manually need the actual
    invocation, not a paraphrase. Showing this BEFORE the run also lets
    them see how far we got if the backend crashes mid-execution.

    The line is mirrored to the report file too, so a saved report tells
    the full story of what was attempted.
    """
    if not verbose:
        return
    rendered = " ".join(cmd)
    line = f"  ↪ running: {rendered}"
    if cwd is not None:
        line += f"  (cwd={cwd})"
    print(line, file=sys.stderr)
    if report_file:
        report_file.write(line + "\n")


# -----------------------------------------------------------------------------
# verify_item — main per-MHL dispatcher
# -----------------------------------------------------------------------------

def verify_item(
    target: Path,
    verbose: bool,
    schema: bool,
    report_file: TextIO | None = None,
) -> int:
    """
    Verify a single MHL manifest, dispatching to the right backend.

    Detection rule: if any path component is exactly 'ascmhl' the manifest
    belongs to an ASC-MHL package; otherwise it's legacy MHL. This matches
    the convention used by ascmhl-debug, where manifests live at
    `<root>/ascmhl/manifest.mhl`.

    Returns the backend's exit code so the caller can aggregate.
    """
    if "ascmhl" in target.parts:
        return _verify_ascmhl(target, verbose, schema, report_file)
    return _verify_legacy(target, verbose, schema, report_file)


# --- Legacy (MHL 1.x) path ----------------------------------------------------

def _verify_legacy(
    target: Path,
    verbose: bool,
    schema: bool,
    report_file: TextIO | None,
) -> int:
    """Run simple-mhl against a legacy MHL manifest and translate the result."""
    cmd_path = get_command_path("simple-mhl")
    if not cmd_path:
        # 127 is the conventional 'command not found' exit code; keep the
        # same so report-aggregation tooling can detect it consistently
        # across both backends.
        msg, sev = _LEGACY_RESULTS[127]
        _log_by_severity(sev, msg, report_file)
        return 127

    sub = "xsd-schema-check" if schema else "verify"
    cmd = [cmd_path, sub, str(target)]
    # Pass -v through to simple-mhl when in verbose mode (only for verify;
    # xsd-schema-check has no notion of per-file OK lines). simple-mhl will
    # then emit `OK: <path>` for every successfully verified file, which
    # mhlver's "always show legacy backend output" rule will surface.
    if verbose and not schema:
        cmd.append("-v")
    _verbose_announce(cmd, cwd=None, verbose=verbose, report_file=report_file)

    step = _run_step(cmd)

    # simple-mhl is a tool we control. Its per-file output uses structured
    # `ERROR: <category>: <path>` and `OK: <path>` prefixes that stand
    # alone — they aren't restatements of mhlver's summary line. Always
    # show on terminal.
    table = _LEGACY_SCHEMA_RESULTS if schema else _LEGACY_RESULTS
    _report_via_table(table, step.exit_code, target.name, step.output, report_file,
                      show_backend_output=True)
    return step.exit_code


# --- ASC-MHL (2.0) path -------------------------------------------------------

def _verify_ascmhl(
    target: Path,
    verbose: bool,
    schema: bool,
    report_file: TextIO | None,
) -> int:
    """Run ascmhl-debug against an ASC-MHL manifest and translate the result."""
    cmd_path = get_command_path("ascmhl-debug")
    if not cmd_path:
        msg, sev = _ASCMHL_VERIFY_RESULTS[127]
        _log_by_severity(sev, msg, report_file)
        return 127

    # ascmhl-debug expects to find its bundled XSDs via paths relative to
    # its working directory. Setting cwd to the directory containing this
    # script lets it locate them when the suite is installed alongside.
    suite_dir = Path(__file__).resolve().parent
    cwd = suite_dir if suite_dir.exists() else None
    if not cwd:
        log_error(
            "suite_dir does not exist; ascmhl-debug may not find its XSD files.",
            report_file,
        )

    if schema:
        return _ascmhl_schema_check(target, cmd_path, cwd, verbose, report_file)
    return _ascmhl_verify(target, cmd_path, cwd, verbose, report_file)


def _ascmhl_schema_check(
    target: Path,
    cmd_path: str,
    cwd: Path | None,
    verbose: bool,
    report_file: TextIO | None,
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
    _verbose_announce(mhl_cmd, cwd, verbose, report_file)
    mhl_step = _run_step(mhl_cmd, cwd=cwd)
    _report_via_table(_ASCMHL_SCHEMA_RESULTS, mhl_step.exit_code, str(target),
                      mhl_step.output, report_file,
                      show_backend_output=True)

    # Step 2: ascmhl_chain.xml against the directory schema
    chain_file = target.parent / "ascmhl_chain.xml"
    chain_cmd = [cmd_path, "xsd-schema-check", "--directory_file", str(chain_file)]
    _verbose_announce(chain_cmd, cwd, verbose, report_file)
    chain_step = _run_step(chain_cmd, cwd=cwd)
    _report_via_table(_ASCMHL_SCHEMA_RESULTS, chain_step.exit_code, str(chain_file),
                      chain_step.output, report_file,
                      show_backend_output=True)

    # Manifest failure takes priority; otherwise the chain's code wins.
    return mhl_step.exit_code if mhl_step.exit_code != 0 else chain_step.exit_code


def _ascmhl_verify(
    target: Path,
    cmd_path: str,
    cwd: Path | None,
    verbose: bool,
    report_file: TextIO | None,
) -> int:
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
    summary, much like simple-mhl's ERROR: prefixed lines do for legacy.
    """
    package_dir = target.parent.parent

    cmd = [cmd_path, "verify"]
    if verbose:
        cmd.append("-v")
    cmd.append(str(package_dir))

    _verbose_announce(cmd, cwd, verbose, report_file)
    step = _run_step(cmd, cwd=cwd)
    _report_via_table(_ASCMHL_VERIFY_RESULTS, step.exit_code, str(package_dir),
                      step.output, report_file,
                      show_backend_output=True)
    return step.exit_code


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
    """
    seen_ascmhl_parents: set[Path] = set()
    selected: list[Path] = []

    for f in sorted(find_mhl_files(root)):
        if f.parent.name == "ascmhl":
            # Use the package root (grandparent) as the dedup key.
            package_root = f.parent.parent
            if package_root in seen_ascmhl_parents:
                # Replace earlier manifests for this package with this one
                # (we're iterating in sorted order, so this is the latest).
                selected = [s for s in selected if s.parent.parent != package_root]
            seen_ascmhl_parents.add(package_root)
        selected.append(f)

    return selected


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
    """
    report_dir = src if src.is_dir() else src.parent
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = report_dir / f"mhlver_report_{src.name}_{timestamp}.log"
    fh = open(report_path, "w", encoding="utf-8")
    try:
        fh.write(f"mhlver v{MHLVER_VERSION} report — "
                 f"{datetime.now().strftime('%Y.%m.%d %H:%M:%S')}\n")
        fh.write(f"path: {src}\n")
        fh.write("---\n")
        yield fh, report_path
        fh.write("---\n")
    finally:
        fh.close()


# -----------------------------------------------------------------------------
# Duration formatting
# -----------------------------------------------------------------------------

def _format_duration(seconds: float) -> str:
    """Render seconds as a compact human-readable duration."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    if seconds < 3600:
        return f"{int(seconds // 60)}m {int(seconds % 60)}s"
    return f"{int(seconds // 3600)}h {int((seconds % 3600) // 60)}m {int(seconds % 60)}s"


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
        "-r", "--report", action="store_true",
        help="export a timestamped report log to the target directory",
    )
    parser.add_argument(
        "-s", "--xsd-schema-check", action="store_true",
        help="validate XML Schema Definition",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="print invoked commands and per-file status",
    )
    parser.add_argument("--version", action="version", version=MHLVER_VERSION)
    parser.add_argument(
        "path", nargs="?", default=".",
        help="path to MHL file or directory (default: current directory)",
    )

    args = parser.parse_args()
    src = Path(args.path).resolve()

    if not src.exists():
        log_error("Argument should be a file or directory that exists in the filesystem")
        sys.exit(2)

    # Open the report file if requested. Using a context manager means we
    # don't have to remember to close it on every exit path.
    if args.report:
        with _open_report(src) as (rf, rp):
            exit_status = _run(src, args.verbose, args.xsd_schema_check, rf)
            rf.write(f"exit status: {exit_status}\n")
        print(f"report saved to: {rp}")
    else:
        exit_status = _run(src, args.verbose, args.xsd_schema_check, None)

    sys.exit(exit_status)


def _run(
    src: Path,
    verbose: bool,
    schema: bool,
    report_file: TextIO | None,
) -> int:
    """
    Execute the verification pass on `src`.

    Returns the aggregate exit code: 0 if every MHL verified, otherwise the
    first non-zero code encountered. Operators commonly check for any
    failure rather than caring about which code; the first-non-zero rule
    keeps the most informative error visible.
    """
    started = datetime.now()
    exit_status = 0

    if src.is_file():
        exit_status = verify_item(src, verbose, schema, report_file)
    elif src.is_dir():
        # Find and dedup MHL files. Set-based dedup is more robust than the
        # original's sorted-prev-grandparent trick which assumed alphabetical
        # ordering would group same-package manifests together.
        mhl_files = _select_mhl_files(src)
        if not mhl_files:
            log_warning(f"No MHL files found under {src}", report_file)

        for f in mhl_files:
            if report_file:
                report_file.write("---\n")
            code = verify_item(f, verbose, schema, report_file)
            # Preserve the FIRST non-zero exit code so the operator sees the
            # most actionable error. Don't overwrite with later failures.
            if exit_status == 0:
                exit_status = code

    elapsed = (datetime.now() - started).total_seconds()
    duration_str = _format_duration(elapsed)
    if exit_status == 0:
        log_success(
            f"✨️ MHL scan and verification completed in {duration_str}. "
            "All MHL files found have been successfully verified.",
            report_file,
        )
    else:
        log_error(
            f"❌ Verification failed for some of the MHL files (took {duration_str}). "
            "See details above.",
            report_file,
        )
    return exit_status


if __name__ == "__main__":
    main()
