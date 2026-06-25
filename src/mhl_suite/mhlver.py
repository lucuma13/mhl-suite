#!/usr/bin/env python3
# =============================================================================
# mhlver — One MHL tool to verify them all
# =============================================================================
# Copyright (c) 2026 Luis Gómez Gutiérrez. Licensed MIT.
#
# mhlver walks a path looking for MHL manifests and verifies each one by
# delegating to the right backend:
#
#     Classic MHL (v1)  -> verified in-process via mhl_suite.classicmhl (ClassicMHLBackend)
#     ASC-MHL  (v2)     -> verified in-process via mhl_suite.ascmhl (AscMHLBackend)
#
# It detects ASC-MHL packages by the conventional `ascmhl/` folder containing
# the manifest. Each backend's exit code is translated into a human-readable
# status line via dispatch tables (see _CLASSICMHL_RESULTS, _ASCMHL_VERIFY_RESULTS).
#
# With -S/--size-only the files are size-checked only (no hashing): for classic
# manifests the in-process engine size-checks, while for ASC-MHL  — first gates
# on manifest integrity in-process (loading the history verifies the chain and
# each manifest's hash without hashing media), then compares sizes in-process via
# ascmhl.sizecheck (since ascmhl does not check sizes).
#
# Exit code policy: the first non-zero backend exit code becomes mhlver's
# exit code, so an automation script gets a meaningful signal even when many
# rolls verify together.
# =============================================================================

import argparse
import importlib.metadata
import sys
from collections.abc import Callable, Iterator
from datetime import datetime
from pathlib import Path
from typing import Protocol, TextIO

from lxml import etree
from rich.console import Console, Group
from rich.live import Live
from rich.progress import BarColumn, Progress, TextColumn
from rich.text import Text

from mhl_suite._internal.unicodepaths import normalization_variant_on_disk
from mhl_suite.ascmhl import verify as ascmhl_verify
from mhl_suite.ascmhl.sizecheck import verify_ascmhl_sizes
from mhl_suite.classicmhl.verify import render_verify_lines, schema_report, verify_manifest
from mhl_suite.shared.report import (
    FileResult,
    ManifestResult,
    _format_file_result,  # noqa: F401 — re-exported for tests
    _open_report,
    _render_report,
)

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


# --- ASC-MHL output rendering -------------------------------------------------
#
# Both dialects are verified in-process now: classic via mhl_suite.classicmhl.verify
# and ASC-MHL via mhl_suite.ascmhl.verify, each returning structured outcomes — so
# there is no backend stdout to parse. _render_ascmhl_lines reproduces the
# per-file terminal text from an AscVerifyReport (the ASC-MHL counterpart to
# classicmhl.render_verify_lines): failure lines always, OK lines only when
# verbose, matching the old `ascmhl-debug verify [-v]` output mhlver used to relay.


def _render_ascmhl_lines(report: "ascmhl_verify.AscVerifyReport", verbose: bool) -> list[str]:
    """Render an AscVerifyReport to the per-file lines shown on the terminal."""
    out: list[str] = []
    if verbose:
        out.extend(e.line for e in report.entries if e.status == "ok")
    out.extend(e.line for e in report.entries if e.status in ("missing", "mismatch", "new"))
    return out


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

# --- ASC-MHL (2.0) verify exit codes ----------------------------------------
# These come from the vendored ascmhl/errors.py (each a click.ClickException
# subclass carrying an exit_code), surfaced in-process by mhl_suite.ascmhl.verify.
#
# As with the classic MHL table, mhlver gives a single short status line per
# manifest; the per-file detail (which file mismatched, which manifest is
# missing) comes from the structured AscVerifyReport, rendered by
# _render_ascmhl_lines. The exit code preserves the precise failure category.
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
}


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
# Verify backends — the port
# -----------------------------------------------------------------------------
# Both backends verify in-process and return the same (exit_code, ManifestResult
# | None), so the orchestrator stays uniform. ClassicMHLBackend drives
# mhl_suite.classicmhl.verify; AscMHLBackend drives mhl_suite.ascmhl.verify. Both
# advance the progress bar through the same on_bytes hook as each file is hashed.


class VerifyBackend(Protocol):
    """A manifest-verification backend.

    `on_bytes` advances a progress bar from the in-process hasher as each file
    finishes hashing; a backend calls it when verifying (not in schema mode).
    """

    def verify(
        self,
        target: Path,
        verbose: bool,
        schema: bool,
        *,
        size_only: bool = False,
        console: "_ConsoleLike | None" = None,
        progress_active: bool = False,
        on_bytes: "Callable[[int], None] | None" = None,
    ) -> "tuple[int, ManifestResult | None]": ...


class ClassicMHLBackend:
    """Verifies classic MHL in-process via the core engine."""

    def verify(
        self,
        target: Path,
        verbose: bool,
        schema: bool,
        *,
        size_only: bool = False,
        console: "_ConsoleLike | None" = None,
        progress_active: bool = False,
        on_bytes: "Callable[[int], None] | None" = None,
    ) -> "tuple[int, ManifestResult | None]":
        return _verify_classicmhl(
            target,
            verbose,
            schema,
            size_only=size_only,
            console=console,
            progress_active=progress_active,
            on_bytes=on_bytes,
        )


class AscMHLBackend:
    """Verifies ASC-MHL in-process via the vendored engine (mhl_suite.ascmhl)."""

    def verify(
        self,
        target: Path,
        verbose: bool,
        schema: bool,
        *,
        size_only: bool = False,
        console: "_ConsoleLike | None" = None,
        progress_active: bool = False,
        on_bytes: "Callable[[int], None] | None" = None,
    ) -> "tuple[int, ManifestResult | None]":
        return _verify_ascmhl(
            target,
            verbose,
            schema,
            size_only=size_only,
            console=console,
            progress_active=progress_active,
            on_bytes=on_bytes,
        )


# -----------------------------------------------------------------------------
# verify_item — main per-MHL dispatcher
# -----------------------------------------------------------------------------


def verify_item(
    target: Path,
    verbose: bool,
    schema: bool,
    size_only: bool = False,
    console: "_ConsoleLike | None" = None,
    progress_active: bool = False,
    on_bytes: "Callable[[int], None] | None" = None,
) -> "tuple[int, ManifestResult | None]":
    """
    Verify a single MHL manifest by selecting the right backend.

    Detection rule: if any path component is exactly 'ascmhl' the manifest
    belongs to an ASC-MHL package and is verified through the vendored ASC-MHL
    engine (AscMHLBackend); otherwise it is classic MHL, verified through the
    classic engine (ClassicMHLBackend). Both verify in-process and satisfy the
    VerifyBackend port, so the orchestrator only ever sees
    `(exit_code, ManifestResult | None)`.

    `size_only` requests a fast size-only check. `progress_active` suppresses
    per-manifest success lines when a rich progress bar is already showing
    progress (errors and warnings are always shown). `on_bytes` advances a
    progress bar as each file is hashed (both backends).

    Returns (exit_code, ManifestResult | None). ManifestResult is None when
    schema-check mode is active (no per-file detail is available then).
    """
    backend: VerifyBackend = AscMHLBackend() if "ascmhl" in target.parts else ClassicMHLBackend()
    return backend.verify(
        target,
        verbose,
        schema,
        size_only=size_only,
        console=console,
        progress_active=progress_active,
        on_bytes=on_bytes,
    )


# --- Classic MHL (v1) path -----------------------------------------------------


def _verify_classicmhl(
    target: Path,
    verbose: bool,
    schema: bool,
    size_only: bool = False,
    console: "_ConsoleLike | None" = None,
    progress_active: bool = False,
    on_bytes: "Callable[[int], None] | None" = None,
) -> "tuple[int, ManifestResult | None]":
    """Verify a classic MHL manifest in-process via the core engine.

    Schema mode runs core.verify.schema_report; verify/size-only run
    core.verify.verify_manifest, whose structured FileOutcomes map straight onto
    FileResult — no subprocess, no text round-trip. render_verify_lines reproduces
    the exact `simple-mhl verify` stdout so the terminal output is unchanged.

    `on_bytes`, when given, advances the caller's progress bar as each file is
    hashed (the in-process equivalent of the old subprocess animation tick).
    """
    if schema:
        code, lines = schema_report(str(target))
        _report_via_table(
            _CLASSICMHL_SCHEMA_RESULTS,
            code,
            target.name,
            "\n".join(lines),
            show_backend_output=True,
            show_status_on_terminal=not progress_active,
            console=console,
        )
        return code, None

    report = verify_manifest(str(target), size_only=size_only, on_progress=on_bytes)

    if report.malformed:
        # Malformed XML: the engine read nothing and produced no per-file detail.
        template, _sev = _CLASSICMHL_RESULTS[20]
        _report_via_table(
            _CLASSICMHL_RESULTS,
            20,
            target.name,
            "",
            show_backend_output=True,
            show_status_on_terminal=not progress_active,
            console=console,
        )
        mr = ManifestResult(
            manifest_path=target,
            manifest_status="error",
            manifest_error=template.format(target=target.name),
        )
        return 20, mr

    # render_verify_lines reproduces the exact `simple-mhl verify` stdout at the
    # requested verbosity (OK lines and the indented detail continuations are
    # included only when verbose), matching the old subprocess terminal output.
    output = "\n".join(render_verify_lines(report, verbose))
    _report_via_table(
        _CLASSICMHL_RESULTS,
        report.code,
        target.name,
        output,
        show_backend_output=True,
        show_status_on_terminal=not progress_active,
        console=console,
    )

    # FileOutcome and FileResult share the same fields — a direct, parse-free map.
    file_results = [
        FileResult(
            path=e.path,
            status=e.status,
            detail=e.detail,
            size_only=e.size_only,
            existence_only=e.existence_only,
        )
        for e in report.entries
    ]
    if report.code == 0:
        mstatus = "ok"
    elif file_results:
        mstatus = "failed"
    else:
        mstatus = "error"
    template, _ = _CLASSICMHL_RESULTS.get(report.code, ("Unexpected exit {code}", "warning"))
    merror = "" if mstatus != "error" else template.format(target=target.name)
    mr = ManifestResult(
        manifest_path=target,
        manifest_status=mstatus,
        manifest_error=merror,
        file_results=file_results,
    )
    return report.code, mr


# --- ASC-MHL (v2) path --------------------------------------------------------


def _verify_ascmhl(
    target: Path,
    verbose: bool,
    schema: bool,
    size_only: bool = False,
    console: "_ConsoleLike | None" = None,
    progress_active: bool = False,
    on_bytes: "Callable[[int], None] | None" = None,
) -> "tuple[int, ManifestResult | None]":
    """Verify an ASC-MHL package in-process via the vendored engine, by mode."""
    # Size-only: an integrity gate plus a byte-free size compare (ascmhl does
    # not check sizes), all in-process.
    if size_only and not schema:
        return _ascmhl_verify_sizeonly(target, verbose, console=console, progress_active=progress_active)
    if schema:
        code = _ascmhl_schema_check(target, verbose, console=console, progress_active=progress_active)
        return code, None
    return _ascmhl_verify(target, verbose, console=console, progress_active=progress_active, on_bytes=on_bytes)


def _ascmhl_schema_check(
    target: Path,
    verbose: bool,
    console: "_ConsoleLike | None" = None,
    progress_active: bool = False,
) -> int:
    """
    Schema-check both halves of an ASC-MHL package in-process: the manifest
    itself against ASCMHL.xsd and the sibling ascmhl_chain.xml against the
    directory schema.

    Both checks always run; the worst exit code (preferring the manifest's) is
    returned so the caller has a single signal. Validation errors are always
    shown — they carry the line numbers and structural detail an operator needs
    to fix the file.
    """
    # Step 1: the .mhl manifest against the manifest schema.
    mhl_code, mhl_lines = ascmhl_verify.schema_check(target)
    _report_via_table(
        _ASCMHL_SCHEMA_RESULTS,
        mhl_code,
        str(target),
        "\n".join(mhl_lines),
        show_backend_output=True,
        show_status_on_terminal=not progress_active,
        console=console,
    )

    # Step 2: ascmhl_chain.xml against the directory schema.
    chain_file = target.parent / "ascmhl_chain.xml"
    chain_code, chain_lines = ascmhl_verify.schema_check(chain_file, directory_file=True)
    _report_via_table(
        _ASCMHL_SCHEMA_RESULTS,
        chain_code,
        str(chain_file),
        "\n".join(chain_lines),
        show_backend_output=True,
        show_status_on_terminal=not progress_active,
        console=console,
    )

    # Manifest failure takes priority; otherwise the chain's code wins.
    return mhl_code if mhl_code != 0 else chain_code


def _ascmhl_verify(
    target: Path,
    verbose: bool,
    console: "_ConsoleLike | None" = None,
    progress_active: bool = False,
    on_bytes: "Callable[[int], None] | None" = None,
) -> "tuple[int, ManifestResult]":
    """
    Verify an ASC-MHL package in-process via mhl_suite.ascmhl.verify.

    ASC-MHL convention: the manifest at <root>/ascmhl/<gen>.mhl describes the
    contents of <root>, so we verify the parent of the ascmhl/ folder
    (target.parent.parent). verify_package returns structured per-file outcomes
    and reports byte progress through on_bytes as each file is hashed — the same
    progress mechanism as the classic backend. _render_ascmhl_lines reproduces
    the per-file terminal text (failure lines always, OK lines when verbose).
    """
    package_dir = target.parent.parent
    report = ascmhl_verify.verify_package(package_dir, on_progress=on_bytes)

    output = "\n".join(_render_ascmhl_lines(report, verbose))
    _report_via_table(
        _ASCMHL_VERIFY_RESULTS,
        report.code,
        str(package_dir),
        output,
        show_backend_output=True,
        show_status_on_terminal=not progress_active,
        console=console,
    )

    # FileOutcome and FileResult share the same fields — a direct, parse-free map.
    file_results = [FileResult(path=e.path, status=e.status, detail=e.detail) for e in report.entries]
    mstatus = "ok" if report.code == 0 else "failed"
    mr = ManifestResult(
        manifest_path=target,
        manifest_status=mstatus,
        file_results=file_results,
    )
    return report.code, mr


def _ascmhl_verify_sizeonly(
    target: Path,
    verbose: bool,
    console: "_ConsoleLike | None" = None,
    progress_active: bool = False,
) -> "tuple[int, ManifestResult]":
    """
    Size-only verify an ASC-MHL package, gating on manifest integrity first.

    Two phases:

      1. Integrity gate — ascmhl_verify.integrity_check loads the history
         in-process, which verifies the chain file and every generation
         manifest's own hash without hashing any media. This catches a tampered
         or missing manifest/chain before we trust their contents.
      2. Size phase — ascmhl does not check file sizes, so we use our own
         'ascmhl/sizecheck.py': verify_ascmhl_sizes parses the manifests and compares
         each recorded <path size> against the file on disk, reading no file bytes.
    """
    package_dir = target.parent.parent

    # --- Phase 1: manifest-integrity gate (in-process) ---
    gate_code, gate_msg = ascmhl_verify.integrity_check(package_dir)
    if gate_code != 0:
        template, _sev = _ASCMHL_VERIFY_RESULTS.get(
            gate_code,
            ("🚨 ASC-MHL manifest integrity check failed: {target}", "error"),
        )
        _report_via_table(
            _ASCMHL_VERIFY_RESULTS,
            gate_code,
            str(package_dir),
            gate_msg,
            show_backend_output=True,
            show_status_on_terminal=not progress_active,
            console=console,
        )
        mr = ManifestResult(
            manifest_path=target,
            manifest_status="error",
            manifest_error=template.format(target=package_dir),
        )
        return gate_code, mr

    # --- Phase 2: size checks (manifests proven intact above) ---
    try:
        size_results = verify_ascmhl_sizes(target)
    except (etree.XMLSyntaxError, OSError):
        msg = f"🚨 Malformed XML: {package_dir} cannot be parsed."
        log_error(msg, console=console)
        mr = ManifestResult(manifest_path=target, manifest_status="error", manifest_error=msg)
        return 20, mr

    # Translate to FileResult, flagging every OK entry as size-only so the report
    # summary reads "VERIFIED (SIZE-ONLY CHECKS)". The OK path carries its size in
    # the displayed path, matching the output from simple-mhl: "<path>  size: <n>" form.
    file_results: list[FileResult] = []
    out_lines: list[str] = []
    for r in size_results:
        if r.status == "ok":
            file_results.append(FileResult(path=f"{r.path}  {r.detail}", status="ok", size_only=True))
            if verbose:
                out_lines.append(f"[OK] {r.path}  {r.detail}")
        elif r.status == "missing":
            file_results.append(FileResult(path=r.path, status="missing"))
            out_lines.append(f"[ERROR] missing file: {r.path}")
        else:  # mismatch — detail is "size mismatch: …", "no size recorded", or "blocked …"
            file_results.append(FileResult(path=r.path, status="mismatch", detail=r.detail))
            if ": " in r.detail:
                label, paren = r.detail.split(": ", 1)
                out_lines.append(f"[ERROR] {label}: {r.path}")
                if verbose:
                    out_lines.append(f"        ({paren})")
            else:
                out_lines.append(f"[ERROR] {r.detail}: {r.path}")

    code = 0 if all(fr.status == "ok" for fr in file_results) else 10
    _report_via_table(
        _ASCMHL_VERIFY_RESULTS,
        code,
        str(package_dir),
        "\n".join(out_lines),
        show_backend_output=True,
        show_status_on_terminal=not progress_active,
        console=console,
    )

    mr = ManifestResult(
        manifest_path=target,
        manifest_status="ok" if code == 0 else "failed",
        file_results=file_results,
    )
    return code, mr


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

# Hash element local-names simple-mhl can recompute (mirrors ALGO_MAP keys in
# simple_mhl). An entry whose only hash child is <null> — or which records no
# computable hash — is verified by size/existence alone and reads zero bytes,
# so its <size> must not weight the byte-based progress total.
_COMPUTABLE_HASH_TAGS = frozenset({"md5", "sha1", "xxhash", "xxh64", "xxhash64", "xxhash64be"})


def _mhl_total_bytes(mhl_file: Path) -> int:
    """
    Sum the <size> of every recomputable-hash entry in a classic MHL
    manifest to get the byte weight of the files verify will actually read.

    Used to weight progress-bar units by actual data volume rather than
    manifest count, giving a more accurate ETA when manifests vary wildly
    in size (e.g. 500 GB camera originals vs 2 GB proxies).

    A <null> (size-only / existence-only) entry is verified with a single
    stat() and reads zero bytes, so its <size> is excluded — counting it would
    surge the bar ahead of real hashing progress.
    """

    try:
        tree = etree.parse(str(mhl_file))
    except (OSError, etree.XMLSyntaxError):
        return 0
    total = 0
    for h in tree.iterfind(".//{*}hash"):
        size_el = h.find("{*}size")
        if size_el is None or not size_el.text or not size_el.text.strip().isdecimal():
            continue
        # Only count entries verify reads bytes for (skip <null>-only / no-hash entries).
        if any(
            isinstance(c.tag, str)
            and (c.tag.rpartition("}")[2] if "}" in c.tag else c.tag).lower() in _COMPUTABLE_HASH_TAGS
            for c in h
        ):
            total += int(size_el.text)
    return total


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


def _manifest_weights(mhl_files: "list[Path]", size_only: bool) -> "dict[Path, int]":
    """Per-manifest progress-bar weights: byte volume normally, count under -S.

    Size-only reads no file bytes (one stat() per entry), so byte weights are
    meaningless — every manifest finishes near-instantly. Weighting each manifest
    equally then makes the bar track manifest count instead of a byte total that
    would jump straight to full.
    """
    if size_only:
        return dict.fromkeys(mhl_files, 1)
    return {f: (_ascmhl_total_bytes(f) if "ascmhl" in f.parts else _mhl_total_bytes(f)) for f in mhl_files}


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
                console=con,
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
        code, mr = verify_item(src, verbose, schema, size_only)
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
                code, mr = verify_item(f, verbose, schema, size_only)
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
