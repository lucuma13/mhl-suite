# =============================================================================
# mhl_suite.ascmhl.verify — print-free, structured ASC-MHL verification
# =============================================================================
# The in-process entry point mhlver drives instead of shelling out to the
# `ascmhl`/`ascmhl-debug` CLI. It mirrors classicmhl.verify's contract: never
# prints, never sys.exit()s, returns a structured report whose FileOutcomes
# mhlver maps straight onto its own report model — no stdout round-trip, no
# regex parsing.
#
# The heavy lifting still lives in the vendored upstream engine
# (mhl_suite.ascmhl.vendor.commands.verify_entire_folder); this module silences its
# logger (logger.quiet) and hands it a `report` collector + `on_progress` hook,
# then translates the ClickException it raises on failure into an exit code.
# This keeps the vendored engine faithful to upstream and re-syncable while
# giving the suite a clean library boundary.
# =============================================================================

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import click
from lxml import etree

from mhl_suite.ascmhl.vendor import commands, errors, logger
from mhl_suite.shared.results import FileOutcome

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


@dataclass
class AscVerifyReport:
    """Structured outcome of verifying one ASC-MHL package.

    `code` is the upstream ASC-MHL exit code (see ascmhl/errors.py): 0 clean,
    10 missing files, 11 hash mismatch, 12 directory-hash mismatch, 20 single
    file not found, 21 new files, 30/31/32/33 history/chain/manifest problems.
    mhlver's `_ASCMHL_VERIFY_RESULTS` already maps these to status lines.

    `entries` are the per-file outcomes in traversal order. `notices` mirror
    classicmhl's manifest-level notes (unused today, kept for symmetry).
    """

    entries: list[FileOutcome] = field(default_factory=list)
    code: int = 0
    notices: list[str] = field(default_factory=list)


def verify_package(root_path: "str | Path", *, on_progress: "Callable[[int], None] | None" = None) -> AscVerifyReport:
    """Verify the ASC-MHL package rooted at `root_path` in-process.

    `root_path` is the directory the manifest describes (the parent of the
    `ascmhl/` folder). `on_progress`, if given, is called with each file's byte
    size as it finishes hashing, so a caller can drive a progress bar — the
    ASC-MHL counterpart to classicmhl.verify_manifest(on_progress=...).

    Returns an AscVerifyReport. Failure is signalled by `code`, never by an
    exception or process exit. The vendored engine's logger output is suppressed
    so the caller owns all terminal rendering.
    """
    entries: list[FileOutcome] = []
    prev_quiet = logger.quiet
    logger.quiet = True
    try:
        commands.verify_entire_folder(str(root_path), False, None, None, on_progress=on_progress, report=entries)
        code = 0
    except click.ClickException as exc:
        # Every ascmhl failure mode is a click.ClickException subclass carrying an
        # `exit_code` (see ascmhl/errors.py). Anything else is a genuine bug and
        # propagates.
        code = getattr(exc, "exit_code", 1)
    finally:
        logger.quiet = prev_quiet
    return AscVerifyReport(entries=entries, code=code)


def schema_check(file_path: "str | Path", *, directory_file: bool = False) -> "tuple[int, list[str]]":
    """Validate an ASC-MHL file against its bundled XSD, returning (code, lines).

    `directory_file=True` validates an ascmhl_chain.xml against the directory
    schema; otherwise a manifest is validated against ASCMHL.xsd. Mirrors
    classicmhl.verify.schema_report: code is 0 (valid), 11 (schema
    non-compliant — matches ascmhl's VerificationFailedException), 20
    (malformed/unreadable XML), or 60 (bundled XSD not found). Never prints.
    """
    schema_name = "ASCMHLDirectory__combined.xsd" if directory_file else "ASCMHL.xsd"
    try:
        xsd_path = commands._bundled_xsd_path(schema_name)
    except FileNotFoundError as exc:
        return 60, [f"Error: {exc}"]

    try:
        tree = etree.parse(str(file_path))
        xsd = etree.XMLSchema(etree.parse(xsd_path))
    except etree.XMLSyntaxError as exc:
        return 20, [f"Error: XML parsing failed - {exc}"]
    except OSError as exc:
        return 20, [f"Error: file read failed - {exc}"]

    if not xsd.validate(tree):
        return 11, [f"Error: XSD validation failed - {err.message} (line {err.line})" for err in xsd.error_log]
    return 0, []


def integrity_check(root_path: "str | Path") -> "tuple[int, str]":
    """Load the ASC-MHL history to gate on manifest/chain integrity, no hashing.

    Loading validates the chain file and each generation manifest's own hash
    without reading any media — the in-process replacement for the `ascmhl info`
    integrity gate mhlver used on its size-only path. Returns (code, message):
    (0, "") when the history is intact, otherwise the upstream exit code and the
    exception message.
    """
    try:
        history = commands.MHLHistory.load_from_path(str(root_path))
        if len(history.hash_lists) == 0:
            raise errors.NoMHLHistoryException(str(root_path))
        return 0, ""
    except click.ClickException as exc:
        return getattr(exc, "exit_code", 1), exc.format_message()
