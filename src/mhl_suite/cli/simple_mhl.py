#!/usr/bin/env python3
"""
simple-mhl — modern verification and sealing tool for classic MHL files.

This module is the command-line interface, and the only place in the classic
path that writes to the terminal or exits the process: the engines
(classic_seal, classic_verify) return structured results or raise typed
errors, and this module renders them (via the shared renderer in mhl_suite.verify) and maps them to
exit codes.

Three subcommands are exposed via argparse:

    simple-mhl seal <directory>          — walk a directory and write an MHL
    simple-mhl verify <file.mhl>         — re-hash files listed in a manifest
    simple-mhl xsd-schema-check <file>   — validate XML structure against XSD
"""

import argparse
import os
import sys

from mhl_suite import __version__
from mhl_suite._exit_codes import ExitCode
from mhl_suite.algorithms import (
    CLASSIC_CANONICAL_KEYS,
    CLASSIC_KEYS,
    NULL_TAG,
    classic_canonical_tag,
    classic_seal_tag,
)
from mhl_suite.classic_seal import SealError, seal_classic
from mhl_suite.classic_verify import verify_classic
from mhl_suite.discovery import is_ascmhl_v2
from mhl_suite.osutils import normalization_variant_on_disk, to_terminal_sep
from mhl_suite.update_checker import run_with_update_check
from mhl_suite.verify import VERIFY_ALL, render_verify_lines
from mhl_suite.xsd_check import classic_schema_report

# -----------------------------------------------------------------------------
# Path guards (CLI-side: they write to stderr and exit)
# -----------------------------------------------------------------------------


def _validate_mhl_path(mhl_file: str) -> None:
    """
    Validate that `mhl_file` is a readable MHL file path, exiting with a
    structured error message if not. Covers: path does not exist (with a
    Unicode-normalization "did you mean" hint), path is a directory (with a
    specific hint for ASC-MHL v2 packages), path lacks a .mhl extension.
    """
    if not os.path.exists(mhl_file):
        msg = f"Error: '{mhl_file}' not found\n"
        variant = normalization_variant_on_disk(mhl_file)
        if variant is not None:
            shown = variant if os.path.isabs(mhl_file) else os.path.relpath(variant)
            msg += f"  A path with a different Unicode normalization exists — did you mean:\n    {shown}\n"
        sys.stderr.write(msg)
        sys.exit(ExitCode.ERROR)
    if os.path.isdir(mhl_file):
        if os.path.basename(os.path.normpath(mhl_file)) == "ascmhl":
            sys.stderr.write(
                f"Error: '{mhl_file}' is an ASC-MHL v2 package directory.\n"
                "  simple-mhl only handles classic MHL files. "
                "You may want to use mhlver to verify this ASC-MHL.\n"
            )
        else:
            sys.stderr.write(
                f"Error: '{mhl_file}' is a directory.\n"
                "  The verify command requires a path to an MHL file (e.g. manifest.mhl).\n"
            )
        sys.exit(ExitCode.ERROR)
    if not mhl_file.lower().endswith(".mhl"):
        sys.stderr.write(
            f"Error: '{mhl_file}' does not have a .mhl extension.\n"
            "  The verify command requires a path to an MHL file (e.g. manifest.mhl).\n"
        )
        sys.exit(ExitCode.ERROR)


def _reject_ascmhl_v2(mhl_file: str) -> None:
    """
    Reject an ASC-MHL v2 manifest handed to simple-mhl, redirecting the
    operator to mhlver. Malformed XML is left to verify_classic (which maps it
    to exit 40), so is_ascmhl_v2 swallows parse errors and returns False here.
    """
    if is_ascmhl_v2(mhl_file):
        sys.stderr.write(
            f"Error: '{mhl_file}' is an ASC-MHL v2 manifest.\n"
            "  simple-mhl only handles classic MHL files. "
            "You may want to use mhlver to verify this ASC-MHL.\n"
        )
        sys.exit(ExitCode.ERROR)


# -----------------------------------------------------------------------------
# Verify command
# -----------------------------------------------------------------------------


def verify(
    mhl_file: str, verbose: bool = False, algorithm: "str | list[str] | None" = None, size_only: bool = False
) -> None:
    """
    Verify a classic MHL manifest and present the result on the terminal.

    Thin wrapper over classic_verify.verify_classic: validates the path,
    rejects ASC-MHL v2, runs the engine, prints the rendered [OK]/[ERROR]
    lines, then exits on the report's code.

    Exit codes (see _exit_codes.ExitCode): 0 clean, 1 not an MHL file, 2 bad
    algorithm, 40 malformed XML, 10 missing files only, 11 hash mismatch (wins
    over missing); size-only mode reports 13 for any size mismatch.
    """
    _validate_mhl_path(mhl_file)
    _reject_ascmhl_v2(mhl_file)
    try:
        report = verify_classic(mhl_file, algorithm=algorithm, size_only=size_only)
    except ValueError as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(2)
    for line in render_verify_lines(report, verbose):
        # Paths are stored forward-slash internally; the terminal is the one
        # place we show the native separator.
        print(to_terminal_sep(line))
    if report.code:
        sys.exit(report.code)


# -----------------------------------------------------------------------------
# Seal command
# -----------------------------------------------------------------------------


def seal(path: str, algorithms: "list[str]", verbose: bool, output_dir: "str | None") -> None:
    """Seal a directory, rendering SealError as stderr text with exit 2."""
    try:
        seal_classic(path, algorithms, verbose, output_dir)
    except SealError as e:
        sys.stderr.write(f"{e}\n")
        sys.exit(2)


# -----------------------------------------------------------------------------
# XSD schema validation
# -----------------------------------------------------------------------------


def validate_schema(mhl_file: str) -> None:
    """Validate `mhl_file` against the bundled XSD, writing errors and exiting on failure."""
    code, lines = classic_schema_report(mhl_file)
    for line in lines:
        sys.stderr.write(line + "\n")
    if code:
        sys.exit(code)


# -----------------------------------------------------------------------------
# CLI entry point
# -----------------------------------------------------------------------------


def _dedup_keys_by_tag(keys: list[str]) -> list[str]:
    """
    De-duplicate algorithm keys by their manifest tag, first occurrence wins,
    so `xxhash` and `xxh64` together record a single <xxhash64be>.
    """
    out: list[str] = []
    seen_tags: set[str] = set()
    for name in keys:
        tag = classic_seal_tag(name)
        if tag not in seen_tags:
            seen_tags.add(tag)
            out.append(name)
    return out


def parse_algorithms(value: str) -> list[str]:
    """
    argparse type= for `seal -a`: parse a comma-separated list of algorithm
    names into a validated, de-duplicated list of keys.

    Aliases resolving to the same manifest tag are collapsed (first wins).
    `null` (no digest) is accepted here; its exclusivity is enforced later in
    _resolve_seal_algorithms. Unknown names raise argparse.ArgumentTypeError,
    which argparse turns into a usage error (exit 2).
    """
    keys: list[str] = []
    for raw in value.split(","):
        name = raw.strip().lower()
        if not name:
            continue
        if name != NULL_TAG and name not in CLASSIC_KEYS:
            raise argparse.ArgumentTypeError(
                f"unsupported algorithm '{name}' (choose from {', '.join(sorted([*CLASSIC_CANONICAL_KEYS, NULL_TAG]))})"
            )
        keys.append(name)
    if not keys:
        raise argparse.ArgumentTypeError("no algorithm given")
    return _dedup_keys_by_tag(keys)


def combine_seal_algorithms(parsed: "list[list[str]] | None") -> list[str]:
    """
    Merge repeated `seal -a` occurrences into one de-duplicated key list.

    With action="append" each `-a` yields its own parsed list, so `-a md5 -a
    sha1` arrives as [["md5"], ["sha1"]]. None means no `-a` was given, so we
    fall back to the default of xxh64 (written as <xxhash64be>).
    """
    if not parsed:
        return ["xxh64"]
    flat = [name for group in parsed for name in group]
    return _dedup_keys_by_tag(flat)


def parse_verify_algorithms(value: str) -> "str | list[str]":
    """
    argparse type= for `verify -a`: parse a comma-separated list of algorithm
    names or the keyword 'all'.

    Returns the VERIFY_ALL sentinel if 'all' appears anywhere (it supersedes
    any specific names), otherwise a de-duplicated list of canonical manifest
    tags (aliases collapse, e.g. xxhash/xxh64 → xxhash64be). Unknown names
    raise argparse.ArgumentTypeError, which argparse turns into a usage error
    (exit 2).
    """
    names = [raw.strip().lower() for raw in value.split(",")]
    names = [n for n in names if n]
    if not names:
        raise argparse.ArgumentTypeError("no algorithm given")
    if VERIFY_ALL in names:
        return VERIFY_ALL
    tags: list[str] = []
    seen: set[str] = set()
    for name in names:
        if name not in CLASSIC_KEYS:
            raise argparse.ArgumentTypeError(
                f"unsupported algorithm '{name}' (choose from all, {', '.join(sorted(CLASSIC_CANONICAL_KEYS))})"
            )
        tag = classic_canonical_tag(name)
        if tag not in seen:
            seen.add(tag)
            tags.append(tag)
    return tags


def combine_verify_algorithms(
    parsed: "list[str | list[str]] | None",
) -> "str | list[str] | None":
    """
    Merge repeated `verify -a` occurrences into one selection.

    With action="append" each `-a` yields its own parsed value. None means no
    `-a` was given (verify the fastest available). 'all' supersedes any
    specific names, and specific tags are flattened and de-duplicated in
    order.
    """
    if not parsed:
        return None
    if VERIFY_ALL in parsed:
        return VERIFY_ALL
    tags: list[str] = []
    seen: set[str] = set()
    for group in parsed:
        for tag in group:
            if tag not in seen:
                seen.add(tag)
                tags.append(tag)
    return tags


def main() -> None:
    """Console-script entry point: the CLI body runs inside the PyPI update check."""
    run_with_update_check("mhl-suite", __version__, _main)


def _main() -> None:
    # --- Smart dispatch ------------------------------------------------------
    # When invoked without an explicit subcommand we inspect the sole
    # positional argument (if there is exactly one) and infer the intended
    # operation:
    #
    #   simple-mhl <directory>   →  simple-mhl seal <directory>
    #   simple-mhl <file>.mhl    →  simple-mhl verify <file>.mhl
    #
    # This is done by rewriting sys.argv before argparse sees it, so all
    # normal validation (choices=, required=, etc.) still applies. We only
    # rewrite when the first token after the program name is not already a
    # recognised subcommand or flag, keeping full backwards-compatibility.
    _SUBCOMMANDS = {"seal", "verify", "xsd-schema-check"}
    _raw = sys.argv[1:]
    if _raw and _raw[0] not in _SUBCOMMANDS and not _raw[0].startswith("-"):
        _candidate = _raw[0]
        if os.path.isdir(_candidate):
            sys.argv = [sys.argv[0], "seal", *_raw]
        elif _candidate.lower().endswith(".mhl"):
            sys.argv = [sys.argv[0], "verify", *_raw]
        # Anything else falls through to argparse's normal "invalid choice".

    # -v / --verbose is a global flag: sharing it through a parent parser lets
    # it appear either before or after the subcommand. default=SUPPRESS is
    # essential: without it the subparser's own default would clobber a True
    # set by the top-level parser; with SUPPRESS the attribute is only written
    # when -v is actually present, so whichever parser sees it wins.
    global_opts = argparse.ArgumentParser(add_help=False)
    global_opts.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=argparse.SUPPRESS,
        help="enable verbose output (accepted before or after the subcommand)",
    )

    parser = argparse.ArgumentParser(
        prog="simple-mhl",
        description="Modern verification and sealing tool for classic MHL files",
        parents=[global_opts],
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    seal_p = subparsers.add_parser(
        "seal",
        help="seal a directory",
        parents=[global_opts],
    )
    seal_p.add_argument("path", help="path to directory to seal")
    seal_p.add_argument(
        "-a",
        "--algorithm",
        type=parse_algorithms,
        action="append",
        default=None,
        metavar="ALGO[,ALGO...]",
        help="hash algorithm: xxh64 (default), md5, sha1, null (size-only)",
    )
    seal_p.add_argument(
        "-S",
        "--size-only",
        action="store_true",
        help="record file sizes only, no digest (alias for -a null)",
    )
    seal_p.add_argument(
        "-o",
        "--output-dir",
        dest="output_dir",
        default=None,
        metavar="DIR",
        help="directory to write the MHL into (default: directory root)",
    )
    seal_p.set_defaults(
        func=lambda a: seal(
            a.path,
            combine_seal_algorithms(([[NULL_TAG]] if a.size_only else []) + (a.algorithm or [])),
            a.verbose,
            a.output_dir,
        )
    )

    verify_p = subparsers.add_parser("verify", help="verify an MHL file", parents=[global_opts])
    verify_p.add_argument("path", help="path to MHL file")
    verify_p.add_argument(
        "-a",
        "--algorithm",
        type=parse_verify_algorithms,
        action="append",
        default=None,
        metavar="ALGO[,ALGO...]",
        help="hash algorithm: xxh64, md5, sha1, or all (default: fastest)",
    )
    verify_p.add_argument(
        "-S",
        "--size-only",
        action="store_true",
        help="check file sizes only (skip hashing)",
    )
    verify_p.set_defaults(func=lambda a: verify(a.path, a.verbose, combine_verify_algorithms(a.algorithm), a.size_only))

    xsd_p = subparsers.add_parser(
        "xsd-schema-check",
        help="validate against XML Schema Definition",
        parents=[global_opts],
    )
    xsd_p.add_argument("path", help="path to MHL file")
    xsd_p.set_defaults(func=lambda a: validate_schema(a.path))

    # --- '-h <algo>' (instead of -a <algo>) hint -----------------------------
    # A user who typed 'seal -h xxhash' probably meant '-a xxhash' ('-h' for
    # "hash" instead of -a for "algorithm"). So when '-h' is immediately
    # followed by a valid algorithm name, we prepend a hint to the help menu.
    _argv = sys.argv[1:]
    for _i in range(len(_argv) - 1):
        if _argv[_i] not in ("-h", "--help"):
            continue
        _sub = next((t for t in _argv[:_i] if t in _SUBCOMMANDS), None)
        if _sub not in ("seal", "verify"):
            continue
        _valid = set(CLASSIC_KEYS) | ({VERIFY_ALL} if _sub == "verify" else {NULL_TAG})
        _algo = _argv[_i + 1]
        if _algo in _valid:
            print(f"\nDid you mean '-a {_algo}' (-a / --algorithm)?\n", file=sys.stderr)
            {"seal": seal_p, "verify": verify_p}[_sub].print_help()
            sys.exit(2)

    args = parser.parse_args()
    # SUPPRESS leaves verbose unset when -v is given nowhere; normalise to
    # False.
    if not hasattr(args, "verbose"):
        args.verbose = False
    args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
