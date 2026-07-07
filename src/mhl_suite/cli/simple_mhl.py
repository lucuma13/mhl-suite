#!/usr/bin/env python3
"""
simple-mhl — modern verification and sealing tool for classic MHL files.

This module is the command-line interface. The hashing, sealing, and
verification logic lives in mhl_suite; simple_mhl wires argparse up to it and
renders the engine's structured results to the terminal.

Three subcommands are exposed via argparse:

    simple-mhl seal <directory>          — walk a directory and write an MHL
    simple-mhl verify <file.mhl>         — re-hash files listed in a manifest
    simple-mhl xsd-schema-check <file>   — validate XML structure against XSD

A few engine helpers are re-exported here (see __all__) solely so the test suite
can reach them through the simple_mhl namespace. The os and etree modules are
imported for the same reason: simple_mhl.os and simple_mhl.etree resolve to the
shared module singletons, so a test patching an attribute on them is seen by the
engine's calls too.
"""

import argparse
import os
import sys

from lxml import etree  # noqa: F401 — re-exported so tests can patch simple_mhl.etree.* (shared lxml module)

from mhl_suite import __version__
from mhl_suite.classic_seal import (
    _build_creatorinfo,
    _iter_files_for_seal,
    seal_classic,
)
from mhl_suite.classic_verify import (
    _VERIFY_ALL,
    _localname,
    _reject_ascmhl_v2,
    _validate_mhl_path,
    render_verify_lines,
    schema_report,
    verify_classic,
)
from mhl_suite.hashing import (
    _NULL_TAG,
    ALGO_MAP,
    _seal_tag,
    get_hash,
    get_hashes,
)
from mhl_suite.osutils import to_terminal_sep

# Re-exports for the test suite (see the module docstring). Only names the CLI
# itself uses or that a test reaches through the simple_mhl namespace are kept
# here — do not prune them as "unused imports".
__all__ = [
    "ALGO_MAP",
    "_NULL_TAG",
    "_VERIFY_ALL",
    "_build_creatorinfo",
    "_iter_files_for_seal",
    "_localname",
    "_reject_ascmhl_v2",
    "_seal_tag",
    "_validate_mhl_path",
    "combine_seal_algorithms",
    "combine_verify_algorithms",
    "get_hash",
    "get_hashes",
    "main",
    "parse_algorithms",
    "parse_verify_algorithms",
    "render_verify_lines",
    "schema_report",
    "seal_classic",
    "validate_schema",
    "verify",
    "verify_classic",
]

# -----------------------------------------------------------------------------
# Verify command
# -----------------------------------------------------------------------------


def verify(
    mhl_file: str, verbose: bool = False, algorithm: "str | list[str] | None" = None, size_only: bool = False
) -> None:
    """
    Verify a classic MHL manifest and present the result on the terminal.

    Thin wrapper over classic_verify.verify_classic: validates the path, rejects
    ASC-MHL v2, runs the engine, prints the rendered [OK]/[ERROR] lines, then
    exits on the report's code. Output is identical to the historic verify().

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
# XSD schema validation
# -----------------------------------------------------------------------------


def validate_schema(mhl_file: str) -> None:
    """Validate `mhl_file` against the bundled XSD, writing errors and exiting on failure."""
    code, lines = schema_report(mhl_file)
    for line in lines:
        sys.stderr.write(line + "\n")
    if code:
        sys.exit(code)


# -----------------------------------------------------------------------------
# CLI entry point
# -----------------------------------------------------------------------------


def _dedup_keys_by_tag(keys: list[str]) -> list[str]:
    """
    De-duplicate ALGO_MAP keys by their manifest tag, first occurrence wins.

    Aliases resolving to the same manifest tag collapse, so `xxhash` and `xxh64`
    together record a single <xxhash64be>.
    """
    out: list[str] = []
    seen_tags: set[str] = set()
    for name in keys:
        tag = _seal_tag(name)
        if tag not in seen_tags:
            seen_tags.add(tag)
            out.append(name)
    return out


def parse_algorithms(value: str) -> list[str]:
    """
    argparse type= for `seal -a`: parse a comma-separated list of algorithm
    names into a validated, de-duplicated list of ALGO_MAP keys.

    Aliases resolving to the same manifest tag are collapsed (first wins), so
    `-a xxhash,xxh64` records a single <xxhash64be>. `null` (no digest) is
    accepted here; its exclusivity is enforced later in
    _resolve_seal_algorithms. Unknown names raise argparse.ArgumentTypeError,
    which argparse turns into a usage error (exit 2).
    """
    keys: list[str] = []
    for raw in value.split(","):
        name = raw.strip().lower()
        if not name:
            continue
        if name != _NULL_TAG and name not in ALGO_MAP:
            raise argparse.ArgumentTypeError(
                f"unsupported algorithm '{name}' (choose from {', '.join(sorted([*ALGO_MAP, _NULL_TAG]))})"
            )
        keys.append(name)
    if not keys:
        raise argparse.ArgumentTypeError("no algorithm given")
    return _dedup_keys_by_tag(keys)


def combine_seal_algorithms(parsed: list[list[str]] | None) -> list[str]:
    """
    Merge repeated `seal -a` occurrences into one de-duplicated key list.

    With action="append" each `-a` yields its own parsed list, so `-a md5 -a
    sha1` arrives as [["md5"], ["sha1"]]. None means no `-a` was given, so we
    fall back to the historic default of xxhash.
    """
    if not parsed:
        return ["xxhash"]
    flat = [name for group in parsed for name in group]
    return _dedup_keys_by_tag(flat)


def parse_verify_algorithms(value: str) -> "str | list[str]":
    """
    argparse type= for `verify -a`: parse a comma-separated list of algorithm
    names or the keyword 'all'.

    Returns the _VERIFY_ALL sentinel if 'all' appears anywhere (it supersedes
    any specific names), otherwise a de-duplicated list of canonical manifest
    tags (aliases collapse, e.g. xxhash/xxh64 → xxhash64be). Requested order is
    preserved for the error message only; selection itself is order-independent.
    Unknown names raise argparse.ArgumentTypeError, which argparse turns into a
    usage error (exit 2).
    """
    names = [raw.strip().lower() for raw in value.split(",")]
    names = [n for n in names if n]
    if not names:
        raise argparse.ArgumentTypeError("no algorithm given")
    if _VERIFY_ALL in names:
        return _VERIFY_ALL
    tags: list[str] = []
    seen: set[str] = set()
    for name in names:
        if name not in ALGO_MAP:
            raise argparse.ArgumentTypeError(
                f"unsupported algorithm '{name}' (choose from all, {', '.join(sorted(ALGO_MAP))})"
            )
        tag = ALGO_MAP[name][1]
        if tag not in seen:
            seen.add(tag)
            tags.append(tag)
    return tags


def combine_verify_algorithms(
    parsed: "list[str | list[str]] | None",
) -> "str | list[str] | None":
    """
    Merge repeated `verify -a` occurrences into one selection.

    With action="append" each `-a` yields its own parsed value, so `-a md5 -a
    sha1` arrives as [["md5"], ["sha1"]]. None means no `-a` was given (verify
    the fastest available). 'all' supersedes any specific names, and specific
    tags are flattened and de-duplicated in order.
    """
    if not parsed:
        return None
    if _VERIFY_ALL in parsed:
        return _VERIFY_ALL
    tags: list[str] = []
    seen: set[str] = set()
    for group in parsed:
        for tag in group:
            if tag not in seen:
                seen.add(tag)
                tags.append(tag)
    return tags


def main() -> None:
    # --- Smart dispatch ----------------------------------------------------------------------------------------------
    # When invoked without an explicit subcommand we inspect the sole positional
    # argument (if there is exactly one) and infer the intended operation:
    #
    #   simple-mhl <directory>   →  simple-mhl seal <directory>
    #   simple-mhl <file>.mhl    →  simple-mhl verify <file>.mhl
    #
    # This is done by rewriting sys.argv before argparse sees it, so all normal
    # validation (choices=, required=, etc.) still applies.  We only rewrite
    # when the first token after the program name is not already a recognised
    # subcommand or flag, keeping full backwards-compatibility.
    _SUBCOMMANDS = {"seal", "verify", "xsd-schema-check"}
    _raw = sys.argv[1:]
    if _raw and _raw[0] not in _SUBCOMMANDS and not _raw[0].startswith("-"):
        # Candidate: a single bare path with no subcommand prefix.
        _candidate = _raw[0]
        if os.path.isdir(_candidate):
            # Directory → seal, injecting the subcommand into argv.
            sys.argv = [sys.argv[0], "seal", *_raw]
        elif _candidate.lower().endswith(".mhl"):
            # .mhl file → verify, injecting the subcommand into argv.
            sys.argv = [sys.argv[0], "verify", *_raw]
        # Anything else falls through to argparse, which will produce its
        # normal "argument command: invalid choice" error message.

    # -v / --verbose is a global flag: sharing it through a parent parser lets
    # it appear either before or after the subcommand, so "simple-mhl -v seal ."
    # and "simple-mhl seal -v ." behave identically. default=SUPPRESS is
    # essential: without it the subparser's own default would clobber a True set
    # by the top-level parser. With SUPPRESS, the attribute is only written when
    # -v is actually present, so whichever parser sees it wins; we fall back to
    # False below when it appears nowhere.
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

    # seal subcommand. argparse choices= rejects bad algorithm names before we
    # waste a directory walk on them.
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
        help="hash algorithm: xxhash (default), md5, sha1, null (size-only)",
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
        func=lambda a: seal_classic(a.path, combine_seal_algorithms(a.algorithm), a.verbose, a.output_dir)
    )

    # verify subcommand
    verify_p = subparsers.add_parser("verify", help="verify an MHL file", parents=[global_opts])
    verify_p.add_argument("path", help="path to MHL file")
    verify_p.add_argument(
        "-a",
        "--algorithm",
        type=parse_verify_algorithms,
        action="append",
        default=None,
        metavar="ALGO[,ALGO...]",
        help="hash algorithm: xxhash, md5, sha1, or all (default: fastest)",
    )
    verify_p.add_argument(
        "-S",
        "--size-only",
        action="store_true",
        help="check file sizes only (skip hashing)",
    )
    verify_p.set_defaults(func=lambda a: verify(a.path, a.verbose, combine_verify_algorithms(a.algorithm), a.size_only))

    # xsd-schema-check subcommand
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
        _valid = set(ALGO_MAP) | ({_VERIFY_ALL} if _sub == "verify" else {_NULL_TAG})
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
