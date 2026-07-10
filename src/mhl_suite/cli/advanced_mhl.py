#!/usr/bin/env python3
"""
advanced-mhl — native sealing and verification tool for ASC MHL histories.

This module is the command-line interface, and the only place in the ASC-MHL
path that writes to the terminal or exits the process: the engines
(ascmhl_seal, ascmhl_ops, ascmhl_history) return structured results or raise
typed errors, and this module renders them (via the shared renderer in
mhl_suite.verify) and maps them to exit codes.

Subcommands (ASC MHL Specification v1.0 operations):

    advanced-mhl seal <directory>       — create or append a generation (5.6.2/5.6.5)
    advanced-mhl verify <directory>     — verify and append a generation (5.6.4)
    advanced-mhl diff <directory>       — unknown/missing files, no hashing (5.6.3)
    advanced-mhl rename <old> <new>     — rename and record previousPath (5.6.6)
    advanced-mhl flatten <dir> <dest>   — packing list + collection (5.6.7)
    advanced-mhl xsd-schema-check <f>   — validate against the bundled XSD
"""

import argparse
import os
import sys

from mhl_suite import __version__
from mhl_suite._exit_codes import ExitCode
from mhl_suite.algorithms import ASC_FORMATS
from mhl_suite.ascmhl_history import ASCMHL_FOLDER, HistoryError, NoHistoryError, verify_ascmhl
from mhl_suite.ascmhl_ops import diff_ascmhl, flatten_ascmhl, rename_ascmhl
from mhl_suite.ascmhl_seal import AscmhlSealError, SealOptions, SealResult, seal_ascmhl
from mhl_suite.osutils import to_terminal_sep
from mhl_suite.update_checker import run_with_update_check
from mhl_suite.verify import Status, VerifyReport, render_verify_lines, status_line
from mhl_suite.xsd_check import ascmhl_schema_report

DEFAULT_ALGORITHM = "xxh128"


# -----------------------------------------------------------------------------
# Shared argument handling
# -----------------------------------------------------------------------------


def parse_asc_algorithms(value: str) -> list[str]:
    """
    argparse type= for `-a`: a comma-separated list of ASC hash format names,
    validated against the closed XSD set and de-duplicated in order.
    """
    names = [raw.strip().lower() for raw in value.split(",") if raw.strip()]
    if not names:
        raise argparse.ArgumentTypeError("no algorithm given")
    for name in names:
        if name not in ASC_FORMATS:
            raise argparse.ArgumentTypeError(
                f"unsupported algorithm '{name}' (choose from {', '.join(sorted(ASC_FORMATS))})"
            )
    return list(dict.fromkeys(names))


def combine_algorithms(parsed: "list[list[str]] | None") -> tuple[str, ...]:
    """Merge repeated `-a` occurrences (action="append") into one ordered tuple; default xxh128."""
    if not parsed:
        return (DEFAULT_ALGORITHM,)
    return tuple(dict.fromkeys(name for group in parsed for name in group))


def gather_ignore_patterns(patterns: "list[str] | None", spec_file: "str | None") -> tuple[str, ...]:
    """`-i` patterns plus the non-empty lines of an `--ignore-spec` file, in order."""
    out = list(patterns or [])
    if spec_file is not None:
        try:
            with open(spec_file, encoding="utf-8") as fh:
                out.extend(line.rstrip("\n") for line in fh if line.strip())
        except OSError as exc:
            sys.stderr.write(f"Error: cannot read ignore spec '{spec_file}': {exc.strerror or exc}\n")
            sys.exit(2)
    return tuple(out)


def _fail(error: Exception) -> "int":
    """Map an engine exception to (stderr text, exit code)."""
    if isinstance(error, HistoryError):
        sys.stderr.write(f"{error}\n")
        return int(error.code)
    sys.stderr.write(f"{error}\n")
    return 2


# -----------------------------------------------------------------------------
# Commands
# -----------------------------------------------------------------------------


def _print_report(report: VerifyReport, verbose: bool) -> None:
    for line in render_verify_lines(report, verbose):
        print(to_terminal_sep(line))


def _print_seal_result(result: SealResult, verbose: bool) -> None:
    """
    Seal-flavoured rendering: newly recorded files are the operation's point,
    so they show as [NEW] (verbose) rather than the verify renderer's
    "unknown file" failure; everything else reuses the shared renderer.
    """
    for line in result.report.notices:
        print(to_terminal_sep(line))
    for entry in result.report.entries:
        if entry.status == Status.NEW:
            if verbose:
                print(to_terminal_sep(f"[NEW] {entry.path}"))
        elif entry.status == Status.OK:
            if verbose:
                print(to_terminal_sep(status_line(entry)))
        else:
            print(to_terminal_sep(status_line(entry)))
    if verbose:
        for manifest in result.manifests_written:
            print(f"Created new generation: {manifest}")


def seal(
    path: str, algorithms: tuple[str, ...], directory_hashes: bool, patterns: tuple[str, ...], verbose: bool
) -> None:
    """Seal a directory: initiate or append one generation per history level."""
    options = SealOptions(algorithms=algorithms, directory_hashes=directory_hashes, ignore_patterns=patterns)
    try:
        result = seal_ascmhl(path, options)
    except (AscmhlSealError, HistoryError) as e:
        sys.exit(_fail(e))
    _print_seal_result(result, verbose)
    if result.write_failures and result.seal_code == ExitCode.OK:
        sys.exit(ExitCode.ERROR)
    sys.exit(int(result.seal_code))


def verify(
    path: str,
    algorithms: "tuple[str, ...] | None",
    directory_hashes: bool,
    patterns: tuple[str, ...],
    read_only: bool,
    verbose: bool,
) -> None:
    """
    Verify a managed data set. By default this appends a new generation
    recording the results (spec 5.6.4); --read-only checks without writing.
    """
    if not os.path.isdir(os.path.join(path, ASCMHL_FOLDER)):
        sys.exit(_fail(NoHistoryError(os.path.abspath(path))))
    if read_only:
        report = verify_ascmhl(path, selection=list(algorithms) if algorithms else None)
        _print_report(report, verbose)
        sys.exit(int(report.code))
    options = SealOptions(
        algorithms=algorithms or (DEFAULT_ALGORITHM,),
        directory_hashes=directory_hashes,
        ignore_patterns=patterns,
    )
    try:
        result = seal_ascmhl(path, options)
    except (AscmhlSealError, HistoryError) as e:
        sys.exit(_fail(e))
    _print_report(result.report, verbose)
    if verbose:
        for manifest in result.manifests_written:
            print(f"Created new generation: {manifest}")
    sys.exit(int(result.report.code))


def diff(path: str, verbose: bool) -> None:
    """Report unknown and missing files; no hashing, nothing written."""
    report = diff_ascmhl(path)
    _print_report(report, verbose)
    sys.exit(int(report.code))


def rename(old: str, new: str, verbose: bool) -> None:
    """Rename a file/directory and record previousPath in a new generation."""
    try:
        manifest, report = rename_ascmhl(old, new)
    except (AscmhlSealError, HistoryError) as e:
        sys.exit(_fail(e))
    _print_report(report, verbose)
    if verbose:
        print(f"Created new generation: {manifest}")
    sys.exit(int(report.code))


def flatten(path: str, destination: str, verbose: bool) -> None:
    """Consolidate a history into a packing list plus collection entry."""
    try:
        packinglist, collection = flatten_ascmhl(path, destination)
    except (AscmhlSealError, HistoryError) as e:
        sys.exit(_fail(e))
    print(f"Created packing list: {packinglist}")
    if verbose:
        print(f"Updated collection: {collection}")


def validate_schema(file_path: str) -> None:
    """Validate a manifest (.mhl) or chain/collection (.xml) file against the bundled XSD."""
    directory_file = file_path.lower().endswith(".xml")
    code, lines = ascmhl_schema_report(file_path, directory_file=directory_file)
    for line in lines:
        sys.stderr.write(line + "\n")
    if code:
        sys.exit(code)


# -----------------------------------------------------------------------------
# CLI entry point
# -----------------------------------------------------------------------------

_SUBCOMMANDS = {"seal", "verify", "diff", "rename", "flatten", "xsd-schema-check"}


def main() -> None:
    """Console-script entry point: the CLI body runs inside the PyPI update check."""
    run_with_update_check("mhl-suite", __version__, _main)


def _dispatch_bare_argument() -> None:
    """
    Smart dispatch: `advanced-mhl <dir>` verifies when the directory already
    carries a history and seals when it doesn't; a bare .mhl/.xml file goes to
    the schema check. sys.argv is rewritten before argparse sees it, so all
    normal validation still applies.
    """
    raw = sys.argv[1:]
    if not raw or raw[0] in _SUBCOMMANDS or raw[0].startswith("-"):
        return
    candidate = raw[0]
    if os.path.isdir(candidate):
        command = "verify" if os.path.isdir(os.path.join(candidate, ASCMHL_FOLDER)) else "seal"
        sys.argv = [sys.argv[0], command, *raw]
    elif candidate.lower().endswith((".mhl", ".xml")):
        sys.argv = [sys.argv[0], "xsd-schema-check", *raw]
    # Anything else falls through to argparse's normal "invalid choice".


def _add_seal_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-a",
        "--algorithm",
        type=parse_asc_algorithms,
        action="append",
        default=None,
        metavar="ALGO[,ALGO...]",
        help=f"hash format: {', '.join(sorted(ASC_FORMATS))} (default: {DEFAULT_ALGORITHM})",
    )
    parser.add_argument(
        "-n",
        "--no-directory-hashes",
        dest="directory_hashes",
        action="store_false",
        help="skip directory (content/structure) hashes",
    )
    parser.add_argument(
        "-i",
        "--ignore",
        action="append",
        default=None,
        metavar="PATTERN",
        help="ignore pattern (gitignore syntax, may be repeated); the recorded list only grows",
    )
    parser.add_argument(
        "--ignore-spec",
        default=None,
        metavar="FILE",
        help="file of ignore patterns, one per line",
    )


def _main() -> None:
    _dispatch_bare_argument()

    global_opts = argparse.ArgumentParser(add_help=False)
    global_opts.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=argparse.SUPPRESS,
        help="enable verbose output (accepted before or after the subcommand)",
    )

    parser = argparse.ArgumentParser(
        prog="advanced-mhl",
        description="Native sealing and verification tool for ASC MHL histories (ASC MHL spec v1.0)",
        parents=[global_opts],
    )
    parser.add_argument("--version", action="version", version=__version__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    seal_p = subparsers.add_parser(
        "seal", help="seal a directory (create or extend its ASC MHL history)", parents=[global_opts]
    )
    seal_p.add_argument("path", help="directory to seal")
    _add_seal_options(seal_p)
    seal_p.set_defaults(
        func=lambda a: seal(
            a.path,
            combine_algorithms(a.algorithm),
            a.directory_hashes,
            gather_ignore_patterns(a.ignore, a.ignore_spec),
            a.verbose,
        )
    )

    verify_p = subparsers.add_parser(
        "verify", help="verify a managed data set (appends a new generation)", parents=[global_opts]
    )
    verify_p.add_argument("path", help="directory carrying an ascmhl history")
    _add_seal_options(verify_p)
    verify_p.add_argument(
        "--read-only",
        action="store_true",
        help="verify without writing a new generation (spec 5.6.4 normally appends one)",
    )
    verify_p.set_defaults(
        func=lambda a: verify(
            a.path,
            combine_algorithms(a.algorithm) if a.algorithm else None,
            a.directory_hashes,
            gather_ignore_patterns(a.ignore, a.ignore_spec),
            a.read_only,
            a.verbose,
        )
    )

    diff_p = subparsers.add_parser("diff", help="report unknown and missing files (no hashing)", parents=[global_opts])
    diff_p.add_argument("path", help="directory carrying an ascmhl history")
    diff_p.set_defaults(func=lambda a: diff(a.path, a.verbose))

    rename_p = subparsers.add_parser(
        "rename", help="rename a file or directory, recording previousPath", parents=[global_opts]
    )
    rename_p.add_argument("old", help="current path")
    rename_p.add_argument("new", help="new path")
    rename_p.set_defaults(func=lambda a: rename(a.old, a.new, a.verbose))

    flatten_p = subparsers.add_parser(
        "flatten", help="consolidate a history into a packing-list manifest", parents=[global_opts]
    )
    flatten_p.add_argument("path", help="directory carrying an ascmhl history")
    flatten_p.add_argument("destination", help="directory to write the packing list and collection into")
    flatten_p.set_defaults(func=lambda a: flatten(a.path, a.destination, a.verbose))

    xsd_p = subparsers.add_parser(
        "xsd-schema-check", help="validate against the ASC MHL XML Schema", parents=[global_opts]
    )
    xsd_p.add_argument("path", help="path to a .mhl manifest or ascmhl_chain/collection .xml")
    xsd_p.set_defaults(func=lambda a: validate_schema(a.path))

    args = parser.parse_args()
    if not hasattr(args, "verbose"):
        args.verbose = False
    args.func(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
