"""
Classic MHL verification: the manifest parser and the dialect policy.

parse_classic_manifest() streams a classic manifest into the engine's
FileRecords (one pass, also yielding the byte weight the progress bar uses);
verify_classic() runs those records through the shared engine
(mhl_suite.verify) and applies classic policy — exit-code derivation and the
weak-check notices. Never prints and never exits: parse failures raise
MalformedManifestError inside the parser only (an I/O error during hashing is
a per-file outcome, not a malformed manifest), and the CLIs render the
returned VerifyReport via the shared renderer (mhl_suite.verify).
"""

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

from lxml import etree

from mhl_suite import verify as verify_core
from mhl_suite._exit_codes import ExitCode
from mhl_suite.algorithms import CLASSIC_TAGS, NULL_TAG, classic_canonical_tag, classic_check
from mhl_suite.verify import VERIFY_ALL, ErrorKind, FileRecord, Status, VerifyEntry, VerifyReport

if TYPE_CHECKING:
    from collections.abc import Callable


class MalformedManifestError(Exception):
    """The manifest is not well-formed / readable XML."""


def _localname(tag: object) -> str:
    """
    Return the local-name part of a possibly-namespaced XML tag.

    lxml stores namespaced tags as '{uri}localname'. rpartition('}')[2] gives
    'localname' if the brace exists and the whole tag if it doesn't. Non-string
    tags (lxml Comment and ProcessingInstruction nodes carry a callable as
    their .tag attribute) are returned as an empty string so callers can safely
    match them against element names.
    """
    if not isinstance(tag, str):
        return ""
    return tag.rpartition("}")[2] if "}" in tag else tag


def _free_processed(h: "etree._Element") -> None:
    """
    Release `h` and every already-processed sibling during iterparse, keeping
    peak DOM memory proportional to a single element regardless of manifest
    size.
    """
    h.clear()
    parent = h.getparent()
    if parent is not None:
        while h.getprevious() is not None:
            del parent[0]


@dataclass
class ParsedManifest:
    """A classic manifest reduced to engine records plus its progress weight."""

    records: list[FileRecord]
    # Total recorded bytes of the entries verify will actually hash-read (<null>
    # and unrecognised-only entries read no media bytes), used to weight the
    # progress bar.
    hash_bytes: int


def parse_classic_manifest(mhl_file: str) -> ParsedManifest:
    """
    Stream `mhl_file` (iterparse, one <hash> element in memory at a time) into
    FileRecords. Raises MalformedManifestError when the file cannot be read or
    parsed as XML — the caller maps that to ExitCode.MALFORMED_XML.

    Per entry: the <file> path as recorded (forward slashes), every recognised
    hash element as a HashCheck (unrecognised formats are skipped exactly as if
    absent), the <null> marker, and the <size> — a non-decimal size becomes a
    per-file defect rather than failing the parse, because isdecimal() rejects
    the Unicode "digits" int() would silently convert to the wrong value
    (corruption or tampering). Entries without a <file> child are silently
    skipped (xsd-schema-check would have caught them).
    """
    records: list[FileRecord] = []
    hash_bytes = 0
    try:
        for _, h in etree.iterparse(mhl_file, events=("end",), tag="{*}hash"):
            file_el = h.find("{*}file")
            if file_el is None or file_el.text is None:
                _free_processed(h)
                continue

            checks = []
            has_null = False
            for child in h:
                name = _localname(child.tag).lower()
                if name == NULL_TAG:
                    has_null = True
                    continue
                check = classic_check(name, child.text or "")
                if check is not None:
                    checks.append(check)

            recorded_size: int | None = None
            defect: ErrorKind | None = None
            size_el = h.find("{*}size")
            if size_el is not None and size_el.text is not None:
                size_text = size_el.text.strip()
                if size_text.isdecimal():
                    recorded_size = int(size_text)
                else:
                    defect = ErrorKind.MALFORMED_SIZE

            records.append(
                FileRecord(
                    path=file_el.text,
                    checks=checks,
                    recorded_size=recorded_size,
                    has_null=has_null,
                    defect=defect,
                )
            )
            if checks and recorded_size is not None:
                hash_bytes += recorded_size
            _free_processed(h)
    except (etree.XMLSyntaxError, OSError) as exc:
        raise MalformedManifestError(str(exc)) from exc
    return ParsedManifest(records=records, hash_bytes=hash_bytes)


def _resolve_selection(algorithm: "str | list[str] | None") -> "str | list[str] | None":
    """
    Resolve the optional -a value to an engine selection: None (fastest
    single), VERIFY_ALL, or a list of canonical manifest tags. A bad name
    raises ValueError (the CLI validates via argparse before reaching here;
    mhlver always passes None).
    """
    if algorithm is None or algorithm == VERIFY_ALL:
        return algorithm
    if isinstance(algorithm, str):
        canonical = classic_canonical_tag(algorithm)
        if canonical not in CLASSIC_TAGS:
            raise ValueError(f"unsupported algorithm '{algorithm}'")
        return [canonical]
    for tag in algorithm:
        if tag not in CLASSIC_TAGS:
            raise ValueError(f"unsupported algorithm '{tag}'")
    return algorithm


def _weak_check_notices(records: "list[FileRecord]", entries: "list[VerifyEntry]") -> list[str]:
    """
    The manifest-level notice naming which weak (non-hash) checks the verify
    relied on, so an existence-only pass doesn't read as a size-only one.
    Derived from records-zipped-with-entries (the engine returns exactly one entry per
    record, in order): a <null> record counts once its file was actually
    reached (missing/traversal-blocked entries never got a weak check).
    """
    saw_size_only = False
    saw_existence_only = False
    saw_hash = False
    for record, entry in zip(records, entries, strict=True):
        if entry.status == Status.MISSING or entry.error == ErrorKind.TRAVERSAL:
            continue
        if record.has_null and not record.checks:
            if record.recorded_size is not None:
                saw_size_only = True
            else:
                saw_existence_only = True
        elif entry.hashes or entry.error == ErrorKind.IO:
            saw_hash = True

    if not (saw_size_only or saw_existence_only):
        return []
    kinds = []
    if saw_size_only:
        kinds.append("size-only")
    if saw_existence_only:
        kinds.append("existence-only")
    kind_phrase = " and ".join(kinds)
    if saw_hash:
        return [f"Partially verified with {kind_phrase} checks (some hashes missing from the manifest)."]
    # No hashes are stored either way. Sizes are: all present (size-only only),
    # all absent (existence-only only), or partial (a mix of both null kinds).
    if not saw_existence_only:
        stored = "hashes"
    elif saw_size_only:
        stored = "hashes and some sizes"
    else:
        stored = "hashes and sizes"
    return [f"Verified with {kind_phrase} checks ({stored} missing from the manifest)."]


def verify_classic(
    mhl_file: str,
    *,
    algorithm: "str | list[str] | None" = None,
    size_only: bool = False,
    on_progress: "Callable[[int], None] | None" = None,
    parsed: "ParsedManifest | None" = None,
) -> VerifyReport:
    """
    Verify each file listed in `mhl_file` against its stored hash and return a
    structured VerifyReport. Never prints and never calls sys.exit — the caller
    decides how to present the result (see the shared renderer (mhl_suite.verify)). `parsed` lets a
    caller that already parsed the manifest (mhl_suite.discovery, for progress
    weights) hand it over instead of parsing twice.

    `algorithm` selects which recorded hash(es) to check: None (the fastest
    recorded), "all" (every recorded hash), or a list of canonical manifest
    tags; a bad selection raises ValueError. `size_only` skips hashing and
    checks each entry's recorded <size> against the file on disk. `on_progress`
    is forwarded to the engine (per-chunk byte counts; may fire from worker
    threads, so it must be thread-safe).

    Report codes (see _exit_codes.ExitCode): 0 clean, 40 malformed XML, 10
    missing only, 11 hash-mismatch/error (wins over missing); size-only mode
    reports 13 for any size mismatch or per-file error.
    """
    selection = _resolve_selection(algorithm)

    try:
        if parsed is None:
            parsed = parse_classic_manifest(mhl_file)
    except MalformedManifestError:
        return VerifyReport(code=ExitCode.MALFORMED_XML, malformed=True, size_only_mode=size_only)

    # All file references in the manifest are relative to the directory the
    # manifest lives in — that directory is the engine's traversal jail.
    entries = verify_core.verify_records(
        os.path.dirname(os.path.abspath(mhl_file)),
        parsed.records,
        selection=selection,
        size_only=size_only,
        missing_size_is_error=True,
        on_progress=on_progress,
    )

    notices = [] if size_only else _weak_check_notices(parsed.records, entries)

    n_missing = sum(1 for e in entries if e.status == Status.MISSING)
    n_fail = sum(1 for e in entries if e.status in (Status.MISMATCH, Status.ERROR))
    # Mismatch wins over missing everywhere — a run with both reports the
    # mismatch code. size_only failures are size mismatches, never hash ones.
    if n_fail:
        code = ExitCode.SIZE_MISMATCH if size_only else ExitCode.HASH_MISMATCH
    elif n_missing:
        code = ExitCode.MISSING
    else:
        code = ExitCode.OK

    return VerifyReport(entries=entries, code=code, notices=notices, size_only_mode=size_only)
