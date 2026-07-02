"""
Classic MHL verification engine.

verify_classic() re-hashes the files listed in a classic MHL manifest and returns a structured VerifyReport — no
printing, no sys.exit. The simple-mhl CLI renders that report to [OK]/[ERROR] text via render_verify_lines() and exits
on report.code; mhlver's classic backend maps the VerifyEntries straight onto its own report model. schema_report()
does the same for XSD validation.

Per-entry detail (the "(calc … | stored …)" continuations) is always computed at full fidelity so the report is
identical regardless of the CLI -v flag; the renderer decides whether to show the verbose continuation.

get_hashes and the calibration/probe helpers live in mhl_suite.hashing and are reached through the module object so a
test monkeypatching them still bites.
"""

import importlib.resources
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING, cast

import xxhash
from lxml import etree

from mhl_suite import hashing
from mhl_suite._exit_codes import ExitCode
from mhl_suite.hashing import _NULL_RANK, _NULL_TAG, ALGO_MAP, _Hasher
from mhl_suite.osutils import (
    normalization_variant_on_disk,
    resolve_on_disk,
)
from mhl_suite.verify_results import VerifyEntry, VerifyReport

if TYPE_CHECKING:
    from collections.abc import Callable

# `verify -a all` sentinel: verify every recorded hash per entry rather than a single fixed format. "all" is reserved —
# no manifest tag can collide with it.
_VERIFY_ALL = "all"

# The distinct manifest element names seal writes (aliases collapse to these), used to validate a verify selection
# passed by a direct caller.
_CANONICAL_TAGS = frozenset(tag for _factory, tag, _rank in ALGO_MAP.values())

# ---------------------------------------------------------------------------------------------------------------------
# XSD location
# ---------------------------------------------------------------------------------------------------------------------


def get_xsd_path() -> str:
    """
    Locate the bundled MediaHashList_v1_1.xsd. Returns the path.

    Raises FileNotFoundError if the XSD cannot be found in either the installed-package location or the source-checkout
    fallback.

    Looks first at the importlib.resources location used when this package is installed normally, then at the package's
    sibling 'xsd/' folder for the case where the suite is run directly from a checkout. This module lives at the package
    root (mhl_suite/), so the checkout fallback resolves the xsd/ directory alongside it.
    """
    try:
        resource = importlib.resources.files("mhl_suite.xsd").joinpath("MediaHashList_v1_1.xsd")
        if resource.is_file():
            return str(resource)
    except (ImportError, FileNotFoundError, TypeError):
        pass

    # Source-checkout fallback: mhl_suite/classic_verify.py → mhl_suite/xsd/.
    local = Path(__file__).resolve().parent / "xsd" / "MediaHashList_v1_1.xsd"
    if local.exists():
        return str(local)

    raise FileNotFoundError(f"Could not locate MediaHashList_v1_1.xsd (tried {local})")


# ---------------------------------------------------------------------------------------------------------------------
# Manifest path / version guards (used by the CLI before verifying)
# ---------------------------------------------------------------------------------------------------------------------


def _localname(tag: object) -> str:
    """
    Return the local-name part of a possibly-namespaced XML tag.

    lxml stores namespaced tags as '{uri}localname'. rpartition('}')[2] gives 'localname' if the brace exists and the
    whole tag if it doesn't. Faster than etree.QName() because it skips the QName object construction.

    Non-string tags (lxml Comment and ProcessingInstruction nodes carry a callable as their .tag attribute) are returned
    as an empty string so callers can safely test membership in a frozenset of string tag names.
    """
    if not isinstance(tag, str):
        return ""
    return tag.rpartition("}")[2] if "}" in tag else tag


def _validate_mhl_path(mhl_file: str) -> None:
    """
    Validate that `mhl_file` is a readable MHL file path, exiting with a structured error message if not. Covers:
      * path does not exist
      * path is a directory (with a specific hint for ASC-MHL v2 packages)
      * path lacks a .mhl extension
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


def _is_newer_than_classic(version: str) -> bool:
    """
    True if a `version` attribute's major component is newer than classic MHL: classic manifests are 1.x, ASC-MHL is
    2.0+. Comparing only the major part means minor differences within v1 don't matter and multi-part future versions
    like 2.1.1 are handled. An empty or unparsable value is treated as not-newer.
    """
    try:
        return int(version.split(".", maxsplit=1)[0]) > 1
    except ValueError:
        return False


def is_ascmhl_v2(mhl_file: "str | Path") -> bool:
    """
    True if `mhl_file`'s root element declares ASC-MHL v2 rather than classic MHL.

    Reads only the root start-tag (iterparse, stopping at the first element) and checks for the ASC-MHL v2 namespace
    (urn:ASC:MHL:v2.0) or a `version` whose major component is > 1 — so a future 2.x/3.x/10.x is recognised even without
    the namespace. This is the authoritative dialect signal (classic MHL is version 1.x, ASC-MHL is 2.0+), used both by
    simple-mhl's guard below and by the mhlver orchestrator's backend routing. Any parse/read error yields False (treat
    as not-v2); the malformedness surfaces later where the file is actually verified.
    """
    try:
        with open(mhl_file, "rb") as f:
            for _, root in etree.iterparse(f, events=("start",)):
                ns = etree.QName(root).namespace
                return ns == "urn:ASC:MHL:v2.0" or _is_newer_than_classic(root.get("version", ""))
    except (etree.XMLSyntaxError, OSError):
        return False
    return False


def _reject_ascmhl_v2(mhl_file: str) -> None:
    """
    Reject an ASC-MHL v2 manifest handed to simple-mhl, redirecting the operator to mhlver.

    Malformed XML is left to verify_classic()'s main loop (which maps it to exit 40), so is_ascmhl_v2 swallows parse
    errors and returns False here.
    """
    if is_ascmhl_v2(mhl_file):
        sys.stderr.write(
            f"Error: '{mhl_file}' is an ASC-MHL v2 manifest.\n"
            "  simple-mhl only handles classic MHL files. "
            "You may want to use mhlver to verify this ASC-MHL.\n"
        )
        sys.exit(ExitCode.ERROR)


# -----------------------------------------------------------------------------
# xxHash matching
# -----------------------------------------------------------------------------
# xxHash tags may be big-endian or little-endian hex, and have historically carried a 32-bit integer, so verify must
# account for all of those cases:
#   * xxhash64be — XXH64 as big-endian hex (the canonical modern form)
#   * xxhash64   — the above, or XXH64 as little-endian hex
#   * xxhash     — the above, or XXH32 as a decimal integer (very old form!) Only one digest is computed per entry: the
# stored value's shape selects which.
_XXH64_BE_ONLY = frozenset({"xxhash64be"})
_XXH64_BE_OR_LE = frozenset({"xxhash64", "xxh64"})
# A 32-bit XXH32 in decimal is at most 10 digits (leading zeros might have been stripped). A longer all-digit value
# under <xxhash> is therefore hex, not a decimal integer.
_XXH32_MAX_DECIMAL_DIGITS = 10

# Verify-only factories. XXH32 is needed to recompute the oldest decimal xxHash but is never offered for sealing, so it
# stays out of ALGO_MAP. Cast for the same reason ALGO_MAP is: xxhash's constructor parameter names differ from the
# _Hasher protocol.
_XXH64_FACTORY = cast("Callable[[], _Hasher]", xxhash.xxh64)
_XXH32_FACTORY = cast("Callable[[], _Hasher]", xxhash.xxh32)


def _swap64(value: int) -> int:
    """Return a 64-bit value with its byte order reversed (big-endian <-> little-endian)."""
    return int.from_bytes(value.to_bytes(8, "big"), "little")


def _matches_be(expected: str, computed: int) -> bool:
    """True if `expected` (hex) equals `computed` (a big-endian intdigest), strictly."""
    try:
        return int(expected, 16) == computed
    except ValueError:
        return False


def _matches_be_or_le(expected: str, computed: int) -> bool:
    """
    True if `expected` (hex) equals `computed` in either byte order.

    The two orders are reorderings of the same hash, so accepting both only rescues an intact file recorded in the
    opposite endianness — it never lets a differing file pass.
    """
    try:
        stored = int(expected, 16)
    except ValueError:
        return False
    return stored == computed or stored == _swap64(computed)


def _matches_decimal(expected: str, computed: int) -> bool:
    """True if `expected` (a decimal integer) equals `computed` (an intdigest)."""
    try:
        return int(expected) == computed
    except ValueError:
        return False


def _xxhash_route(localname: str, expected: str) -> "tuple[Callable[[], _Hasher], Callable[[str], bool]] | None":
    """
    Choose the single hash to compute for an xxHash element and the rule that accepts
    its stored value.

    Returns (factory, matches): `matches` receives the computed big-endian hex digest. Returns None when `localname` is
    not an xxHash tag (e.g. md5/sha1), so the caller uses its normal path. The stored value's shape decides which
    algorithm to compute, so a hex digest never pays to compute XXH32: a 16-character hex value is XXH64; a decimal
    value of up to 10 digits (leading zeros may have been dropped) is a 32-bit XXH32.
    """
    name = localname.lower()
    if name in _XXH64_BE_ONLY:
        return _XXH64_FACTORY, lambda calc: _matches_be(expected, int(calc, 16))
    if name in _XXH64_BE_OR_LE:
        return _XXH64_FACTORY, lambda calc: _matches_be_or_le(expected, int(calc, 16))
    if name == "xxhash":
        if expected.isdecimal() and len(expected) <= _XXH32_MAX_DECIMAL_DIGITS:
            return _XXH32_FACTORY, lambda calc: _matches_decimal(expected, int(calc, 16))
        return _XXH64_FACTORY, lambda calc: _matches_be_or_le(expected, int(calc, 16))
    return None


def _make_ci_matcher(expected: str) -> "Callable[[str], bool]":
    """
    Return a case-insensitive exact-hex matcher for a non-xxHash digest.

    md5/sha1 are plain hex with no endianness or legacy-integer ambiguity, so the rule is a straight case-folded compare
    — the counterpart to _xxhash_route's shape-aware matchers, in the same (computed hex) -> bool shape so
    _verify_hashes can treat every check uniformly.
    """
    lowered = expected.lower()
    return lambda calc: calc.lower() == lowered


def _verify_hashes(
    candidate: str,
    checks: "list[tuple[str, str]]",
    rel_path: str,
    on_progress: "Callable[[int], None] | None" = None,
) -> VerifyEntry:
    """
    Verify `candidate` against every (tag, expected) pair in `checks`, hashing in
    a single read pass, and return the resulting VerifyEntry.

    The file is OK only when every check matches; any single mismatch fails the entry. All digests come from one read of
    the file (read-once via get_hashes), so verifying N recorded hashes costs one disk pass, not N. Per-file
    ValueError/OSError become a "cannot verify" error outcome so a thread-pool worker reports rather than tearing down
    the whole verify. `on_progress` is forwarded to get_hashes so the caller's progress bar advances per chunk as the
    file is read.

    `detail` and `detail_line` are always populated at verbose fidelity; the renderer decides whether to show the
    continuation. The single-check detail is the parenthetical "(calc … | stored …)"; an -a all multi-hash mismatch
    keeps a bare "hash mismatch" detail (its continuation is a per-tag block, not a single parenthetical).
    """
    factories: list[Callable[[], _Hasher]] = []
    plans: list[tuple[str, str, Callable[[str], bool]]] = []
    for tag, raw_expected in checks:
        expected = raw_expected.strip()
        route = _xxhash_route(tag, expected)
        if route is not None:
            factory, matches = route
        else:
            factory, matches = ALGO_MAP[tag][0], _make_ci_matcher(expected)
        factories.append(factory)
        plans.append((tag, expected, matches))

    try:
        calculated = hashing.get_hashes(candidate, factories, on_progress=on_progress)
    except (ValueError, OSError) as e:
        return VerifyEntry(path=rel_path, status="error", detail=str(e), line=f"[ERROR] cannot verify {rel_path}: {e}")

    checked = [
        (tag, expected, calc, matches(calc)) for (tag, expected, matches), calc in zip(plans, calculated, strict=True)
    ]

    if all(ok for *_, ok in checked):
        shown = "  ".join(f"{tag}: {calc}" for tag, _e, calc, _ok in checked)
        return VerifyEntry(path=rel_path, status="ok", line=f"[OK] {rel_path}  {shown}")
    if len(checked) == 1:
        tag, expected, calc, _ok = checked[0]
        return VerifyEntry(
            path=rel_path,
            status="mismatch",
            detail=f"hash mismatch: calc {tag}: {calc} | stored {tag}: {expected}",
            line=f"[ERROR] hash mismatch: {rel_path}",
            detail_line=f"        (calc {tag}: {calc} | stored {tag}: {expected})",
        )
    detail_lines = [
        f"        {tag} {'OK' if ok else 'MISMATCH'}: calc {calc} | stored {expected}"
        for tag, expected, calc, ok in checked
    ]
    return VerifyEntry(
        path=rel_path,
        status="mismatch",
        detail="hash mismatch",
        line=f"[ERROR] hash mismatch: {rel_path}",
        detail_line="\n".join(detail_lines),
    )


# -----------------------------------------------------------------------------
# Hash-node selection
# -----------------------------------------------------------------------------


def _manifest_tag_of(localname: str) -> str:
    """
    Normalize a hash element's local name to its canonical manifest tag.

    Aliases collapse the way seal records them (xxhash/xxh64/xxhash64 → xxhash64be); unknown / read-only tags pass
    through unchanged. Lets an `-a xxhash` override match a recorded <xxhash64be> (or legacy <xxhash>).
    """
    entry = ALGO_MAP.get(localname)
    return entry[1] if entry is not None else localname


def _verify_rank(name: str) -> "int | None":
    """
    Return verify's preference for a hash element's local-name, or None to ignore it.

    Computable algorithms rank by their ALGO_MAP entry; <null> ranks last. Any other tag — one we cannot recompute —
    returns None, so the selector skips it as if the element were absent.
    """
    entry = ALGO_MAP.get(name)
    if entry is not None:
        return entry[2]
    return _NULL_RANK if name == _NULL_TAG else None


def _select_hash_nodes(
    h: "etree._Element", selection: "str | list[str] | None"
) -> "tuple[list[tuple[etree._Element, str]], list[str] | None]":
    """
    Pick which child hash element(s) of `h` to verify.

    `selection` is one of:
      * None             — verify the single fastest recorded hash (default)
      * _VERIFY_ALL      — verify every recorded recognised hash (`-a all`)
      * list of manifest tags — verify exactly those formats (`-a md5,xxhash`)

    Returns (nodes, missing). On success `nodes` is a non-empty list of (element, localname) and `missing` is None.
    Otherwise `nodes` is empty and `missing` is: a non-empty (sorted) list of requested tags not recorded for this
    entry, or [] when nothing recognised is recorded at all.

    For a list selection, requested order is irrelevant — matching nodes are returned in manifest document order, so `-a
    md5,sha1` and `-a sha1,md5` verify identically.

    A <null> entry carries no digest, so it is only ever selected alone and only when no computable hash is recorded —
    the caller then verifies it by size.
    """
    candidates: list[tuple[int, etree._Element, str]] = []
    for child in h:
        name = _localname(child.tag)
        rank = _verify_rank(name)
        if rank is not None:
            candidates.append((rank, child, name))
    real = [(rank, node, name) for rank, node, name in candidates if name != _NULL_TAG]
    null = next(((node, name) for _r, node, name in candidates if name == _NULL_TAG), None)

    if isinstance(selection, list):
        # A specific -a md5,sha1: verify exactly the requested tags, document order.
        wanted = set(selection)
        chosen = [(node, name) for _r, node, name in real if _manifest_tag_of(name) in wanted]
        found = {_manifest_tag_of(name) for _node, name in chosen}
        missing = sorted(t for t in wanted if t not in found)
        return ([], missing) if missing else (chosen, None)
    if not real:
        # No computable hash: fall back to <null> (size-only) if present.
        return ([null], None) if null is not None else ([], [])
    if selection == _VERIFY_ALL:
        return [(node, name) for _rank, node, name in real], None
    # Default: the single fastest recorded hash (lowest rank).
    _rank, node, name = min(real, key=lambda c: c[0])
    return [(node, name)], None


def _size_check(h: "etree._Element", candidate: str, rel_path: str) -> "tuple[int | None, VerifyEntry | None]":
    """
    Compare the manifest's <size> against the file on disk.

    Returns (actual_size, None) when the recorded size matches — actual_size is handed back so the hash phase can reuse
    it to carve recheck windows without a second stat(). Returns (None, None) when the entry records no <size> at all
    (nothing to pre-check). Returns (None, outcome) when there is something to report: a malformed <size>, a file that
    vanished, or a size mismatch.

    The mismatch detail is built at full fidelity regardless of verbosity; the renderer hides the continuation when not
    verbose.
    """
    size_el = h.find("{*}size")
    if size_el is None or size_el.text is None:
        return None, None
    # isdecimal() rejects superscripts/other Unicode "digits" that int() would silently convert to the wrong value
    # (corruption or tampering).
    size_text = size_el.text.strip()
    if not size_text.isdecimal():
        return None, VerifyEntry(
            path=rel_path,
            status="error",
            detail="malformed size field",
            line=f"[ERROR] malformed size field: {rel_path}",
        )
    try:
        actual_size = os.path.getsize(candidate)
    except OSError:
        # Vanished between resolution and getsize() — report missing rather than a bare OSError traceback.
        return None, VerifyEntry(path=rel_path, status="missing", line=f"[ERROR] missing file: {rel_path}")
    manifest_size = int(size_text)
    if manifest_size != actual_size:
        return None, VerifyEntry(
            path=rel_path,
            status="mismatch",
            detail=f"size mismatch: calc size: {actual_size} | stored size: {manifest_size}",
            line=f"[ERROR] size mismatch: {rel_path}",
            detail_line=f"        (calc size: {actual_size} | stored size: {manifest_size})",
        )
    return actual_size, None


def _free_processed(h: "etree._Element") -> None:
    """
    Release `h` and every already-processed sibling during iterparse.

    Clearing the element alone empties its content but leaves an empty node attached to the root, so a manifest with no
    entries that reach the hash phase (all-missing, all-<null>, or -S size-only) would still accumulate one dead element
    per file. Dropping the preceding siblings too keeps peak DOM memory proportional to a single element regardless of
    which branch handled the entry.
    """
    h.clear()
    parent = h.getparent()
    if parent is not None:
        while h.getprevious() is not None:
            del parent[0]


# ---------------------------------------------------------------------------------------------------------------------
# verify_classic — the engine entry point
# ---------------------------------------------------------------------------------------------------------------------


def verify_classic(  # noqa: C901 — flat per-entry verify ladder, not nested complexity
    mhl_file: str,
    *,
    algorithm: "str | list[str] | None" = None,
    size_only: bool = False,
    on_progress: "Callable[[int], None] | None" = None,
) -> VerifyReport:
    """
    Verify each file listed in `mhl_file` against its stored hash and return a structured VerifyReport. Never prints and
    never calls sys.exit — the caller decides how to present the result (see render_verify_lines).

    `algorithm` selects which recorded hash(es) to check: None (the fastest recorded), the _VERIFY_ALL sentinel (every
    recorded hash), or a list of canonical manifest tags. A bad selection raises ValueError (the CLI validates via
    argparse before reaching here; mhlver always passes None).

    `size_only` skips hashing and checks each entry's recorded <size> against the file on disk. `on_progress`, if given,
    is called with each chunk's byte count as files are hashed (per-chunk, not once per file), so a caller can drive a
    progress bar that advances within a large file; it may fire from a worker thread when files are hashed concurrently.

    Report codes (see _exit_codes.ExitCode): 0 clean, 40 malformed XML, 10 missing only, 11 hash-mismatch/error (wins
    over missing); size-only mode reports 13 for any size mismatch. The per-file detail and the [OK]/[ERROR] lines are
    always built at verbose fidelity; render_verify_lines picks what to show.
    """
    # Resolve the optional -a value to a selection: None (fastest single), _VERIFY_ALL (every recorded hash), or a list
    # of canonical manifest tags.
    selection: str | list[str] | None
    if algorithm is None or algorithm == _VERIFY_ALL:
        selection = algorithm
    elif isinstance(algorithm, str):
        if algorithm not in ALGO_MAP:
            raise ValueError(f"unsupported algorithm '{algorithm}'")
        selection = [ALGO_MAP[algorithm][1]]
    else:
        for tag in algorithm:
            if tag not in _CANONICAL_TAGS:
                raise ValueError(f"unsupported algorithm '{tag}'")
        selection = algorithm

    # All file references in the manifest are relative to the directory the manifest lives in. We capture this once as
    # the canonical jail for the path-traversal check. Trailing separator avoids prefix-collision: '/foo' matches
    # '/foo/bar' but not '/foobar'.
    mhl_dir = os.path.abspath(os.path.dirname(os.path.abspath(mhl_file)))
    mhl_dir_with_sep = mhl_dir + os.sep

    # Per-entry outcomes in manifest order. Cheap failures (traversal, missing, malformed/size, no-hash) and null-OK are
    # decided inline while streaming; entries that still need a hash pass get a None placeholder filled by the parallel
    # phase below.
    results: list[VerifyEntry | None] = []

    # Entries deferred to the parallel hash phase: parallel arrays plus the slot in `results` each fills. `hash_sizes`
    # reuse the size pre-check's stat.
    hash_paths: list[str] = []
    hash_sizes: list[int] = []
    hash_slots: list[int] = []
    hash_jobs: list[Callable[[], VerifyEntry]] = []
    calib_algo: str | None = None

    # Per-call cache of directory listings ({dir: {NFC(name): real_name}}), populated lazily by resolve_on_disk when a
    # literal path lookup misses.
    dir_index: dict[str, dict[str, str]] = {}

    # Track which weak (non-hash) <null> checks were relied on and whether any entry was hash-verified, so the notice
    # names the kinds used and distinguishes a fully weak-checked manifest from a mixed one.
    saw_size_only = False
    saw_existence_only = False
    saw_hash = False

    try:
        for _, h in etree.iterparse(mhl_file, events=("end",), tag="{*}hash"):
            # Exactly one <file> child expected; malformed entries without one are silently skipped (xsd-schema-check
            # would have caught them).
            file_el = h.find("{*}file")
            if file_el is None or file_el.text is None:
                _free_processed(h)
                continue

            # Manifests store forward-slash paths — we never convert to the native separator here: os.path.join /
            # normpath below accept forward slashes and normalise them for the on-disk lookup, and resolve_on_disk is
            # fed the already-native os.path.relpath(jailed, …). The one place that renders the native separator is the
            # terminal.
            rel_path = file_el.text

            # --- Path traversal guard -----------------------------------
            jailed = os.path.normpath(os.path.join(mhl_dir, rel_path))
            if jailed != mhl_dir and not jailed.startswith(mhl_dir_with_sep):
                results.append(
                    VerifyEntry(
                        path=rel_path,
                        status="error",
                        detail="blocked traversal attempt",
                        line=f"[ERROR] blocked traversal attempt: {rel_path}",
                    )
                )
                _free_processed(h)
                continue

            # --- Resolve to the real on-disk path --------------------------------------------------------------------
            candidate = resolve_on_disk(mhl_dir, os.path.relpath(jailed, mhl_dir), dir_index)
            if candidate is None:
                results.append(VerifyEntry(path=rel_path, status="missing", line=f"[ERROR] missing file: {rel_path}"))
                _free_processed(h)
                continue

            # --- Size-only mode --------------------------------------------------------------------------------------
            if size_only:
                actual_size, size_outcome = _size_check(h, candidate, rel_path)
                if size_outcome is not None:
                    results.append(size_outcome)
                elif actual_size is None:
                    results.append(
                        VerifyEntry(
                            path=rel_path,
                            status="error",
                            detail="no size recorded",
                            line=f"[ERROR] no size recorded: {rel_path} "
                            "(try 'simple-mhl verify' for full hash verification)",
                        )
                    )
                else:
                    results.append(
                        VerifyEntry(
                            path=rel_path, status="ok", size_only=True, line=f"[OK] {rel_path}  size: {actual_size}"
                        )
                    )
                _free_processed(h)
                continue

            # Pick which recorded hash(es) to verify.
            nodes, missing = _select_hash_nodes(h, selection)
            if not nodes:
                if missing:  # requested hash(es) not stored for this entry
                    label = "hash" if len(missing) == 1 else "hashes"
                    results.append(
                        VerifyEntry(
                            path=rel_path,
                            status="error",
                            detail=f"requested {label} {', '.join(missing)} not stored",
                            line=f"[ERROR] requested {label} {', '.join(missing)} not stored: {rel_path}",
                        )
                    )
                else:  # nothing recognised recorded at all
                    results.append(
                        VerifyEntry(
                            path=rel_path,
                            status="error",
                            detail="no supported hash found",
                            line=f"[ERROR] no supported hash found: {rel_path}",
                        )
                    )
                _free_processed(h)
                continue

            # A single <null> node means this entry carries no hash. Flag which kind of weak check it is now (before the
            # size check) so the notice fires even when the size mismatches. A recorded <size> makes it size-only; its
            # absence makes it existence-only.
            is_null_entry = len(nodes) == 1 and nodes[0][1] == _NULL_TAG
            if is_null_entry:
                size_el = h.find("{*}size")
                if size_el is not None and size_el.text is not None:
                    saw_size_only = True
                else:
                    saw_existence_only = True

            # --- File size pre-check ---------------------------------------------------------------------------------
            actual_size, size_outcome = _size_check(h, candidate, rel_path)
            if size_outcome is not None:
                results.append(size_outcome)
                _free_processed(h)
                continue

            # 'null' tag records no digest: existence + size are the whole check.
            if is_null_entry:
                if actual_size is not None:
                    results.append(
                        VerifyEntry(
                            path=rel_path,
                            status="ok",
                            size_only=True,
                            line=f"[OK] {rel_path}  size: {actual_size} (size-only check - no hash stored)",
                        )
                    )
                else:
                    results.append(
                        VerifyEntry(
                            path=rel_path,
                            status="ok",
                            existence_only=True,
                            line=f"[OK] {rel_path}  (existence-only check — no hash or size stored)",
                        )
                    )
                _free_processed(h)
                continue

            # Needs a hash pass — defer it to the parallel phase.
            saw_hash = True
            checks = [(name, node.text or "") for node, name in nodes]
            slot = len(results)
            results.append(None)
            hash_slots.append(slot)
            hash_paths.append(candidate)
            hash_sizes.append(actual_size if actual_size is not None else 0)
            hash_jobs.append(
                lambda c=candidate, ck=checks, r=rel_path: _verify_hashes(c, ck, r, on_progress=on_progress)
            )
            # Calibrate the storage probe against the first deferred algorithm.
            if calib_algo is None:
                calib_algo = checks[0][0]

            _free_processed(h)

    except (etree.XMLSyntaxError, OSError):
        return VerifyReport(code=ExitCode.MALFORMED_XML, malformed=True)

    # --- Parallel hash phase -----------------------------------------------------------------------------------------
    # on_progress is forwarded into each job (per-chunk, from get_hashes) so the bar advances within a file rather than
    # jumping once it finishes; under the adaptive controller those callbacks may fire from worker threads.
    if calib_algo is not None:
        hashed_iter = hashing._hash_jobs_auto(
            hash_paths, hash_sizes, hash_jobs, lambda: hashing._calibrate_hash_bw(calib_algo)
        )
        for slot, outcome in zip(hash_slots, hashed_iter, strict=True):
            results[slot] = outcome

    entries: list[VerifyEntry] = [r for r in results if r is not None]

    # A <null> entry carries no hash — surface that the manifest verified some or all files on size or existence alone,
    # naming the kinds used so an existence-only pass doesn't read as a size-only one. Shown regardless of verbosity.
    notices: list[str] = []
    if saw_size_only or saw_existence_only:
        kinds = []
        if saw_size_only:
            kinds.append("size-only")
        if saw_existence_only:
            kinds.append("existence-only")
        kind_phrase = " and ".join(kinds)
        if saw_hash:
            notices.append(f"Partially verified with {kind_phrase} checks (some hashes missing from the manifest).")
        else:
            # No hashes are stored either way. Sizes are: all present (size-only only), all absent (existence-only
            # only), or partial (a mix of both null kinds).
            if not saw_existence_only:
                stored = "hashes"
            elif saw_size_only:
                stored = "hashes and some sizes"
            else:
                stored = "hashes and sizes"
            notices.append(f"Verified with {kind_phrase} checks ({stored} missing from the manifest).")

    n_missing = sum(1 for e in entries if e.status == "missing")
    n_fail = sum(1 for e in entries if e.status in ("mismatch", "error"))
    # Mismatch wins over missing everywhere — a run with both reports the mismatch code. size_only failures are size
    # mismatches, never hash mismatches.
    mismatch_code = ExitCode.SIZE_MISMATCH if size_only else ExitCode.HASH_MISMATCH
    if n_fail:
        code = mismatch_code
    elif n_missing:
        code = ExitCode.MISSING
    else:
        code = ExitCode.OK

    return VerifyReport(entries=entries, code=code, notices=notices)


def render_verify_lines(report: VerifyReport, verbose: bool) -> list[str]:
    """
    Render a VerifyReport to the exact stdout lines `simple-mhl verify` emits.

    Order matches the historic emit: [OK] lines (verbose only, manifest order), then the size/existence notice(s), then
    all missing lines, then all mismatch/error lines. Verbose adds each failure's indented detail continuation.
    Non-verbose drops the [OK] lines and the continuations — exactly the plain output, so both the CLI and mhlver render
    from one place.
    """
    out: list[str] = []
    if verbose:
        out.extend(e.line for e in report.entries if e.status == "ok")
    out.extend(report.notices)
    for e in report.entries:
        if e.status == "missing":
            out.append(e.line)
            if verbose and e.detail_line:
                out.append(e.detail_line)
    for e in report.entries:
        if e.status in ("mismatch", "error"):
            out.append(e.line)
            if verbose and e.detail_line:
                out.append(e.detail_line)
    return out


# ---------------------------------------------------------------------------------------------------------------------
# XSD schema validation
# ---------------------------------------------------------------------------------------------------------------------


def schema_report(mhl_file: str) -> "tuple[int, list[str]]":
    """
    Validate `mhl_file` against the bundled MediaHashList_v1_1.xsd.

    Returns (code, lines) where code is 0 (valid), 41 (schema non-compliant), or 40 (malformed/unreadable XML), and
    lines are the stderr-style "Error: …" messages to surface. A missing bundled XSD is a broken install, not a manifest
    fact, so it surfaces as the generic error code (1) rather than its own code. Never prints or exits.
    """
    try:
        xsd_path = get_xsd_path()
    except FileNotFoundError as exc:
        return ExitCode.ERROR, [f"Error: {exc}"]

    try:
        # Parse both documents and compile the schema. lxml's XMLSchema constructor compiles the validator; the cost is
        # small (a few KiB schema) and not worth caching for a single-file CLI tool.
        tree = etree.parse(mhl_file)
        xsd = etree.XMLSchema(etree.parse(xsd_path))
    except etree.XMLSyntaxError as e:
        return ExitCode.MALFORMED_XML, [f"Error: XML parsing failed - {e}"]
    except OSError as e:
        return ExitCode.MALFORMED_XML, [f"Error: file read failed - {e}"]

    if not xsd.validate(tree):
        return ExitCode.SCHEMA_NONCOMPLIANT, [
            f"Error: XSD validation failed - {err.message} (line {err.line})" for err in xsd.error_log
        ]
    return ExitCode.OK, []
