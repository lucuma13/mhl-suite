"""
Classic MHL seal engine.

Walks a directory, hashes every non-excluded file (read-once across all
requested formats, concurrency auto-tuned by mhl_suite.hashing), and streams a
classic MHL manifest to disk as digests arrive — the manifest is never built
as an in-memory DOM, so a 100k-file shoot costs one <hash> element of memory.

Argument and filesystem problems raise SealError for the CLI to render and map
to an exit code; this module never calls sys.exit. Verbose per-file [OK]/[SKIP]
lines are still printed here (seal is the interactive command's body), but all
failures travel as exceptions.
"""

import getpass
import os
import sys
import unicodedata
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from typing import BinaryIO

from lxml import etree

from mhl_suite import __version__, hashing
from mhl_suite.algorithms import NULL_TAG, classic_seal_algorithm, classic_seal_tag
from mhl_suite.ignorelist import is_os_junk
from mhl_suite.osutils import friendly_hostname, normalization_variant_on_disk


class SealError(Exception):
    """A seal cannot proceed (bad arguments, unusable target, empty files). The message is CLI-ready stderr text."""


# -----------------------------------------------------------------------------
# Filesystem walking
# -----------------------------------------------------------------------------


def _iter_files_for_seal(
    root: str,
    mhl_path: str,
    on_skip: "Callable[[str, str, bool], None] | None" = None,
) -> Iterator[tuple[str, os.stat_result]]:
    """
    Walk `root` recursively and yield (absolute_path, stat_result) for every
    file that should appear in the manifest, in deterministic sorted order.
    Hidden files and directories (names starting with '.') are included.

    Skips:
      * OS-generated metadata (see mhl_suite.ignorelist), which the system
        rewrites on its own and would break re-verification
      * the manifest file itself (so we don't hash what we're writing)
      * entries that disappear or stat-fail mid-walk

    `on_skip`, if given, is called as on_skip(path, reason, is_warning) for
    each skipped entry (except the manifest itself). is_warning is True for an
    unreadable directory — a silently-dropped directory means media missing
    from the manifest, so the caller surfaces it regardless of verbosity.

    Implementation note: os.scandir rather than os.walk because DirEntry
    caches the stat() info from getdents64, saving a syscall per file (~13%
    faster on a 1000-file tree). Structured iteratively (stack-based) to avoid
    Python's recursion limit on deeply nested shoots.
    """
    # Stack of directories yet to descend. Within each directory entries are
    # sorted lexicographically and subdirectories explored depth-first in that
    # same order — deterministic, though not globally sorted by full path.
    pending = [root]

    while pending:
        current = pending.pop()
        try:
            entries = list(os.scandir(current))
        except OSError as exc:
            # Permission or vanished-directory. Unlike os.walk's silent
            # onerror=None, we report it: a dropped directory means its files
            # are absent from the manifest and therefore unprotected.
            if on_skip is not None:
                on_skip(current, f"unreadable: {exc.strerror or exc}", True)
            continue

        entries.sort(key=lambda e: e.name)

        # Two passes so files in this directory get yielded before recursing
        # into subdirectories.
        subdirs: list[str] = []
        for entry in entries:
            if is_os_junk(entry.name):
                if on_skip is not None:
                    on_skip(entry.path, "OS metadata", False)
                continue
            try:
                if entry.is_dir(follow_symlinks=False):
                    subdirs.append(entry.path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    if on_skip is not None:
                        on_skip(entry.path, "not a regular file", False)
                    continue
                # Skip the manifest we're currently writing.
                if entry.path == mhl_path:
                    continue
                yield entry.path, entry.stat(follow_symlinks=False)
            except OSError:
                # File vanished between scandir and stat — skip it.
                if on_skip is not None:
                    on_skip(entry.path, "vanished", False)
                continue

        # Push subdirs in reverse so popping gives lexicographic order.
        pending.extend(reversed(subdirs))


# -----------------------------------------------------------------------------
# Argument resolution
# -----------------------------------------------------------------------------


def _resolve_seal_algorithms(algorithms: "list[str]") -> list[str]:
    """
    Validate seal algorithm keys and collapse alias duplicates (first wins).

    argparse's type= normally catches bad names, but seal_classic() can be
    called directly, so we re-validate here and raise SealError on an unknown
    algorithm. Aliases resolving to the same manifest tag (e.g.
    xxhash/xxh64/xxhash64be) are deduped, preserving first-appearance order.

    `null` records no digest, so combining it with any computable algorithm is
    contradictory and rejected.
    """
    for algorithm in algorithms:
        if algorithm != NULL_TAG:
            try:
                classic_seal_tag(algorithm)
            except KeyError:
                raise SealError(f"Error: unsupported algorithm '{algorithm}'") from None
    if NULL_TAG in algorithms and any(a != NULL_TAG for a in algorithms):
        raise SealError("Error: 'null' cannot be combined with other algorithms")
    seen_tags: set[str] = set()
    resolved: list[str] = []
    for a in algorithms:
        tag = classic_seal_tag(a)
        if tag not in seen_tags:
            seen_tags.add(tag)
            resolved.append(a)
    return resolved


def _resolve_output_dir(root: str, output_dir: "str | None") -> str:
    """
    Resolve and validate where seal writes the manifest, raising SealError on
    a bad choice.

    None keeps the manifest at the sealed root (default). Otherwise it must be
    `root` itself or a parent directory: verify resolves each <file> entry
    relative to the manifest's directory and blocks any '..' escape, so only
    an ancestor keeps the recorded paths traversal-free. Returns the absolute
    directory.
    """
    if output_dir is None:
        return root
    output_dir = os.path.abspath(output_dir)
    if not os.path.isdir(output_dir):
        raise SealError(f"Error: output directory '{output_dir}' is not a directory")
    if root != output_dir and not root.startswith(output_dir + os.sep):
        raise SealError(f"Error: output directory '{output_dir}' must be the sealed directory or a parent directory")
    return output_dir


def _reject_empty_files(entries: "list[tuple[str, os.stat_result]]", root: str, fd: int, mhl_path: str) -> None:
    """
    Abort the seal (SealError) if any walked entry is a zero-byte file.

    The XSD makes <size> mandatory and xs:positiveInteger (>= 1) — so an empty
    file must not be represented in any seal mode. The scan is a pure
    in-memory pass over the stat info the walk already collected, running
    before any hashing so no compute is wasted. On abort it closes + unlinks
    the O_EXCL manifest the caller already claimed.
    """
    empty = [fp for fp, st in entries if st.st_size == 0]
    if not empty:
        return
    os.close(fd)
    os.unlink(mhl_path)

    lines = []
    for fp in empty:
        rel = os.path.relpath(fp, root)
        filename = rel.replace(os.sep, "/") if os.sep != "/" else rel
        lines.append(f"[ERROR] cannot seal empty file: {filename}")
    lines.append("  Remove or exclude any empty files and retry.")
    raise SealError("\n".join(lines))


# -----------------------------------------------------------------------------
# Hashing
# -----------------------------------------------------------------------------


def _hash_files(paths: list[str], sizes: list[int], algorithms: "list[str]") -> "Iterator[tuple[list[str], str]]":
    """
    Yield (digests, hashdate) per path — one digest per algorithm in order,
    plus the ISO-8601 UTC instant hashing finished — through the adaptive
    controller (concurrency auto-tuned to the storage).

    The hashdate is captured inside the worker the moment get_hashes returns,
    so it reflects when that file's read-once pass actually completed even
    when files are hashed concurrently in windows. get_hashes/run_hash_jobs
    are resolved at call time (module globals) so test monkeypatches still
    intercept them.
    """
    factories = [classic_seal_algorithm(a).factory for a in algorithms]
    jobs: list[hashing.HashJob[tuple[list[str], str]]] = [
        (
            lambda mon, p=p: (
                hashing.get_hashes(p, factories, on_progress=mon),
                datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
            )
        )
        for p in paths
    ]
    return hashing.run_hash_jobs(paths, sizes, jobs, lambda: hashing.calibrate_hash_bandwidth(factories))


# -----------------------------------------------------------------------------
# Streaming manifest writer
# -----------------------------------------------------------------------------

# finishdate is written into the header before hashing starts, then patched in
# place once the walk completes — the placeholder is the same byte length as
# every real ISO-8601 UTC stamp, so the patch never shifts the file.
_FINISHDATE_PLACEHOLDER = "0000-00-00T00:00:00Z"


def _serialize(element: "etree._Element", indent: str = "  ") -> bytes:
    """One pretty-printed element, indented for its place inside <hashlist>."""
    text = etree.tostring(element, pretty_print=True, encoding="unicode")
    return "".join(f"{indent}{line}\n" for line in text.splitlines()).encode("utf-8")


def _creatorinfo_element(tool: str, iso_now: str) -> "etree._Element":
    """The <creatorinfo> block; finishdate carries the fixed-width placeholder."""
    info = etree.Element("creatorinfo")
    for tag, value in [
        ("username", getpass.getuser()),
        ("hostname", friendly_hostname()),
        ("tool", tool),
        ("startdate", iso_now),
        ("finishdate", _FINISHDATE_PLACEHOLDER),
    ]:
        etree.SubElement(info, tag).text = value
    return info


def _write_header(fh: BinaryIO, iso_now: str) -> int:
    """
    Write the manifest prologue (declaration, <hashlist>, creatorinfo) and
    return the byte offset of the finishdate placeholder so the caller can
    patch it once hashing completes.
    """
    fh.write(b'<?xml version="1.0" encoding="UTF-8"?>\n<hashlist version="1.1">\n')
    info_bytes = _serialize(_creatorinfo_element(f"simple-mhl {__version__}", iso_now))
    placeholder_at = fh.tell() + info_bytes.index(_FINISHDATE_PLACEHOLDER.encode("ascii"))
    fh.write(info_bytes)
    return placeholder_at


def _hash_element(
    rel_path_posix: str, stat_result: os.stat_result, xml_tags: list[str], digests: list[str], hashdate: str
) -> "etree._Element":
    """Build one <hash> element (one hash child per sealed format, then <hashdate>)."""
    h = etree.Element("hash")
    etree.SubElement(h, "file").text = rel_path_posix
    etree.SubElement(h, "size").text = str(stat_result.st_size)
    mtime = datetime.fromtimestamp(stat_result.st_mtime, UTC)
    etree.SubElement(h, "lastmodificationdate").text = mtime.strftime("%Y-%m-%dT%H:%M:%SZ")
    for xml_tag, digest in zip(xml_tags, digests, strict=True):
        etree.SubElement(h, xml_tag).text = digest
    etree.SubElement(h, "hashdate").text = hashdate
    return h


# -----------------------------------------------------------------------------
# Seal command
# -----------------------------------------------------------------------------


def seal_classic(root: str, algorithms: "list[str]", verbose: bool = False, output_dir: "str | None" = None) -> str:
    """
    Walk `root`, hash every non-excluded file, and write an MHL manifest.
    Returns the manifest path; raises SealError (CLI-ready message) when the
    seal cannot proceed.

    `algorithms` is one or more hash-algorithm keys (see mhl_suite.algorithms).
    When more than one is given, every file is read once and all digests are
    computed from that single stream, and the manifest records one hash
    element per format per file.

    `output_dir` chooses where the manifest is written. It defaults to the
    sealed directory root. When given, it must be `root` itself or an ancestor
    — verify resolves each <file> entry relative to the manifest's own
    directory and rejects any entry that escapes it via '..', so only an
    ancestor keeps every recorded path traversal-free. The <file> paths are
    therefore written relative to `output_dir`.

    Behaviour:
      * Manifest filename: <basename>_<UTC-timestamp>.mhl (named after `root`),
        claimed atomically with O_CREAT|O_EXCL (numeric suffix on collision) so
        two parallel seal invocations always land on distinct paths.
      * Hidden files and directories are included; only OS-generated metadata
        (see mhl_suite.ignorelist) is skipped. Files that vanish during the
        walk are skipped without aborting.
      * The manifest is streamed: each <hash> element is written as its
        file's digests arrive, and the header's finishdate placeholder is
        patched in place at the end — peak memory holds one element, not the
        tree.
      * Concurrency is fully automatic (mhl_suite.hashing measures the storage
        and parallelises only when that's faster).

    Output (print, not part of the result):
      [OK] <path>  <algo>: <digest>             (verbose only, per hashed file)
      [SKIP] <path> (<reason>)                  (verbose only, skipped entry)
      [WARNING] skipped: <path> (<reason>)      (always, on stderr; dropped dir)
      Created MHL: <path>                       (verbose only, on completion)
    """
    algorithms = _resolve_seal_algorithms(algorithms)

    root = os.path.abspath(root)
    if not os.path.isdir(root):
        msg = f"Error: '{root}' is not a directory"
        variant = normalization_variant_on_disk(root)
        if variant is not None and os.path.isdir(variant):
            msg += f"\n  A directory with a different Unicode normalization exists — did you mean:\n    {variant}"
        raise SealError(msg)

    output_dir = _resolve_output_dir(root, output_dir)

    base_name = os.path.basename(root)

    # iso_now stamps the <creatorinfo> start date.
    # Each file's <hashdate> is captured separately as that file is hashed.
    now_dt = datetime.now(UTC)
    timestamp_for_filename = now_dt.strftime("%Y-%m-%d_%H%M%S")
    iso_now = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Find a non-colliding manifest filename and claim it atomically.
    # O_CREAT | O_EXCL makes the existence check and creation a single syscall,
    # eliminating the TOCTOU race of exists()-then-open; the second of two
    # concurrent seals gets FileExistsError and moves to the next suffix.
    mhl_name = f"{base_name}_{timestamp_for_filename}.mhl"
    mhl_path = os.path.join(output_dir, mhl_name)
    suffix = 0
    fd: int | None = None
    while fd is None:
        try:
            fd = os.open(mhl_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o666)
        except FileExistsError:
            suffix += 1
            mhl_path = os.path.join(output_dir, f"{base_name}_{timestamp_for_filename}_{suffix}.mhl")

    def _on_skip(path: str, reason: str, is_warning: bool) -> None:
        rel = os.path.relpath(path, root)
        rel_posix = rel.replace(os.sep, "/") if os.sep != "/" else rel
        if is_warning:
            # Always shown: a dropped directory leaves files unprotected.
            sys.stderr.write(f"[WARNING] skipped: {rel_posix} ({reason})\n")
        elif verbose:
            print(f"[SKIP] {rel_posix} ({reason})")

    # Walk the tree first (reporting skips as we go), then hash. Materialising
    # the entry list lets files hash concurrently while the manifest is still
    # emitted in deterministic walk order.
    entries = list(_iter_files_for_seal(root, mhl_path, on_skip=_on_skip))

    # Refuse zero-byte files before any hashing; on abort this releases the
    # O_EXCL manifest fd claimed above.
    _reject_empty_files(entries, root, fd, mhl_path)

    xml_tags = [classic_seal_tag(a) for a in algorithms]
    paths = [fp for fp, _ in entries]
    # `null` records no digest, so a null seal reads no bytes — each entry
    # just gets an empty <null> and the run timestamp.
    is_null = algorithms == [NULL_TAG]
    if is_null:
        digests: Iterator[tuple[list[str], str]] = (([""], iso_now) for _ in entries)
    else:
        digests = _hash_files(paths, [st.st_size for _, st in entries], algorithms)

    # Stream the manifest through the fd we already hold from the O_EXCL open
    # (never re-opening by path, which would be another race window).
    with os.fdopen(fd, "r+b") as fh:
        finishdate_at = _write_header(fh, iso_now)

        for (filepath, stat_result), (file_digests, hashdate) in zip(entries, digests, strict=True):
            # Paths are relative to the manifest's own directory (output_dir)
            # so verify resolves them correctly; forward slashes per the MHL
            # spec, NFC-normalised so accented filenames round-trip across
            # macOS (NFD on disk) and Linux/Windows (NFC) alike.
            rel_path = os.path.relpath(filepath, output_dir)
            rel_path_posix = rel_path.replace(os.sep, "/") if os.sep != "/" else rel_path
            rel_path_posix = unicodedata.normalize("NFC", rel_path_posix)

            fh.write(_serialize(_hash_element(rel_path_posix, stat_result, xml_tags, file_digests, hashdate)))
            if verbose:
                if is_null:
                    print(f"[OK] {rel_path_posix}  size: {stat_result.st_size}")
                else:
                    shown = "  ".join(f"{t}: {d}" for t, d in zip(xml_tags, file_digests, strict=True))
                    print(f"[OK] {rel_path_posix}  {shown}")

        fh.write(b"</hashlist>\n")

        # Patch the real completion instant over the fixed-width placeholder —
        # useful for auditing how long the seal took.
        fh.seek(finishdate_at)
        fh.write(datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ").encode("ascii"))

    if verbose:
        print(f"Created MHL: {mhl_path}")
    return mhl_path
