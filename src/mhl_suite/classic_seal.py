"""
Classic MHL seal engine.

Walks a directory, hashes every non-excluded file, and writes a classic MHL manifest. The hashing controller lives in
mhl_suite.hashing and is reached through the module object so test monkeypatches still intercept it.
"""

import getpass
import os
import sys
import unicodedata
from collections.abc import Callable, Iterator
from datetime import UTC, datetime

from lxml import etree

from mhl_suite import __version__, hashing
from mhl_suite.hashing import _NULL_TAG, ALGO_MAP, _seal_tag
from mhl_suite.ignorelist import is_os_junk
from mhl_suite.osutils import friendly_hostname, normalization_variant_on_disk

# ---------------------------------------------------------------------------------------------------------------------
# Filesystem walking
# ---------------------------------------------------------------------------------------------------------------------


def _iter_files_for_seal(
    root: str,
    mhl_path: str,
    on_skip: "Callable[[str, str, bool], None] | None" = None,
) -> Iterator[tuple[str, os.stat_result]]:
    """
    Walk `root` recursively and yield (absolute_path, stat_result) for every file that should appear in the manifest, in
    deterministic sorted order. Hidden files and directories (names starting with '.') are included.

    Skips:
      * OS-generated metadata (see mhl_suite.ignorelist), which the system rewrites on its own and would break
        re-verification
      * the manifest file itself (so we don't hash what we're writing)
      * entries that disappear or stat-fail mid-walk

    `on_skip`, if given, is called as on_skip(path, reason, is_warning) for each skipped entry (except the manifest
    itself). is_warning is True for an unreadable directory — a silently-dropped directory means media missing from the
    manifest, so the caller surfaces it regardless of verbosity.

    Implementation note: we use os.scandir rather than os.walk because DirEntry caches the stat() info from getdents64,
    saving a syscall per file. Bench showed ~13% faster traversal on a 1000-file tree. The code is structured
    iteratively (stack-based) rather than recursively to avoid Python's recursion limit on deeply nested shoots.
    """
    # Stack of directories yet to descend. We push/pop in a way that yields files in deterministic order: within each
    # directory entries are sorted lexicographically, and subdirectories are explored depth-first in that same order.
    # The overall manifest is NOT globally sorted by full path — a deeply nested a/b/c.mov appears before a sibling
    # d.mov at the parent level. This is fine; the manifest only needs to be deterministic, not follow any specific
    # canonical global order.
    pending = [root]

    while pending:
        current = pending.pop()
        try:
            # scandir returns DirEntry objects whose .stat() is satisfied from the readdir cache (no extra syscall) on
            # most filesystems.
            entries = list(os.scandir(current))
        except OSError as exc:
            # Permission or vanished-directory. Unlike os.walk's silent onerror=None, we report it: a dropped directory
            # means its files are absent from the manifest and therefore unprotected.
            if on_skip is not None:
                on_skip(current, f"unreadable: {exc.strerror or exc}", True)
            continue

        # Sort by name within the directory for deterministic output order.
        entries.sort(key=lambda e: e.name)

        # Two passes so files in this directory get yielded before recursing into subdirectories — gives a depth-first,
        # sorted-per-level walk equivalent to os.walk(topdown=True) with sorted dirnames.
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


# ---------------------------------------------------------------------------------------------------------------------
# Seal command
# ---------------------------------------------------------------------------------------------------------------------


def _build_creatorinfo(parent: etree._Element, tool: str, iso_now: str) -> etree._Element:
    """Append a <creatorinfo> block to `parent` and return it."""
    info = etree.SubElement(parent, "creatorinfo")
    for tag, value in [
        ("username", getpass.getuser()),
        ("hostname", friendly_hostname()),
        ("tool", tool),
        ("startdate", iso_now),
        ("finishdate", iso_now),  # placeholder, updated after the walk
    ]:
        etree.SubElement(info, tag).text = value
    return info


def _resolve_seal_algorithms(algorithms: "list[str]") -> list[str]:
    """
    Validate seal algorithm keys and collapse alias duplicates (first wins).

    argparse's type= normally catches bad names, but seal_classic() can be called directly, so we re-validate here and
    exit 2 on an unknown algorithm. Aliases resolving to the same manifest tag (e.g. xxhash/xxh64/xxhash64be) are
    deduped, preserving first-appearance order, so each tag is emitted at most once.

    `null` records no digest, so combining it with any computable algorithm is contradictory and rejected (exit 2).
    """
    for algorithm in algorithms:
        if algorithm != _NULL_TAG and algorithm not in ALGO_MAP:
            sys.stderr.write(f"Error: unsupported algorithm '{algorithm}'\n")
            sys.exit(2)
    if _NULL_TAG in algorithms and any(a != _NULL_TAG for a in algorithms):
        sys.stderr.write("Error: 'null' cannot be combined with other algorithms\n")
        sys.exit(2)
    seen_tags: set[str] = set()
    resolved: list[str] = []
    for a in algorithms:
        tag = _seal_tag(a)
        if tag not in seen_tags:
            seen_tags.add(tag)
            resolved.append(a)
    return resolved


def _resolve_output_dir(root: str, output_dir: "str | None") -> str:
    """
    Resolve and validate where seal writes the manifest, exiting 2 on a bad choice.

    None keeps the manifest at the sealed root (default). Otherwise it must be `root` itself or a parent directory:
    verify resolves each <file> entry relative to the manifest's directory and blocks any '..' escape, so only an
    ancestor keeps the recorded paths traversal-free. Returns the absolute directory.
    """
    if output_dir is None:
        return root
    output_dir = os.path.abspath(output_dir)
    if not os.path.isdir(output_dir):
        sys.stderr.write(f"Error: output directory '{output_dir}' is not a directory\n")
        sys.exit(2)
    if root != output_dir and not root.startswith(output_dir + os.sep):
        sys.stderr.write(f"Error: output directory '{output_dir}' must be the sealed directory or a parent directory\n")
        sys.exit(2)
    return output_dir


def _reject_empty_files(entries: "list[tuple[str, os.stat_result]]", root: str, fd: int, mhl_path: str) -> None:
    """
    Abort the seal (exit 2) if any walked entry is a zero-byte file.

    The XSD makes <size> mandatory and xs:positiveInteger (>= 1) — so an empty file (zero bytes) must not be represented
    in any seal mode. The scan is a pure in-memory pass over the stat info the walk already collected (no extra
    syscalls), running before any hashing so no compute is wasted. On abort it closes + unlinks the O_EXCL manifest the
    caller already claimed.
    """
    empty = [fp for fp, st in entries if st.st_size == 0]
    if not empty:
        return
    os.close(fd)
    os.unlink(mhl_path)

    for fp in empty:
        rel = os.path.relpath(fp, root)
        filename = rel.replace(os.sep, "/") if os.sep != "/" else rel
        sys.stderr.write(f"[ERROR] cannot seal empty file: {filename}\n")

    sys.stderr.write("  Remove or exclude any empty files and retry.\n")
    sys.exit(2)


def seal_classic(root: str, algorithms: "list[str]", verbose: bool = False, output_dir: "str | None" = None) -> None:
    """
    Walk `root`, hash every non-excluded file, and write an MHL manifest.

    `algorithms` is one or more hash-algorithm keys (see ALGO_MAP). When more than one is given, every file is read once
    and all digests are computed from that single stream (read-once multi-hashing), and the manifest records one hash
    element per format per file.

    `output_dir` chooses where the manifest is written. It defaults to the sealed directory root. When given, it must be
    `root` itself or an ancestor — verify resolves each <file> entry relative to the manifest's own directory and
    rejects any entry that escapes it via '..', so only an ancestor keeps every recorded path traversal-free. The <file>
    paths are therefore written relative to `output_dir`, gaining a leading "<sealed-folder>/…" prefix when it is a true
    ancestor.

    Behaviour:
      * Manifest filename: <basename>_<UTC-timestamp>.mhl (named after `root`)
      * Collisions: if the file already exists, append a numeric suffix until unique.
      * Hidden files and directories are included; only OS-generated metadata (.DS_Store, macOS ._* resource forks,
        Spotlight/Trash/Time Machine and other volume-internal items — see mhl_suite.ignorelist) is skipped.
      * Files that vanish during the walk are skipped without aborting.
      * Concurrency is fully automatic: _hash_files_auto measures the storage and parallelises only when that's faster,
        staying sequential otherwise.

    Output format:
      [OK] <path>  <algo>: <digest>             (verbose only, per hashed file)
      [SKIP] <path> (<reason>)                  (verbose only, skipped entry)
      [WARNING] skipped: <path> (<reason>)      (always, on stderr; dropped dir)
      Created MHL: <path>                       (verbose only, on completion)

    Exits with code 2 on argument errors (handled by argparse before we get here) and lets unexpected OSError on the
    final write propagate so the operator sees the real diagnostic.
    """
    algorithms = _resolve_seal_algorithms(algorithms)

    root = os.path.abspath(root)
    if not os.path.isdir(root):
        msg = f"Error: '{root}' is not a directory\n"
        variant = normalization_variant_on_disk(root)
        if variant is not None and os.path.isdir(variant):
            msg += f"  A directory with a different Unicode normalization exists — did you mean:\n    {variant}\n"
        sys.stderr.write(msg)
        sys.exit(2)

    output_dir = _resolve_output_dir(root, output_dir)

    base_name = os.path.basename(root)

    # iso_now stamps the run's <creationdate> and <creatorinfo> start/finish. Each file's <hashdate> is captured
    # separately as that file is hashed.
    now_dt = datetime.now(UTC)
    timestamp_for_filename = now_dt.strftime("%Y-%m-%d_%H%M%S")
    iso_now = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Find a non-colliding manifest filename and claim it atomically.
    #
    # We use O_CREAT | O_EXCL so the existence check and file creation are a single syscall — eliminating the TOCTOU
    # race that would exist if we checked os.path.exists() and then separately opened the file for writing.  Two
    # parallel seal invocations (e.g. from concurrent post- transfer scripts on a shared NAS) will now always land on
    # distinct paths; the second process to attempt any given path gets FileExistsError and moves on to the next suffix.
    mhl_name = f"{base_name}_{timestamp_for_filename}.mhl"
    mhl_path = os.path.join(output_dir, mhl_name)
    suffix = 0
    fd: int | None = None
    while fd is None:
        try:
            fd = os.open(mhl_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o666)
        except FileExistsError:
            suffix += 1
            mhl_path = os.path.join(output_dir, f"{base_name}_{timestamp_for_filename}_{suffix}.mhl")

    # Build the manifest skeleton. We construct in memory and write at the end; for typical shoots (<5000 files) the
    # in-memory tree is a few MB of XML which is fine. For pathologically large trees a streaming writer (etree.xmlfile)
    # would help, but the seal-time cost is dominated by hashing the bytes, not by holding the tree in RAM.
    doc = etree.Element("hashlist", version="1.1")
    etree.SubElement(doc, "creationdate").text = iso_now

    info = _build_creatorinfo(doc, f"simple-mhl {__version__}", iso_now)

    # xml_tags name the manifest element each digest is written into, in the same order _hash_files_auto returns them.
    xml_tags = [_seal_tag(a) for a in algorithms]

    def _on_skip(path: str, reason: str, is_warning: bool) -> None:
        rel = os.path.relpath(path, root)
        rel_posix = rel.replace(os.sep, "/") if os.sep != "/" else rel
        if is_warning:
            # Always shown: a dropped directory leaves files unprotected.
            sys.stderr.write(f"[WARNING] skipped: {rel_posix} ({reason})\n")
        elif verbose:
            print(f"[SKIP] {rel_posix} ({reason})")

    # Walk the tree first (reporting skips as we go), then hash. Materialising the entry list lets us hash files
    # concurrently while still emitting the manifest in deterministic walk order. The list holds (path, stat) tuples — a
    # few tens of MB even for a 100k-frame shoot, dwarfed by the XML tree built alongside it. Concurrency is decided
    # entirely by _hash_files_auto, which measures the storage and stays sequential whenever that's faster.
    entries = list(_iter_files_for_seal(root, mhl_path, on_skip=_on_skip))

    # Refuse zero-byte files before any hashing (see _reject_empty_files); on abort it releases the O_EXCL manifest fd
    # we claimed above.
    _reject_empty_files(entries, root, fd, mhl_path)

    paths = [fp for fp, _ in entries]
    # `null` records no digest, so a null seal reads no bytes — each entry just gets an empty <null> and the run
    # timestamp. Any other selection hashes for real, auto-tuning concurrency to the storage.
    is_null = algorithms == [_NULL_TAG]
    if is_null:
        digests: Iterator[tuple[list[str], str]] = (([""], iso_now) for _ in entries)
    else:
        digests = hashing._hash_files_auto(paths, [st.st_size for _, st in entries], algorithms)

    for (filepath, stat_result), (file_digests, hashdate) in zip(entries, digests, strict=True):
        # Paths are relative to the manifest's own directory (output_dir) so verify resolves them correctly; this equals
        # root in the default case.
        rel_path = os.path.relpath(filepath, output_dir)
        # The MHL spec requires forward slashes regardless of platform. On Windows, os.path.relpath returns backslashes;
        # replace them so the manifest is portable between operating systems.
        rel_path_posix = rel_path.replace(os.sep, "/") if os.sep != "/" else rel_path
        # Normalize to NFC so accented filenames are stored as precomposed codepoints (e.g. é = U+00E9) rather than the
        # NFD decomposed form (e = U+0065 + combining acute U+0301) that macOS HFS+/APFS returns from the filesystem. A
        # consistent NFC manifest round-trips correctly on Linux (byte-exact path matching) and Windows, both of which
        # use NFC natively.
        rel_path_posix = unicodedata.normalize("NFC", rel_path_posix)

        h = etree.SubElement(doc, "hash")
        etree.SubElement(h, "file").text = rel_path_posix
        etree.SubElement(h, "size").text = str(stat_result.st_size)
        mtime = datetime.fromtimestamp(stat_result.st_mtime, UTC)
        etree.SubElement(h, "lastmodificationdate").text = mtime.strftime("%Y-%m-%dT%H:%M:%SZ")
        # One hash element per format, in resolved order, then <hashdate>.
        for xml_tag, digest in zip(xml_tags, file_digests, strict=True):
            etree.SubElement(h, xml_tag).text = digest
        if verbose:
            if is_null:
                print(f"[OK] {rel_path_posix}  size: {stat_result.st_size}")
            else:
                shown = "  ".join(f"{t}: {d}" for t, d in zip(xml_tags, file_digests, strict=True))
                print(f"[OK] {rel_path_posix}  {shown}")
        etree.SubElement(h, "hashdate").text = hashdate

    # Update finishdate to reflect actual completion; useful for auditing how long the seal took.
    finish_el = info.find("finishdate")
    if finish_el is not None:
        finish_el.text = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Pretty-print so a human can read the manifest in a text editor; lxml adds the XML declaration and UTF-8 encoding
    # header. We write via the fd we already hold from the O_EXCL open above so we never re-open the file by path (which
    # would be another race window).
    with os.fdopen(fd, "wb") as fh:
        etree.ElementTree(doc).write(fh, xml_declaration=True, encoding="UTF-8", pretty_print=True)

    if verbose:
        print(f"Created MHL: {mhl_path}")
