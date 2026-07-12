"""
ASC-MHL generation engine and manifest/chain writers.

One operation serves both `generate` and `verify`: hash every file in scope
(read-once across all requested formats, concurrency auto-tuned by
mhl_suite.hashing), label each computed hash against the loaded history —
`original` for unrecorded files, `verified`/`failed` against a recorded hash
(spec 5.6.4) — and append a new generation manifest to the history (spec
5.6.5), initiating the history (ascmhl/ folder, generation 0001, chain file)
when there is none (spec 5.6.2).

Nested histories are generated bottom-up in the same operation: every manifest
written shares the operation's UTC start timestamp (spec 6.3), each child's
new manifest is referenced from its parent (hashlistreference, spec 6.5.5),
and a nested root's directory hashes are taken from the child's fresh
roothash (spec 6.5.2 Note 1). Updates never propagate upward from here —
that rule belongs to the rename operation in mhl_suite.ascmhl_ops.

The writer half is shared with ascmhl_ops (rename and flatten write
manifests too): dataclasses describing one manifest's content and streaming
writers that emit spec/XSD-conformant XML — element order per ASCMHL.xsd,
UTF-8, NFC posix paths. Chain and collection files share one schema and one
writer (spec 7/8).

Argument and filesystem problems raise AscmhlGenerateError for the CLI to render;
history-integrity problems raise ascmhl_history.HistoryError with its pinned
3x code. This module never prints and never exits.
"""

import getpass
import os
import unicodedata
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from lxml import etree

from mhl_suite import __version__, hashing
from mhl_suite import ascmhl_dirhash as dirhash
from mhl_suite._exit_codes import ExitCode
from mhl_suite.algorithms import ASC_FORMATS, asc_check
from mhl_suite.ascmhl_history import (
    ASCMHL_FOLDER,
    CHAIN_FILENAME,
    DEFAULT_IGNORE_PATTERNS,
    Generation,
    History,
    Recorded,
    ascmhl_exit_code,
    build_ignore_spec,
    collect_recorded,
    load_history,
    parse_chain,
)
from mhl_suite.osutils import friendly_hostname, normalization_variant_on_disk
from mhl_suite.sorting import sort_key
from mhl_suite.verify import ErrorKind, HashComparison, Status, VerifyEntry, VerifyReport

if TYPE_CHECKING:
    from collections.abc import Callable, Iterable, Sequence

# The hash-format element order inside HashType and the directory-hash
# containers — both are XSD <sequence>s, so emission order is normative.
FORMAT_ORDER = ("c4", "md5", "sha1", "xxh128", "xxh3", "xxh64")

MANIFEST_NAMESPACE = "urn:ASC:MHL:v2.0"
DIRECTORY_NAMESPACE = "urn:ASC:MHL:DIRECTORY:v2.0"


class AscmhlGenerateError(Exception):
    """The operation cannot proceed (bad arguments, unusable target). The message is CLI-ready stderr text."""


# -----------------------------------------------------------------------------
# Manifest description (what one generation records)
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class HashEntryOut:
    """One hash-format element to write (a HashFormatType instance)."""

    fmt: str
    digest: str
    action: "str | None" = None
    hashdate: "str | None" = None


@dataclass
class FileEntryOut:
    """One <hash> record to write."""

    path: str  # posix, relative to the manifest's scope, NFC
    entries: "list[HashEntryOut]"
    size: "int | None" = None
    creation_date: "str | None" = None
    last_modification_date: "str | None" = None
    previous_path: "str | None" = None


@dataclass
class DirEntryOut:
    """One <directoryhash> record to write."""

    path: str
    content: "list[HashEntryOut]"
    structure: "list[HashEntryOut]"
    creation_date: "str | None" = None
    last_modification_date: "str | None" = None
    previous_path: "str | None" = None


@dataclass
class ManifestOut:
    """Everything one generation manifest records."""

    creation_date: str  # ISO-8601 UTC; the operation's start instant
    process: str  # in-place | transfer | flatten
    ignore_patterns: "Sequence[str]" = ()
    # (content entries, structure entries) for the scope root, or None when
    # directory hashes were not computed.
    root_hash: "tuple[list[HashEntryOut], list[HashEntryOut]] | None" = None
    files: "list[FileEntryOut]" = field(default_factory=list)
    directories: "list[DirEntryOut]" = field(default_factory=list)
    references: "list[tuple[str, str]]" = field(default_factory=list)  # (rel path, c4)


# -----------------------------------------------------------------------------
# XML writers
# -----------------------------------------------------------------------------


def manifest_filename(number: int, folder_name: str, op_start: datetime) -> str:
    """The generation manifest name of spec 6.3: NNNN_<folder>_<date>_<time>Z.mhl."""
    return f"{number:04d}_{folder_name}_{op_start.strftime('%Y-%m-%d_%H%M%S')}Z.mhl"


def _iso(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _serialize(element: "etree._Element", indent: str = "  ") -> bytes:
    """One pretty-printed element, indented for its place inside the root."""
    text = etree.tostring(element, pretty_print=True, encoding="unicode")
    return "".join(f"{indent}{line}\n" for line in text.splitlines()).encode("utf-8")


def _format_sorted(entries: "Iterable[HashEntryOut]") -> "list[HashEntryOut]":
    """Hash-format elements in the XSD sequence order (unknown formats rejected)."""
    return sorted(entries, key=lambda e: FORMAT_ORDER.index(e.fmt))


def _hash_format_element(entry: HashEntryOut) -> "etree._Element":
    element = etree.Element(entry.fmt)
    element.text = entry.digest
    if entry.action is not None:
        element.set("action", entry.action)
    if entry.hashdate is not None:
        element.set("hashdate", entry.hashdate)
    return element


def _path_element(parent: "etree._Element", record: "FileEntryOut | DirEntryOut", size: "int | None" = None) -> None:
    path = etree.SubElement(parent, "path")
    path.text = record.path
    if size is not None:
        path.set("size", str(size))
    if record.creation_date is not None:
        path.set("creationdate", record.creation_date)
    if record.last_modification_date is not None:
        path.set("lastmodificationdate", record.last_modification_date)


def _creatorinfo_element(creation_date: str) -> "etree._Element":
    """
    The <creatorinfo> block. Kept symmetric with simple-mhl's: creation date,
    hostname and tool (XSD-required) plus one plain author element carrying
    the username.
    """
    info = etree.Element("creatorinfo")
    etree.SubElement(info, "creationdate").text = creation_date
    etree.SubElement(info, "hostname").text = friendly_hostname()
    tool = etree.SubElement(info, "tool")
    tool.text = "advanced-mhl"
    tool.set("version", __version__)
    etree.SubElement(info, "author").text = getpass.getuser()
    return info


def _processinfo_element(manifest: ManifestOut) -> "etree._Element":
    info = etree.Element("processinfo")
    etree.SubElement(info, "process").text = manifest.process
    if manifest.root_hash is not None:
        content_entries, structure_entries = manifest.root_hash
        roothash = etree.SubElement(info, "roothash")
        for tag, entries in (("content", content_entries), ("structure", structure_entries)):
            container = etree.SubElement(roothash, tag)
            for entry in _format_sorted(entries):
                container.append(_hash_format_element(entry))
    if manifest.ignore_patterns:
        ignore = etree.SubElement(info, "ignore")
        for pattern in manifest.ignore_patterns:
            etree.SubElement(ignore, "pattern").text = pattern
    return info


def _file_element(record: FileEntryOut) -> "etree._Element":
    element = etree.Element("hash")
    _path_element(element, record, size=record.size)
    for entry in _format_sorted(record.entries):
        element.append(_hash_format_element(entry))
    if record.previous_path is not None:
        etree.SubElement(element, "previousPath").text = record.previous_path
    return element


def _dir_element(record: DirEntryOut) -> "etree._Element":
    element = etree.Element("directoryhash")
    _path_element(element, record)
    for tag, entries in (("content", record.content), ("structure", record.structure)):
        container = etree.SubElement(element, tag)
        for entry in _format_sorted(entries):
            container.append(_hash_format_element(entry))
    if record.previous_path is not None:
        etree.SubElement(element, "previousPath").text = record.previous_path
    return element


def write_manifest(file_path: "str | Path", manifest: ManifestOut) -> None:
    """
    Stream one generation manifest to `file_path` (opened exclusively — a
    pre-existing file raises FileExistsError rather than being clobbered).
    Records are interleaved in path order inside <hashes>; hash-format
    children follow the XSD sequence order.
    """
    with open(file_path, "xb") as fh:
        fh.write(b'<?xml version="1.0" encoding="UTF-8"?>\n<hashlist version="2.0" xmlns="urn:ASC:MHL:v2.0">\n')
        fh.write(_serialize(_creatorinfo_element(manifest.creation_date)))
        fh.write(_serialize(_processinfo_element(manifest)))
        _write_hashes(fh, manifest)
        if manifest.references:
            fh.write(b"  <references>\n")
            for rel_path, c4_digest in manifest.references:
                ref = etree.Element("hashlistreference")
                etree.SubElement(ref, "path").text = rel_path
                etree.SubElement(ref, "c4").text = c4_digest
                fh.write(_serialize(ref, "    "))
            fh.write(b"  </references>\n")
        fh.write(b"</hashlist>\n")


def _write_hashes(fh: BinaryIO, manifest: ManifestOut) -> None:
    """
    The <hashes> block, omitted entirely when there is nothing to record.

    manifest.files already arrives in order (it is the order they were hashed
    in); this merges the <directoryhash> records into that same order, which is
    what puts each directory immediately ahead of its own subtree and ahead of
    its siblings' files.
    """
    records: list[FileEntryOut | DirEntryOut] = [*manifest.files, *manifest.directories]
    if not records:
        return
    fh.write(b"  <hashes>\n")
    for record in sorted(records, key=lambda r: sort_key(r.path, is_dir=isinstance(r, DirEntryOut))):
        element = _file_element(record) if isinstance(record, FileEntryOut) else _dir_element(record)
        fh.write(_serialize(element, "    "))
    fh.write(b"  </hashes>\n")


def write_directory_file(file_path: "str | Path", entries: "list[tuple[str, str, str]]") -> None:
    """
    Write an ASC MHL directory document — the chain file (spec 7) and the
    collection file (spec 8) share this schema. `entries` are
    (manifest path, hash format, digest) triples in order; sequencenr runs
    from 1 (spec 7.4.1).
    """
    with open(file_path, "wb") as fh:
        fh.write(b'<?xml version="1.0" encoding="UTF-8"?>\n<ascmhldirectory xmlns="urn:ASC:MHL:DIRECTORY:v2.0">\n')
        for number, (rel_path, fmt, digest) in enumerate(entries, start=1):
            element = etree.Element("hashlist")
            element.set("sequencenr", str(number))
            etree.SubElement(element, "path").text = rel_path
            etree.SubElement(element, fmt).text = digest
            fh.write(_serialize(element))
        fh.write(b"</ascmhldirectory>\n")


def append_directory_entry(file_path: Path, rel_path: str, fmt: str, digest: str) -> None:
    """Append one entry to a chain/collection file, creating it when absent (sequencenr stays continuous)."""
    existing = parse_chain(file_path) if file_path.exists() else []
    write_directory_file(file_path, [*existing, (rel_path, fmt, digest)])


# -----------------------------------------------------------------------------
# The generate/verify engine
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class GenerateOptions:
    """What a generate/verify-append operation computes and records."""

    algorithms: "tuple[str, ...]" = ("xxh128",)
    directory_hashes: bool = True
    ignore_patterns: "tuple[str, ...]" = ()


@dataclass
class GenerateResult:
    """
    The outcome of one generate/verify operation. `report.code` carries the
    verify-semantics exit code (the pinned precedence, unknown files included);
    `generate_code` treats newly recorded files as the point of the operation
    rather than drift. `write_failures` lists manifests that could not be
    written (e.g. a read-only volume) — the hashing results stay valid.
    """

    report: VerifyReport
    generate_code: ExitCode
    manifests_written: "list[Path]" = field(default_factory=list)
    write_failures: "list[str]" = field(default_factory=list)


@dataclass
class _FileItem:
    """One on-disk file of a level's scope."""

    abs_path: str
    rel: str  # level-relative posix, NFC
    stat: os.stat_result
    recorded: "Recorded | None" = None
    formats: "list[str]" = field(default_factory=list)
    digests: "dict[str, str]" = field(default_factory=dict)
    hashdate: str = ""


@dataclass
class _DirItem:
    """One on-disk directory of a level's scope (root included, rel='')."""

    rel: str
    stat: "os.stat_result | None"
    files: "list[_FileItem]" = field(default_factory=list)
    subdirs: "list[_DirItem]" = field(default_factory=list)
    child_history: "History | None" = None  # a nested history owns this subtree


@dataclass
class _Level:
    """One history level of the operation (the media directory root or a nested history)."""

    prefix: str  # media-directory-relative posix prefix ('' at the root)
    history: History
    merged_ignores: "list[str]"
    tree: _DirItem
    files: "list[_FileItem]"
    recorded: "list[Recorded]"
    children: "list[_Level]"
    unreadable: "list[tuple[str, str]]" = field(default_factory=list)  # (rel dir, os error)
    # Outcome, filled during assembly:
    roothash: "dict[str, tuple[str, str]] | None" = None
    manifest_path: "Path | None" = None
    manifest_c4: "str | None" = None


def _scope_path(prefix: str, rel: str) -> str:
    """Join a level prefix and a level-relative path into a media-directory-relative one."""
    if not rel:
        return prefix
    return f"{prefix}/{rel}" if prefix else rel


def _resolve_algorithms(algorithms: "Sequence[str]") -> "tuple[str, ...]":
    """Validate and de-duplicate the requested ASC hash formats (order kept)."""
    for name in algorithms:
        if name not in ASC_FORMATS:
            raise AscmhlGenerateError(
                f"Error: unsupported algorithm '{name}' (choose from {', '.join(sorted(ASC_FORMATS))})"
            )
    resolved = tuple(dict.fromkeys(algorithms))
    if not resolved:
        raise AscmhlGenerateError("Error: no algorithm given")
    return resolved


def _load_root_history(root: Path) -> History:
    """
    The history tree the operation appends to: the root's own history when one
    exists, else an uninitiated root level over any nested histories below
    (spec 5.6.2 Note 3 — a new history references pre-existing nested ones).
    """
    if (root / ASCMHL_FOLDER).is_dir():
        return load_history(root)
    children: list[History] = []
    for dirpath, dirnames, _filenames in os.walk(root):
        if dirpath != str(root) and ASCMHL_FOLDER in dirnames:
            children.append(load_history(dirpath))
            dirnames.clear()
    return History(root=root, generations=[], children=children)


def _level_view(history: History, merged_ignores: "list[str]") -> History:
    """
    This level's records viewed in isolation (no children — nested histories
    are their own levels) with the operation's merged ignore patterns staged
    as a pending generation, so the loader's ignore matcher and record
    collector apply exactly what this operation will record.
    """
    pending = Generation(
        number=(history.generations[-1].number + 1 if history.generations else 1),
        file_path=history.root / ASCMHL_FOLDER / "pending",
        records=[],
        ignore_patterns=merged_ignores,
    )
    return History(root=history.root, generations=[*history.generations, pending])


def _scan_level(prefix: str, history: History, options: GenerateOptions) -> _Level:
    """Walk one level's scope (stopping at nested history roots) and collect its recorded set."""
    merged = list(
        dict.fromkeys([*history.latest_ignore_patterns(), *options.ignore_patterns, *DEFAULT_IGNORE_PATTERNS])
    )
    view = _level_view(history, merged)
    matcher = build_ignore_spec(view)
    recorded = collect_recorded(view, matcher)
    child_roots = {os.fspath(child.root): child for child in history.children}

    files: list[_FileItem] = []
    unreadable: list[tuple[str, str]] = []

    def walk(abs_dir: str, rel: str, stat_result: "os.stat_result | None") -> _DirItem:
        node = _DirItem(rel=rel, stat=stat_result, child_history=child_roots.get(abs_dir))
        if node.child_history is not None:
            return node
        try:
            entries = list(os.scandir(abs_dir))
        except OSError as exc:
            unreadable.append((rel or ".", exc.strerror or str(exc)))
            return node
        for entry in entries:
            entry_rel = _scope_path(rel, unicodedata.normalize("NFC", entry.name))
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
                if is_dir:
                    if not matcher.match_file(entry_rel + "/"):
                        node.subdirs.append(walk(entry.path, entry_rel, entry.stat(follow_symlinks=False)))
                elif entry.is_file(follow_symlinks=False) and not matcher.match_file(entry_rel):
                    item = _FileItem(abs_path=entry.path, rel=entry_rel, stat=entry.stat(follow_symlinks=False))
                    node.files.append(item)
                    files.append(item)
            except OSError:
                continue  # vanished between scandir and stat
        return node

    tree = walk(os.fspath(history.root), "", _stat_or_none(history.root))

    # The walk runs in filesystem order; this is where the level's order is
    # decided, before _hash_all consumes the list, so hashing order and manifest
    # order are the same one. The _DirItem tree stays unsorted: its only
    # consumer is the directory hash, which sorts its own child digests.
    files.sort(key=lambda item: sort_key(item.rel))
    unreadable.sort(key=lambda u: sort_key(u[0]))

    recorded_by_path = {r.path: r for r in recorded}
    for item in files:
        item.recorded = recorded_by_path.get(item.rel)
        extra = () if item.recorded is None or item.recorded.original is None else (item.recorded.original[0],)
        item.formats = list(dict.fromkeys([*options.algorithms, *extra]))

    children = [
        _scan_level(_scope_path(prefix, child.root.relative_to(history.root).as_posix()), child, options)
        for child in history.children
    ]
    return _Level(
        prefix=prefix,
        history=history,
        merged_ignores=merged,
        tree=tree,
        files=files,
        recorded=recorded,
        children=children,
        unreadable=unreadable,
    )


def _stat_or_none(path: Path) -> "os.stat_result | None":
    try:
        return path.stat()
    except OSError:
        return None


def _flatten_levels(level: _Level) -> "list[_Level]":
    out = [level]
    for child in level.children:
        out.extend(_flatten_levels(child))
    return out


def _hash_all(
    levels: "list[_Level]",
    options: GenerateOptions,
    on_progress: "Callable[[int], None] | None",
    on_total: "Callable[[int], None] | None" = None,
) -> None:
    """
    Hash every file of every level in one adaptive run (read-once across each
    file's formats, per Implementation Guidelines 2.3), stamping a per-file
    hashdate the moment its digests are computed.

    `on_total`, if given, is called once with the byte volume about to be hashed
    (every file on disk, recorded or new) before hashing starts — the true
    progress weight for the append path, which the recorded-bytes estimate can
    undercount when new files are present. Sizes come from the scan's cached
    stats, so this reads nothing extra.
    """
    items = [item for level in levels for item in level.files]
    if not items:
        return
    if on_total is not None:
        on_total(sum(item.stat.st_size for item in items))

    def make_job(item: _FileItem) -> "hashing.HashJob[tuple[list[str], str]]":
        factories = [ASC_FORMATS[fmt].factory for fmt in item.formats]

        def job(mon: "Callable[[int], None]") -> "tuple[list[str], str]":
            progress = hashing.chain_progress(mon, on_progress) if on_progress is not None else mon
            return hashing.get_hashes(item.abs_path, factories, on_progress=progress), _iso(datetime.now(UTC))

        return job

    jobs = [make_job(item) for item in items]
    calibrate_factories = [ASC_FORMATS[fmt].factory for fmt in options.algorithms]
    results = hashing.run_hash_jobs(
        [i.abs_path for i in items],
        [i.stat.st_size for i in items],
        jobs,
        lambda: hashing.calibrate_hash_bandwidth(calibrate_factories),
    )
    for item, (digests, hashdate) in zip(items, results, strict=True):
        item.digests = dict(zip(item.formats, digests, strict=True))
        item.hashdate = hashdate


def _file_dates(stat_result: os.stat_result) -> "tuple[str | None, str]":
    """(creationdate or None where the platform has no birth time, lastmodificationdate)."""
    birthtime = getattr(stat_result, "st_birthtime", None)
    created = _iso(datetime.fromtimestamp(birthtime, UTC)) if birthtime is not None else None
    return created, _iso(datetime.fromtimestamp(stat_result.st_mtime, UTC))


def _label_files(level: _Level, entries: "list[VerifyEntry]") -> "list[FileEntryOut]":
    """
    Reduce a level's on-disk files to manifest records and report entries:
    unrecorded files record `original` hashes, recorded files are verified
    against their original-generation hash and record every computed format as
    `verified` or `failed` (spec 5.6.4/6.5.1).
    """
    out: list[FileEntryOut] = []
    for item in level.files:
        scope_path = _scope_path(level.prefix, item.rel)
        recorded = item.recorded
        original = recorded.original if recorded is not None else None
        if recorded is not None and original is None:
            # Recorded, but nothing usable to verify against (spec 5.6.4):
            # an unsuccessful verification, and no new record is written.
            entries.append(
                VerifyEntry(
                    path=scope_path,
                    status=Status.ERROR,
                    error=ErrorKind.UNUSABLE_HASH,
                    detail="no hash entry labeled original or verified",
                )
            )
            continue
        if recorded is None or original is None:
            action = "original"
            entries.append(VerifyEntry(path=scope_path, status=Status.NEW, actual_size=item.stat.st_size))
        else:
            fmt, expected = original
            check = asc_check(fmt, expected)
            matched = check is not None and check.matches(item.digests[fmt])
            action = "verified" if matched else "failed"
            entries.append(
                VerifyEntry(
                    path=scope_path,
                    status=Status.OK if matched else Status.MISMATCH,
                    hashes=[HashComparison(tag=fmt, expected=expected, computed=item.digests[fmt], ok=matched)],
                    recorded_size=recorded.record.size,
                    actual_size=item.stat.st_size,
                )
            )
        created, modified = _file_dates(item.stat)
        out.append(
            FileEntryOut(
                path=item.rel,
                entries=[HashEntryOut(fmt, item.digests[fmt], action, item.hashdate) for fmt in item.formats],
                size=item.stat.st_size,
                creation_date=created,
                last_modification_date=modified,
            )
        )
    return out


def _completeness(level: _Level, entries: "list[VerifyEntry]") -> None:
    """Recorded paths absent from the scanned scope are missing (spec 5.6.4)."""
    present_files = {item.rel for item in level.files}
    present_dirs: set[str] = set()

    def collect_dirs(node: _DirItem) -> None:
        if node.rel:
            present_dirs.add(node.rel)
        for sub in node.subdirs:
            collect_dirs(sub)

    collect_dirs(level.tree)
    for r in level.recorded:
        present = r.path in (present_dirs if r.record.is_directory else present_files)
        if not present:
            entries.append(VerifyEntry(path=_scope_path(level.prefix, r.path), status=Status.MISSING))
    for rel_dir, error_text in level.unreadable:
        entries.append(
            VerifyEntry(
                path=_scope_path(level.prefix, rel_dir),
                status=Status.ERROR,
                error=ErrorKind.IO,
                detail=f"cannot scan directory: {error_text}",
            )
        )


def latest_dir_entries(history: History, rel: str) -> "tuple[dict[str, str], dict[str, str]]":
    """The most recent recorded (content, structure) digests per format for a directory path."""
    content: dict[str, str] = {}
    structure: dict[str, str] = {}
    for gen in reversed(history.generations):
        rec = gen.by_path.get(rel)
        if rec is None or not rec.is_directory:
            continue
        for target, recorded_entries in ((content, rec.dir_content), (structure, rec.dir_structure)):
            for entry in recorded_entries:
                if entry.action != "failed":
                    target.setdefault(entry.fmt, entry.digest)
    return content, structure


def _dir_action(fmt: str, computed: str, recorded: "dict[str, str]") -> "tuple[str, bool]":
    """(action, failed?) for a computed directory hash against the latest recorded one."""
    expected = recorded.get(fmt)
    if expected is None:
        return "original", False
    check = asc_check(fmt, expected)
    if check is not None and check.matches(computed):
        return "verified", False
    return "failed", True


def _directory_hashes(
    level: _Level, options: GenerateOptions, records: "list[DirEntryOut]", notices: "list[str]"
) -> "tuple[dict[str, tuple[str, str]], bool]":
    """
    Compute content/structure hashes bottom-up for every directory of the
    level's scope (spec 6.5.2 + Appendix G), taking a nested history root's
    pair from that child's fresh roothash (spec 6.5.2 Note 1). Returns the
    scope root's pair per format and whether any recorded value failed.
    """
    failed_any = False

    def compute(node: _DirItem) -> "dict[str, tuple[str, str]]":
        nonlocal failed_any
        if node.child_history is not None:
            # A nested history root: its pair is the child's fresh roothash
            # (spec 6.5.2 Note 1), recorded here like any other directory.
            child_level = next(c for c in level.children if c.history is node.child_history)
            pair = child_level.roothash or {}
        else:
            sub_hashes = [(sub, compute(sub)) for sub in node.subdirs]
            pair = {}
            for fmt in options.algorithms:
                content = dirhash.content_hash(
                    fmt,
                    [item.digests[fmt] for item in node.files] + [h[fmt][0] for _sub, h in sub_hashes if fmt in h],
                )
                structure = dirhash.structure_hash(
                    fmt,
                    [(os.path.basename(item.rel), item.digests[fmt]) for item in node.files]
                    + [(os.path.basename(sub.rel), h[fmt][1]) for sub, h in sub_hashes if fmt in h],
                )
                pair[fmt] = (content, structure)
        if node.rel:  # the scope root is recorded as <roothash>, not a record
            recorded_content, recorded_structure = latest_dir_entries(level.history, node.rel)
            content_entries: list[HashEntryOut] = []
            structure_entries: list[HashEntryOut] = []
            for fmt, (content, structure) in pair.items():
                for digest, recorded, target, label in (
                    (content, recorded_content, content_entries, "content"),
                    (structure, recorded_structure, structure_entries, "structure"),
                ):
                    action, failed = _dir_action(fmt, digest, recorded)
                    target.append(HashEntryOut(fmt, digest, action))
                    if failed:
                        failed_any = True
                        notices.append(
                            f"[ERROR] directory hash mismatch: {_scope_path(level.prefix, node.rel)} ({fmt} {label})"
                        )
            created, modified = (None, None) if node.stat is None else _file_dates(node.stat)
            records.append(
                DirEntryOut(
                    path=node.rel,
                    content=content_entries,
                    structure=structure_entries,
                    creation_date=created,
                    last_modification_date=modified,
                )
            )
        return pair

    return compute(level.tree), failed_any


def _write_generation(level: _Level, manifest: ManifestOut, op_start: datetime, result: GenerateResult) -> None:
    """Write the level's new manifest and chain entry; a write failure is reported, never fatal here."""
    ascmhl_dir = level.history.root / ASCMHL_FOLDER
    number = level.history.generations[-1].number + 1 if level.history.generations else 1
    name = manifest_filename(number, level.history.root.name, op_start)
    manifest_path = ascmhl_dir / name
    try:
        ascmhl_dir.mkdir(exist_ok=True)
        write_manifest(manifest_path, manifest)
        c4_digest = hashing.get_hashes(os.fspath(manifest_path), [ASC_FORMATS["c4"].factory])[0]
        append_directory_entry(ascmhl_dir / CHAIN_FILENAME, name, "c4", c4_digest)
    except OSError as exc:
        manifest_path.unlink(missing_ok=True)
        result.write_failures.append(f"cannot write new generation {manifest_path}: {exc.strerror or exc}")
        return
    level.manifest_path = manifest_path
    level.manifest_c4 = c4_digest
    result.manifests_written.append(manifest_path)


def _assemble_level(
    level: _Level, options: GenerateOptions, op_start: datetime, result: GenerateResult, entries: "list[VerifyEntry]"
) -> bool:
    """Generate one level bottom-up (children first); returns whether any directory hash failed."""
    dir_failed = False
    for child in level.children:
        dir_failed |= _assemble_level(child, options, op_start, result, entries)

    files = _label_files(level, entries)
    _completeness(level, entries)

    dir_records: list[DirEntryOut] = []
    root_hash = None
    if options.directory_hashes:
        roothash, level_failed = _directory_hashes(level, options, dir_records, result.report.notices)
        level.roothash = roothash
        dir_failed |= level_failed
        root_hash = (
            [HashEntryOut(fmt, pair[0]) for fmt, pair in roothash.items()],
            [HashEntryOut(fmt, pair[1]) for fmt, pair in roothash.items()],
        )

    references = []
    for child in level.children:
        if child.manifest_path is not None and child.manifest_c4 is not None:
            rel = child.manifest_path.relative_to(level.history.root).as_posix()
            references.append((rel, child.manifest_c4))

    manifest = ManifestOut(
        creation_date=_iso(op_start),
        process="in-place",
        ignore_patterns=level.merged_ignores,
        root_hash=root_hash,
        files=files,
        directories=dir_records,
        references=references,
    )
    _write_generation(level, manifest, op_start, result)
    return dir_failed


def generate_ascmhl(
    root: "str | Path",
    options: "GenerateOptions | None" = None,
    *,
    on_progress: "Callable[[int], None] | None" = None,
    on_total: "Callable[[int], None] | None" = None,
) -> GenerateResult:
    """
    Generate a new generation for (or verify-append) the directory `root` as an ASC-MHL managed data
    set: initiate or append one generation per history level, bottom-up, all
    sharing this operation's UTC start timestamp. Never prints, never exits.

    Raises AscmhlGenerateError for unusable arguments and lets
    ascmhl_history.HistoryError propagate for a broken existing history (the
    chain gate runs before any media is read). Manifest write failures (e.g.
    a read-only volume, Implementation Guidelines 2.7) are reported in
    `write_failures` while the verification outcome stands.

    `on_progress` receives per-chunk byte counts as files hash; `on_total`, if
    given, receives the total byte volume to be hashed once, before hashing —
    letting a caller correct a progress bar whose weight excluded new files.
    """
    options = options or GenerateOptions()
    algorithms = _resolve_algorithms(options.algorithms)
    options = GenerateOptions(algorithms, options.directory_hashes, tuple(options.ignore_patterns))

    root = Path(os.path.abspath(os.fspath(root)))
    if not root.is_dir():
        msg = f"Error: '{root}' is not a directory"
        variant = normalization_variant_on_disk(os.fspath(root))
        if variant is not None and os.path.isdir(variant):
            msg += f"\n  A directory with a different Unicode normalization exists — did you mean:\n    {variant}"
        raise AscmhlGenerateError(msg)

    op_start = datetime.now(UTC)
    history = _load_root_history(root)
    top = _scan_level("", history, options)
    levels = _flatten_levels(top)
    _hash_all(levels, options, on_progress, on_total)

    result = GenerateResult(report=VerifyReport(), generate_code=ExitCode.OK)
    entries: list[VerifyEntry] = []
    dir_failed = _assemble_level(top, options, op_start, result, entries)

    entries.sort(key=lambda e: sort_key(e.path))
    code = ascmhl_exit_code(entries)
    if code != ExitCode.HASH_MISMATCH and dir_failed:
        code = ExitCode.DIRECTORY_HASH_MISMATCH
    result.report.entries = entries
    result.report.code = code
    result.generate_code = _generate_exit_code(entries, dir_failed=dir_failed)
    result.report.notices.extend(f"[WARNING] {failure}" for failure in result.write_failures)
    return result


def _generate_exit_code(entries: "list[VerifyEntry]", *, dir_failed: bool) -> ExitCode:
    """
    The generate-semantics exit code: recording new files is the operation's
    purpose, so Status.NEW never fails a generate; failures and absences do.
    """
    if any(e.status in (Status.MISMATCH, Status.ERROR) for e in entries):
        return ExitCode.HASH_MISMATCH
    if dir_failed:
        return ExitCode.DIRECTORY_HASH_MISMATCH
    if any(e.status == Status.MISSING for e in entries):
        return ExitCode.MISSING
    return ExitCode.OK
