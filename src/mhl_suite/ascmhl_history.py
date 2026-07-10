"""
ASC-MHL history reading: the native loader, the history model, and read-only
verification. Everything here only ever *reads* a History — the manifest
writers and the generation-appending engine live in mhl_suite.ascmhl_seal,
the remaining operations in mhl_suite.ascmhl_ops.

The suite owns the parsing end-to-end: load_history() reads a media
directory's `ascmhl/` folder — validating the chain file (each generation
manifest's recorded hash is recomputed — the history integrity gate of spec
5.4), parsing every generation manifest, and descending into nested child
histories — and verify_ascmhl() reduces the loaded history to the shared
engine's FileRecords (original-generation hash and size per file,
`previousPath` renames resolved, ignore patterns applied) plus the ASC-only
policy the engine doesn't know about: new-file detection and the exit-code
precedence.

The ASC MHL specification (v1.0) is the authority for what verifying means
here, notably:
  * previousPath chains are resolved across any number of generations —
    files renamed "throughout the lifecycle" stay verifiable (5.3.3).
  * A hash entry labeled `original` or `verified` can vouch for a file;
    `failed` and unlabeled entries cannot (5.6.4).
  * A recorded file whose entries are all unusable is an unsuccessful
    verification, never a "new file" — unknown means *not recorded* (5.6.3).
  * Every history's recorded ignore patterns govern its own subtree, and the
    mandatory default set always applies (5.6.1.2).

Where the spec is silent, behaviour stays interoperable with the reference
`ascmhl` tool: generation-file discovery, traversal/report order, and the
10/11/20/21/30-33 exit codes. The test suite pins both — spec conformance on
hand-written histories, interop on histories sealed by the reference library
(a dev dependency only). Never prints, never exits.
"""

import os
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import pathspec
from lxml import etree
from pathspec.patterns.gitignore.spec import GitIgnoreSpecPattern

from mhl_suite import hashing
from mhl_suite import verify as verify_core
from mhl_suite._exit_codes import ExitCode
from mhl_suite.algorithms import ASC_FORMATS, asc_check
from mhl_suite.osutils import resolve_on_disk
from mhl_suite.verify import ErrorKind, FileRecord, Status, VerifyEntry, VerifyReport

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator

ASCMHL_FOLDER = "ascmhl"
CHAIN_FILENAME = "ascmhl_chain.xml"

# Generation manifest naming convention: 0001_name_date.mhl (the leading
# sequence number is what matters; ._ AppleDouble copies are skipped). Public:
# discovery applies the same rule when collecting a History's generations.
GENERATION_RE = re.compile(r"^(\d{4,})(?:_(.+))?$")

# The ASC-MHL default ignore set is mandated by the specification to always
# apply — .DS_Store files and the ascmhl folders themselves mutate as a
# history is appended, so no records for them can exist and they must never be
# flagged as new.
DEFAULT_IGNORE_PATTERNS = (".DS_Store", "ascmhl", "ascmhl/")


# -----------------------------------------------------------------------------
# History-integrity errors (the 3x exit codes)
# -----------------------------------------------------------------------------


class HistoryError(Exception):
    """A structural problem with the ASC-MHL history itself; `code` is the pinned 3x exit code."""

    code: ExitCode = ExitCode.ERROR


class NoHistoryError(HistoryError):
    code = ExitCode.NO_HISTORY

    def __init__(self, path: "str | Path") -> None:
        super().__init__(f"Missing ASC MHL history at path {path}")


class NoChainError(HistoryError):
    code = ExitCode.NO_CHAIN

    def __init__(self, path: "str | Path") -> None:
        super().__init__(f"Missing ASC MHL chain file for path {path}")


class ModifiedManifestError(HistoryError):
    code = ExitCode.MODIFIED_MANIFEST

    def __init__(self, path: "str | Path") -> None:
        super().__init__(f"Modified ASC MHL manifest in history at path {path}")


class MissingManifestError(HistoryError):
    code = ExitCode.MISSING_MANIFEST

    def __init__(self, path: "str | Path") -> None:
        super().__init__(f"Missing ASC MHL manifest in history at path {path}")


# -----------------------------------------------------------------------------
# History model
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class HashEntry:
    """One hash-format element of a <hash> / <directoryhash> record."""

    fmt: str
    digest: str
    action: "str | None" = None
    hashdate: "str | None" = None


@dataclass
class MediaRecord:
    """One <hash> / <directoryhash> element of a generation manifest."""

    path: str  # posix, relative to the owning history's root
    size: "int | None" = None
    previous_path: "str | None" = None
    is_directory: bool = False
    # The <path> element's optional date attributes, as recorded.
    creation_date: "str | None" = None
    last_modification_date: "str | None" = None
    # File hash entries in document order (empty for a <directoryhash>).
    entries: "list[HashEntry]" = field(default_factory=list)
    # A <directoryhash>'s <content>/<structure> hash entries (files have none).
    dir_content: "list[HashEntry]" = field(default_factory=list)
    dir_structure: "list[HashEntry]" = field(default_factory=list)


@dataclass
class Generation:
    """One parsed generation manifest (a NNNN_*.mhl file)."""

    number: int
    file_path: Path
    records: list[MediaRecord]
    ignore_patterns: list[str]  # recorded <ignore> patterns (may be empty)
    # Lookup by current name only, and by current-or-previous name — the two
    # queries rename resolution needs (first record in document order wins).
    by_path: dict[str, MediaRecord] = field(default_factory=dict)
    by_any_path: dict[str, MediaRecord] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for rec in self.records:
            self.by_path.setdefault(rec.path, rec)
            if rec.previous_path is not None:
                self.by_any_path.setdefault(rec.previous_path, rec)
            self.by_any_path.setdefault(rec.path, rec)


@dataclass
class History:
    """A loaded ASC MHL History: its generations plus nested child histories."""

    root: Path
    generations: list[Generation]
    children: "list[History]" = field(default_factory=list)

    def walk(self) -> "Iterator[tuple[str, History]]":
        """Yield (posix path prefix relative to this root, history) for self and every descendant."""
        yield "", self
        for child in self.children:
            prefix = child.root.relative_to(self.root).as_posix()
            for sub_prefix, sub in child.walk():
                yield (f"{prefix}/{sub_prefix}" if sub_prefix else prefix), sub

    def latest_ignore_patterns(self) -> list[str]:
        """The ignore patterns of the latest generation (empty when none were recorded)."""
        return self.generations[-1].ignore_patterns if self.generations else []


# -----------------------------------------------------------------------------
# Parsing
# -----------------------------------------------------------------------------


def _local(tag: object) -> str:
    """Local name of a possibly-namespaced lxml tag ('' for comments/PIs)."""
    if not isinstance(tag, str):
        return ""
    return tag.rpartition("}")[2] if "}" in tag else tag


def _free(element: "etree._Element") -> None:
    """Release a processed iterparse element and its preceding siblings."""
    element.clear()
    parent = element.getparent()
    while parent is not None and element.getprevious() is not None:
        del parent[0]


def _hash_entries(container: "etree._Element") -> "list[HashEntry]":
    """The recognised hash-format children of `container`, in document order."""
    entries: list[HashEntry] = []
    for child in container:
        name = _local(child.tag)
        if name in ASC_FORMATS and child.text:
            entries.append(HashEntry(name, child.text.strip(), child.get("action"), child.get("hashdate")))
    return entries


def _parse_media_element(element: "etree._Element", *, is_directory: bool) -> "MediaRecord | None":
    """
    Reduce one <hash> / <directoryhash> element to a MediaRecord (None without
    a <path>). Only direct children are read — a <metadata> block may contain
    arbitrary XML, including elements that happen to share hash-format names.
    A <directoryhash>'s content/structure entries are not verifiable file
    content; they are kept for record copying (rename, roothash reuse).
    """
    record = MediaRecord(path="", is_directory=is_directory)
    for child in element:
        name = _local(child.tag)
        if name == "path" and not record.path:
            if child.text:
                record.path = child.text.strip()
            size_text = (child.get("size") or "").strip()
            if size_text.isdecimal():
                record.size = int(size_text)
            record.creation_date = child.get("creationdate")
            record.last_modification_date = child.get("lastmodificationdate")
        elif name == "previousPath" and child.text:
            record.previous_path = child.text.strip()
        elif not is_directory and name in ASC_FORMATS and child.text:
            record.entries.append(HashEntry(name, child.text.strip(), child.get("action"), child.get("hashdate")))
        elif is_directory and name == "content":
            record.dir_content = _hash_entries(child)
        elif is_directory and name == "structure":
            record.dir_structure = _hash_entries(child)
    return record if record.path else None


def parse_generation_manifest(file_path: Path, number: int) -> Generation:
    """
    Parse one generation manifest (streaming iterparse) into a Generation:
    file and directory records with sizes/renames/hash entries, plus the
    recorded ignore patterns. The <roothash> block inside <processinfo>
    describes the root directory, not a file, and carries no <path> — it never
    becomes a record.
    """
    records: list[MediaRecord] = []
    ignore_patterns: list[str] = []
    with open(file_path, "rb") as fh:
        for _, element in etree.iterparse(fh, events=("end",), tag=("{*}hash", "{*}directoryhash", "{*}ignore")):
            name = _local(element.tag)
            if name == "ignore":
                ignore_patterns.extend(p.text.strip() for p in element.iterfind("{*}pattern") if p.text)
            else:
                record = _parse_media_element(element, is_directory=(name == "directoryhash"))
                if record is not None:
                    records.append(record)
            _free(element)
    return Generation(number=number, file_path=file_path, records=records, ignore_patterns=ignore_patterns)


def parse_chain(chain_path: Path) -> "list[tuple[str, str, str]]":
    """
    Parse ascmhl_chain.xml into (manifest filename, hash format, digest)
    triples in document order. A missing chain file yields no entries (the
    caller decides whether that is an error).
    """
    if not chain_path.exists():
        return []
    entries: list[tuple[str, str, str]] = []
    with open(chain_path, "rb") as fh:
        for _, element in etree.iterparse(fh, events=("end",), tag="{*}hashlist"):
            filename = ""
            hash_format = ""
            digest = ""
            for child in element:
                name = _local(child.tag)
                if name == "path" and child.text:
                    filename = child.text.strip()
                elif name in ASC_FORMATS and child.text:
                    hash_format = name
                    digest = child.text.strip()
            if filename and hash_format:
                entries.append((filename, hash_format, digest))
            _free(element)
    return entries


def _validate_chain(ascmhl_dir: Path) -> None:
    """
    The history integrity gate (spec 5.4): the chain file must exist alongside
    the generation manifests, and every generation it references must be
    present with its recorded hash unchanged.
    """
    chain_path = ascmhl_dir / CHAIN_FILENAME
    if ascmhl_dir.exists() and not chain_path.exists():
        raise NoChainError(chain_path)
    for filename, hash_format, digest in parse_chain(chain_path):
        manifest = ascmhl_dir / filename
        if not manifest.exists():
            raise MissingManifestError(manifest)
        check = asc_check(hash_format, digest)
        if check is None:  # unverifiable chain entry: treat as tampering
            raise ModifiedManifestError(manifest)
        computed = hashing.get_hashes(str(manifest), [check.algorithm.factory])[0]
        if not check.matches(computed):
            raise ModifiedManifestError(manifest)


def load_history(root_path: "str | Path") -> History:
    """
    Load the ASC-MHL history rooted at `root_path` (the folder the manifests
    describe, parent of `ascmhl/`), including nested child histories.

    Raises a HistoryError subclass for the history-integrity failures
    (missing history 30 / modified manifest 31 / missing chain 32 / missing
    manifest 33); malformed XML raises lxml's XMLSyntaxError for the caller to
    map. No media files are read — only the chain gate re-hashes the (small)
    manifest files themselves.
    """
    root = Path(os.path.abspath(os.fspath(root_path)))
    ascmhl_dir = root / ASCMHL_FOLDER

    _validate_chain(ascmhl_dir)

    numbered: list[tuple[int, Path]] = []
    if ascmhl_dir.is_dir():
        for entry in ascmhl_dir.iterdir():
            if entry.name.startswith("._") or entry.suffix != ".mhl":
                continue
            match = GENERATION_RE.match(entry.stem)
            if match:  # non-conforming names are skipped
                numbered.append((int(match.group(1)), entry))
    if not numbered:
        raise NoHistoryError(root)

    generations = [parse_generation_manifest(path, number) for number, path in sorted(numbered)]

    history = History(root=root, generations=generations)
    # Find nested child histories: any subdirectory with its own ascmhl/
    # folder owns everything beneath it, so the walk does not descend further
    # there.
    for dirpath, dirnames, _filenames in os.walk(root):
        if dirpath != str(root) and ASCMHL_FOLDER in dirnames:
            history.children.append(load_history(dirpath))
            dirnames.clear()
    return history


# -----------------------------------------------------------------------------
# Reducing a history to engine records
# -----------------------------------------------------------------------------


def resolve_hashes(
    history: History, rel_path: str
) -> "tuple[MediaRecord, tuple[str, str] | None, list[tuple[str, str]]] | None":
    """
    Resolve a file's current path to its usable hash records within one history.

    The current name is hopped back through recorded previousPath elements
    newest generation first — each generation records at most one rename per
    file, so one hop per generation walks any A→B→C chain (and a back-and-
    forth rename) to the earliest name, as spec 5.3.3 requires ("renamed
    throughout the lifecycle"). The generations are then searched oldest-first
    — tracking the name forward through recorded renames, so entries recorded
    under a later name still count — gathering every usable hash entry: only
    action="original" or "verified" entries count (spec 5.6.4; `failed` and
    unlabeled entries may not vouch).

    Returns (record, original, usable) — the record supplies the recorded size;
    `original` is the first action="original" entry (else the earliest
    "verified"), the single hash a default verify checks (interop with the
    reference tool); `usable` is one (format, digest) per distinct usable
    format, original-preferred, the full set an `all`/selection verify checks.
    Both are empty-ish (original None, usable []) when the path is recorded but
    has no usable entry; None when the path is unknown entirely.
    """
    name = rel_path
    for gen in reversed(history.generations):
        rec = gen.by_path.get(name)
        if rec is not None and rec.previous_path:
            name = rec.previous_path

    seen: MediaRecord | None = None
    original: tuple[MediaRecord, tuple[str, str]] | None = None
    verified: tuple[MediaRecord, tuple[str, str]] | None = None
    # format → (digest, is_original): an original entry supersedes a verified.
    usable: dict[str, tuple[str, bool]] = {}
    for gen in history.generations:
        rec = gen.by_any_path.get(name)
        if rec is None:
            continue
        if rec.previous_path == name:
            name = rec.path  # the rename this generation recorded
        seen = seen or rec
        for entry in rec.entries:
            if entry.fmt not in ASC_FORMATS:
                continue
            if entry.action == "original":
                if original is None:
                    original = (rec, (entry.fmt, entry.digest))
                if not usable.get(entry.fmt, ("", False))[1]:
                    usable[entry.fmt] = (entry.digest, True)
            elif entry.action == "verified":
                if verified is None:
                    verified = (rec, (entry.fmt, entry.digest))
                usable.setdefault(entry.fmt, (entry.digest, False))

    if seen is None:
        return None
    record, best = original or verified or (seen, None)
    usable_list = [(fmt, digest) for fmt, (digest, _is_original) in usable.items()]
    return record, best, usable_list


class IgnoreMatcher:
    """
    History-wide ignore matching for a verify run. The root history's latest
    recorded patterns apply to the whole tree, and each nested history's
    recorded patterns apply within its own subtree, matched against paths
    relative to that history's root — spec 5.6.1.2: a manifest's patterns
    govern operations on the data set *it* manages. Paths are media-directory-
    relative posix; directories carry a trailing slash, as gitignore matching
    expects.
    """

    def __init__(self, history: History) -> None:
        # (subtree prefix, spec); the root spec (prefix "") is always present,
        # child specs only when that history recorded patterns of its own —
        # the mandatory defaults (.DS_Store, ascmhl) already match at every
        # depth through the root spec.
        self._specs: list[tuple[str, pathspec.PathSpec]] = []
        for prefix, sub in history.walk():
            recorded = sub.latest_ignore_patterns()
            if prefix and not recorded:
                continue
            merged = list(dict.fromkeys([*(recorded or DEFAULT_IGNORE_PATTERNS), *DEFAULT_IGNORE_PATTERNS]))
            # GitIgnoreSpecPattern, not the registered 'gitignore' (basic)
            # factory: it implements the gitignore dialect the spec's Appendix
            # C patterns are written in (and matches the reference tool's
            # 'gitwildmatch' behaviour).
            self._specs.append((prefix, pathspec.PathSpec.from_lines(GitIgnoreSpecPattern, merged)))

    def match_file(self, path: str) -> bool:
        for prefix, spec in self._specs:
            if not prefix:
                if spec.match_file(path):
                    return True
            elif path.startswith(prefix + "/") and spec.match_file(path[len(prefix) + 1 :]):
                return True
        return False


def build_ignore_spec(history: History) -> IgnoreMatcher:
    """
    The ignore matcher for a verify run: every history's latest-generation
    recorded patterns scoped to its subtree, with the mandatory defaults
    always appended (a foreign manifest that recorded custom patterns without
    the defaults must not make verify descend into ascmhl/ and flag the
    manifests as new files).
    """
    return IgnoreMatcher(history)


@dataclass
class Recorded:
    """One recorded path reduced for verification, relative to the media directory."""

    path: str  # posix, media-directory-relative, post-rename
    record: MediaRecord
    original: "tuple[str, str] | None"  # (format, digest) checked by a default verify
    usable: "list[tuple[str, str]]"  # every distinct usable format (original-preferred)


def collect_recorded(history: History, ignore: IgnoreMatcher) -> list[Recorded]:
    """
    Every recorded path across the history and its nested children, resolved
    to media-directory-relative posix form with renames applied and ignored paths
    dropped, in sorted-path order. Each history resolves its own paths (a
    nested history owns its subtree), deduplicated on the final name.
    """
    out: dict[str, Recorded] = {}
    for prefix, sub in history.walk():
        # Renames within this history, one previous→new map per generation: a
        # record's final name is found by applying the maps of every *later*
        # generation in order, so multi-step chains (A→B in gen 2, B→C in gen
        # 3) and back-and-forth renames both land on the last recorded name.
        rename_steps = [
            {rec.previous_path: rec.path for rec in gen.records if rec.previous_path is not None}
            for gen in sub.generations
        ]

        names: dict[str, None] = {}  # ordered de-dup, final names only
        for gen_index, gen in enumerate(sub.generations):
            for rec in gen.records:
                name = rec.path
                for step in rename_steps[gen_index + 1 :]:
                    name = step.get(name, name)
                names.setdefault(name, None)

        for name in names:
            top_rel = f"{prefix}/{name}" if prefix else name
            if ignore.match_file(top_rel):
                continue
            resolved = resolve_hashes(sub, name)
            if resolved is None:
                continue
            record, original, usable = resolved
            out.setdefault(top_rel, Recorded(path=top_rel, record=record, original=original, usable=usable))
    return [out[path] for path in sorted(out)]


def history_byte_total(history: History) -> int:
    """
    The recorded byte volume a full verify of `history` will hash-read (its
    verifiable files' original-generation sizes) — the History's progress-bar
    weight. Reads no media bytes itself.
    """
    ignore = build_ignore_spec(history)
    return sum(
        r.record.size or 0
        for r in collect_recorded(history, ignore)
        if r.original is not None and not r.record.is_directory
    )


# -----------------------------------------------------------------------------
# Disk traversal (new-file detection)
# -----------------------------------------------------------------------------


def scan_disk_files(
    root: Path,
    ignore: IgnoreMatcher,
    on_unreadable: "Callable[[str, OSError], None] | None" = None,
) -> "Iterator[tuple[str, str, os.stat_result]]":
    """
    Yield (rel, abs_path, lstat) for every non-ignored file under `root` —
    the media-directory-relative posix path, the real on-disk absolute path,
    and the entry's stat — post-order lexicographic (a stable report order,
    shared with the reference tool). The stat comes from the scandir entry's
    cache (the type check already paid for it), so the scan costs no extra
    syscalls. Ignore patterns see directories with a trailing slash, as
    gitignore matching expects; symlinked directories are not followed.

    `on_unreadable`, if given, is called as on_unreadable(rel_dir, exc) for a
    directory that cannot be scanned ('.' for the root itself) — a silently
    dropped directory would leave any new files inside it undetected, so the
    caller must be able to surface it.
    """

    def walk(dir_path: str, rel_prefix: str) -> "Iterator[tuple[str, str, os.stat_result]]":
        try:
            entries = sorted(os.scandir(dir_path), key=lambda e: e.name)
        except OSError as exc:
            if on_unreadable is not None:
                on_unreadable(rel_prefix.rstrip("/") or ".", exc)
            return
        files: list[tuple[str, str, os.stat_result]] = []
        subdirs: list[tuple[str, str]] = []
        for entry in entries:
            rel = f"{rel_prefix}{entry.name}"
            try:
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                continue
            if ignore.match_file(rel + "/" if is_dir else rel):
                continue
            if is_dir:
                subdirs.append((entry.path, rel))
            elif entry.is_file(follow_symlinks=False):
                files.append((rel, entry.path, entry.stat(follow_symlinks=False)))
        for sub_path, sub_rel in subdirs:
            yield from walk(sub_path, sub_rel + "/")
        yield from files

    yield from walk(str(root), "")


def walk_disk_files(
    root: Path,
    ignore: IgnoreMatcher,
    on_unreadable: "Callable[[str, OSError], None] | None" = None,
) -> "Iterator[str]":
    """The rel paths of scan_disk_files, for callers that need no stat data."""
    yield from (rel for rel, _path, _stat in scan_disk_files(root, ignore, on_unreadable))


class _DiskScan:
    """
    One scandir pass over the managed data set, shared by the hash and
    completeness phases so a verify walks (and stats) the tree exactly once.
    Lookups mirror resolve_on_disk: literal bytes first, then the NFC form —
    and a miss here is not final, callers fall back to resolve_on_disk (which
    also matches case-insensitive-filesystem spellings the walk can't know).
    """

    def __init__(self, root: Path, ignore: IgnoreMatcher) -> None:
        self.files: dict[str, tuple[str, int]] = {}  # rel as on disk → (abs path, size)
        self._nfc: dict[str, tuple[str, int]] = {}
        self.unreadable: list[VerifyEntry] = []

        def on_unreadable(rel_dir: str, exc: OSError) -> None:
            self.unreadable.append(
                VerifyEntry(
                    path=rel_dir,
                    status=Status.ERROR,
                    error=ErrorKind.IO,
                    detail=f"cannot scan directory: {exc.strerror or exc}",
                )
            )

        for rel, abs_path, stat_result in scan_disk_files(root, ignore, on_unreadable):
            info = (abs_path, stat_result.st_size)
            self.files[rel] = info
            self._nfc.setdefault(unicodedata.normalize("NFC", rel), info)

    def resolve(self, rel: str) -> "tuple[str, int] | None":
        """The real path and size recorded for `rel`, or None on a walk miss."""
        hit = self.files.get(rel)
        return hit if hit is not None else self._nfc.get(unicodedata.normalize("NFC", rel))


def _completeness_entries(
    root: Path, recorded: "list[Recorded]", verifiable_paths: set[str], disk: _DiskScan
) -> list[VerifyEntry]:
    """
    The completeness pass over everything the hash phase didn't settle.

    Recorded paths outside the verifiable set must still exist (absent →
    missing); a recorded *file* among them has no usable hash entry (nothing
    labeled original or verified — spec 5.6.4), which is an unsuccessful
    verification, never a "new file" — spec 5.6.3 defines unknown files as
    those *not* recorded in the history. The disk scan then reports everything
    the history has no record for as new; a directory it could not scan is
    surfaced as an error, because new files inside it would otherwise go
    undetected without a trace.
    """
    entries: list[VerifyEntry] = []
    recorded_paths = {r.path for r in recorded}
    dir_index: dict[str, dict[str, str]] = {}
    for r in recorded:
        if r.path in verifiable_paths:
            continue
        # Directories never appear in the file scan, and a differently-cased
        # recorded spelling can miss it — resolve_on_disk settles both.
        if disk.resolve(r.path) is None and resolve_on_disk(str(root), r.path.replace("/", os.sep), dir_index) is None:
            entries.append(VerifyEntry(path=r.path, status=Status.MISSING))
        elif not r.record.is_directory:
            entries.append(
                VerifyEntry(
                    path=r.path,
                    status=Status.ERROR,
                    error=ErrorKind.UNUSABLE_HASH,
                    detail="no hash entry labeled original or verified",
                )
            )

    entries.extend(disk.unreadable)
    entries.extend(VerifyEntry(path=rel, status=Status.NEW) for rel in disk.files if rel not in recorded_paths)
    return entries


# -----------------------------------------------------------------------------
# verify_ascmhl — the dialect entry point
# -----------------------------------------------------------------------------


def ascmhl_exit_code(entries: "list[VerifyEntry]") -> ExitCode:
    """
    The ASC-MHL verification exit code for a set of per-file entries — a fixed
    precedence, pinned for tool interop: hash mismatch / per-file failure 11
    beats new-files 21, which beats nothing-verifiable-found 20 (no record
    reached the hash comparison), which beats missing-files 10.
    """
    if any(e.status in (Status.MISMATCH, Status.ERROR) for e in entries):
        return ExitCode.HASH_MISMATCH
    if any(e.status == Status.NEW for e in entries):
        return ExitCode.NEW_FILES
    if not any(e.hashes for e in entries):
        return ExitCode.SINGLE_FILE_NOT_FOUND
    if any(e.status == Status.MISSING for e in entries):
        return ExitCode.MISSING
    return ExitCode.OK


def verify_ascmhl(
    root_path: "str | Path",
    *,
    size_only: bool = False,
    selection: "str | list[str] | None" = None,
    on_progress: "Callable[[int], None] | None" = None,
    history: "History | None" = None,
) -> VerifyReport:
    """
    Verify the managed data set rooted at `root_path` (the media directory,
    parent of the `ascmhl/` folder) and return a
    structured VerifyReport. Never prints and never exits.

    Loading the history is the integrity gate: a broken chain or modified
    manifest surfaces as its pinned 3x code (with the reason as a notice) and
    unparsable XML as MALFORMED_XML, before any media is read. `selection`
    picks which recorded hash(es) to check: None checks a single hash per file
    (the original entry, matching the reference tool — spec 5.6.4's "one of the
    algorithms recorded"), VERIFY_ALL checks every recorded format, and a list
    of format names checks exactly those (an unrecorded one is a hash-not-stored
    error). `size_only` compares recorded sizes without hashing (ASC-MHL's size
    attribute is optional, so a record without one is existence-checked, never
    failed); it ignores `selection`.
    `on_progress` receives per-chunk byte counts from the engine's adaptive
    hasher and may fire from worker threads.

    Report codes follow a fixed precedence (pinned for tool interop): hash
    mismatch / per-file failure 11 beats new-files 21, which beats
    nothing-verifiable-found 20, which beats missing-files 10; size-only
    failures report 13.

    `history` lets a caller that already loaded the History (mhl_suite.
    discovery, for progress weights) hand it over instead of paying the load —
    and the chain gate — twice.
    """
    root = Path(os.path.abspath(os.fspath(root_path)))
    try:
        if history is None:
            history = load_history(root)
    except HistoryError as err:
        return VerifyReport(code=err.code, notices=[str(err)], size_only_mode=size_only)
    except (etree.XMLSyntaxError, OSError):
        return VerifyReport(code=ExitCode.MALFORMED_XML, malformed=True, size_only_mode=size_only)

    ignore = build_ignore_spec(history)
    recorded = collect_recorded(history, ignore)

    # Records the engine can verify: files with at least one usable hash entry
    # (a usable set is non-empty exactly when an original-preferred hash exists,
    # so this set is the same regardless of selection). With no selection only
    # the original hash is checked (reference-tool interop); `all` or a format
    # list feeds every usable format through and lets the engine pick.
    verifiable = [r for r in recorded if r.usable and not r.record.is_directory]
    file_records: list[FileRecord] = []
    for r in verifiable:
        pairs = r.usable if selection is not None else ([r.original] if r.original is not None else [])
        checks = [c for fmt, digest in pairs if (c := asc_check(fmt, digest)) is not None]
        file_records.append(FileRecord(path=r.path, checks=checks, recorded_size=r.record.size))

    if size_only:
        # No disk scan: size-only stats only the recorded files, which can be
        # far fewer than the tree holds. Directories and unverifiable records
        # are skipped (nothing recorded to compare); missing/mismatch already
        # classified.
        entries = verify_core.verify_records(
            root, file_records, selection=selection, size_only=True, missing_size_is_error=False
        )
        n_fail = sum(1 for e in entries if e.status in (Status.MISMATCH, Status.ERROR))
        n_missing = sum(1 for e in entries if e.status == Status.MISSING)
        code = ExitCode.SIZE_MISMATCH if n_fail else (ExitCode.MISSING if n_missing else ExitCode.OK)
        return VerifyReport(entries=entries, code=code, size_only_mode=True)

    # One disk scan feeds both phases: the hash phase resolves paths and sizes
    # from it instead of stat-ing each record, and the completeness pass reuses
    # it instead of walking again.
    disk = _DiskScan(root, ignore)
    entries = verify_core.verify_records(
        root,
        file_records,
        selection=selection,
        missing_size_is_error=False,
        on_progress=on_progress,
        resolved=disk.resolve,
    )

    # --- ASC-only policy: completeness of the rest of the recorded set -------
    verifiable_paths = {r.path for r in verifiable}
    entries.extend(_completeness_entries(root, recorded, verifiable_paths, disk))

    return VerifyReport(entries=entries, code=ascmhl_exit_code(entries))
