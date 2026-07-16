"""
ASC-MHL operations beyond generation: diff, rename, flatten.

Diff (spec 5.6.3) compares a history's recorded set against the file system
without hashing anything: files on disk but never recorded are unknown, files
recorded but absent are missing. Rename (spec 5.6.6) renames a file or
directory on disk and appends one generation — to the *closest* enclosing
history only (spec 5.3.2; nested updates never propagate upward) — recording
the former name in previousPath. Flatten (spec 5.6.7) consolidates a history,
nested histories included, into one standalone "packing list" manifest plus
an ascmhl_collection.xml entry (spec 5.5), copying the earliest usable hash
per (file, format) with its action preserved and skipping `failed` entries.

All manifest/collection output goes through the writers in
mhl_suite.ascmhl_generate; loading and record resolution reuse
mhl_suite.ascmhl_history. Never prints, never exits: argument problems raise
AscmhlGenerateError, history-integrity problems raise HistoryError (diff maps
them into its report, matching verify_ascmhl).
"""

import os
import unicodedata
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from lxml import etree

from mhl_suite import hashing
from mhl_suite._exit_codes import ExitCode
from mhl_suite.algorithms import ASC_FORMATS, asc_check
from mhl_suite.ascmhl_generate import (
    AscmhlGenerateError,
    DirEntryOut,
    FileEntryOut,
    HashEntryOut,
    ManifestOut,
    append_directory_entry,
    latest_dir_entries,
    manifest_filename,
    write_manifest,
)
from mhl_suite.ascmhl_history import (
    ASCMHL_FOLDER,
    CHAIN_FILENAME,
    DEFAULT_IGNORE_PATTERNS,
    HashEntry,
    History,
    HistoryError,
    MediaRecord,
    NoHistoryError,
    build_ignore_spec,
    collect_recorded,
    load_history,
    resolve_hashes,
    walk_disk_files,
)
from mhl_suite.osutils import resolve_on_disk
from mhl_suite.sorting import sort_key
from mhl_suite.verify import HashComparison, Status, VerifyEntry, VerifyReport

if TYPE_CHECKING:
    from collections.abc import Iterator

COLLECTION_FILENAME = "ascmhl_collection.xml"


def _iso(moment: datetime) -> str:
    return moment.astimezone().isoformat(timespec="seconds")


# -----------------------------------------------------------------------------
# Diff
# -----------------------------------------------------------------------------


def diff_ascmhl(root_path: "str | Path") -> VerifyReport:
    """
    Report unknown files (on disk, neither recorded nor ignored) and missing
    files (recorded, absent from disk) for the media directory rooted at `root_path`.
    No hashes are computed. Report codes: unknown-files 21 beats
    missing 10; history-integrity failures surface as their pinned 3x codes,
    exactly like verify_ascmhl.
    """
    root = Path(os.path.abspath(os.fspath(root_path)))
    try:
        history = load_history(root)
    except HistoryError as err:
        return VerifyReport(code=err.code, notices=[str(err)])
    except (etree.XMLSyntaxError, OSError):
        return VerifyReport(code=ExitCode.MALFORMED_XML, malformed=True)

    ignore = build_ignore_spec(history)
    recorded = collect_recorded(history, ignore)
    recorded_paths = {r.path for r in recorded}

    dir_index: dict[str, dict[str, str]] = {}
    entries: list[VerifyEntry] = [
        VerifyEntry(path=r.path, status=Status.MISSING)
        for r in recorded
        if resolve_on_disk(str(root), r.path.replace("/", os.sep), dir_index) is None
    ]
    entries.extend(
        VerifyEntry(path=rel, status=Status.NEW) for rel in walk_disk_files(root, ignore) if rel not in recorded_paths
    )
    entries.sort(key=lambda e: sort_key(e.path))

    if any(e.status == Status.NEW for e in entries):
        code = ExitCode.NEW_FILES
    elif entries:
        code = ExitCode.MISSING
    else:
        code = ExitCode.OK
    return VerifyReport(entries=entries, code=code)


# -----------------------------------------------------------------------------
# Rename
# -----------------------------------------------------------------------------


def _enclosing_history_root(path: Path) -> "Path | None":
    """The closest ancestor directory of `path` that carries an ascmhl/ folder."""
    for candidate in path.parents:
        if (candidate / ASCMHL_FOLDER).is_dir():
            return candidate
    return None


def _rel_posix(path: Path, root: Path) -> str:
    return unicodedata.normalize("NFC", path.relative_to(root).as_posix())


def _validate_rename(old: Path, new: Path) -> Path:
    """Validate a rename request and return the owning history root."""
    if not os.path.lexists(old):
        raise AscmhlGenerateError(f"Error: '{old}' not found")
    if old == new:
        raise AscmhlGenerateError("Error: old and new path are identical")
    if os.path.lexists(new):
        raise AscmhlGenerateError(f"Error: '{new}' already exists")
    if not new.parent.is_dir():
        raise AscmhlGenerateError(f"Error: '{new.parent}' is not a directory")
    history_root = _enclosing_history_root(old)
    if history_root is None:
        raise NoHistoryError(old)
    if _enclosing_history_root(new) != history_root:
        raise AscmhlGenerateError("Error: cannot rename across ASC MHL history boundaries")
    for rel in (old.relative_to(history_root), new.relative_to(history_root)):
        if ASCMHL_FOLDER in rel.parts:
            raise AscmhlGenerateError("Error: cannot rename inside an ascmhl folder")
    return history_root


def _rehashed_file_entry(
    history: History,
    root: Path,
    old_rel: str,
    new_rel: str,
    entries: "list[VerifyEntry]",
) -> "FileEntryOut | None":
    """
    Rehash one renamed file against its recorded hash (looked up under its
    former name) and build the record carrying previousPath — the spec 6.5
    rename shape: the digest re-verified, labeled verified or failed. An
    unrecorded file yields None (there is no record to carry forward).
    """
    resolved = resolve_hashes(history, old_rel)
    if resolved is None:
        return None
    record, original, _usable = resolved
    if original is None:
        return None
    fmt, expected = original
    computed = hashing.get_hashes(os.fspath(root / new_rel), [ASC_FORMATS[fmt].factory])[0]
    hashdate = _iso(datetime.now(UTC))
    check = asc_check(fmt, expected)
    matched = check is not None and check.matches(computed)
    entries.append(
        VerifyEntry(
            path=new_rel,
            status=Status.OK if matched else Status.MISMATCH,
            hashes=[HashComparison(tag=fmt, expected=expected, computed=computed, ok=matched)],
            recorded_size=record.size,
        )
    )
    stat_result = (root / new_rel).stat()
    birthtime = getattr(stat_result, "st_birthtime", None)
    return FileEntryOut(
        path=new_rel,
        entries=[HashEntryOut(fmt, computed, "verified" if matched else "failed", hashdate)],
        size=stat_result.st_size,
        creation_date=None if birthtime is None else _iso(datetime.fromtimestamp(birthtime, UTC)),
        last_modification_date=_iso(datetime.fromtimestamp(stat_result.st_mtime, UTC)),
        previous_path=old_rel,
    )


def _copied_dir_entry(history: History, old_rel: str, new_rel: str) -> "DirEntryOut | None":
    """
    The directoryhash record for a renamed directory: content/structure
    copied from the latest recorded values, labeled verified — a pure rename
    cannot change either, since a directory's own name is not part of its own
    hashes (spec 6.5.2, whose example does exactly this). None when the
    history never recorded hashes for the directory.
    """
    content, structure = latest_dir_entries(history, old_rel)
    if not content or not structure:
        return None
    return DirEntryOut(
        path=new_rel,
        content=[HashEntryOut(fmt, digest, "verified") for fmt, digest in content.items()],
        structure=[HashEntryOut(fmt, digest, "verified") for fmt, digest in structure.items()],
        previous_path=old_rel,
    )


def rename_ascmhl(old_path: "str | Path", new_path: "str | Path") -> "tuple[Path, VerifyReport]":
    """
    Rename `old_path` to `new_path` on disk and record the rename in a new
    generation of the closest enclosing ASC MHL history (spec 5.6.6/5.3.2).
    Returns (manifest written, report of the re-verification performed).

    A renamed file is rehashed in its recorded format and recorded with
    previousPath, labeled verified/failed. For a renamed directory, its
    directoryhash values are copied (see _copied_dir_entry) and every
    recorded file beneath it is rehashed and recorded under its new path
    with previousPath, so rename resolution (spec 5.3.3) keeps working for
    the directory's contents. Only files the history itself records are
    touched — a nested history inside the renamed directory needs no update,
    since its records are relative to its own root.
    """
    old = Path(os.path.abspath(os.fspath(old_path)))
    new = Path(os.path.abspath(os.fspath(new_path)))
    history_root = _validate_rename(old, new)
    history = load_history(history_root)  # chain gate before any change

    old_rel = _rel_posix(old, history_root)
    new_rel = _rel_posix(new, history_root)
    is_directory = old.is_dir()

    # The history's own records affected by the rename, under their old paths.
    level = History(root=history.root, generations=history.generations)
    ignore = build_ignore_spec(level)
    if is_directory:
        moved = [r for r in collect_recorded(level, ignore) if r.path == old_rel or r.path.startswith(old_rel + "/")]
    else:
        moved = [r for r in collect_recorded(level, ignore) if r.path == old_rel]
    if not moved:
        raise AscmhlGenerateError(f"Error: '{old_rel}' is not recorded in the ASC MHL history at {history_root}")

    os.rename(old, new)

    op_start = datetime.now(UTC)
    entries: list[VerifyEntry] = []
    files: list[FileEntryOut] = []
    directories: list[DirEntryOut] = []
    for r in moved:
        moved_new = new_rel + r.path[len(old_rel) :]
        if r.record.is_directory:
            copied = _copied_dir_entry(history, r.path, moved_new)
            if copied is not None:
                directories.append(copied)
        else:
            entry = _rehashed_file_entry(history, history_root, r.path, moved_new, entries)
            if entry is not None:
                files.append(entry)
    if is_directory and all(d.path != new_rel for d in directories):
        copied = _copied_dir_entry(history, old_rel, new_rel)
        if copied is not None:
            directories.append(copied)

    manifest = ManifestOut(
        creation_date=_iso(op_start),
        process="in-place",
        ignore_patterns=list(dict.fromkeys([*history.latest_ignore_patterns(), *DEFAULT_IGNORE_PATTERNS])),
        files=files,
        directories=directories,
    )
    manifest_path = _append_generation(history, manifest, op_start)
    code = ExitCode.HASH_MISMATCH if any(e.status == Status.MISMATCH for e in entries) else ExitCode.OK
    return manifest_path, VerifyReport(entries=entries, code=code)


def _append_generation(history: History, manifest: ManifestOut, op_start: datetime) -> Path:
    """Write one more generation manifest for `history` and extend its chain."""
    ascmhl_dir = history.root / ASCMHL_FOLDER
    number = history.generations[-1].number + 1 if history.generations else 1
    name = manifest_filename(number, history.root.name, op_start)
    manifest_path = ascmhl_dir / name
    write_manifest(manifest_path, manifest)
    c4_digest = hashing.get_hashes(os.fspath(manifest_path), [ASC_FORMATS["c4"].factory])[0]
    append_directory_entry(ascmhl_dir / CHAIN_FILENAME, name, "c4", c4_digest)
    return manifest_path


# -----------------------------------------------------------------------------
# Flatten
# -----------------------------------------------------------------------------


def _final_names(sub: History) -> "Iterator[str]":
    """Every recorded file's final (post-rename) name within one history, ordered."""
    rename_steps = [
        {rec.previous_path: rec.path for rec in gen.records if rec.previous_path is not None} for gen in sub.generations
    ]
    names: dict[str, None] = {}
    for gen_index, gen in enumerate(sub.generations):
        for rec in gen.records:
            if rec.is_directory:
                continue  # directory hashes are not consolidated (spec 5.6.7)
            name = rec.path
            for step in rename_steps[gen_index + 1 :]:
                name = step.get(name, name)
            names.setdefault(name, None)
    yield from names


def _flatten_file(sub: History, final_name: str) -> "tuple[dict[str, HashEntry], MediaRecord, str | None] | None":
    """
    Walk one file's records oldest generation first — tracking its name
    forward through recorded renames — and gather what the flattened record
    keeps (spec 5.6.7): the earliest usable entry per format with its action
    preserved (`failed` and unlabeled entries never transfer), the latest
    record (whose path attributes win), and the most recent previousPath.
    """
    # Hop back to the earliest recorded name (one rename per generation).
    name = final_name
    for gen in reversed(sub.generations):
        rec = gen.by_path.get(name)
        if rec is not None and rec.previous_path:
            name = rec.previous_path

    earliest: dict[str, HashEntry] = {}
    latest: MediaRecord | None = None
    previous_path: str | None = None
    for gen in sub.generations:
        rec = gen.by_any_path.get(name)
        if rec is None or rec.is_directory:
            continue
        if rec.previous_path == name:
            name = rec.path  # the rename this generation recorded
        latest = rec
        if rec.previous_path is not None:
            previous_path = rec.previous_path
        for entry in rec.entries:
            if entry.fmt in ASC_FORMATS and entry.action in ("original", "verified"):
                earliest.setdefault(entry.fmt, entry)
    if latest is None or not earliest:
        return None
    return earliest, latest, previous_path


def _packinglist_path(destination: Path, op_start: datetime) -> Path:
    """A non-colliding packinglist__<date>_<time>.mhl path."""
    stem = f"packinglist__{op_start.strftime('%Y-%m-%d_%H%M%S')}"
    path = destination / f"{stem}.mhl"
    suffix = 0
    while path.exists():
        suffix += 1
        path = destination / f"{stem}_{suffix}.mhl"
    return path


def flatten_ascmhl(root_path: "str | Path", destination: "str | Path") -> "tuple[Path, Path]":
    """
    Consolidate the history rooted at `root_path` (nested histories included)
    into one standalone packing-list manifest in `destination`, and record it
    in `destination`'s ascmhl_collection.xml (spec 5.6.7 + 5.5). Returns
    (packing list path, collection path).

    Per file: the earliest entry per hash format, actions preserved, `failed`
    entries skipped; the most recent previousPath kept; path attributes from
    the latest record. Directory hashes are not consolidated. The source
    history is not modified. process=flatten marks the output.
    """
    root = Path(os.path.abspath(os.fspath(root_path)))
    history = load_history(root)  # chain gate; HistoryError propagates
    ignore = build_ignore_spec(history)

    files: list[FileEntryOut] = []
    for prefix, sub in history.walk():
        for final_name in _final_names(sub):
            scope_path = f"{prefix}/{final_name}" if prefix else final_name
            if ignore.match_file(scope_path):
                continue
            flattened = _flatten_file(sub, final_name)
            if flattened is None:
                continue
            earliest, latest, previous_path = flattened
            scope_previous = None
            if previous_path is not None:
                scope_previous = f"{prefix}/{previous_path}" if prefix else previous_path
            files.append(
                FileEntryOut(
                    path=scope_path,
                    entries=[
                        HashEntryOut(entry.fmt, entry.digest, entry.action, entry.hashdate)
                        for entry in earliest.values()
                    ],
                    size=latest.size,
                    creation_date=latest.creation_date,
                    last_modification_date=latest.last_modification_date,
                    previous_path=scope_previous,
                )
            )

    op_start = datetime.now(UTC)
    destination_dir = Path(os.path.abspath(os.fspath(destination)))
    destination_dir.mkdir(parents=True, exist_ok=True)
    packinglist = _packinglist_path(destination_dir, op_start)
    manifest = ManifestOut(
        creation_date=_iso(op_start),
        process="flatten",
        ignore_patterns=list(dict.fromkeys([*history.latest_ignore_patterns(), *DEFAULT_IGNORE_PATTERNS])),
        files=sorted(files, key=lambda f: f.path),
    )
    write_manifest(packinglist, manifest)

    collection = destination_dir / COLLECTION_FILENAME
    c4_digest = hashing.get_hashes(os.fspath(packinglist), [ASC_FORMATS["c4"].factory])[0]
    append_directory_entry(collection, packinglist.name, "c4", c4_digest)
    return packinglist, collection
