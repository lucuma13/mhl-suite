# -----------------------------------------------------------------------------
# Filesystem path resolution across Unicode normalization forms.
#
# Shared internal helpers used by both simple_mhl (classic MHL verify/seal) and
# mhlver (the orchestrator). Kept in one place so the two tools cannot drift in
# how they reconcile NFC/NFD filenames. Not part of the public API — the public
# surface of mhl-suite is the simple-mhl and mhlver CLIs.
#
# Background: filesystems disagree on Unicode normalization. HFS+ forces a
# decomposed (NFD-ish) form; APFS/NTFS-upcase are normalization-*insensitive*
# but byte-preserving; exFAT/ext4 (default)/NTFS are normalization-*sensitive*,
# so "café"-NFC and "café"-NFD are distinct entries. A path that visually
# matches may therefore fail a byte-exact lookup. These helpers match on NFC
# while only ever opening names that actually exist on disk.
# -----------------------------------------------------------------------------

import os
import unicodedata


def resolve_on_disk(base: str, rel_path: str, dir_index: dict[str, dict[str, str]]) -> str | None:
    """Resolve a manifest-relative path to its real on-disk path, matching
    across Unicode normalization forms.

    Walks ``rel_path`` one component at a time from ``base``. Each component is
    tried as literal bytes first — the common case, and the only correct choice
    when several normalization forms coexist on a normalization-*sensitive*
    filesystem (exFAT/ext4/NTFS), where ``café``-NFC and ``café``-NFD are
    distinct entries. On a literal miss we scan the directory once and match the
    component's NFC form against the NFC form of each real entry, so a name
    stored in a different form (e.g. an NFD name from an HFS+ round-trip, looked
    up from an NFC manifest) still resolves. Returns the real absolute path, or
    ``None`` if any component is genuinely absent.

    ``dir_index`` caches each scanned directory as ``{ NFC(name): real_name }``
    so a manifest with many files in one folder scans that folder only once. It
    is passed in (not module-global) so each ``verify()`` call sees a fresh view
    of the filesystem rather than a stale listing from a previous run.
    """
    current = base
    for comp in rel_path.split(os.sep):
        if not comp or comp == os.curdir:
            continue
        literal = os.path.join(current, comp)
        if os.path.lexists(literal):
            current = literal  # fast path: exact bytes exist on disk
            continue
        index = dir_index.get(current)
        if index is None:
            try:
                index = {unicodedata.normalize("NFC", entry.name): entry.name for entry in os.scandir(current)}
            except OSError:
                return None  # current dir unreadable/absent → file is missing
            dir_index[current] = index
        real = index.get(unicodedata.normalize("NFC", comp))
        if real is None:
            return None  # no entry matches in any normalization form
        current = os.path.join(current, real)
    return current


def normalization_variant_on_disk(path: str) -> str | None:
    """If ``path`` does not exist as typed but a Unicode-normalization variant
    of it does, return that real on-disk path; otherwise None.

    Used purely to add a "did you mean" hint to not-found errors for paths a
    user types on the command line (e.g. the .mhl for verify, the root dir for
    seal, or the target for mhlver). It never changes what a command operates
    on — unlike a manifest's internal <file> entries (a portable artifact
    authored elsewhere, which we actively reconcile), the typed path is a local,
    interactive reference, so we leave matching to the OS and only *suggest* the
    real spelling. This keeps behaviour aligned with cat/cp/ls instead of
    silently resolving a path they cannot open.
    """
    abspath = os.path.abspath(path)
    drive, tail = os.path.splitdrive(abspath)
    rel = tail.lstrip(os.sep)
    if not rel:
        return None
    resolved = resolve_on_disk(drive + os.sep, rel, {})
    return resolved if resolved is not None and resolved != abspath else None
