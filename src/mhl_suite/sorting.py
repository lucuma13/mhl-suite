"""
The one ordering the suite imposes on manifest and report entries.

The order we pick is:

    Alpha/                  at every level, subdirectories first, each one
    Alpha/sub/              immediately followed by its whole subtree, then
    Alpha/sub/deep.mov      that level's own files
    Alpha/a1.mov
    Alpha/a2.mov
    Bravo/
    Bravo/b1.mov
    notes.txt

It falls out of a key on the path alone, so callers keep walking the tree
however suits them (classic streams a flat file list, ASC MHL builds a tree for
its directory hashes) and simply sort the materialised list before hashing —
which keeps hashing order, <hashdate> order and manifest order identical.
"""

import re
import unicodedata
from functools import lru_cache
from typing import Any

import pyuca

_DIGIT_RUN = re.compile(r"(\d+)")


@lru_cache(maxsize=1)
def _collator() -> pyuca.Collator:
    """
    Built lazily: constructing it parses the DUCET table and no `--version`,
    `--help` or argparse error should pay for it.
    """
    return pyuca.Collator()


def _collation_key(text: str) -> tuple[int, ...]:
    """
    Unicode Collation Algorithm key.

    Case is a tertiary weight in the UCA, so ordering is case-insensitive — with
    case only separating names that are otherwise identical.
    """
    return tuple(_collator().sort_key(text))


def _name_key(name: str) -> tuple[tuple[int, Any], ...]:
    """
    One path component as alternating text and number chunks, so digit runs
    compare numerically ('take2' before 'take10', not the codepoint order that
    puts 'take10' first).

    Chunks are tagged 0/1 by kind, which keeps a collation key from ever being
    compared against an int, and NFC-normalised so a name decomposed by macOS
    sorts identically to the same name composed elsewhere.

    Which chunks are numbers is decided by the split itself — splitting on a
    capture group alternates text and captured digits, so the odd indices are
    the digit runs. Re-testing a chunk with str.isdigit() instead would not
    agree with the regex: it is true of characters \\d never captures ('²', for
    one), and int() then rejects them.
    """
    chunks = _DIGIT_RUN.split(unicodedata.normalize("NFC", name))
    return tuple((1, int(chunk)) if index % 2 else (0, _collation_key(chunk)) for index, chunk in enumerate(chunks))


def sort_key(path: str, is_dir: bool = False) -> tuple[Any, ...]:
    """
    Sort key for a POSIX relative path, ordering directories ahead of files at
    every level and each directory immediately ahead of its own subtree.

    `is_dir` marks entries that *are* a directory (ASC MHL <directoryhash>
    records). A file's own name ranks after its siblings' directory names; a
    directory's key is a strict prefix of every key beneath it, which is what
    keeps a subtree contiguous under its directory.

    The raw path is appended as a final tiebreaker, because the key ahead of it
    is not injective: numeric chunks make 'take007' and 'take7' equal, and NFC
    makes a composed and a decomposed spelling of the same accented name equal
    (both pairs can coexist in one directory on a case- and
    normalization-preserving volume). Without it their order would fall back to
    readdir order and stop being reproducible.
    """
    components = [c for c in path.split("/") if c]
    last = len(components) - 1
    return (
        tuple((0 if is_dir or i < last else 1, _name_key(c)) for i, c in enumerate(components)),
        path,
    )
