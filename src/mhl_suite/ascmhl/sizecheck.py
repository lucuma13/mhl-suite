# -----------------------------------------------------------------------------
# ASC-MHL size-only verification.
#
# ascmhl backend does not check file sizes — its `verify` always re-hashes
# the whole package. mhlver's classic-MHL path delegates -S to `simple-mhl verify
# -S`, but there is no equivalent for ASC-MHL, so this module provides one: a
# self-contained parser that checks each recorded file's <size> against the file
# on disk, reading no file bytes (one stat() per entry). It is the ASC-MHL
# counterpart to simple_mhl's size-only branch and deliberately mirrors its
# policy: a recorded file with no stored size is a failure ("no size recorded"),
# because the operator explicitly asked to check sizes and there is nothing to
# check.
# -----------------------------------------------------------------------------

import os
from dataclasses import dataclass
from pathlib import Path

from lxml import etree

from mhl_suite._internal.unicodepaths import resolve_on_disk


@dataclass
class SizeCheckResult:
    """Outcome of a single size-only check for one recorded ASC-MHL entry.

    `status` is one of "ok" | "missing" | "mismatch". For "ok", `detail` holds
    the human-readable size ("size: 4170"); for a mismatch it carries the reason
    in the same shape mhlver's report formatter expects ("size mismatch: calc
    size: … | stored size: …", "no size recorded", "blocked traversal attempt").
    """

    path: str
    status: str
    detail: str = ""


ASCMHL_CHAINFILE_NAME = "ascmhl_chain.xml"


def _generation_files_in_chain_order(ascmhl_dir: Path) -> list[Path]:
    """Return the generation (hash list) file paths in the chain's recorded order.

    Reads ``ascmhl_chain.xml`` and follows its ``<hashlist sequencenr="N"><path>``
    entries — the authoritative generation list and order, correct even for hash
    list files whose name lacks a numeric prefix (custom basenames). The chain's
    recorded hashes are ignored here; manifest integrity is the caller's gate. Each
    ``<path>`` is a bare filename directly inside ``ascmhl_dir``; entries with
    separators or a leading dot are ignored defensively.

    Lets etree parse errors / a missing chain propagate as OSError/XMLSyntaxError;
    the caller turns them into a manifest error.
    """
    chain_tree = etree.parse(str(ascmhl_dir / ASCMHL_CHAINFILE_NAME))
    generations: list[tuple[int, Path]] = []
    for generation in chain_tree.iterfind(".//{*}hashlist"):
        path_element = generation.find("{*}path")
        if path_element is None or not path_element.text:
            continue
        ascmhl_filename = path_element.text.strip()
        if not ascmhl_filename:
            continue
        if ascmhl_filename.startswith(".") or "/" in ascmhl_filename or os.sep in ascmhl_filename:
            continue
        try:
            generation_number = int(generation.get("sequencenr", ""))
        except ValueError:
            continue
        generations.append((generation_number, ascmhl_dir / ascmhl_filename))
    generations.sort(key=lambda pair: pair[0])
    return [path for _generation_number, path in generations]


def _collect_expected_sizes(ascmhl_dir: Path) -> "dict[str, str | None]":
    """Map each recorded relative path to its expected size string (earliest wins).

    Reads the generations in chain order (oldest first) and records the ``size``
    attribute of each ``<hash>``'s ``<path>`` on the file's FIRST appearance only —
    the earliest (original) record. ``<directoryhash>`` entries are skipped. A
    ``<previousPath>`` (written when ascmhl records a rename, e.g. ``create -dr``)
    drops the old path and carries its earliest size onto the new path, so a
    renamed file is not reported missing under its former name — matching ascmhl's
    own verify. The value is the raw size string — or ``None`` when the earliest
    record stored no size — left for the caller to validate, so a missing size
    becomes a reported failure rather than a silent skip.

    Lets etree parse errors propagate: a manifest we cannot read must not pass as
    "zero files to check", so the caller turns the exception into a manifest error.
    """
    file_size_for_path: dict[str, str | None] = {}
    for hash_list_file in _generation_files_in_chain_order(ascmhl_dir):
        hash_list_tree = etree.parse(str(hash_list_file))
        # iterfind(".//{*}hash") matches <hash> only, never <directoryhash>, so
        # directory records are excluded without an explicit filter.
        for media_hash in hash_list_tree.iterfind(".//{*}hash"):
            path_element = media_hash.find("{*}path")
            if path_element is None or path_element.text is None:
                continue
            relative_path = path_element.text.strip()
            if not relative_path:
                continue
            previous_path_element = media_hash.find("{*}previousPath")
            previous_path = (
                previous_path_element.text.strip()
                if previous_path_element is not None and previous_path_element.text
                else None
            )
            if previous_path and previous_path in file_size_for_path:
                # Rename: carry the earliest size from the old path onto the new one.
                file_size_for_path[relative_path] = file_size_for_path.pop(previous_path)
            elif relative_path not in file_size_for_path:
                # First appearance sets the baseline; later generations never override.
                file_size_for_path[relative_path] = path_element.get("size")
    return file_size_for_path


def verify_ascmhl_sizes(latest_manifest: Path) -> list[SizeCheckResult]:
    """Size-only verify an ASC-MHL manifest, returning one result per recorded file.

    ``latest_manifest`` is the latest file chosen by ``mhlver._select_mhl_files``.
    The root path is its grandparent (the parent of the ``ascmhl/`` folder); all
    recorded paths are resolved relative to it.

    Each entry is checked by comparing its stored ``<path size>`` against the file
    on disk — no bytes are read. Results, in first-seen path order:
      * ok        — the file exists and its size matches
      * missing   — the file is not on disk
      * mismatch  — size differs, no size is stored, or the path escapes the root

    Path matching reuses ``resolve_on_disk`` so NFC/NFD filename forms reconcile
    exactly as simple-mhl's verify does. Raises ``etree.XMLSyntaxError``/``OSError``
    if a manifest cannot be parsed.
    """
    ascmhl_dir = latest_manifest.parent
    root_path = os.path.abspath(str(latest_manifest.parent.parent))
    # Trailing separator avoids prefix-collision: '/foo' matches '/foo/bar' but
    # not '/foobar' — the same jail check simple_mhl.verify applies.
    root_path_with_sep = root_path + os.sep

    file_size_for_path = _collect_expected_sizes(ascmhl_dir)

    results: list[SizeCheckResult] = []
    # Per-call cache of directory listings used by resolve_on_disk; a fresh view
    # per verify run (never module-global) so a stale listing can't leak across runs.
    dir_index: dict[str, dict[str, str]] = {}

    for relative_path, recorded_size in file_size_for_path.items():
        # Manifests use forward slashes; convert to the platform separator.
        native_relative_path = relative_path.replace("/", os.sep) if os.sep != "/" else relative_path

        # Path traversal guard: collapse '..'/'.' then require the result inside
        # root, blocking a malicious manifest pointing at "../../etc/passwd".
        jailed = os.path.normpath(os.path.join(root_path, native_relative_path))
        if jailed != root_path and not jailed.startswith(root_path_with_sep):
            results.append(SizeCheckResult(relative_path, "mismatch", "blocked traversal attempt"))
            continue

        # No recorded size → failure (operator asked to check sizes; there's none).
        # isdecimal() rejects superscripts/other Unicode "digits" int() would misconvert.
        if recorded_size is None or not recorded_size.strip().isdecimal():
            results.append(SizeCheckResult(relative_path, "mismatch", "no size recorded"))
            continue

        resolved_path = resolve_on_disk(root_path, os.path.relpath(jailed, root_path), dir_index)
        if resolved_path is None:
            results.append(SizeCheckResult(relative_path, "missing"))
            continue
        try:
            actual_size = os.path.getsize(resolved_path)
        except OSError:
            # Vanished between resolution and getsize() — report missing.
            results.append(SizeCheckResult(relative_path, "missing"))
            continue

        expected_size = int(recorded_size)
        if actual_size != expected_size:
            results.append(
                SizeCheckResult(
                    relative_path, "mismatch", f"size mismatch: calc size: {actual_size} | stored size: {expected_size}"
                )
            )
        else:
            results.append(SizeCheckResult(relative_path, "ok", f"size: {actual_size}"))

    return results
