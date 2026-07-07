"""
Importable test helpers shared across the test suite.

Plain functions only — fixtures live in conftest.py. These are reusable builders
and filesystem models pulled out of the old monolithic CLI test files so the
test modules can share them without importing each other.
"""

import os
from pathlib import Path

import xxhash
from ascmhl import commands
from click.testing import CliRunner
from lxml import etree


def make_package(root, files, hash_format="xxh64"):
    """
    Create *files* (rel path -> bytes) under *root* and seal an ASC-MHL package.

    `create` runs with its default directory hashes, so the resulting package
    carries both file and directory hash entries — the latter is what the `-dh`
    directory-hash verify path checks.
    """
    root = Path(root)
    for rel, content in files.items():
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(content)
    result = CliRunner().invoke(commands.create, [str(root), "-h", hash_format])
    assert result.exit_code == 0, result.output
    return root


def statuses(report):
    """{relative path: status} for a VerifyReport's per-file outcomes."""
    return {e.path: e.status for e in report.entries}


def make_tree(root: Path, spec: dict):
    """Create a directory tree from a {relpath: bytes_or_None_for_dir} spec."""
    root.mkdir(parents=True, exist_ok=True)
    for rel, content in spec.items():
        p = root / rel
        if content is None:
            p.mkdir(parents=True, exist_ok=True)
        else:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(content)


def seal_helper(mhl_cli, path: Path, algo="md5"):
    """Seal a directory and return the manifest path."""
    rc, _, _ = mhl_cli(["seal", str(path), "-a", algo])
    assert rc == 0
    return next(path.glob("*.mhl"))


def make_mhl_with_size(dest_dir: Path, filename: str, content: bytes, size_override: str | None = None) -> Path:
    """
    Write a file and a matching MHL, optionally overriding the <size> value.

    Uses xxhash64 (the tool's default algorithm) for the digest so tests
    exercise the primary production code path.
    """
    filepath = dest_dir / filename
    filepath.write_bytes(content)

    digest = xxhash.xxh64(content).hexdigest()
    actual_size = str(len(content))
    recorded_size = size_override if size_override is not None else actual_size

    root = etree.Element("hashlist", version="1.1")
    h = etree.SubElement(root, "hash")
    etree.SubElement(h, "file").text = filename
    etree.SubElement(h, "size").text = recorded_size
    etree.SubElement(h, "lastmodificationdate").text = "2026-01-01T00:00:00Z"
    etree.SubElement(h, "xxhash64be").text = digest
    etree.SubElement(h, "hashdate").text = "2026-01-01T00:00:00Z"

    mhl = dest_dir / "test.mhl"
    etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")
    return mhl


def make_mhl(dest_dir: Path, entries: list[dict]) -> Path:
    """
    Write a minimal MHL referencing the given entries.

    Each entry dict must contain 'file', 'size', and 'md5'. Used by symlink
    tests that build manifests by hand.
    """
    root = etree.Element("hashlist", version="1.1")
    for e in entries:
        h = etree.SubElement(root, "hash")
        etree.SubElement(h, "file").text = e["file"]
        etree.SubElement(h, "size").text = e["size"]
        etree.SubElement(h, "lastmodificationdate").text = "2025-01-01T00:00:00Z"
        etree.SubElement(h, "md5").text = e["md5"]
        etree.SubElement(h, "hashdate").text = "2025-01-01T00:00:00Z"
    mhl = dest_dir / "manual.mhl"
    etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")
    return mhl


def make_multi_hash_mhl(dest_dir: Path, filename: str, content: bytes, hashes: dict[str, str]) -> Path:
    """
    Write a file and a manifest entry carrying the given {tag: value} hashes.

    Elements are emitted in dict order before a single <hashdate>, letting a
    test pin both which hashes are present and their document order.
    """
    target = dest_dir / filename
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)

    root = etree.Element("hashlist", version="1.1")
    h = etree.SubElement(root, "hash")
    etree.SubElement(h, "file").text = filename
    etree.SubElement(h, "size").text = str(len(content))
    etree.SubElement(h, "lastmodificationdate").text = "2026-01-01T00:00:00Z"
    for tag, value in hashes.items():
        etree.SubElement(h, tag).text = value
    etree.SubElement(h, "hashdate").text = "2026-01-01T00:00:00Z"

    mhl = dest_dir / "multi.mhl"
    etree.ElementTree(root).write(str(mhl), xml_declaration=True, encoding="UTF-8")
    return mhl


class _FakeEntry:
    """Minimal stand-in for os.DirEntry — only .name is read by the resolver."""

    def __init__(self, name: str) -> None:
        self.name = name


def _sensitive_fs(existing: set[str]):
    """
    Build (lexists, scandir) callables modelling a normalization-sensitive,
    byte-exact filesystem (exFAT/ext4/NTFS) from a set of absolute paths.

    lexists is exact-string membership, so an NFC name and its NFD equivalent
    are distinct entries (the behaviour that cannot be reproduced on the APFS
    host). scandir returns the immediate children of a path and raises OSError
    when the path has none (modelling a file or a missing directory).
    """

    def lexists(p: str) -> bool:
        return p in existing

    def scandir(d: str):
        prefix = d.rstrip(os.sep) + os.sep
        names: list[str] = []
        for p in existing:
            if p.startswith(prefix):
                name = p[len(prefix) :].split(os.sep, 1)[0]
                if name and name not in names:
                    names.append(name)
        if not names:
            raise OSError(20, "Not a directory", d)
        return [_FakeEntry(n) for n in names]

    return lexists, scandir
