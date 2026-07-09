"""
ASC-MHL directory hashes: the hash-of-hashes process of spec Appendix G and
the content/structure hash pair of DirectoryHashType (spec 6.5.2).

A directory's `content` hash digests *what* is stored beneath it and its
`structure` hash additionally digests *how it is named*: content is a
hash-of-hashes over the immediate children's digests (file hashes, and
subdirectories' content hashes), while structure first collapses each child
to hash(child-name-bytes + child-digest-bytes) — files contribute their file
hash, subdirectories their structure hash — and then takes the hash-of-hashes
of those. Renaming a child therefore changes only the structure hash;
changing bytes anywhere below changes both.

The hash-of-hashes process (Appendix G): sort the child digest strings
lexicographically, decode each to its byte representation per Appendix D
(hex, or base-58 for C4), and feed the bytes to a fresh hasher of the same
format. A childless directory yields the digest of no input. All digests
fed to one parent hash must share its format, so the seal engine runs one
accumulation per requested format.

Pure functions over mhl_suite.algorithms' registry; no IO.
"""

from typing import TYPE_CHECKING

from mhl_suite.algorithms import ASC_FORMATS, C4Hasher

if TYPE_CHECKING:
    from collections.abc import Iterable


def decode_digest(fmt: str, digest: str) -> bytes:
    """
    The byte representation of an ASC-MHL digest string per Appendix D:
    hex-decoded for md5/sha1/xxh*, base-58-decoded (64 SHA-512 bytes) for C4.
    Raises ValueError for an unknown format or malformed digest.
    """
    algo = ASC_FORMATS.get(fmt)
    if algo is None:
        raise ValueError(f"Unsupported ASC-MHL hash format: {fmt}")
    if algo.hex_encoded:
        return bytes.fromhex(digest)
    return C4Hasher.decode(digest)


def hash_data(fmt: str, data: bytes) -> str:
    """One-shot digest of `data` in ASC-MHL format `fmt`."""
    hasher = ASC_FORMATS[fmt].factory()
    hasher.update(data)
    return hasher.hexdigest()


def hash_of_hashes(fmt: str, digests: "Iterable[str]") -> str:
    """
    The Appendix G hash of a list of same-format digests: sorted
    lexicographically as strings, each decoded to bytes and fed to a fresh
    `fmt` hasher. An empty list yields the digest of no input.
    """
    hasher = ASC_FORMATS[fmt].factory()
    for digest in sorted(digests):
        hasher.update(decode_digest(fmt, digest))
    return hasher.hexdigest()


def content_hash(fmt: str, child_digests: "Iterable[str]") -> str:
    """
    A directory's content hash (spec 6.5.2): the hash-of-hashes of its
    immediate children's digests — file hashes for files, content hashes for
    subdirectories.
    """
    return hash_of_hashes(fmt, child_digests)


def structure_hash(fmt: str, children: "Iterable[tuple[str, str]]") -> str:
    """
    A directory's structure hash (spec 6.5.2): each immediate child collapses
    to hash(name-bytes + digest-bytes) — `children` pairs the child's name
    with its file hash (files) or structure hash (subdirectories) — and the
    hash-of-hashes of those item hashes is the result.
    """
    items = [hash_data(fmt, name.encode("utf-8") + decode_digest(fmt, digest)) for name, digest in children]
    return hash_of_hashes(fmt, items)
