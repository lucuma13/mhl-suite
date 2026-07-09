"""
Hash-algorithm registry shared by both MHL dialects.

An Algorithm pairs a hasher constructor with a suite-wide canonical name and a
verify preference rank. Everything the suite knows about a hash format lives
here: how to compute it (factory), how each dialect spells it (classic manifest
tags with their aliases, ASC-MHL format names), and how a stored value is
matched against a computed digest (HashCheck) — including classic MHL's xxHash
endianness and legacy-decimal quirks, which previously lived in the verify
engine.

The C4 ID format (ASC-MHL's reference format) is implemented natively:
SHA-512 re-encoded in the 58-character C4 alphabet, 90 characters with a "c4"
prefix — byte-for-byte the encoding of the reference `ascmhl` implementation.

This module imports only mhl_suite.hashing (the IO leaf); the engines and
parsers build on it.
"""

import hashlib
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

import xxhash

from mhl_suite.hashing import Hasher, get_hashes

if TYPE_CHECKING:
    from collections.abc import Callable


# -----------------------------------------------------------------------------
# C4 ID (ASC-MHL reference format)
# -----------------------------------------------------------------------------


class C4Hasher:
    """
    SHA-512 hasher whose digest is rendered as a C4 ID.

    C4 does not use the hex alphabet: the 512-bit digest is re-encoded base-58
    over the C4 character set (no 0/O/I/l), left-padded with '1' (the C4 zero)
    to a guaranteed 90 characters including the "c4" prefix. hexdigest() is a
    misnomer kept deliberately — it satisfies the Hasher protocol, so a C4
    digest flows through get_hashes/hash_files like any other format.
    """

    __slots__ = ("_sha",)

    _CHARSET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    _LENGTH = 90  # guaranteed C4 ID length, "c4" prefix included

    def __init__(self) -> None:
        self._sha = hashlib.sha512()

    def update(self, data: "bytes | bytearray | memoryview", /) -> None:
        self._sha.update(data)

    def hexdigest(self) -> str:
        value = int.from_bytes(self._sha.digest(), "big")
        digits = ""
        while value:
            value, mod = divmod(value, 58)
            digits = self._CHARSET[mod] + digits
        return "c4" + digits.rjust(self._LENGTH - 2, "1")


# -----------------------------------------------------------------------------
# The registry
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Algorithm:
    """
    One computable hash algorithm.

    `name` is the suite-wide canonical name. `rank` is the verify preference when
    an entry records several formats — lower is preferred (faster). `hex_encoded`
    distinguishes formats whose digests are case-insensitive hex from C4's
    case-significant alphabet. `classic_representable` marks the algorithms
    classic MHL can serialise (the rest are ASC-only); `_classic_tag` overrides
    the on-disk element name in the sole case where it differs from the
    canonical name (xxh64 → <xxhash64be>) — classic spells md5/sha1 as themselves.
    `asc_representable` marks the ASC-MHL hashFormat elements (ASCMHL.xsd's closed
    set c4/md5/sha1/xxh128/xxh3/xxh64) — true for all but the legacy xxh32, which
    exists only to service classic MHL's <xxhash> decimal read path.
    """

    name: str
    factory: "Callable[[], Hasher]"
    rank: int
    hex_encoded: bool = True
    classic_representable: bool = False
    _classic_tag: "str | None" = None
    asc_representable: bool = True

    @property
    def classic_tag(self) -> "str | None":
        """The manifest element name classic serialises this as, or None if classic can't represent it."""
        if not self.classic_representable:
            return None
        return self._classic_tag or self.name


ALGORITHMS: dict[str, Algorithm] = {
    a.name: a
    for a in (
        Algorithm(
            "xxh64",
            cast("Callable[[], Hasher]", xxhash.xxh64),
            0,
            classic_representable=True,
            _classic_tag="xxhash64be",
        ),
        Algorithm("xxh3", cast("Callable[[], Hasher]", xxhash.xxh3_64), 1),
        Algorithm("xxh128", cast("Callable[[], Hasher]", xxhash.xxh3_128), 2),
        Algorithm("xxh32", cast("Callable[[], Hasher]", xxhash.xxh32), 3, asc_representable=False),
        Algorithm("md5", cast("Callable[[], Hasher]", hashlib.md5), 4, classic_representable=True),
        Algorithm("sha1", cast("Callable[[], Hasher]", hashlib.sha1), 5, classic_representable=True),
        Algorithm("c4", C4Hasher, 6, hex_encoded=False),
    )
}


def get_hash(filepath: str, name: str, on_progress: "Callable[[int], None] | None" = None) -> str:
    """
    Compute the digest of `filepath` using algorithm `name` (canonical or
    classic alias). Thin single-format convenience over get_hashes.
    """
    algo = ALGORITHMS.get(name)
    if algo is None and name in _CLASSIC_TAG_ALIASES:
        algo = classic_seal_algorithm(name)
    if algo is None:
        raise ValueError(f"Unsupported hash algorithm: {name}")
    return get_hashes(filepath, [algo.factory], on_progress=on_progress)[0]


# -----------------------------------------------------------------------------
# HashCheck — a stored digest paired with how to verify it
# -----------------------------------------------------------------------------


@dataclass(frozen=True)
class HashCheck:
    """
    One recorded hash value and the rule that accepts it.

    `tag` is the name as recorded in the manifest (classic element name or
    ASC-MHL format name); `canonical` is the dialect-normalised form used to
    match a CLI `-a` selection (classic aliases collapse, e.g. <xxhash> and
    <xxhash64> both canonicalise to "xxhash64be"). `matches` receives the
    computed digest string (hex, or a C4 ID) and decides acceptance — this is
    where classic xxHash's endianness and legacy-decimal shapes are absorbed.
    """

    tag: str
    canonical: str
    algorithm: Algorithm
    expected: str
    matches: "Callable[[str], bool]" = field(compare=False)

    @property
    def rank(self) -> int:
        return self.algorithm.rank


def _ci_hex_matcher(expected: str) -> "Callable[[str], bool]":
    """Case-insensitive exact compare for hex-encoded digests."""
    lowered = expected.lower()
    return lambda calc: calc.lower() == lowered


def _exact_matcher(expected: str) -> "Callable[[str], bool]":
    """Case-significant exact compare (C4 IDs use a mixed-case alphabet)."""
    return lambda calc: calc == expected


# -----------------------------------------------------------------------------
# Classic MHL dialect
# -----------------------------------------------------------------------------
# Classic manifests spell xxHash several ways and have historically stored both
# byte orders and (oldest of all) a 32-bit decimal integer:
#   * xxhash64be — XXH64 as big-endian hex (the canonical modern form)
#   * xxhash64   — the above, or XXH64 as little-endian hex
#   * xxhash     — the above, or XXH32 as a decimal integer
# Only one digest is computed per entry: the stored value's shape selects which.

NULL_TAG = "null"

# Manifest tag → the algorithm classic serialises as it, derived from the
# registry (one entry per classic-representable algorithm). Keyed by tag, so it
# cannot drift out of sync with the algorithms' own classic_tag declarations.
_CLASSIC_TAG_ALGORITHM: dict[str, Algorithm] = {a.classic_tag: a for a in ALGORITHMS.values() if a.classic_tag}

# Canonical CLI/manifest spelling → manifest tag: an algorithm's own name is
# its canonical spelling (xxh64, md5, sha1)
_CLASSIC_CANONICAL_ALIASES: dict[str, str] = {a.name: a.classic_tag for a in ALGORITHMS.values() if a.classic_tag}

# Legacy classic spellings: accepted for backward compatibility but not
# advertised. Old manifests and CLIs used these; the read-time endianness
# semantics that distinguish them live in classic_check, not here.
_CLASSIC_LEGACY_ALIASES: dict[str, str] = {
    "xxhash": "xxhash64be",
    "xxhash64": "xxhash64be",
    "xxhash64be": "xxhash64be",
}

# Every accepted CLI/manifest spelling → canonical manifest tag.
_CLASSIC_TAG_ALIASES: dict[str, str] = {**_CLASSIC_CANONICAL_ALIASES, **_CLASSIC_LEGACY_ALIASES}

# The distinct manifest element names seal writes (aliases collapse to these).
CLASSIC_TAGS = frozenset(_CLASSIC_TAG_ALGORITHM)

# The advertised classic algorithm vocabulary (null handled separately).
CLASSIC_CANONICAL_KEYS = frozenset(_CLASSIC_CANONICAL_ALIASES)

# Every accepted classic seal/verify CLI spelling, canonical and legacy.
CLASSIC_KEYS = frozenset(_CLASSIC_TAG_ALIASES)

# A 32-bit XXH32 in decimal is at most 10 digits (leading zeros might have been
# stripped). A longer all-digit value under <xxhash> is therefore hex.
_XXH32_MAX_DECIMAL_DIGITS = 10


def classic_canonical_tag(name: str) -> str:
    """
    Normalise a classic hash element's local name to its canonical manifest
    tag; unknown / read-only tags pass through unchanged.
    """
    return _CLASSIC_TAG_ALIASES.get(name, name)


def classic_seal_tag(key: str) -> str:
    """Manifest element name seal writes for a CLI algorithm key (`null` records no digest)."""
    return NULL_TAG if key == NULL_TAG else _CLASSIC_TAG_ALIASES[key]


def classic_seal_algorithm(key: str) -> Algorithm:
    """The Algorithm computed for a classic seal key (not `null`)."""
    return _CLASSIC_TAG_ALGORITHM[_CLASSIC_TAG_ALIASES[key]]


def _swap64(value: int) -> int:
    """Return a 64-bit value with its byte order reversed."""
    return int.from_bytes(value.to_bytes(8, "big"), "little")


def _matches_be(expected: str) -> "Callable[[str], bool]":
    """Strict big-endian hex compare against the computed BE hexdigest."""

    def match(calc: str) -> bool:
        try:
            return int(expected, 16) == int(calc, 16)
        except ValueError:
            return False

    return match


def _matches_be_or_le(expected: str) -> "Callable[[str], bool]":
    """
    Accept the stored hex value in either byte order.

    The two orders are reorderings of the same hash, so accepting both only
    rescues an intact file recorded in the opposite endianness — it never lets
    a differing file pass.
    """

    def match(calc: str) -> bool:
        try:
            stored = int(expected, 16)
            computed = int(calc, 16)
        except ValueError:
            return False
        return stored == computed or stored == _swap64(computed)

    return match


def _matches_decimal(expected: str) -> "Callable[[str], bool]":
    """Accept a legacy decimal-integer stored value against the computed hex digest."""

    def match(calc: str) -> bool:
        try:
            return int(expected) == int(calc, 16)
        except ValueError:
            return False

    return match


def classic_check(localname: str, expected: str) -> "HashCheck | None":
    """
    Build the HashCheck for a classic manifest hash element, or None when the
    element is not a recognised computable format (it is then ignored exactly
    as if absent — <null> is not a HashCheck either; it records no digest).

    The stored value's shape decides which algorithm a legacy <xxhash> pays to
    compute: a decimal value of up to 10 digits is a 32-bit XXH32, anything
    else is XXH64.
    """
    name = localname.lower()
    expected = expected.strip()
    if name == "xxhash64be":
        return HashCheck(localname, "xxhash64be", ALGORITHMS["xxh64"], expected, _matches_be(expected))
    if name in ("xxhash64", "xxh64"):
        return HashCheck(localname, "xxhash64be", ALGORITHMS["xxh64"], expected, _matches_be_or_le(expected))
    if name == "xxhash":
        if expected.isdecimal() and len(expected) <= _XXH32_MAX_DECIMAL_DIGITS:
            return HashCheck(localname, "xxhash64be", ALGORITHMS["xxh32"], expected, _matches_decimal(expected))
        return HashCheck(localname, "xxhash64be", ALGORITHMS["xxh64"], expected, _matches_be_or_le(expected))
    if name in ("md5", "sha1"):
        return HashCheck(localname, name, ALGORITHMS[name], expected, _ci_hex_matcher(expected))
    return None


# -----------------------------------------------------------------------------
# ASC-MHL dialect
# -----------------------------------------------------------------------------
# The valid ASC-MHL hashFormat element names (ASCMHL.xsd's closed set), derived
# from the registry: an ASC format name is exactly the canonical name, so this
# is every algorithm bar legacy xxh32. A <xxh32> element is not schema-valid and
# is not accepted here.
ASC_FORMATS: dict[str, Algorithm] = {a.name: a for a in ALGORITHMS.values() if a.asc_representable}


def asc_check(hash_format: str, expected: str) -> "HashCheck | None":
    """
    Build the HashCheck for an ASC-MHL hash entry, or None for an unknown
    format. ASC-MHL digests are plain hex (case-insensitive) except C4, whose
    mixed-case alphabet is compared exactly.
    """
    algo = ASC_FORMATS.get(hash_format)
    if algo is None:
        return None
    expected = expected.strip()
    matcher = _ci_hex_matcher(expected) if algo.hex_encoded else _exact_matcher(expected)
    return HashCheck(hash_format, hash_format, algo, expected, matcher)
