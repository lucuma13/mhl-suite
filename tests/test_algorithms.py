"""
The hash-algorithm registry (mhl_suite.algorithms): single-format hashing and
the classic xxHash matching rules (endianness and legacy-decimal shapes) that
decide whether a stored value accepts a computed digest.

These test algorithms in isolation — the endianness rules are also driven
end-to-end through verify_classic in test_classic_verify (TestVerifyXxhashVariants).
"""

import pytest
import xxhash

from mhl_suite import algorithms
from mhl_suite.algorithms import CLASSIC_KEYS, classic_seal_algorithm, classic_seal_tag, get_hash


def _le_hex(value: int, nbytes: int) -> str:
    """Little-endian hex of an integer — the byte order some xxHash tags record."""
    return value.to_bytes(nbytes, "little").hex()


class TestGetHash:
    """get_hash is the single-format convenience over get_hashes."""

    def test_get_hash_rejects_unsupported_algorithm(self, tmp_path):
        """get_hash raises ValueError for a name absent from the registry."""
        f = tmp_path / "a.bin"
        f.write_bytes(b"data")
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            get_hash(str(f), "blake2")


class TestClassicSealKeys:
    """Every accepted classic seal key resolves to both a manifest tag and an
    algorithm — the two lookups share the alias keyset, so no spelling (e.g.
    xxh64) can pass CLI validation and then fail at hash time."""

    @pytest.mark.parametrize("key", sorted(CLASSIC_KEYS))
    def test_key_resolves_to_tag_and_algorithm(self, key):
        assert classic_seal_tag(key) in algorithms.CLASSIC_TAGS
        assert classic_seal_algorithm(key).name in algorithms.ALGORITHMS


class TestClassicXxhashEndianness:
    """classic_check absorbs classic MHL's xxHash byte-order shapes: xxhash64be
    is strict big-endian, while xxhash64 accepts either order."""

    content = b"endianness unit"
    be = xxhash.xxh64(content).hexdigest()
    le = _le_hex(xxhash.xxh64(content).intdigest(), 8)

    def test_xxhash64be_is_strict_big_endian(self):
        check = algorithms.classic_check("xxhash64be", self.be)
        assert check is not None
        assert check.matches(self.be) is True
        assert check.matches(self.le) is False

    def test_xxhash64_accepts_either_order(self):
        either = algorithms.classic_check("xxhash64", self.be)
        swapped = algorithms.classic_check("xxhash64", self.le)
        assert either is not None
        assert swapped is not None
        assert either.matches(self.be) is True
        assert swapped.matches(self.be) is True


class TestMatchesDecimal:
    """The legacy decimal <xxhash> rule: a decimal stored value is compared
    numerically against the computed hex digest, and a non-numeric string is
    rejected rather than raising."""

    def test_compares_decimal_string_to_hex_digest(self):
        check = algorithms.classic_check("xxhash", "42")
        assert check is not None
        assert check.algorithm.name == "xxh32"
        assert check.matches(format(42, "08x")) is True
        assert check.matches(format(41, "08x")) is False
        non_numeric = algorithms.classic_check("xxhash", "not-a-number")
        assert non_numeric is not None
        assert non_numeric.matches("2a") is False
