"""
ASC-MHL directory hashes (spec 6.5.2 + Appendix G).

The hand-derived md5 vectors pin our implementation to the specification text
itself; the reference-library comparisons then pin byte-level interop for
every ASC format, C4's base-58 byte representation included.
"""

import hashlib

import pytest
from ascmhl.hasher import DirectoryHashContext

from mhl_suite.algorithms import ASC_FORMATS, C4Hasher
from mhl_suite.ascmhl_dirhash import content_hash, decode_digest, hash_of_hashes, structure_hash

MD5_AA = "4124bc0a9335c27f086f24ba207a4912"  # md5(b"aa")
MD5_BB = "21ad0bd836b90d08f4cf640b4c298e7c"  # md5(b"bb")


class TestHashOfHashes:
    def test_matches_hand_derived_spec_vector(self):
        # Appendix G by hand: sort digests as strings, feed decoded bytes to a
        # fresh hasher (21ad… sorts before 4124…).
        assert hash_of_hashes("md5", [MD5_AA, MD5_BB]) == "d70327850bb904cd86ed6e52980a99ba"

    def test_sorts_digest_strings_not_input_order(self):
        assert hash_of_hashes("md5", [MD5_BB, MD5_AA]) == hash_of_hashes("md5", [MD5_AA, MD5_BB])

    def test_empty_list_is_digest_of_no_input(self):
        # A childless directory hashes to the algorithm's empty digest.
        assert hash_of_hashes("md5", []) == hashlib.md5().hexdigest()
        assert hash_of_hashes("xxh64", []) == "ef46db3751d8e999"


class TestDecodeDigest:
    def test_hex_formats_decode_to_raw_bytes(self):
        assert decode_digest("md5", MD5_AA) == bytes.fromhex(MD5_AA)
        assert decode_digest("xxh64", "ef46db3751d8e999") == bytes.fromhex("ef46db3751d8e999")

    def test_c4_round_trips_to_sha512_bytes(self):
        hasher = C4Hasher()
        hasher.update(b"aa")
        assert decode_digest("c4", hasher.hexdigest()) == hashlib.sha512(b"aa").digest()

    def test_rejects_unknown_format_and_malformed_values(self):
        with pytest.raises(ValueError, match="Unsupported ASC-MHL hash format"):
            decode_digest("xxh32", "0" * 8)  # classic-only format, not ASC-representable
        with pytest.raises(ValueError, match="non-hexadecimal"):
            decode_digest("md5", "zz")
        with pytest.raises(ValueError, match="not a C4 ID"):
            decode_digest("c4", "c4short")
        with pytest.raises(ValueError, match="not a C4 ID"):
            decode_digest("c4", "c4" + "0" * 88)  # '0' is not in the C4 alphabet


class TestDirectoryHashes:
    def test_content_and_structure_match_hand_derived_spec_vectors(self):
        assert content_hash("md5", [MD5_AA, MD5_BB]) == "d70327850bb904cd86ed6e52980a99ba"
        assert structure_hash("md5", [("a.txt", MD5_AA), ("b.txt", MD5_BB)]) == "2215ff8d4f6318ff4aab9aeb7778f320"

    def test_renaming_a_child_changes_structure_but_not_content(self):
        children = [("a.txt", MD5_AA), ("b.txt", MD5_BB)]
        renamed = [("c.txt", MD5_AA), ("b.txt", MD5_BB)]
        assert content_hash("md5", [MD5_AA, MD5_BB]) == content_hash("md5", [MD5_AA, MD5_BB])
        assert structure_hash("md5", children) != structure_hash("md5", renamed)

    @pytest.mark.parametrize("fmt", sorted(ASC_FORMATS))
    def test_matches_reference_library_for_every_asc_format(self, fmt):
        # One directory with two files and one subdirectory, exercised through
        # the reference DirectoryHashContext for byte-level interop.
        file_hashes = {name: _ref_file_hash(fmt, content) for name, content in [("f1", b"x" * 3), ("f2", b"y" * 5)]}
        sub_content = content_hash(fmt, [_ref_file_hash(fmt, b"deep")])
        sub_structure = structure_hash(fmt, [("deep.bin", _ref_file_hash(fmt, b"deep"))])

        ctx = DirectoryHashContext(fmt)
        for name, digest in file_hashes.items():
            ctx.append_file_hash(name, digest)
        ctx.append_directory_hashes("sub", sub_content, sub_structure)

        ours_content = content_hash(fmt, [*file_hashes.values(), sub_content])
        ours_structure = structure_hash(fmt, [*file_hashes.items(), ("sub", sub_structure)])
        assert ours_content == ctx.final_content_hash_str()
        assert ours_structure == ctx.final_structure_hash_str()


def _ref_file_hash(fmt: str, content: bytes) -> str:
    hasher = ASC_FORMATS[fmt].factory()
    hasher.update(content)
    return hasher.hexdigest()
