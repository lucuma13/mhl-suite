"""
The manifest/report order (mhl_suite.sorting).

Pure string tests — the key never touches the disk, which is the point of
deciding order with a key rather than with a walk.
"""

import random

from mhl_suite.sorting import sort_key

NFC_ROSE = "ros\u00e9.mov"  # é as one codepoint, as Linux/Windows write it
NFD_ROSE = "rose\u0301.mov"  # e + combining acute, as macOS writes it


def order(paths: "list[str | tuple[str, bool]]") -> list[str]:
    """
    Sort (path, is_dir) pairs — bare strings are files — from a shuffled input.
    """
    items = [(p, False) if isinstance(p, str) else p for p in paths]
    random.Random(13).shuffle(items)
    return [p for p, _ in sorted(items, key=lambda i: sort_key(i[0], i[1]))]


class TestLevelOrder:
    def test_directories_precede_files_at_every_level(self):
        assert order([("Bravo", True), "aaa.mov", ("Alpha", True), "notes.txt"]) == [
            "Alpha",
            "Bravo",
            "aaa.mov",
            "notes.txt",
        ]

    def test_directory_is_followed_immediately_by_its_own_subtree(self):
        assert order(
            [("Alpha", True), "Alpha/a1.mov", ("Alpha/sub", True), "Alpha/sub/deep.mov", ("Bravo", True), "zz.mov"]
        ) == [
            "Alpha",
            "Alpha/sub",
            "Alpha/sub/deep.mov",
            "Alpha/a1.mov",
            "Bravo",
            "zz.mov",
        ]

    def test_subdirectory_subtree_precedes_the_files_beside_it(self):
        # The case a plain path sort gets wrong: 'Alpha/a1.mov' < 'Alpha/sub'.
        assert order(["Alpha/a1.mov", ("Alpha/sub", True), "Alpha/sub/deep.mov"]) == [
            "Alpha/sub",
            "Alpha/sub/deep.mov",
            "Alpha/a1.mov",
        ]

    def test_file_without_directory_records_still_sorts_subtree_first(self):
        # Classic manifests carry no directory entries; the ordering rule still holds.
        assert order(["notes.txt", "Alpha/a1.mov", "Alpha/sub/deep.mov", "Bravo/b1.mov"]) == [
            "Alpha/sub/deep.mov",
            "Alpha/a1.mov",
            "Bravo/b1.mov",
            "notes.txt",
        ]


class TestNaturalOrder:
    def test_digit_runs_compare_numerically(self):
        assert order(["take10.mov", "take2.mov", "take1.mov"]) == ["take1.mov", "take2.mov", "take10.mov"]

    def test_digit_runs_compare_numerically_mid_name(self):
        assert order(["A001_C010.mov", "A001_C002.mov", "A001_C003.mov"]) == [
            "A001_C002.mov",
            "A001_C003.mov",
            "A001_C010.mov",
        ]

    def test_case_is_ignored_when_ordering(self):
        assert order(["Banana.mov", "apple.mov", "Cherry.mov"]) == ["apple.mov", "Banana.mov", "Cherry.mov"]

    def test_accents_file_with_their_base_letter(self):
        # 'Ö' carries the primary weight of 'O', so 'Ötzi' files among the O's
        # (before 'Oz', on 't' < 'z') rather than after 'Zulu', where its
        # codepoint (U+00D6 > 'Z') would put it.
        assert order(["Zulu.mov", "Ötzi.mov", "Oz.mov"]) == ["Ötzi.mov", "Oz.mov", "Zulu.mov"]

    def test_digit_like_characters_that_are_not_digit_runs_sort_as_text(self):
        # str.isdigit() is true of '²' and '½', but \d captures neither, so
        # treating them as numbers would hand int() something it cannot parse.
        assert order(["b².mov", "a½.mov"]) == ["a½.mov", "b².mov"]

    def test_non_ascii_decimal_digits_still_compare_numerically(self):
        # Arabic-Indic digits are \d (and int() reads them), so they are a run.
        take_10 = "take\u0661\u0660.mov"  # Arabic-Indic 1,0
        take_2 = "take\u0662.mov"  # Arabic-Indic 2
        assert order([take_10, take_2]) == [take_2, take_10]


class TestTotalOrder:
    """
    Names the key alone cannot separate — without the raw-path tiebreak these
    fall back to readdir order.
    """

    def test_leading_zero_collision_is_ordered_deterministically(self):
        assert order(["take007.mov", "take7.mov"]) == order(["take7.mov", "take007.mov"])

    def test_case_collision_is_ordered_deterministically(self):
        assert order(["Shot.mov", "shot.mov"]) == order(["shot.mov", "Shot.mov"])

    def test_composed_and_decomposed_spellings_are_ordered_deterministically(self):
        assert order([NFC_ROSE, NFD_ROSE]) == order([NFD_ROSE, NFC_ROSE])

    def test_normalization_does_not_affect_where_a_name_sorts(self):
        # A name decomposed by macOS sorts where its composed spelling would.
        assert order([NFD_ROSE, "banana.mov", "zulu.mov"]) == ["banana.mov", NFD_ROSE, "zulu.mov"]
        assert order([NFC_ROSE, "banana.mov", "zulu.mov"]) == ["banana.mov", NFC_ROSE, "zulu.mov"]
