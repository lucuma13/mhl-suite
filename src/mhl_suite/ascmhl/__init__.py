# =============================================================================
# mhl_suite.ascmhl — the ASC-MHL dialect
# =============================================================================
# ASC-MHL (v2) support. Today this is just sizecheck.py (in-process size
# verification, since ascmhl does not check sizes); mhlver still verifies ASC-MHL
# hashes out-of-process via the ascmhl CLI. The planned absorption vendors
# ascmhl's engine here and flips mhlver's AscMHLBackend to in-process, reusing
# mhl_suite.shared.hashing and emitting mhl_suite.shared.results.
# =============================================================================
