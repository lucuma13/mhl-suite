# =============================================================================
# mhl_suite.ascmhl — the ASC-MHL dialect
# =============================================================================
# ASC-MHL (v2) support, all in-process. This package has two layers:
#
#   * our code (linted/typed like the rest of the suite):
#       - verify.py    — print-free structured verify (verify_package,
#                        schema_check, integrity_check) that mhlver drives
#       - sizecheck.py — byte-free size-only checker
#   * vendor/ — the official ASC-MHL engine, vendored ~verbatim from upstream
#       v1.2 (MIT) and excluded from the suite's lint/type tooling so it stays
#       re-syncable. See vendor/VENDOR.md.
#
# verify.py drives vendor/ in-process, reusing mhl_suite.shared.hashing (the
# adaptive parallel hasher) and emitting mhl_suite.shared.results.
# =============================================================================
