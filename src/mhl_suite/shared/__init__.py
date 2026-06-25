# =============================================================================
# mhl_suite.shared — cross-dialect layer
# =============================================================================
# The pieces both MHL dialects and both CLIs build on, independent of any one
# dialect:
#   hashing.py — the adaptive parallel hasher + algorithm registry
#   results.py — the verify-result contract (FileOutcome / VerifyReport)
#   report.py  — mhlver's report model + renderer
# This is the home these modules keep after ASC-MHL is absorbed (when its verify
# starts emitting `results` and hashing via `hashing`), so they live here now to
# avoid moving twice.
# =============================================================================
