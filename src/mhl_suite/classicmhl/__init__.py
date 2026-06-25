# =============================================================================
# mhl_suite.classicmhl — the classic / flat-MHL dialect engine
# =============================================================================
# Sealing and verification for classic (v1.1) MHL manifests — the engine behind
# the `simple-mhl` CLI, also driven in-process by mhlver's ClassicMHLBackend.
# It returns structured data (mhl_suite.shared.results) instead of printing or
# calling sys.exit, and hashes via the shared adaptive hasher
# (mhl_suite.shared.hashing). Its ASC-MHL counterpart is mhl_suite.ascmhl.
# =============================================================================
