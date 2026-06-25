# =============================================================================
# mhl_suite.ascmhl.vendor — the official ASC-MHL engine, vendored
# =============================================================================
# These modules are the upstream ASC-MHL CLI (github.com/ascmhl/mhl), synced
# ~verbatim from tag v1.2 and licensed MIT (see vendor/LICENSE). They are
# deliberately kept apart from the suite's own ASC-MHL code (../verify.py,
# ../sizecheck.py) so the boundary between "ours" and "theirs" is structural:
# everything under vendor/ is excluded from the suite's linting/type-checking
# (see pyproject [tool.ruff] extend-exclude and [tool.ty] src.exclude) to stay
# re-syncable. Local modifications are minimal and each marked `# VENDORED PATCH`;
# see vendor/VENDOR.md for the provenance and the full patch list.
# =============================================================================
