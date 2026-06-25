# Vendored ASC-MHL engine

This directory is the official **ASC-MHL** CLI engine, vendored into mhl-suite so
ASC-MHL verification runs in-process (no `ascmhl`/`ascmhl-debug` subprocess).

- **Upstream:** https://github.com/ascmhl/mhl
- **Synced from tag:** `v1.2`
- **License:** MIT — see [`LICENSE`](./LICENSE) (© 2020 ASC). Per-module headers keep
  `__author__`/`__copyright__` (© Pomfort GmbH); `__license__`/`__maintainer__`/`__email__`
  were trimmed (the support contacts don't apply to a vendored copy).

## What's here vs. what's ours

Everything in `vendor/` is upstream and is **excluded from the suite's ruff / ty /
typos** (see `pyproject.toml` `[tool.ruff] extend-exclude`, `[tool.ty] src.exclude`,
and `.pre-commit-config.yaml` typos `exclude`) so re-syncing stays a clean drop-in.
Our own ASC-MHL code lives one level up and **is** linted/type-checked:

- `mhl_suite/ascmhl/verify.py` — print-free structured wrapper (`verify_package`,
  `schema_check`, `integrity_check`) that mhlver drives.
- `mhl_suite/ascmhl/sizecheck.py` — byte-free size-only checker.

CLI-only upstream modules were intentionally **not** vendored: `cli/`,
`_debug_commands.py`, `cli/update.py` (the last drops the `requests`/`packaging` deps).

## Local modifications (re-apply on re-sync)

Every local edit is marked `# VENDORED PATCH` in the source. As of the v1.2 sync:

1. **`__version__.py`** — `ascmhl_tool_version` pinned to a static `"1.2"` (the engine
   is not installed as a separate distribution, so `importlib.metadata.version("ascmhl")`
   can't resolve).
2. **`commands.py` — XSD path** (`_bundled_xsd_path`): load `ASCMHL.xsd` /
   `ASCMHLDirectory__combined.xsd` from the bundled `mhl_suite.xsd` package instead of
   relative to the current working directory.
3. **`commands.py` — two-phase hashing** (`verify_entire_folder`): collect-then-hash
   through `mhl_suite.shared.hashing` (the adaptive parallel controller) with a small
   ASC-format calibrator, plus optional `on_progress` / `report` kwargs. Defaults
   preserve upstream behaviour (exit codes + logger lines) exactly.
4. **`logger.py`** — added a module-level `quiet` flag so the suite can silence
   upstream's `click.echo` output when collecting structured results.

## Re-syncing from a newer upstream release

1. Copy the upstream `ascmhl/*.py` modules into `vendor/` (skip `cli/`,
   `_debug_commands.py`, `update.py`); refresh `LICENSE`.
2. Re-apply the four patches above (search the new tree for the old behaviour).
3. Bump the tag references in this file and the pin in `__version__.py`.
4. Run `pytest tests/test_ascmhl_verify.py tests/test_mhlver.py` — the oracle proves
   the patched engine still yields the upstream exit codes through our wrapper.

**If local patches ever grow beyond this handful of surgical edits** (real bug fixes,
behaviour changes, or features), stop treating this as vendored: move it out of
`vendor/`, drop the lint/type exclusions, run it through the full gate, and record here
that the suite has *forked* from ASC-MHL v1.2 — from then on, cherry-pick upstream fixes
by hand rather than re-syncing wholesale.
