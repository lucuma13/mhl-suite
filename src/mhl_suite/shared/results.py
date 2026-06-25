# =============================================================================
# mhl_suite.shared.results — structured verify result contract
# =============================================================================
# The single result type shared by the engine (classicmhl.verify), the simple-mhl
# CLI, and mhlver's classic backend. verify_manifest() returns a VerifyReport;
# the CLI renders it to [OK]/[ERROR] text, while mhlver maps its FileOutcomes
# straight onto its own report model — no text round-trip in between.
#
# These are formatting-free data carriers: they hold no behaviour and import
# nothing from the rest of the suite, so neither simple_mhl nor mhlver creates
# an import cycle by depending on them.
# =============================================================================

from dataclasses import dataclass, field
from enum import Enum


class VerifyStatus(Enum):
    """Dialect-neutral verification outcome for a manifest.

    Both dialects report a numeric exit `code` (with different per-dialect
    meanings — see mhl_suite.verifyall's dispatch tables), so this enum gives
    library callers one vocabulary to branch on instead of magic numbers. It is
    derived from a report's entries; `code` stays the source of truth for the CLI
    and for tooling that wants the precise per-dialect category.
    """

    OK = "ok"
    MISSING = "missing"  # referenced file(s) absent from disk
    MISMATCH = "mismatch"  # hash or size differs (or a per-file verify error)
    NEW_FILES = "new"  # files on disk not recorded in the manifest/history
    MALFORMED = "malformed"  # the manifest itself could not be parsed


@dataclass
class FileOutcome:
    """Outcome for a single <hash> entry in a classic MHL manifest.

    `status` is the finer-grained classification mhlver's report consumes:
      "ok"       — verified (by hash, or by size/existence for a <null> entry)
      "missing"  — file not found on disk
      "mismatch" — hash or size does not match the manifest
      "error"    — any other per-file failure (traversal block, malformed size,
                   no computable hash, requested hash not stored, OSError, …)

    `detail` carries the structured failure description used by the report
    (e.g. "hash mismatch: calc xxh64: … | stored xxh64: …", or a bare category
    label like "blocked traversal attempt"). It is always populated at verbose
    fidelity so the report renders the same regardless of the CLI -v flag.

    `line` is the primary terminal line ("[OK] …" or "[ERROR] …"); `detail_line`
    is the verbose-only continuation (the indented "(calc … | stored …)" detail,
    which may span several lines for an -a all multi-hash mismatch). Together they
    let one renderer reproduce both the verbose and plain terminal forms.
    """

    path: str
    status: str
    detail: str = ""
    size_only: bool = False
    existence_only: bool = False
    line: str = ""
    detail_line: str = ""


@dataclass
class VerifyReport:
    """The full outcome of verifying one classic MHL manifest.

    `code` is the exit code the CLI surfaces and mhlver maps to a status line:
      0  clean
      20 malformed XML (then `malformed` is True and `entries` is empty)
      30 missing files only
      40 hash/size mismatches (or other per-file errors) only
      70 both missing and mismatch/error

    `notices` are the manifest-level "Verified with size-only checks …" lines
    printed regardless of verbosity, before any per-file failure lines.
    """

    entries: list[FileOutcome] = field(default_factory=list)
    code: int = 0
    malformed: bool = False
    notices: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when the manifest verified cleanly (exit code 0)."""
        return self.code == 0

    @property
    def status(self) -> VerifyStatus:
        """The dialect-neutral outcome, derived from the entries.

        When several conditions co-occur, the most severe present wins, in the
        order malformed → mismatch/error → missing → new → ok. (`code` still
        carries the exact per-dialect category, e.g. classic 70 = missing AND
        mismatch.)
        """
        if self.malformed:
            return VerifyStatus.MALFORMED
        kinds = {e.status for e in self.entries}
        if "mismatch" in kinds or "error" in kinds:
            return VerifyStatus.MISMATCH
        if "missing" in kinds:
            return VerifyStatus.MISSING
        if "new" in kinds:
            return VerifyStatus.NEW_FILES
        return VerifyStatus.OK
