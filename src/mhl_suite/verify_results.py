"""
The result types shared by the engine (classic_verify), the simple-mhl CLI, and
mhlver's classic backend.

verify_classic() returns a VerifyReport; the CLI renders it to [OK]/[ERROR]
text, while mhlver maps its VerifyEntries straight onto its own report model —
no text round-trip in between.

These are formatting-free data carriers: they hold no behaviour and import
nothing from the rest of the suite, so neither simple_mhl nor mhlver creates an
import cycle by depending on them.
"""

from dataclasses import dataclass, field


@dataclass
class VerifyEntry:
    """
    Outcome for a single <hash> entry in a classic MHL manifest.

    `status` is the finer-grained classification mhlver's report consumes:
      * "ok"       — verified (by hash, or by size/existence for a <null> entry)
      * "missing"  — file not found on disk
      * "mismatch" — hash or size does not match the manifest
      * "error"    — any other per-file failure (traversal block, malformed
                     size, no computable hash, requested hash not stored,
                     OSError, …)

    `detail` carries the structured failure description used by the report (e.g.
    "hash mismatch: calc xxh64: … | stored xxh64: …", or a bare category label
    like "blocked traversal attempt"). It is always populated at verbose
    fidelity so the report renders the same regardless of the CLI -v flag.

    `line` is the primary terminal line ("[OK] …" or "[ERROR] …"); `detail_line`
    is the verbose-only continuation (the indented "(calc … | stored …)" detail,
    which may span several lines for an -a all multi-hash mismatch). Together
    they let one renderer reproduce both the verbose and plain terminal forms.
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
    """
    The full outcome of verifying one manifest (either dialect).

    `code` is a value from _exit_codes.ExitCode — harmonised across both
    dialects, so a given integer means one thing everywhere. The classic path
    emits:
      * 0  clean                                              (OK)
      * 10 missing files only                                 (MISSING)
      * 11 hash mismatch / per-file error (wins over missing) (HASH_MISMATCH)
      * 13 size mismatch, size-only mode                      (SIZE_MISMATCH)
      * 40 malformed XML                                      (MALFORMED_XML)
    The ASC-MHL path additionally uses the pinned 12 / 20 / 21 / 30-33 codes
    (hash mismatch is the same 11 in both).

    `notices` are the manifest-level "Verified with size-only checks …" lines
    printed regardless of verbosity, before any per-file failure lines.
    """

    entries: list[VerifyEntry] = field(default_factory=list)
    code: int = 0
    malformed: bool = False
    notices: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when the manifest verified cleanly (exit code 0)."""
        return self.code == 0
