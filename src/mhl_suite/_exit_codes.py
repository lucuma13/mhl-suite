"""
One IntEnum that both verify engines, the verifyall dispatch tables, and the CLIs share.

IntEnum (not Enum) so a member IS its int: `sys.exit(ExitCode.HASH_MISMATCH)` and `report.code == ExitCode.MISSING`
both work without `.value`.
"""

from enum import IntEnum


class ExitCode(IntEnum):
    """Canonical verification exit codes, shared by both MHL dialects."""

    # --- success / catch-all -----------------------------------------------------------------------------------------
    OK = 0
    # Bad invocation (path is not an MHL file, bad argument) or an internal error (e.g. broken install)
    ERROR = 1

    # --- 1x: file content disagrees with the manifest ----------------------------------------------------------------
    MISSING = 10  # PINNED (ascmhl CompletenessCheckFailedException): referenced files absent
    HASH_MISMATCH = 11  # PINNED (ascmhl VerificationFailedException): recomputed hash differs
    DIRECTORY_HASH_MISMATCH = 12  # PINNED (ascmhl VerificationDirectoriesFailedException) — ASC-MHL
    SIZE_MISMATCH = 13  # size differs (size-only mode), distinct from a hash failure

    # --- 2x: file-presence anomalies (ASC-MHL) -----------------------------------------------------------------------
    SINGLE_FILE_NOT_FOUND = 20  # PINNED (ascmhl SingleFileNotFoundException)
    NEW_FILES = 21  # PINNED (ascmhl NewFilesFoundException): files on disk not in the history

    # --- 3x: history & chain integrity (ASC-MHL) ---------------------------------------------------------------------
    NO_HISTORY = 30  # PINNED (ascmhl NoMHLHistoryException)
    MODIFIED_MANIFEST = 31  # PINNED (ascmhl ModifiedMHLManifestFileException)
    NO_CHAIN = 32  # PINNED (ascmhl NoMHLChainException)
    MISSING_MANIFEST = 33  # PINNED (ascmhl MissingMHLManifestException)

    # --- 4x: the manifest document itself is invalid -----------------------------------------------------------------
    MALFORMED_XML = 40  # manifest is not well-formed / unparsable XML
    SCHEMA_NONCOMPLIANT = 41  # well-formed but fails XSD validation
