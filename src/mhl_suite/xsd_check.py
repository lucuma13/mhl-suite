"""
XSD schema validation for both MHL dialects, against the schemas bundled in
mhl_suite.xsd.

The pip-installed reference `ascmhl` wheel does not ship its XSD files, and a
classic manifest's schema is defined by MediaHashList_v1_1.xsd — so the suite
bundles both dialects' schemas and validates against its own copies. One
module, one return shape: (ExitCode, error lines); never prints or exits.
"""

import importlib.resources
from pathlib import Path

from lxml import etree

from mhl_suite._exit_codes import ExitCode

CLASSIC_SCHEMA = "MediaHashList_v1_1.xsd"
ASCMHL_SCHEMA = "ASCMHL.xsd"
ASCMHL_DIRECTORY_SCHEMA = "ASCMHLDirectory__combined.xsd"


def bundled_xsd_path(schema_name: str) -> str:
    """
    Absolute path to a bundled XSD shipped in the mhl_suite.xsd package.

    Looks first at the importlib.resources location used when this package is
    installed normally, then at the package's sibling 'xsd/' folder for the
    case where the suite is run directly from a checkout. Raises
    FileNotFoundError if the schema is missing (a broken install).
    """
    try:
        resource = importlib.resources.files("mhl_suite.xsd").joinpath(schema_name)
        if resource.is_file():
            return str(resource)
    except (ImportError, FileNotFoundError, TypeError):
        pass

    # Source-checkout fallback: mhl_suite/xsd_check.py → mhl_suite/xsd/.
    local = Path(__file__).resolve().parent / "xsd" / schema_name
    if local.exists():
        return str(local)

    raise FileNotFoundError(f"Could not locate {schema_name} (tried {local})")


def _validate(file_path: "str | Path", schema_name: str) -> "tuple[int, list[str]]":
    """
    Validate `file_path` against a bundled schema, returning (code, lines):
    0 (valid), 41 (well-formed but schema non-compliant), 40
    (malformed/unreadable XML), or 1 for a broken install (missing bundled
    XSD — an installation fact, not a manifest fact, so it gets the generic
    error code rather than its own).
    """
    try:
        xsd_path = bundled_xsd_path(schema_name)
    except FileNotFoundError as exc:
        return ExitCode.ERROR, [f"Error: {exc}"]

    try:
        # Parse both documents and compile the schema. lxml's XMLSchema
        # constructor compiles the validator; the cost is small (a few KiB
        # schema) and not worth caching for a single-file CLI tool.
        tree = etree.parse(str(file_path))
        xsd = etree.XMLSchema(etree.parse(xsd_path))
    except etree.XMLSyntaxError as exc:
        return ExitCode.MALFORMED_XML, [f"Error: XML parsing failed - {exc}"]
    except OSError as exc:
        return ExitCode.MALFORMED_XML, [f"Error: file read failed - {exc}"]

    if not xsd.validate(tree):
        return ExitCode.SCHEMA_NONCOMPLIANT, [
            f"Error: XSD validation failed - {err.message} (line {err.line})" for err in xsd.error_log
        ]
    return ExitCode.OK, []


def classic_schema_report(mhl_file: "str | Path") -> "tuple[int, list[str]]":
    """Validate a classic manifest against MediaHashList_v1_1.xsd."""
    return _validate(mhl_file, CLASSIC_SCHEMA)


def ascmhl_schema_report(file_path: "str | Path", *, directory_file: bool = False) -> "tuple[int, list[str]]":
    """
    Validate an ASC-MHL file against its bundled XSD: a generation manifest
    against ASCMHL.xsd, or (`directory_file=True`) an ascmhl_chain.xml against
    the directory schema. Schema non-compliance keeps its own code (41),
    deliberately distinct from the 11 the reference tool reuses for
    hash-mismatch.
    """
    schema = ASCMHL_DIRECTORY_SCHEMA if directory_file else ASCMHL_SCHEMA
    return _validate(file_path, schema)
