"""mhl-suite — verify and seal MHL manifests (classic MHL and ASC-MHL).

Public API. The names re-exported here are the supported, stable library surface;
everything else under ``mhl_suite`` is an implementation detail that may change
without notice. Command-line use is via the ``simple-mhl`` and ``mhlver`` console
scripts (see ``mhl_suite.cli``).

    from mhl_suite import verify_manifest, verify_package, VerifyStatus

    report = verify_package("/path/to/package")   # ASC-MHL
    if not report.ok:
        print(report.status)                      # dialect-neutral category
"""

from importlib.metadata import PackageNotFoundError, version

from mhl_suite.ascmhl.verify import verify_package
from mhl_suite.classicmhl.seal import seal
from mhl_suite.classicmhl.verify import verify_manifest
from mhl_suite.shared.results import FileOutcome, VerifyReport, VerifyStatus

try:
    __version__ = version("mhl-suite")
except PackageNotFoundError:  # pragma: no cover
    __version__ = "unknown"

__all__ = [
    "FileOutcome",
    "VerifyReport",
    "VerifyStatus",
    "__version__",
    "seal",
    "verify_manifest",
    "verify_package",
]
