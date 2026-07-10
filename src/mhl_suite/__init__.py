"""mhl-suite — verify and seal MHL manifests (classic MHL and ASC-MHL)."""

from importlib.metadata import version

# Resolved from installed package metadata; the package must be installed.
# __version__ needs to be declared before the submodule imports (to avoid
# circular-imports).
__version__ = version("mhl-suite")

from mhl_suite.ascmhl_history import verify_ascmhl
from mhl_suite.classic_seal import seal_classic
from mhl_suite.classic_verify import verify_classic
from mhl_suite.hashing import Hasher, get_hashes, hash_files
from mhl_suite.verify import VerifyEntry, VerifyReport

__all__ = [
    "Hasher",
    "VerifyEntry",
    "VerifyReport",
    "__version__",
    "get_hashes",
    "hash_files",
    "seal_classic",
    "verify_ascmhl",
    "verify_classic",
]
