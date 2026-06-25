"""
__author__ = "Patrick Renner, Alexander Sahm"
__copyright__ = "Copyright 2020, Pomfort GmbH"
"""

# Vendored from the official ASC-MHL CLI (github.com/ascmhl/mhl), synced from
# upstream tag v1.2. Upstream reads its version from the installed `ascmhl`
# distribution via importlib.metadata; here the engine is vendored into mhl-suite
# and is not a separate distribution, so the version is pinned statically to the
# synced upstream tag. Bump this when re-syncing from a newer upstream release.
ascmhl_tool_name = "ascmhl"
ascmhl_tool_version = "1.2"

ascmhl_folder_name = "ascmhl"
ascmhl_file_extension = ".mhl"
ascmhl_chainfile_name = "ascmhl_chain.xml"
ascmhl_collectionfile_name = "ascmhl_collection.xml"
# decreasing priority list for verification
ascmhl_supported_hashformats = [
    "md5",
    "sha1",
    "xxh128",
    "xxh3",
    "xxh64",
    "c4",
]
ascmhl_default_hashformat = "xxh128"
ascmhl_reference_hash_format = "c4"  # hash format used to reference other files, e.g. in references and the chain
# ascmhl_default_ignore_patterns = ['.DS_Store', ascmhl_folder_name]
