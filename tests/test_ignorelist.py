"""
The OS-junk ignore list (mhl_suite.ignorelist).

is_os_junk classifies a bare filename as OS-generated metadata (skipped during
seal) or real user content (sealed). Its use by the seal walker is covered in
test_classic_seal; here we pin the classification itself.
"""

import pytest

from mhl_suite import ignorelist


class TestIsOsJunk:
    """Only OS-generated metadata is junk; hidden user files/dirs are not."""

    @pytest.mark.parametrize(
        ("name", "is_junk"),
        [
            # Exact names (case-insensitive)
            (".DS_Store", True),
            (".ds_store", False),  # case-sensitive: only the OS's exact casing matches
            (".Spotlight-V100", True),
            (".Trashes", True),
            (".fseventsd", True),
            ("Thumbs.db", True),
            (".localized", True),
            (".AppleDouble", True),
            (".LSOverride", True),
            (".DocumentRevisions-V100", True),
            (".TemporaryItems", True),
            (".VolumeIcon.icns", True),
            (".com.apple.timemachine.donotpresent", True),
            (".com.apple.timemachine.supported", True),
            (".PKInstallSandboxManager", True),
            (".PKInstallSandboxManager-SystemSoftware", True),
            (".hotfiles.btree", True),
            (".vol", True),
            (".file", True),
            ("lost+found", True),
            # Trailing-carriage-return names (real bytes in the on-disk name)
            ("Icon\r", True),
            (".HFS+ Private Directory Data\r", True),
            # Prefix matches
            ("._MyClip.mov", True),  # macOS AppleDouble resource fork
            ("._", True),  # bare '._' still matches the fork prefix
            (".disk_label", True),
            (".disk_label_2x", True),
            # NOT junk — hidden user content is sealed
            (".hidden.bin", False),
            (".git", False),  # hidden user dir — descended
            (".env", False),
            ("clip.mxf", False),
            ("Icon", False),  # plain 'Icon' (no CR) is a real file, not the marker
            ("lost+found2", False),  # exact match only
        ],
    )
    def test_is_os_junk(self, name, is_junk):
        assert ignorelist.is_os_junk(name) is is_junk
