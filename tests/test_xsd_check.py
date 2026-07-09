"""
XSD schema validation (mhl_suite.xsd_check): the xsd-schema-check outcomes and
the bundled-XSD path resolution both dialects rely on.

The schema-check CLI outcomes are driven through simple_mhl's xsd-schema-check
command; bundled_xsd_path is tested directly, including its installed-package →
checkout-sibling fallback.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mhl_suite import xsd_check

from .helpers import make_tree, seal_helper


class TestSchemaCheck:
    """Tests for xsd-schema-check."""

    def test_schema_check_no_xsd(self, mhl_cli, tmp_path):
        """Malformed XML is rejected before schema validation (exit 40)."""
        bad = tmp_path / "bad.mhl"
        bad.write_text("<not valid xml")
        rc, _, _ = mhl_cli(["xsd-schema-check", str(bad)])
        assert rc == 40

    def test_schema_check_valid_manifest(self, mhl_cli, tmp_path):
        """A properly sealed manifest should pass schema validation (exit 0)."""
        make_tree(tmp_path, {"a.bin": b"hello"})
        mhl = seal_helper(mhl_cli, tmp_path)
        rc, _, _ = mhl_cli(["xsd-schema-check", str(mhl)])
        assert rc == 0

    def test_schema_check_invalid_structure(self, mhl_cli, tmp_path):
        """A manifest with unrecognised tags should fail schema validation (exit 41)."""
        bad_mhl = tmp_path / "invalid.mhl"
        bad_mhl.write_text(
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<hashlist version="1.1">\n'
            "  <fake_tag>This breaks the schema</fake_tag>\n"
            "</hashlist>\n"
        )
        rc, _, err = mhl_cli(["xsd-schema-check", str(bad_mhl)])
        assert rc == 41
        assert "XSD validation failed" in err


class TestValidateSchemaXsdNotFound:
    """validate_schema() must exit 1 (broken install) when the bundled XSD is missing."""

    def test_xsd_not_found_exits_1_with_stderr(self, mhl_cli, tmp_path, monkeypatch):
        """When bundled_xsd_path raises FileNotFoundError, xsd-schema-check must
        exit 1 and write an error message to stderr."""

        mhl_file = tmp_path / "dummy.mhl"
        mhl_file.write_text('<?xml version="1.0" encoding="UTF-8"?>\n<hashlist version="1.1"/>\n')

        def _raise(schema_name):
            raise FileNotFoundError("Could not locate MediaHashList_v1_1.xsd (tried /fake/path)")

        monkeypatch.setattr(xsd_check, "bundled_xsd_path", _raise)

        rc, _, err = mhl_cli(["xsd-schema-check", str(mhl_file)])
        assert rc == 1
        assert "could not locate" in err.lower() or "mediahashlist" in err.lower()

    def test_validate_schema_oserror_exits_40(self, mhl_cli, tmp_path):
        """An OSError reading the MHL file (e.g. file disappears after the
        existence check) must produce exit 40."""
        # A directory masquerading as a .mhl file: lxml raises OSError trying
        # to open it, and validate_schema maps that to exit 40.
        mhl_path = tmp_path / "broken.mhl"
        mhl_path.mkdir()
        rc, _, _err = mhl_cli(["xsd-schema-check", str(mhl_path)])
        assert rc == 40


class TestBundledXsdPathFallbackPaths:
    """bundled_xsd_path fallback: importlib.resources raises → local xsd/ sibling."""

    def test_fallback_resolves_against_real_module_layout(self):
        """The checkout fallback must find the bundled XSD at the module's *real*
        location, not a patched one. The other tests fake __file__ to exercise the path arithmetic, which means they
        pass regardless of how deep the module actually sits — so they can't catch a restructure that moves the module
        between directory depths (e.g. the parent.parent → parent flatten). This one forces the importlib path to fail
        and asserts the fallback lands on a file that exists, with no __file__ patching, so it breaks if the relative
        offset stops matching the real tree.
        """
        with patch.object(xsd_check.importlib.resources, "files", side_effect=ImportError("no package")):
            result = xsd_check.bundled_xsd_path("MediaHashList_v1_1.xsd")
        assert Path(result).is_file()
        assert Path(result).name == "MediaHashList_v1_1.xsd"

    def test_resource_present_but_not_a_file_falls_through(self):
        """When files() succeeds but is_file() returns False (e.g. a namespace
        package without the XSD installed), bundled_xsd_path falls through to the checkout fallback rather than
        returning the non-file resource. Resolved against the real layout (no __file__ patch) so it also stays correct
        across restructures."""
        fake_resource = MagicMock()
        fake_resource.is_file.return_value = False
        fake_pkg = MagicMock()
        fake_pkg.joinpath.return_value = fake_resource

        with patch.object(xsd_check.importlib.resources, "files", return_value=fake_pkg):
            result = xsd_check.bundled_xsd_path("MediaHashList_v1_1.xsd")
        assert Path(result).is_file()
        assert Path(result).name == "MediaHashList_v1_1.xsd"

    def test_raises_file_not_found_when_both_paths_absent(self, tmp_path):
        """FileNotFoundError is raised when neither the package resource nor the
        local xsd/ folder exists (tmp_path has no xsd/ subdirectory)."""

        with (
            patch.object(
                xsd_check.importlib.resources,
                "files",
                side_effect=ImportError("no package"),
            ),
            patch.object(xsd_check, "__file__", str(tmp_path / "xsd_check.py")),
            pytest.raises(FileNotFoundError, match=r"MediaHashList_v1_1\.xsd"),
        ):
            xsd_check.bundled_xsd_path("MediaHashList_v1_1.xsd")
