"""Unit tests for VersionController (registrar).

Tests the registrar's version endpoint and the v3 version root endpoint.
"""

import unittest
from typing import cast
from unittest.mock import MagicMock, patch

from keylime import api_version as keylime_api_version
from keylime.web.registrar.version_controller import VersionController


class TestVersionControllerVersion(unittest.TestCase):
    """Test cases for VersionController.version()."""

    def setUp(self):
        """Set up test fixtures."""
        mock_action_handler = MagicMock()
        self.controller = cast(VersionController, VersionController(mock_action_handler))
        self.mock_respond = MagicMock()
        self.controller.respond = self.mock_respond  # type: ignore[assignment]

    def test_version_returns_success(self):
        """Test that version() returns 200 with current and supported versions."""
        self.controller.version()  # pylint: disable=not-callable

        self.mock_respond.assert_called_once()
        call_args = self.mock_respond.call_args[0]
        self.assertEqual(call_args[0], 200)
        self.assertEqual(call_args[1], "Success")

        data = call_args[2]
        self.assertEqual(data["current_version"], keylime_api_version.current_version())
        self.assertEqual(data["supported_versions"], keylime_api_version.all_versions())

    def test_version_includes_v3(self):
        """Test that the supported versions list includes v3.0."""
        self.controller.version()  # pylint: disable=not-callable

        data = self.mock_respond.call_args[0][2]
        self.assertIn("3.0", data["supported_versions"])


class TestVersionControllerShowVersionRoot(unittest.TestCase):
    """Test cases for VersionController.show_version_root()."""

    def setUp(self):
        """Set up test fixtures."""
        mock_action_handler = MagicMock()
        self.controller = cast(VersionController, VersionController(mock_action_handler))

    @patch("keylime.web.registrar.version_controller.APIResource")
    def test_show_version_root_returns_jsonapi_document(self, mock_api_resource):
        """Test that show_version_root() returns a 200 JSON:API document with registrar metadata."""
        mock_resource = MagicMock()
        mock_api_resource.return_value = mock_resource

        self.controller.show_version_root()

        mock_api_resource.assert_called_once_with(
            "registrar",
            {"supported_versions": keylime_api_version.all_versions()},
        )
        mock_resource.send_via.assert_called_once_with(self.controller)

    @patch("keylime.web.registrar.version_controller.APIResource")
    def test_show_version_root_includes_v3_in_supported_versions(self, mock_api_resource):
        """Test that the supported_versions attribute includes v3.0."""
        mock_resource = MagicMock()
        mock_api_resource.return_value = mock_resource

        self.controller.show_version_root()

        attributes = mock_api_resource.call_args[0][1]
        self.assertIn("3.0", attributes["supported_versions"])


if __name__ == "__main__":
    unittest.main()
