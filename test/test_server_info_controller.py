"""Unit tests for ServerInfoController (verifier).

Tests the verifier's server info endpoints including version reporting,
root redirect, and version root responses for both v2 (pull) and v3+
(push) modes.
"""

import unittest
from typing import Any, cast
from unittest.mock import MagicMock, patch

from keylime.web.verifier.server_info_controller import ServerInfoController


def _make_controller() -> Any:
    """Create a ServerInfoController with a mocked action handler."""
    mock_action_handler = MagicMock()
    return cast(ServerInfoController, ServerInfoController(mock_action_handler))


class TestServerInfoControllerShowRoot(unittest.TestCase):
    """Test cases for ServerInfoController.show_root()."""

    def setUp(self):
        self.controller = _make_controller()
        self.controller.redirect = MagicMock()

    @patch("keylime.web.verifier.server_info_controller.api_version")
    def test_show_root_redirects_to_v3_when_current_is_v3(self, mock_api_version):
        """Test that show_root redirects to v3 path when current version is 3.x."""
        mock_api_version.current_version.return_value = "3.0"
        mock_api_version.major.return_value = 3
        mock_api_version.latest_minor_version.return_value = "3.0"

        self.controller.show_root()

        self.controller.redirect.assert_called_once_with("/v3.0/")

    @patch("keylime.web.verifier.server_info_controller.api_version")
    def test_show_root_redirects_to_current_version_when_above_v3(self, mock_api_version):
        """Test that show_root redirects to current version path when > v3."""
        mock_api_version.current_version.return_value = "4.1"
        mock_api_version.major.return_value = 4

        self.controller.show_root()

        self.controller.redirect.assert_called_once_with("/v4.1/")


class TestServerInfoControllerShowVersionRoot(unittest.TestCase):
    """Test cases for ServerInfoController.show_version_root()."""

    def setUp(self):
        self.controller = _make_controller()
        self.controller.respond = MagicMock()

    def test_show_version_root_v2_returns_405(self):
        """Test that v2 version root returns 405 with proper message."""
        self.controller.action_handler.request.path = "/v2.0/"

        self.controller.show_version_root()

        self.controller.respond.assert_called_once_with(405, "Not Implemented: Use /agents/ interface instead")

    def test_show_version_root_v1_returns_405(self):
        """Test that v1 version root also returns 405."""
        self.controller.action_handler.request.path = "/v1.0/"

        self.controller.show_version_root()

        self.controller.respond.assert_called_once_with(405, "Not Implemented: Use /agents/ interface instead")

    def test_show_version_root_v3_returns_200(self):
        """Test that v3+ version root returns 200."""
        self.controller.action_handler.request.path = "/v3.0/"

        self.controller.show_version_root()

        self.controller.respond.assert_called_once_with(200)


class TestServerInfoControllerShowVersions(unittest.TestCase):
    """Test cases for ServerInfoController.show_versions()."""

    def setUp(self):
        self.controller = _make_controller()
        self.controller.respond = MagicMock()

    @patch("keylime.web.verifier.server_info_controller.config")
    @patch("keylime.web.verifier.server_info_controller.api_version")
    def test_show_versions_pull_mode_returns_version_info(self, mock_api_version, mock_config):
        """Test that pull mode returns version information with 200."""
        mock_config.get.return_value = "pull"
        mock_api_version.current_version.return_value = "2.1"
        mock_api_version.all_versions.return_value = ["1.0", "2.0", "2.1"]

        self.controller.show_versions()

        expected_data = {
            "current_version": "2.1",
            "supported_versions": ["1.0", "2.0", "2.1"],
        }
        self.controller.respond.assert_called_once_with(200, "Success", expected_data)

    @patch("keylime.web.verifier.server_info_controller.config")
    def test_show_versions_push_mode_returns_410(self, mock_config):
        """Test that push mode returns 410 Gone."""
        mock_config.get.return_value = "push"

        self.controller.show_versions()

        self.controller.respond.assert_called_once_with(410, "Gone")


if __name__ == "__main__":
    unittest.main()
