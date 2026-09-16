"""Unit tests for ServerInfoController (verifier).

Tests the verifier's server info endpoints including version reporting,
root redirect, and version root responses for v3+ API.
"""

import unittest
from typing import Any, cast
from unittest.mock import MagicMock, patch

from keylime import api_version
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

    @patch("keylime.web.verifier.server_info_controller.APIResource")
    @patch("keylime.web.verifier.server_info_controller.config")
    @patch("keylime.web.verifier.server_info_controller.cloud_verifier_common")
    def test_show_version_root_v3_returns_jsonapi_document(self, mock_cvc, mock_config, mock_api_resource):
        """Test that v3+ version root returns a JSON:API document with verifier metadata."""
        self.controller.action_handler.request.path = "/v3.0/"
        mock_cvc.DEFAULT_VERIFIER_ID = "default"
        mock_config.get.side_effect = lambda section, key, fallback=None: {
            ("verifier", "uuid"): "my-verifier-uuid",
            ("verifier", "mode"): "push",
        }.get((section, key), fallback)
        mock_config.getboolean.return_value = False
        mock_resource = MagicMock()
        mock_api_resource.return_value = mock_resource

        self.controller.show_version_root()

        mock_api_resource.assert_called_once_with(
            "verifier",
            "my-verifier-uuid",
            {
                "mode": "push",
                "supported_versions": api_version.all_versions(),
                "require_allow_list_signatures": False,
            },
        )
        mock_resource.send_via.assert_called_once_with(self.controller)

    @patch("keylime.web.verifier.server_info_controller.APIResource")
    @patch("keylime.web.verifier.server_info_controller.config")
    @patch("keylime.web.verifier.server_info_controller.cloud_verifier_common")
    def test_show_version_root_v3_mode_defaults_to_pull_when_empty(self, mock_cvc, mock_config, mock_api_resource):
        """Test that an empty mode config value is normalised to 'pull'."""
        self.controller.action_handler.request.path = "/v3.0/"
        mock_cvc.DEFAULT_VERIFIER_ID = "default"
        mock_config.get.side_effect = lambda section, key, fallback=None: {
            ("verifier", "uuid"): "default",
            ("verifier", "mode"): "",
        }.get((section, key), fallback)
        mock_config.getboolean.return_value = False
        mock_resource = MagicMock()
        mock_api_resource.return_value = mock_resource

        self.controller.show_version_root()

        _, _, attrs = mock_api_resource.call_args[0]
        self.assertEqual(attrs["mode"], "pull")

    def test_show_version_root_v2_delegates_to_v2_handler(self):
        """Test that v2 version root delegates to the legacy v2 MainHandler."""
        self.controller.action_handler.request.path = "/v2.1/"
        mock_v2_handler = MagicMock()
        # pylint: disable-next=protected-access
        self.controller._new_v2_main_handler = MagicMock(return_value=mock_v2_handler)  # type: ignore[method-assign]

        self.controller.show_version_root()

        # pylint: disable-next=protected-access
        self.controller._new_v2_main_handler.assert_called_once()
        mock_v2_handler.get.assert_called_once()


class TestServerInfoControllerShowVersions(unittest.TestCase):
    """Test cases for ServerInfoController.show_versions()."""

    def setUp(self):
        self.controller = _make_controller()
        self.controller.respond = MagicMock()

    @patch("keylime.web.verifier.server_info_controller.config")
    def test_show_versions_push_mode_returns_410(self, mock_config):
        """Test that push mode returns 410 Gone."""
        mock_config.get.return_value = "push"

        self.controller.show_versions()

        self.controller.respond.assert_called_once_with(410, "Gone")


if __name__ == "__main__":
    unittest.main()
