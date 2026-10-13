"""Unit tests for IdentityController (verifier).

Tests the verifier's identity verification endpoint, covering:
- v2 delegation to the legacy VerifyIdentityHandler
- v3 410 Gone response (endpoint is intentionally removed in push-mode)
"""

import unittest
from typing import Any, cast
from unittest.mock import MagicMock, patch

from keylime.web.base.action_handler import StopAction
from keylime.web.verifier.identity_controller import IdentityController

MODULE = "keylime.web.verifier.identity_controller"


def _controller_for_version(major: int) -> Any:
    """Create an IdentityController with a mocked action handler."""
    mock_action_handler = MagicMock()
    mock_action_handler.request.path = f"/v{major}.0/verify/identity"
    mock_action_handler.request.body = b""
    controller = cast(IdentityController, IdentityController(mock_action_handler))
    controller.send_response = MagicMock()
    return controller


class TestIdentityControllerV2(unittest.TestCase):
    """Test that v2 requests delegate to the legacy handler."""

    def test_verify_delegates_to_legacy_handler(self):
        """For major version 2, verify() calls the legacy VerifyIdentityHandler.get()."""
        controller = _controller_for_version(2)
        mock_handler = MagicMock()

        with patch.object(controller, "_new_v2_handler", return_value=mock_handler):
            controller.verify()

        mock_handler.get.assert_called_once()
        controller.send_response.assert_not_called()


class TestIdentityControllerV3(unittest.TestCase):
    """Test that v3 requests receive 410 Gone."""

    def test_verify_returns_410_for_v3(self):
        """For major version 3+, verify() must respond with HTTP 410 Gone."""
        controller = _controller_for_version(3)

        with self.assertRaises(StopAction):
            controller.verify()

        controller.send_response.assert_called_once()
        status_code = controller.send_response.call_args[0][0]
        self.assertEqual(status_code, 410, f"Expected 410 Gone, got {status_code}")

    def test_verify_410_response_is_json_api(self):
        """The 410 response must use the JSON:API content type."""
        controller = _controller_for_version(3)

        with self.assertRaises(StopAction):
            controller.verify()

        content_type = controller.send_response.call_args[0][3]
        self.assertIn("vnd.api+json", content_type)

    def test_verify_410_body_contains_error(self):
        """The 410 response body must contain a JSON:API errors array."""
        controller = _controller_for_version(3)

        with self.assertRaises(StopAction):
            controller.verify()

        body = controller.send_response.call_args[0][2]
        self.assertIn("errors", body)
        self.assertTrue(len(body["errors"]) > 0)

    def test_verify_410_error_mentions_push_mode(self):
        """The 410 error detail must explain why the endpoint is unavailable in push mode."""
        controller = _controller_for_version(3)

        with self.assertRaises(StopAction):
            controller.verify()

        body = controller.send_response.call_args[0][2]
        error_detail = body["errors"][0].get("detail", "")
        self.assertIn("push", error_detail.lower())
