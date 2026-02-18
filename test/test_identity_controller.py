"""Unit tests for IdentityController (verifier).

Tests the verifier's identity verification endpoint including parameter
validation, agent lookup, and quote verification for v2 API.
"""

import unittest
from typing import Any, cast
from unittest.mock import MagicMock, patch

from keylime.web.verifier.identity_controller import IdentityController

MODULE = "keylime.web.verifier.identity_controller"

VALID_QUERY = "agent_uuid=test-uuid&quote=test-quote&nonce=test-nonce&hash_alg=sha256"


def _make_controller(query: str = VALID_QUERY) -> Any:
    """Create an IdentityController with a mocked action handler."""
    mock_action_handler = MagicMock()
    mock_action_handler.request.path = "/v2.1/verify/identity"
    mock_action_handler.request.query = query
    controller = cast(IdentityController, IdentityController(mock_action_handler))
    return controller


def _v3_controller() -> Any:
    """Create a controller with request path set to v3."""
    ctrl = _make_controller()
    ctrl.action_handler.request.path = "/v3.0/verify/identity"
    return ctrl


class TestIdentityControllerMissingParams(unittest.TestCase):
    """Test cases for missing query parameters."""

    def test_missing_agent_uuid_returns_400(self):
        """Test that missing agent_uuid returns 400."""
        controller = _make_controller(query="quote=q&nonce=n&hash_alg=h")
        controller.respond = MagicMock()

        controller.verify()

        controller.respond.assert_called_once_with(400, "missing query parameter 'agent_uuid'")

    def test_empty_agent_uuid_returns_400(self):
        """Test that empty agent_uuid returns 400."""
        controller = _make_controller(query="agent_uuid=&quote=q&nonce=n&hash_alg=h")
        controller.respond = MagicMock()

        controller.verify()

        controller.respond.assert_called_once_with(400, "missing query parameter 'agent_uuid'")

    def test_missing_quote_returns_400(self):
        """Test that missing quote returns 400."""
        controller = _make_controller(query="agent_uuid=a&nonce=n&hash_alg=h")
        controller.respond = MagicMock()

        controller.verify()

        controller.respond.assert_called_once_with(400, "missing query parameter 'quote'")

    def test_missing_nonce_returns_400(self):
        """Test that missing nonce returns 400."""
        controller = _make_controller(query="agent_uuid=a&quote=q&hash_alg=h")
        controller.respond = MagicMock()

        controller.verify()

        controller.respond.assert_called_once_with(400, "missing query parameter 'nonce'")

    def test_missing_hash_alg_returns_400(self):
        """Test that missing hash_alg returns 400."""
        controller = _make_controller(query="agent_uuid=a&quote=q&nonce=n")
        controller.respond = MagicMock()

        controller.verify()

        controller.respond.assert_called_once_with(400, "missing query parameter 'hash_alg'")


class TestIdentityControllerVerify(unittest.TestCase):
    """Test cases for IdentityController.verify()."""

    def setUp(self):
        self.controller = _make_controller()
        self.controller.respond = MagicMock()

    @patch(f"{MODULE}.cloud_verifier_common")
    @patch(f"{MODULE}.get_AgentAttestStates")
    @patch(f"{MODULE}.session_context")
    def test_verify_v2_success(self, mock_session_ctx, mock_get_aas, mock_cvc):
        """Test that v2 verify returns 200 with valid=1 on success."""
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_agent = MagicMock()
        mock_session.query.return_value.options.return_value.filter_by.return_value.one_or_none.return_value = (
            mock_agent
        )
        mock_attest_state = MagicMock()
        mock_get_aas.return_value.get_by_agent_id.return_value = mock_attest_state
        mock_cvc.process_verify_identity_quote.return_value = None

        self.controller.verify()

        self.controller.respond.assert_called_once_with(200, "Success", {"valid": 1})

    @patch(f"{MODULE}.cloud_verifier_common")
    @patch(f"{MODULE}.get_AgentAttestStates")
    @patch(f"{MODULE}.session_context")
    def test_verify_v2_failure(self, mock_session_ctx, mock_get_aas, mock_cvc):
        """Test that v2 verify returns 200 with valid=0 on validation failure."""
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_agent = MagicMock()
        mock_session.query.return_value.options.return_value.filter_by.return_value.one_or_none.return_value = (
            mock_agent
        )
        mock_attest_state = MagicMock()
        mock_get_aas.return_value.get_by_agent_id.return_value = mock_attest_state
        mock_failure = MagicMock()
        mock_failure.__bool__ = MagicMock(return_value=True)
        mock_event = MagicMock()
        mock_event.context = "quote mismatch"
        mock_failure.events = [mock_event]
        mock_cvc.process_verify_identity_quote.return_value = mock_failure

        self.controller.verify()

        self.controller.respond.assert_called_once_with(200, "Success", {"valid": 0, "reason": "quote mismatch"})

    @patch(f"{MODULE}.session_context")
    def test_verify_v2_agent_not_found(self, mock_session_ctx):
        """Test that v2 verify returns 404 when agent not found."""
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.options.return_value.filter_by.return_value.one_or_none.return_value = None

        self.controller.verify()

        self.controller.respond.assert_called_once_with(404, "agent id not found")

    def test_verify_v3_returns_404(self):
        """Test that v3+ verify returns 404 (not yet implemented)."""
        controller = _v3_controller()
        controller.respond = MagicMock()

        controller.verify()

        controller.respond.assert_called_once_with(404)


if __name__ == "__main__":
    unittest.main()
