"""Unit tests for AgentController (verifier).

Tests the verifier's agent management endpoints including listing,
showing, creating, deleting, and updating agents for v3 API.
"""

import base64
import unittest
from typing import Any, cast
from unittest.mock import MagicMock, patch

from keylime.web.base.action_handler import StopAction
from keylime.web.verifier.agent_controller import AgentController

MODULE = "keylime.web.verifier.agent_controller"


def _v3_controller(query: str = "", body: bytes = b"") -> Any:
    """Create an AgentController with a mocked action handler for v3."""
    mock_action_handler = MagicMock()
    mock_action_handler.request.path = "/v3.0/agents/"
    mock_action_handler.request.query = query
    mock_action_handler.request.body = body
    controller = cast(AgentController, AgentController(mock_action_handler))
    return controller


class TestAgentControllerIndex(unittest.TestCase):
    """Test cases for AgentController.index()."""

    @patch(f"{MODULE}.VerifierAgentModel")
    def test_index_v3_returns_agent_list(self, mock_agent_model):
        """Test that v3 index returns agents as JSON:API resource list."""
        controller = _v3_controller()
        controller.send_response = MagicMock()

        mock_agent = MagicMock()
        mock_agent.agent_id = "test-uuid-1234"
        mock_agent.render.return_value = {
            "operational_state": 3,
            "accept_attestations": True,
            "attestation_count": 5,
            "verifier_id": "default",
        }
        mock_agent_model.all.return_value = [mock_agent]

        controller.index()

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 200)
        body = args[2]
        self.assertIn("data", body)
        self.assertEqual(len(body["data"]), 1)
        self.assertEqual(body["data"][0]["type"], "agent")
        self.assertEqual(body["data"][0]["id"], "test-uuid-1234")

    @patch(f"{MODULE}.VerifierAgentModel")
    def test_index_v3_empty_returns_empty_array(self, mock_agent_model):
        """Test that v3 index returns empty array when no agents exist."""
        controller = _v3_controller()
        controller.send_response = MagicMock()

        mock_agent_model.all.return_value = []

        controller.index()

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 200)
        body = args[2]
        self.assertIn("data", body)
        self.assertEqual(body["data"], [])


class TestAgentControllerShow(unittest.TestCase):
    """Test cases for AgentController.show()."""

    @patch(f"{MODULE}.VerifierAgentModel")
    def test_show_v3_found_returns_resource(self, mock_agent_model):
        """Test that v3 show returns agent as JSON:API resource when found."""
        controller = _v3_controller()
        controller.action_handler.request.path = "/v3.0/agents/test-uuid-1234"
        controller.send_response = MagicMock()

        mock_agent = MagicMock()
        mock_agent.agent_id = "test-uuid-1234"
        mock_agent.render.return_value = {
            "operational_state": 3,
            "ip": "127.0.0.1",
            "port": 9002,
            "attestation_count": 5,
        }
        mock_agent_model.get.return_value = mock_agent

        with self.assertRaises(StopAction):
            controller.show("test-uuid-1234")

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 200)
        body = args[2]
        self.assertIn("data", body)
        self.assertEqual(body["data"]["type"], "agent")
        self.assertEqual(body["data"]["id"], "test-uuid-1234")

    @patch(f"{MODULE}.VerifierAgentModel")
    def test_show_v3_not_found_returns_404(self, mock_agent_model):
        """Test that v3 show returns 404 when agent not found."""
        controller = _v3_controller()
        controller.send_response = MagicMock()

        mock_agent_model.get.return_value = None

        with self.assertRaises(StopAction):
            controller.show("test-uuid-1234")

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 404)
        body = args[2]
        self.assertIn("errors", body)


class TestAgentControllerCreate(unittest.TestCase):
    """Test cases for AgentController.create()."""

    @patch(f"{MODULE}.VerifierAgentModel")
    @patch(f"{MODULE}.resolve_mb_policy_for_agent")
    @patch(f"{MODULE}.resolve_ima_policy_for_agent")
    @patch(f"{MODULE}.validate_mtls_cert")
    @patch(f"{MODULE}.build_agent_data")
    @patch(f"{MODULE}.config")
    def test_create_v3_success_returns_201(
        self, mock_config, mock_build, mock_mtls, mock_ima_svc, mock_mb_svc, mock_agent_model
    ):
        """Test that v3 create succeeds and returns agent resource."""
        controller = _v3_controller()
        controller._api_request_body = MagicMock()  # pylint: disable=protected-access  # Satisfy @require_json_api
        controller.send_response = MagicMock()

        mock_config.get.return_value = "push"
        mock_build.return_value = {"agent_id": "valid-uuid-1234", "supported_version": "2.1", "mtls_cert": None}
        mock_mtls.return_value = None
        mock_ima_policy = MagicMock()
        mock_ima_policy.id = 1
        mock_mb_policy = MagicMock()
        mock_mb_policy.id = 2
        mock_ima_svc.return_value = (mock_ima_policy, None)
        mock_mb_svc.return_value = (mock_mb_policy, None)

        mock_created = MagicMock()
        mock_created.agent_id = "valid-uuid-1234"
        mock_created.render.return_value = {"operational_state": 3, "attestation_count": 0}
        # First .get() call checks for duplicate (returns None), second reads back the created agent
        mock_agent_model.get.side_effect = [None, mock_created]

        agent_data = {
            "id": "valid-uuid-1234",
            "runtime_policy": base64.b64encode(b"{}").decode(),
            "mb_policy_name": "",
            "mb_policy": "{}",
        }

        with self.assertRaises(StopAction):
            controller.create(agent=agent_data)

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        body = args[2]
        self.assertIn("data", body)
        self.assertEqual(body["data"]["type"], "agent")
        self.assertEqual(body["data"]["id"], "valid-uuid-1234")

    @patch(f"{MODULE}.VerifierAgentModel")
    @patch(f"{MODULE}.validate_mtls_cert")
    @patch(f"{MODULE}.build_agent_data")
    @patch(f"{MODULE}.config")
    def test_create_v3_duplicate_returns_409(self, mock_config, mock_build, mock_mtls, mock_agent_model):
        """Test that v3 create returns 409 when agent already exists."""
        controller = _v3_controller()
        controller._api_request_body = MagicMock()  # pylint: disable=protected-access
        controller.send_response = MagicMock()

        mock_config.get.return_value = "push"
        mock_build.return_value = {"agent_id": "valid-uuid-1234", "supported_version": "2.1", "mtls_cert": None}
        mock_mtls.return_value = None
        # Duplicate check: .get() returns an existing agent
        mock_agent_model.get.return_value = MagicMock()

        agent_data = {
            "id": "valid-uuid-1234",
            "runtime_policy": base64.b64encode(b"{}").decode(),
            "mb_policy_name": "",
            "mb_policy": "{}",
        }

        with self.assertRaises(StopAction):
            controller.create(agent=agent_data)

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 409)

    def test_create_v3_missing_data_returns_error(self):
        """Test that v3 create returns error when no agent data provided."""
        controller = _v3_controller()
        controller._api_request_body = MagicMock()  # pylint: disable=protected-access
        controller.send_response = MagicMock()

        with self.assertRaises(StopAction):
            controller.create()

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 400)


class TestAgentControllerDelete(unittest.TestCase):
    """Test cases for AgentController.delete()."""

    @patch(f"{MODULE}._delete_agent_v3")
    @patch(f"{MODULE}.clear_agent_policy_cache")
    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.cloud_verifier_common")
    @patch(f"{MODULE}.VerifierAgentModel")
    def test_delete_v3_push_mode_returns_204(
        self, mock_agent_model, mock_cvc, mock_config, _mock_clear_cache, mock_delete_fn
    ):
        """Test that v3 delete in push mode returns 204."""
        controller = _v3_controller()
        controller.send_response = MagicMock()

        mock_agent = MagicMock()
        mock_agent.verifier_id = "default"
        mock_agent_model.get.return_value = mock_agent
        mock_config.get.side_effect = lambda section, key, **kw: {
            ("verifier", "uuid"): "default",
            ("verifier", "mode"): "push",
        }.get((section, key), kw.get("fallback", ""))
        mock_cvc.DEFAULT_VERIFIER_ID = "default"

        controller.delete("test-uuid-1234")

        mock_delete_fn.assert_called_once()
        controller.send_response.assert_called_once_with(204)

    @patch(f"{MODULE}.VerifierAgentModel")
    def test_delete_v3_not_found_returns_404(self, mock_agent_model):
        """Test that v3 delete returns 404 when agent not found."""
        controller = _v3_controller()
        controller.send_response = MagicMock()

        mock_agent_model.get.return_value = None

        with self.assertRaises(StopAction):
            controller.delete("test-uuid-1234")

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 404)

    @patch(f"{MODULE}.clear_agent_policy_cache")
    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.cloud_verifier_common")
    @patch(f"{MODULE}.VerifierAgentModel")
    def test_delete_v3_pull_active_returns_202(self, mock_agent_model, mock_cvc, mock_config, _mock_clear_cache):
        """Test that v3 delete of active pull-mode agent returns 202."""
        controller = _v3_controller()
        controller.send_response = MagicMock()

        mock_agent = MagicMock()
        mock_agent.verifier_id = "default"
        mock_agent.operational_state = 3  # GET_QUOTE (active)
        mock_agent_model.get.return_value = mock_agent
        mock_config.get.side_effect = lambda section, key, **kw: {
            ("verifier", "uuid"): "default",
            ("verifier", "mode"): "pull",
        }.get((section, key), kw.get("fallback", ""))
        mock_cvc.DEFAULT_VERIFIER_ID = "default"

        controller.delete("test-uuid-1234")

        controller.send_response.assert_called_once_with(202)


class TestAgentControllerUpdate(unittest.TestCase):
    """Test cases for AgentController.update()."""

    @patch(f"{MODULE}.VerifierAgentModel")
    def test_update_v3_success(self, mock_agent_model):
        """Test that v3 update succeeds and returns updated agent resource."""
        controller = _v3_controller()
        controller.action_handler.request.path = "/v3.0/agents/test-uuid-1234"
        controller._api_request_body = MagicMock()  # pylint: disable=protected-access
        controller.send_response = MagicMock()

        mock_existing = MagicMock()
        mock_existing.agent_id = "test-uuid-1234"
        mock_existing.render.return_value = {
            "operational_state": 3,
            "meta_data": "updated",
            "attestation_count": 5,
        }
        mock_agent_model.get.return_value = mock_existing

        with self.assertRaises(StopAction):
            controller.update("test-uuid-1234", agent={"meta_data": "updated"})

        mock_existing.change.assert_called()
        mock_existing.commit_changes.assert_called_once()
        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 200)
        body = args[2]
        self.assertIn("data", body)
        self.assertEqual(body["data"]["type"], "agent")

    @patch(f"{MODULE}.VerifierAgentModel")
    def test_update_v3_not_found_returns_404(self, mock_agent_model):
        """Test that v3 update returns 404 when agent not found."""
        controller = _v3_controller()
        controller._api_request_body = MagicMock()  # pylint: disable=protected-access
        controller.send_response = MagicMock()

        mock_agent_model.get.return_value = None

        with self.assertRaises(StopAction):
            controller.update("test-uuid-1234", agent={"meta_data": "x"})

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 404)

    @patch(f"{MODULE}.VerifierAgentModel")
    def test_update_v3_immutable_field_returns_422(self, mock_agent_model):
        """Test that v3 update rejects immutable fields with 422."""
        controller = _v3_controller()
        controller._api_request_body = MagicMock()  # pylint: disable=protected-access
        controller.send_response = MagicMock()

        mock_existing = MagicMock()
        mock_agent_model.get.return_value = mock_existing

        with self.assertRaises(StopAction):
            controller.update("test-uuid-1234", agent={"ak_tpm": "should_not_change"})

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 422)

    @patch(f"{MODULE}.IMAPolicy")
    @patch(f"{MODULE}.VerifierAgentModel")
    def test_update_v3_policy_reassignment(self, mock_agent_model, mock_ima_policy):
        """Test that v3 update can reassign IMA policy by name."""
        controller = _v3_controller()
        controller.action_handler.request.path = "/v3.0/agents/test-uuid-1234"
        controller._api_request_body = MagicMock()  # pylint: disable=protected-access
        controller.send_response = MagicMock()

        mock_existing = MagicMock()
        mock_existing.agent_id = "test-uuid-1234"
        mock_existing.render.return_value = {"operational_state": 3}
        mock_agent_model.get.return_value = mock_existing

        mock_policy = MagicMock()
        mock_policy.id = 42
        mock_ima_policy.get.return_value = mock_policy

        with self.assertRaises(StopAction):
            controller.update("test-uuid-1234", agent={"ima_policy_name": "new_policy"})

        mock_existing.change.assert_any_call("ima_policy_id", 42)
        mock_existing.commit_changes.assert_called_once()


if __name__ == "__main__":
    unittest.main()
