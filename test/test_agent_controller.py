"""Unit tests for AgentController (verifier).

Tests the verifier's agent management endpoints including listing,
showing, creating, deleting, reactivating, and stopping agents for v2 API.
"""

import base64
import json as std_json
import unittest
from typing import Any, cast
from unittest.mock import MagicMock, patch

from keylime.web.base.action_handler import StopAction
from keylime.web.verifier.agent_controller import AgentController

MODULE = "keylime.web.verifier.agent_controller"


def _make_controller(path: str = "/v2.1/agents/", query: str = "", body: bytes = b"") -> Any:
    """Create an AgentController with a mocked action handler."""
    mock_action_handler = MagicMock()
    mock_action_handler.request.path = path
    mock_action_handler.request.query = query
    mock_action_handler.request.body = body
    controller = cast(AgentController, AgentController(mock_action_handler))
    return controller


def _v3_controller() -> Any:
    """Create a controller with request path set to v3."""
    return _make_controller(path="/v3.0/agents/")


class TestAgentControllerIndex(unittest.TestCase):
    """Test cases for AgentController.index()."""

    @patch(f"{MODULE}.session_context")
    def test_index_v2_returns_uuid_list(self, mock_session_ctx):
        """Test that v2 index returns list of agent UUIDs."""
        controller = _make_controller()
        controller.respond = MagicMock()
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.all.return_value = [("uuid1",), ("uuid2",)]

        controller.index()

        controller.respond.assert_called_once_with(200, "Success", {"uuids": [("uuid1",), ("uuid2",)]})

    @patch(f"{MODULE}.cloud_verifier_common")
    @patch(f"{MODULE}.session_context")
    def test_index_v2_bulk_returns_status(self, mock_session_ctx, mock_cvc):
        """Test that v2 index with bulk param returns agent statuses."""
        controller = _make_controller(query="bulk=true")
        controller.respond = MagicMock()
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_agent = MagicMock()
        mock_agent.agent_id = "uuid1"
        mock_session.query.return_value.options.return_value.options.return_value.all.return_value = [mock_agent]
        mock_cvc.process_get_status.return_value = {"status": "ok"}

        controller.index()

        call_args = controller.respond.call_args
        self.assertEqual(call_args[0][0], 200)
        self.assertEqual(call_args[0][1], "Success")
        self.assertIn("uuid1", call_args[0][2])

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

    @patch(f"{MODULE}.cloud_verifier_common")
    @patch(f"{MODULE}.session_context")
    def test_show_v2_found_returns_status(self, mock_session_ctx, mock_cvc):
        """Test that v2 show returns agent status when found."""
        controller = _make_controller(path="/v2.1/agents/valid-uuid-1234")
        controller.respond = MagicMock()
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_agent = MagicMock()
        mock_session.query.return_value.options.return_value.options.return_value.filter_by.return_value.one_or_none.return_value = (
            mock_agent
        )
        mock_cvc.process_get_status.return_value = {"status": "ok"}

        controller.show("valid-uuid-1234")

        controller.respond.assert_called_once_with(200, "Success", {"status": "ok"})

    @patch(f"{MODULE}.session_context")
    def test_show_v2_not_found_returns_404(self, mock_session_ctx):
        """Test that v2 show returns 404 when agent not found."""
        controller = _make_controller(path="/v2.1/agents/valid-uuid-1234")
        controller.respond = MagicMock()
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.options.return_value.options.return_value.filter_by.return_value.one_or_none.return_value = (
            None
        )

        controller.show("valid-uuid-1234")

        controller.respond.assert_called_once_with(404, "agent id not found")

    @patch(f"{MODULE}.validators")
    def test_show_v2_invalid_agent_id_returns_400(self, mock_validators):
        """Test that v2 show returns 400 for invalid agent ID."""
        controller = _make_controller(path="/v2.1/agents/invalid!")
        controller.respond = MagicMock()
        mock_validators.valid_agent_id.return_value = False

        controller.show("invalid!")

        controller.respond.assert_called_once_with(400, "agent_id not not valid")

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

    def test_create_v2_no_agent_id_returns_400(self):
        """Test that v2 create returns 400 when agent_id is missing."""
        controller = _make_controller()
        controller.respond = MagicMock()
        controller.action_handler.matching_route = None

        controller.create()

        controller.respond.assert_called_once_with(400, "uri not supported")

    def test_create_v2_empty_body_returns_400(self):
        """Test that v2 create returns 400 when body is empty."""
        controller = _make_controller(body=b"")
        controller.respond = MagicMock()
        controller.action_handler.matching_route.capture_params.return_value = {"agent_id": "valid-uuid-1234"}

        controller.create()

        controller.respond.assert_called_once_with(400, "Expected non zero content length")

    @patch(f"{MODULE}.validators")
    def test_create_v2_invalid_agent_id_returns_400(self, mock_validators):
        """Test that v2 create returns 400 for invalid agent ID."""
        controller = _make_controller()
        controller.respond = MagicMock()
        mock_validators.valid_agent_id.return_value = False
        controller.action_handler.matching_route.capture_params.return_value = {"agent_id": "invalid!"}

        controller.create()

        controller.respond.assert_called_once_with(400, "agent_id not not valid")

    @patch(f"{MODULE}.resolve_mb_policy_for_agent")
    @patch(f"{MODULE}.resolve_ima_policy_for_agent")
    @patch(f"{MODULE}.validate_mtls_cert")
    @patch(f"{MODULE}.build_agent_data")
    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.session_context")
    def test_create_v2_duplicate_agent_returns_409(
        self, mock_session_ctx, mock_config, mock_build, mock_mtls, _mock_ima_svc, _mock_mb_svc
    ):
        """Test that v2 create returns 409 when agent already exists."""
        body = {
            "runtime_policy": base64.b64encode(b"{}").decode(),
            "mb_policy_name": "",
            "mb_policy": "{}",
        }
        controller = _make_controller(body=std_json.dumps(body).encode())
        controller.respond = MagicMock()
        controller.action_handler.matching_route.capture_params.return_value = {"agent_id": "valid-uuid-1234"}
        mock_config.get.return_value = "pull"
        mock_build.return_value = {"agent_id": "valid-uuid-1234", "supported_version": "2.1", "mtls_cert": None}
        mock_mtls.return_value = None
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        # Agent count > 0 means duplicate
        mock_session.query.return_value.filter_by.return_value.count.return_value = 1

        controller.create()

        # Should respond with 409
        call_args = controller.respond.call_args
        self.assertEqual(call_args[0][0], 409)
        self.assertIn("already exists", call_args[0][1])

    @patch(f"{MODULE}.resolve_mb_policy_for_agent")
    @patch(f"{MODULE}.resolve_ima_policy_for_agent")
    @patch(f"{MODULE}.validate_mtls_cert")
    @patch(f"{MODULE}.build_agent_data")
    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.session_context")
    def test_create_v2_ima_policy_error_returns_error(
        self, mock_session_ctx, mock_config, mock_build, mock_mtls, mock_ima_svc, _mock_mb_svc
    ):
        """Test that v2 create returns error when IMA policy resolution fails."""
        body = {
            "runtime_policy": base64.b64encode(b"{}").decode(),
            "mb_policy_name": "",
            "mb_policy": "{}",
        }
        controller = _make_controller(body=std_json.dumps(body).encode())
        controller.respond = MagicMock()
        controller.action_handler.matching_route.capture_params.return_value = {"agent_id": "valid-uuid-1234"}
        mock_config.get.return_value = "pull"
        mock_build.return_value = {"agent_id": "valid-uuid-1234", "supported_version": "2.1", "mtls_cert": None}
        mock_mtls.return_value = None
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.filter_by.return_value.count.return_value = 0
        mock_ima_svc.return_value = (None, (409, "IMA policy already exists"))

        controller.create()

        controller.respond.assert_called_once_with(409, "IMA policy already exists")

    @patch(f"{MODULE}.resolve_mb_policy_for_agent")
    @patch(f"{MODULE}.resolve_ima_policy_for_agent")
    @patch(f"{MODULE}.validate_mtls_cert")
    @patch(f"{MODULE}.build_agent_data")
    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.session_context")
    def test_create_v2_mb_policy_error_returns_error(
        self, mock_session_ctx, mock_config, mock_build, mock_mtls, mock_ima_svc, mock_mb_svc
    ):
        """Test that v2 create returns error when MB policy resolution fails."""
        body = {
            "runtime_policy": base64.b64encode(b"{}").decode(),
            "mb_policy_name": "",
            "mb_policy": "{}",
        }
        controller = _make_controller(body=std_json.dumps(body).encode())
        controller.respond = MagicMock()
        controller.action_handler.matching_route.capture_params.return_value = {"agent_id": "valid-uuid-1234"}
        mock_config.get.return_value = "pull"
        mock_build.return_value = {"agent_id": "valid-uuid-1234", "supported_version": "2.1", "mtls_cert": None}
        mock_mtls.return_value = None
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.filter_by.return_value.count.return_value = 0
        mock_ima_svc.return_value = (MagicMock(), None)
        mock_mb_svc.return_value = (None, (404, "mb_policy not found"))

        controller.create()

        controller.respond.assert_called_once_with(404, "mb_policy not found")

    @patch(f"{MODULE}.resolve_mb_policy_for_agent")
    @patch(f"{MODULE}.resolve_ima_policy_for_agent")
    @patch(f"{MODULE}.validate_mtls_cert")
    @patch(f"{MODULE}.build_agent_data")
    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.session_context")
    def test_create_v2_success_returns_200(
        self, mock_session_ctx, mock_config, mock_build, mock_mtls, mock_ima_svc, mock_mb_svc
    ):
        """Test that v2 create returns 200 on successful enrollment."""
        body = {
            "runtime_policy": base64.b64encode(b"{}").decode(),
            "mb_policy_name": "",
            "mb_policy": "{}",
        }
        controller = _make_controller(body=std_json.dumps(body).encode())
        controller.respond = MagicMock()
        controller.action_handler.matching_route.capture_params.return_value = {"agent_id": "valid-uuid-1234"}
        mock_config.get.return_value = "push"
        mock_build.return_value = {"agent_id": "valid-uuid-1234", "supported_version": "2.1", "mtls_cert": None}
        mock_mtls.return_value = None
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.filter_by.return_value.count.return_value = 0
        mock_ima_svc.return_value = (MagicMock(), None)
        mock_mb_svc.return_value = (MagicMock(), None)

        controller.create()

        controller.respond.assert_called_once_with(200, "Success")

    @patch(f"{MODULE}.VerifierAgentModel")
    @patch(f"{MODULE}.resolve_mb_policy_for_agent")
    @patch(f"{MODULE}.resolve_ima_policy_for_agent")
    @patch(f"{MODULE}.validate_mtls_cert")
    @patch(f"{MODULE}.build_agent_data")
    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.session_context")
    def test_create_v3_success_returns_201(
        self, mock_session_ctx, mock_config, mock_build, mock_mtls, mock_ima_svc, mock_mb_svc, mock_agent_model
    ):
        """Test that v3 create succeeds and returns agent resource."""
        controller = _v3_controller()
        controller._api_request_body = MagicMock()  # Satisfy @require_json_api
        controller.send_response = MagicMock()

        mock_config.get.return_value = "push"
        mock_build.return_value = {"agent_id": "valid-uuid-1234", "supported_version": "2.1", "mtls_cert": None}
        mock_mtls.return_value = None
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.filter_by.return_value.count.return_value = 0
        mock_ima_svc.return_value = (MagicMock(), None)
        mock_mb_svc.return_value = (MagicMock(), None)

        mock_created = MagicMock()
        mock_created.agent_id = "valid-uuid-1234"
        mock_created.render.return_value = {"operational_state": 3, "attestation_count": 0}
        mock_agent_model.get.return_value = mock_created

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

    @patch(f"{MODULE}.validate_mtls_cert")
    @patch(f"{MODULE}.build_agent_data")
    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.session_context")
    def test_create_v3_duplicate_returns_409(self, mock_session_ctx, mock_config, mock_build, mock_mtls):
        """Test that v3 create returns 409 when agent already exists."""
        controller = _v3_controller()
        controller._api_request_body = MagicMock()
        controller.send_response = MagicMock()

        mock_config.get.return_value = "push"
        mock_build.return_value = {"agent_id": "valid-uuid-1234", "supported_version": "2.1", "mtls_cert": None}
        mock_mtls.return_value = None
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.filter_by.return_value.count.return_value = 1  # Duplicate

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
        controller._api_request_body = MagicMock()
        controller.send_response = MagicMock()

        with self.assertRaises(StopAction):
            controller.create()

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 400)


class TestAgentControllerDelete(unittest.TestCase):
    """Test cases for AgentController.delete()."""

    @patch(f"{MODULE}.clear_agent_policy_cache")
    @patch(f"{MODULE}.verifier_db_delete_agent")
    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.cloud_verifier_common")
    @patch(f"{MODULE}.session_context")
    def test_delete_v2_terminal_state_returns_200(
        self, mock_session_ctx, mock_cvc, mock_config, mock_db_delete, _mock_clear_cache
    ):
        """Test that v2 delete of terminal-state agent returns 200."""
        controller = _make_controller(path="/v2.1/agents/valid-uuid-1234")
        controller.respond = MagicMock()
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_agent = MagicMock()
        mock_agent.verifier_id = "default"
        mock_agent.operational_state = 8  # states.TERMINATED
        mock_session.query.return_value.filter_by.return_value.first.return_value = mock_agent
        mock_config.get.side_effect = lambda section, key, **kw: {
            ("verifier", "uuid"): "default",
            ("verifier", "mode"): "pull",
        }.get((section, key), kw.get("fallback", ""))
        mock_cvc.DEFAULT_VERIFIER_ID = "default"

        controller.delete("valid-uuid-1234")

        mock_db_delete.assert_called_once()
        controller.respond.assert_called_once_with(200, "Success")

    @patch(f"{MODULE}.clear_agent_policy_cache")
    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.cloud_verifier_common")
    @patch(f"{MODULE}.session_context")
    def test_delete_v2_active_state_returns_202(self, mock_session_ctx, mock_cvc, mock_config, _mock_clear_cache):
        """Test that v2 delete of active-state agent returns 202."""
        controller = _make_controller(path="/v2.1/agents/valid-uuid-1234")
        controller.respond = MagicMock()
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_agent = MagicMock()
        mock_agent.verifier_id = "default"
        mock_agent.operational_state = 3  # states.GET_QUOTE (active)
        mock_session.query.return_value.filter_by.return_value.first.return_value = mock_agent
        mock_update_agent = MagicMock()
        mock_session.get.return_value = mock_update_agent
        mock_config.get.side_effect = lambda section, key, **kw: {
            ("verifier", "uuid"): "default",
            ("verifier", "mode"): "pull",
        }.get((section, key), kw.get("fallback", ""))
        mock_cvc.DEFAULT_VERIFIER_ID = "default"

        controller.delete("valid-uuid-1234")

        controller.respond.assert_called_once_with(202, "Accepted")

    @patch(f"{MODULE}.session_context")
    def test_delete_v2_not_found_returns_404(self, mock_session_ctx):
        """Test that v2 delete returns 404 when agent not found."""
        controller = _make_controller(path="/v2.1/agents/valid-uuid-1234")
        controller.respond = MagicMock()
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.filter_by.return_value.first.return_value = None

        controller.delete("valid-uuid-1234")

        controller.respond.assert_called_once_with(404, "agent id not found")

    @patch(f"{MODULE}.cloud_verifier_common")
    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.session_context")
    def test_delete_v2_wrong_verifier_returns_404(self, mock_session_ctx, mock_config, mock_cvc):
        """Test that v2 delete returns 404 when agent belongs to different verifier."""
        controller = _make_controller(path="/v2.1/agents/valid-uuid-1234")
        controller.respond = MagicMock()
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_agent = MagicMock()
        mock_agent.verifier_id = "other-verifier"
        mock_session.query.return_value.filter_by.return_value.first.return_value = mock_agent
        mock_config.get.return_value = "my-verifier"
        mock_cvc.DEFAULT_VERIFIER_ID = "default"

        controller.delete("valid-uuid-1234")

        controller.respond.assert_called_once_with(404, "agent id associated to this verifier")

    @patch(f"{MODULE}.clear_agent_policy_cache")
    @patch(f"{MODULE}.verifier_db_delete_agent")
    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.cloud_verifier_common")
    @patch(f"{MODULE}.session_context")
    def test_delete_v2_push_mode_returns_200(
        self, mock_session_ctx, mock_cvc, mock_config, mock_db_delete, _mock_clear_cache
    ):
        """Test that v2 delete in push mode always returns 200."""
        controller = _make_controller(path="/v2.1/agents/valid-uuid-1234")
        controller.respond = MagicMock()
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_agent = MagicMock()
        mock_agent.verifier_id = "default"
        mock_session.query.return_value.filter_by.return_value.first.return_value = mock_agent
        mock_config.get.side_effect = lambda section, key, **kw: {
            ("verifier", "uuid"): "default",
            ("verifier", "mode"): "push",
        }.get((section, key), kw.get("fallback", ""))
        mock_cvc.DEFAULT_VERIFIER_ID = "default"

        controller.delete("valid-uuid-1234")

        mock_db_delete.assert_called_once()
        controller.respond.assert_called_once_with(200, "Success")

    @patch(f"{MODULE}.verifier_db_delete_agent")
    @patch(f"{MODULE}.clear_agent_policy_cache")
    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.cloud_verifier_common")
    @patch(f"{MODULE}.session_context")
    @patch(f"{MODULE}.VerifierAgentModel")
    def test_delete_v3_push_mode_returns_204(
        self, mock_agent_model, mock_session_ctx, mock_cvc, mock_config, _mock_clear_cache, mock_db_delete
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
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)

        controller.delete("test-uuid-1234")

        mock_db_delete.assert_called_once()
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
    @patch(f"{MODULE}.session_context")
    @patch(f"{MODULE}.VerifierAgentModel")
    def test_delete_v3_pull_active_returns_202(
        self, mock_agent_model, mock_session_ctx, mock_cvc, mock_config, _mock_clear_cache
    ):
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
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_update_agent = MagicMock()
        mock_session.get.return_value = mock_update_agent

        controller.delete("test-uuid-1234")

        controller.send_response.assert_called_once_with(202)


class TestAgentControllerReactivate(unittest.TestCase):
    """Test cases for AgentController.reactivate()."""

    @patch(f"{MODULE}.cloud_verifier_common")
    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.session_context")
    def test_reactivate_v2_push_mode_returns_200(self, mock_session_ctx, mock_config, mock_cvc):
        """Test that v2 reactivate in push mode re-enables attestations."""
        controller = _make_controller(path="/v2.1/agents/valid-uuid-1234/reactivate")
        controller.respond = MagicMock()
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_agent = MagicMock()
        mock_agent.ip = None
        mock_agent.port = None
        mock_session.query.return_value.filter_by.return_value.one.return_value = mock_agent
        mock_config.get.return_value = "default"
        mock_cvc.DEFAULT_VERIFIER_ID = "default"

        controller.reactivate("valid-uuid-1234")

        controller.respond.assert_called_once_with(200, "Success")

    @patch(f"{MODULE}.cloud_verifier_common")
    @patch(f"{MODULE}._from_db_obj")
    @patch(f"{MODULE}.web_util")
    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.session_context")
    def test_reactivate_v2_pull_mode_returns_200(
        self, mock_session_ctx, mock_config, _mock_web_util, mock_from_db_obj, mock_cvc
    ):
        """Test that v2 reactivate in pull mode starts polling."""
        controller = _make_controller(path="/v2.1/agents/valid-uuid-1234/reactivate")
        controller.respond = MagicMock()
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_agent = MagicMock()
        mock_agent.ip = "127.0.0.1"
        mock_agent.port = 9002
        mock_session.query.return_value.filter_by.return_value.one.return_value = mock_agent
        mock_config.get.return_value = "default"
        mock_cvc.DEFAULT_VERIFIER_ID = "default"
        mock_from_db_obj.return_value = {
            "mtls_cert": "disabled",
            "ssl_context": None,
            "operational_state": 0,
        }

        with patch(f"{MODULE}.asyncio"):
            with patch("keylime.cloud_verifier_tornado.process_agent"):
                controller.reactivate("valid-uuid-1234")

        controller.respond.assert_called_once_with(200, "Success")


class TestAgentControllerStop(unittest.TestCase):
    """Test cases for AgentController.stop()."""

    @patch(f"{MODULE}.cloud_verifier_common")
    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.session_context")
    def test_stop_v2_returns_200(self, mock_session_ctx, mock_config, mock_cvc):
        """Test that v2 stop returns 200."""
        controller = _make_controller(path="/v2.1/agents/valid-uuid-1234/stop")
        controller.respond = MagicMock()
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_agent = MagicMock()
        mock_session.query.return_value.filter_by.return_value.one.return_value = mock_agent
        mock_config.get.return_value = "default"
        mock_cvc.DEFAULT_VERIFIER_ID = "default"

        controller.stop("valid-uuid-1234")

        controller.respond.assert_called_once_with(200, "Success")

    @patch(f"{MODULE}.validators")
    def test_stop_v2_invalid_agent_id_returns_400(self, mock_validators):
        """Test that v2 stop returns 400 for invalid agent ID."""
        controller = _make_controller(path="/v2.1/agents/invalid!/stop")
        controller.respond = MagicMock()
        mock_validators.valid_agent_id.return_value = False

        controller.stop("invalid!")

        controller.respond.assert_called_once_with(400, "agent_id not not valid")


class TestAgentControllerUpdate(unittest.TestCase):
    """Test cases for AgentController.update()."""

    @patch(f"{MODULE}.VerifierAgentModel")
    def test_update_v3_success(self, mock_agent_model):
        """Test that v3 update succeeds and returns updated agent resource."""
        controller = _v3_controller()
        controller.action_handler.request.path = "/v3.0/agents/test-uuid-1234"
        controller._api_request_body = MagicMock()
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
        controller._api_request_body = MagicMock()
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
        controller._api_request_body = MagicMock()
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
        controller._api_request_body = MagicMock()
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
