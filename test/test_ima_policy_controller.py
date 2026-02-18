"""Unit tests for IMAPolicyController (verifier).

Tests the verifier's IMA runtime policy endpoints including listing,
showing, creating, overwriting, and deleting policies for v2 and v3 APIs.
"""

import base64
import unittest
from typing import Any, cast
from unittest.mock import MagicMock, patch

from sqlalchemy.orm.exc import NoResultFound  # pyright: ignore

from keylime.web.base.exceptions import StopAction
from keylime.web.verifier.ima_policy_controller import IMAPolicyController

MODULE = "keylime.web.verifier.ima_policy_controller"


def _make_controller(**kwargs: Any) -> Any:
    """Create an IMAPolicyController with a mocked action handler."""
    mock_action_handler = MagicMock()
    controller = cast(IMAPolicyController, IMAPolicyController(mock_action_handler))
    for key, value in kwargs.items():
        setattr(controller, key, value)
    return controller


def _v2_controller(**kwargs: Any) -> Any:
    """Create a controller with request path set to v2."""
    ctrl = _make_controller(**kwargs)
    ctrl.action_handler.request.path = "/v2.1/allowlists/"
    return ctrl


def _v3_controller(**kwargs: Any) -> Any:
    """Create a controller with request path set to v3."""
    ctrl = _make_controller(**kwargs)
    ctrl.action_handler.request.path = "/v3.0/policies/ima/"
    return ctrl


def _encoded_policy() -> bytes:
    """Return a base64-encoded runtime policy for request bodies."""
    return base64.b64encode(b'{"meta": {}}')


class TestIMAPolicyControllerIndex(unittest.TestCase):
    """Test cases for IMAPolicyController.index()."""

    def setUp(self):
        self.controller = _v2_controller()
        self.controller.respond = MagicMock()

    @patch(f"{MODULE}.session_context")
    def test_index_v2_returns_policy_names(self, mock_session_ctx):
        """Test that v2 index returns list of runtime policy names."""
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.all.return_value = [("policy1",), ("policy2",)]

        self.controller.index()

        self.controller.respond.assert_called_once_with(200, "Success", {"runtimepolicy names": ["policy1", "policy2"]})

    @patch(f"{MODULE}.session_context")
    def test_index_v2_returns_empty_list(self, mock_session_ctx):
        """Test that v2 index returns empty list when no policies exist."""
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.all.return_value = []

        self.controller.index()

        self.controller.respond.assert_called_once_with(200, "Success", {"runtimepolicy names": []})

    @patch(f"{MODULE}.IMAPolicy")
    def test_index_v3_returns_all_policies(self, mock_policy_cls):
        """Test that v3 index returns all IMA policies as JSON:API resources."""
        controller = _v3_controller()
        controller.send_response = MagicMock()

        mock_policy = MagicMock()
        mock_policy.name = "policy1"
        mock_policy.render.return_value = {"name": "policy1", "ima_policy": "{}"}
        mock_policy_cls.all.return_value = [mock_policy]

        controller.index()

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 200)
        body = args[2]
        self.assertIn("data", body)
        self.assertIsInstance(body["data"], list)
        self.assertEqual(len(body["data"]), 1)
        self.assertEqual(body["data"][0]["type"], "ima_policy")
        self.assertEqual(body["data"][0]["id"], "policy1")

    @patch(f"{MODULE}.IMAPolicy")
    def test_index_v3_empty_returns_empty_array(self, mock_policy_cls):
        """Test that v3 index returns empty array when no policies exist."""
        controller = _v3_controller()
        controller.send_response = MagicMock()

        mock_policy_cls.all.return_value = []

        controller.index()

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 200)
        body = args[2]
        self.assertIn("data", body)
        self.assertEqual(body["data"], [])


class TestIMAPolicyControllerShow(unittest.TestCase):
    """Test cases for IMAPolicyController.show()."""

    def setUp(self):
        self.controller = _v2_controller()
        self.controller.respond = MagicMock()

    @patch(f"{MODULE}.session_context")
    def test_show_v2_found_returns_policy(self, mock_session_ctx):
        """Test that v2 show returns policy details when found."""
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_allowlist = MagicMock()
        mock_allowlist.name = "test_policy"
        mock_allowlist.tmp_policy = '{"tpm": {}}'
        mock_allowlist.ima_policy = '{"ima": {}}'
        mock_session.query.return_value.filter_by.return_value.one.return_value = mock_allowlist

        self.controller.show("test_policy")

        self.controller.respond.assert_called_once_with(
            200,
            "Success",
            {"name": "test_policy", "tmp_policy": '{"tpm": {}}', "runtime_policy": '{"ima": {}}'},
        )

    @patch(f"{MODULE}.session_context")
    def test_show_v2_not_found_returns_404(self, mock_session_ctx):
        """Test that v2 show returns 404 when policy not found."""
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.filter_by.return_value.one.side_effect = NoResultFound

        self.controller.show("nonexistent")

        self.controller.respond.assert_called_once_with(404, "Runtime policy nonexistent not found")

    @patch(f"{MODULE}.IMAPolicy")
    def test_show_v3_found_returns_resource(self, mock_policy_cls):
        """Test that v3 show returns policy as JSON:API resource when found."""
        controller = _v3_controller()
        controller.action_handler.request.path = "/v3/policies/ima/test_policy"
        controller.send_response = MagicMock()

        mock_policy = MagicMock()
        mock_policy.name = "test_policy"
        mock_policy.render.return_value = {"name": "test_policy", "ima_policy": "{}"}
        mock_policy_cls.get.return_value = mock_policy

        with self.assertRaises(StopAction):
            controller.show("test_policy")

        mock_policy_cls.get.assert_called_once_with(name="test_policy")
        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 200)
        body = args[2]
        self.assertIn("data", body)
        self.assertEqual(body["data"]["type"], "ima_policy")
        self.assertEqual(body["data"]["id"], "test_policy")

    @patch(f"{MODULE}.IMAPolicy")
    def test_show_v3_not_found_returns_404(self, mock_policy_cls):
        """Test that v3 show returns 404 error when policy not found."""
        controller = _v3_controller()
        controller.send_response = MagicMock()

        mock_policy_cls.get.return_value = None

        with self.assertRaises(StopAction):
            controller.show("nonexistent")

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 404)
        body = args[2]
        self.assertIn("errors", body)
        self.assertEqual(body["errors"][0]["code"], "not_found")


class TestIMAPolicyControllerCreate(unittest.TestCase):
    """Test cases for IMAPolicyController.create()."""

    def setUp(self):
        self.controller = _v2_controller()
        self.controller.respond = MagicMock()

    @patch(f"{MODULE}.ima")
    @patch(f"{MODULE}.signing")
    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.session_context")
    def test_create_v2_success(self, mock_session_ctx, mock_config, mock_signing, mock_ima):
        """Test that v2 create succeeds and returns 201."""
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.filter_by.return_value.count.return_value = 0
        mock_signing.get_runtime_policy_keys.return_value = b"key"
        mock_config.getboolean.return_value = False
        mock_ima.runtime_policy_db_contents.return_value = {"name": "new_policy", "ima_policy": "{}"}
        body = b'{"runtime_policy": "' + _encoded_policy() + b'"}'
        self.controller.action_handler.request.body = body
        self.controller.action_handler.matching_route.capture_params.return_value = {"name": "new_policy"}

        self.controller.create()

        self.controller.respond.assert_called_once_with(201)
        mock_session.add.assert_called_once()

    @patch(f"{MODULE}.ima")
    @patch(f"{MODULE}.signing")
    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.session_context")
    def test_create_v2_duplicate_returns_409(self, mock_session_ctx, mock_config, mock_signing, mock_ima):
        """Test that v2 create returns 409 when policy already exists."""
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.filter_by.return_value.count.return_value = 1
        mock_signing.get_runtime_policy_keys.return_value = b"key"
        mock_config.getboolean.return_value = False
        mock_ima.runtime_policy_db_contents.return_value = {"name": "existing", "ima_policy": "{}"}
        body = b'{"runtime_policy": "' + _encoded_policy() + b'"}'
        self.controller.action_handler.request.body = body
        self.controller.action_handler.matching_route.capture_params.return_value = {"name": "existing"}

        self.controller.create()

        self.controller.respond.assert_called_once_with(409, "Runtime policy with name existing already exists")

    @patch(f"{MODULE}.ima")
    @patch(f"{MODULE}.signing")
    @patch(f"{MODULE}.config")
    def test_create_v2_invalid_signature_returns_error(self, mock_config, mock_signing, mock_ima):
        """Test that v2 create returns error when signature verification fails."""
        mock_signing.get_runtime_policy_keys.return_value = b"key"
        mock_config.getboolean.return_value = True
        mock_ima.ImaValidationError = type("ImaValidationError", (Exception,), {"code": 401, "message": "bad sig"})
        mock_ima.verify_runtime_policy.side_effect = mock_ima.ImaValidationError()
        body = b'{"runtime_policy": "' + _encoded_policy() + b'"}'
        self.controller.action_handler.request.body = body
        self.controller.action_handler.matching_route.capture_params.return_value = {"name": "test"}

        self.controller.create()

        self.controller.respond.assert_called_once_with(401, "bad sig")

    def test_create_v2_empty_body_returns_400(self):
        """Test that v2 create returns 400 when body is empty."""
        self.controller.action_handler.request.body = b""
        self.controller.action_handler.matching_route.capture_params.return_value = {"name": "test"}

        self.controller.create()

        self.controller.respond.assert_called_once_with(400, "Expected non zero content length")

    def test_create_v2_no_name_returns_400(self):
        """Test that v2 create returns 400 when name is missing from URL."""
        self.controller.action_handler.matching_route = None

        self.controller.create()

        self.controller.respond.assert_called_once_with(400, "Invalid URL")

    @patch(f"{MODULE}._validate_and_format_ima_policy")
    @patch(f"{MODULE}.IMAPolicy")
    def test_create_v3_success(self, mock_policy_cls, mock_validate):
        """Test that v3 create succeeds and returns resource with 201."""
        controller = _v3_controller()
        controller._api_request_body = MagicMock()  # Satisfy @require_json_api
        controller.send_response = MagicMock()

        mock_policy_cls.get.return_value = None  # No duplicate
        mock_validate.return_value = ({"name": "new_policy", "ima_policy": "{}"}, None)
        mock_policy = MagicMock()
        mock_policy.render.return_value = {"name": "new_policy", "ima_policy": "{}"}
        mock_policy_cls.return_value = mock_policy

        with self.assertRaises(StopAction):
            controller.create(
                ima_policy={
                    "name": "new_policy",
                    "runtime_policy": base64.b64encode(b'{"meta": {}}').decode(),
                }
            )

        mock_policy.commit_changes.assert_called_once()
        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 201)
        body = args[2]
        self.assertIn("data", body)
        self.assertEqual(body["data"]["type"], "ima_policy")

    @patch(f"{MODULE}.IMAPolicy")
    def test_create_v3_duplicate_returns_409(self, mock_policy_cls):
        """Test that v3 create returns 409 when policy already exists."""
        controller = _v3_controller()
        controller._api_request_body = MagicMock()
        controller.send_response = MagicMock()

        mock_policy_cls.get.return_value = MagicMock()  # Duplicate exists

        with self.assertRaises(StopAction):
            controller.create(
                ima_policy={
                    "name": "existing",
                    "runtime_policy": base64.b64encode(b'{"meta": {}}').decode(),
                }
            )

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 409)
        body = args[2]
        self.assertIn("errors", body)
        self.assertEqual(body["errors"][0]["code"], "conflict")

    @patch(f"{MODULE}._validate_and_format_ima_policy")
    @patch(f"{MODULE}.IMAPolicy")
    def test_create_v3_invalid_policy_returns_error(self, mock_policy_cls, mock_validate):
        """Test that v3 create returns error when policy validation fails."""
        controller = _v3_controller()
        controller._api_request_body = MagicMock()
        controller.send_response = MagicMock()

        mock_policy_cls.get.return_value = None
        mock_validate.return_value = ({}, (400, "bad format"))

        with self.assertRaises(StopAction):
            controller.create(
                ima_policy={
                    "name": "bad_policy",
                    "runtime_policy": base64.b64encode(b"invalid").decode(),
                }
            )

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 400)

    def test_create_v3_missing_data_returns_error(self):
        """Test that v3 create returns error when no ima_policy data provided."""
        controller = _v3_controller()
        controller._api_request_body = MagicMock()
        controller.send_response = MagicMock()

        with self.assertRaises(StopAction):
            controller.create()

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 400)


class TestIMAPolicyControllerOverwrite(unittest.TestCase):
    """Test cases for IMAPolicyController.overwrite()."""

    def setUp(self):
        self.controller = _v2_controller()
        self.controller.respond = MagicMock()

    @patch(f"{MODULE}.ima")
    @patch(f"{MODULE}.signing")
    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.session_context")
    def test_overwrite_v2_success(self, mock_session_ctx, mock_config, mock_signing, mock_ima):
        """Test that v2 overwrite succeeds and returns 201."""
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.filter_by.return_value.count.return_value = 1
        mock_signing.get_runtime_policy_keys.return_value = b"key"
        mock_config.getboolean.return_value = False
        mock_ima.runtime_policy_db_contents.return_value = {"name": "existing", "ima_policy": "{}"}
        body = b'{"runtime_policy": "' + _encoded_policy() + b'"}'
        self.controller.action_handler.request.body = body

        self.controller.overwrite("existing")

        self.controller.respond.assert_called_once_with(201)
        mock_session.query.return_value.filter_by.return_value.update.assert_called_once()

    @patch(f"{MODULE}.ima")
    @patch(f"{MODULE}.signing")
    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.session_context")
    def test_overwrite_v2_not_found_returns_404(self, mock_session_ctx, mock_config, mock_signing, mock_ima):
        """Test that v2 overwrite returns 404 when policy doesn't exist."""
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.filter_by.return_value.count.return_value = 0
        mock_signing.get_runtime_policy_keys.return_value = b"key"
        mock_config.getboolean.return_value = False
        mock_ima.runtime_policy_db_contents.return_value = {"name": "nonexistent", "ima_policy": "{}"}
        body = b'{"runtime_policy": "' + _encoded_policy() + b'"}'
        self.controller.action_handler.request.body = body

        self.controller.overwrite("nonexistent")

        self.controller.respond.assert_called_once_with(
            404, "Runtime policy with name nonexistent does not already exist, use POST to create"
        )

    def test_overwrite_v2_empty_body_returns_400(self):
        """Test that v2 overwrite returns 400 when body is empty."""
        self.controller.action_handler.request.body = b""

        self.controller.overwrite("test")

        self.controller.respond.assert_called_once_with(400, "Expected non zero content length")


class TestIMAPolicyControllerUpdate(unittest.TestCase):
    """Test cases for IMAPolicyController.update() (v3 only)."""

    @patch(f"{MODULE}._validate_and_format_ima_policy")
    @patch(f"{MODULE}.IMAPolicy")
    def test_update_v3_success(self, mock_policy_cls, mock_validate):
        """Test that v3 update succeeds and returns updated resource."""
        controller = _v3_controller()
        controller.action_handler.request.path = "/v3/policies/ima/test_policy"
        controller._api_request_body = MagicMock()
        controller.send_response = MagicMock()

        mock_existing = MagicMock()
        mock_existing.render.return_value = {"name": "test_policy", "ima_policy": '{"new": true}'}
        mock_policy_cls.get.return_value = mock_existing
        mock_validate.return_value = ({"name": "test_policy", "ima_policy": '{"new": true}'}, None)

        with self.assertRaises(StopAction):
            controller.update(
                "test_policy",
                ima_policy={
                    "runtime_policy": base64.b64encode(b'{"new": true}').decode(),
                },
            )

        mock_existing.commit_changes.assert_called_once()
        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 200)
        body = args[2]
        self.assertIn("data", body)
        self.assertEqual(body["data"]["type"], "ima_policy")

    @patch(f"{MODULE}.IMAPolicy")
    def test_update_v3_not_found_returns_404(self, mock_policy_cls):
        """Test that v3 update returns 404 when policy not found."""
        controller = _v3_controller()
        controller._api_request_body = MagicMock()
        controller.send_response = MagicMock()

        mock_policy_cls.get.return_value = None

        with self.assertRaises(StopAction):
            controller.update(
                "nonexistent",
                ima_policy={
                    "runtime_policy": base64.b64encode(b'{"meta": {}}').decode(),
                },
            )

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 404)
        body = args[2]
        self.assertIn("errors", body)
        self.assertEqual(body["errors"][0]["code"], "not_found")

    @patch(f"{MODULE}.IMAPolicy")
    def test_update_v3_missing_data_returns_error(self, mock_policy_cls):
        """Test that v3 update returns error when no policy data provided."""
        controller = _v3_controller()
        controller._api_request_body = MagicMock()
        controller.send_response = MagicMock()

        mock_policy_cls.get.return_value = MagicMock()

        with self.assertRaises(StopAction):
            controller.update("test_policy")

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 400)


class TestIMAPolicyControllerDelete(unittest.TestCase):
    """Test cases for IMAPolicyController.delete()."""

    def setUp(self):
        self.controller = _v2_controller()
        self.controller.respond = MagicMock()
        self.controller.send_response = MagicMock()

    @patch(f"{MODULE}.session_context")
    def test_delete_v2_success_returns_204(self, mock_session_ctx):
        """Test that v2 delete succeeds and returns 204."""
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_policy = MagicMock()
        mock_policy.id = 1
        mock_session.query.return_value.filter_by.return_value.one.return_value = mock_policy
        mock_session.query.return_value.filter_by.return_value.one_or_none.return_value = None

        self.controller.delete("test_policy")

        self.controller.send_response.assert_called_once_with(204)
        self.controller.respond.assert_not_called()

    @patch(f"{MODULE}.session_context")
    def test_delete_v2_not_found_returns_404(self, mock_session_ctx):
        """Test that v2 delete returns 404 when policy not found."""
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.filter_by.return_value.one.side_effect = NoResultFound

        self.controller.delete("nonexistent")

        self.controller.respond.assert_called_once_with(404, "Runtime policy nonexistent not found")

    @patch(f"{MODULE}.session_context")
    def test_delete_v2_in_use_returns_409(self, mock_session_ctx):
        """Test that v2 delete returns 409 when policy is in use by an agent."""
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_policy = MagicMock()
        mock_policy.id = 1
        mock_agent = MagicMock()
        mock_agent.agent_id = "agent-123"
        mock_session.query.return_value.filter_by.return_value.one.return_value = mock_policy
        mock_session.query.return_value.filter_by.return_value.one_or_none.return_value = mock_agent

        self.controller.delete("test_policy")

        self.controller.respond.assert_called_once_with(
            409, "Can't delete allowlist as it's currently in use by agent agent-123"
        )

    @patch(f"{MODULE}.VerifierAgent")
    @patch(f"{MODULE}.IMAPolicy")
    def test_delete_v3_success_returns_204(self, mock_policy_cls, mock_agent_cls):
        """Test that v3 delete succeeds and returns 204."""
        controller = _v3_controller()
        controller.send_response = MagicMock()

        mock_policy = MagicMock()
        mock_policy.id = 1
        mock_policy_cls.get.return_value = mock_policy
        mock_agent_cls.all_ids.return_value = []

        controller.delete("test_policy")

        mock_policy.delete.assert_called_once()
        controller.send_response.assert_called_once_with(204)

    @patch(f"{MODULE}.IMAPolicy")
    def test_delete_v3_not_found_returns_404(self, mock_policy_cls):
        """Test that v3 delete returns 404 when policy not found."""
        controller = _v3_controller()
        controller.send_response = MagicMock()

        mock_policy_cls.get.return_value = None

        with self.assertRaises(StopAction):
            controller.delete("nonexistent")

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 404)

    @patch(f"{MODULE}.VerifierAgent")
    @patch(f"{MODULE}.IMAPolicy")
    def test_delete_v3_in_use_returns_409(self, mock_policy_cls, mock_agent_cls):
        """Test that v3 delete returns 409 when policy is in use."""
        controller = _v3_controller()
        controller.send_response = MagicMock()

        mock_policy = MagicMock()
        mock_policy.id = 1
        mock_policy_cls.get.return_value = mock_policy
        mock_agent_cls.all_ids.return_value = ["agent-123"]

        with self.assertRaises(StopAction):
            controller.delete("test_policy")

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 409)
        body = args[2]
        self.assertIn("errors", body)
        self.assertEqual(body["errors"][0]["code"], "conflict")


if __name__ == "__main__":
    unittest.main()
