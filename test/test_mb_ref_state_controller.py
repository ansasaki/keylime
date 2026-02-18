"""Unit tests for MBRefStateController (verifier).

Tests the verifier's measured boot policy endpoints including listing,
showing, creating, overwriting, and deleting policies for v2 and v3 APIs.
"""

import unittest
from typing import Any, cast
from unittest.mock import MagicMock, patch

from sqlalchemy.orm.exc import NoResultFound  # pyright: ignore

from keylime.web.base.exceptions import StopAction
from keylime.web.verifier.mb_ref_state_controller import MBRefStateController

MODULE = "keylime.web.verifier.mb_ref_state_controller"


def _make_controller(**kwargs: Any) -> Any:
    """Create a MBRefStateController with a mocked action handler.

    Keyword arguments are set as attributes on the controller (e.g.
    request body, path params).
    """
    mock_action_handler = MagicMock()
    controller = cast(MBRefStateController, MBRefStateController(mock_action_handler))
    for key, value in kwargs.items():
        setattr(controller, key, value)
    return controller


def _v2_controller(**kwargs: Any) -> Any:
    """Create a controller with request path set to v2."""
    ctrl = _make_controller(**kwargs)
    ctrl.action_handler.request.path = "/v2.1/mbpolicies/"
    return ctrl


def _v3_controller(**kwargs: Any) -> Any:
    """Create a controller with request path set to v3."""
    ctrl = _make_controller(**kwargs)
    ctrl.action_handler.request.path = "/v3.0/refstates/uefi/"
    return ctrl


class TestMBRefStateControllerIndex(unittest.TestCase):
    """Test cases for MBRefStateController.index()."""

    def setUp(self):
        self.controller = _v2_controller()
        self.controller.respond = MagicMock()

    @patch(f"{MODULE}.session_context")
    def test_index_v2_returns_policy_names(self, mock_session_ctx):
        """Test that v2 index returns list of policy names."""
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.all.return_value = [("policy1",), ("policy2",)]

        self.controller.index()

        self.controller.respond.assert_called_once_with(200, "Success", {"mbpolicy names": ["policy1", "policy2"]})

    @patch(f"{MODULE}.session_context")
    def test_index_v2_returns_empty_list(self, mock_session_ctx):
        """Test that v2 index returns empty list when no policies exist."""
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.all.return_value = []

        self.controller.index()

        self.controller.respond.assert_called_once_with(200, "Success", {"mbpolicy names": []})

    @patch(f"{MODULE}.MBPolicy")
    def test_index_v3_returns_all_policies(self, mock_policy_cls):
        """Test that v3 index returns all MB policies as JSON:API resources."""
        controller = _v3_controller()
        controller.send_response = MagicMock()

        mock_policy = MagicMock()
        mock_policy.name = "policy1"
        mock_policy.render.return_value = {"name": "policy1", "mb_policy": "{}"}
        mock_policy_cls.all.return_value = [mock_policy]

        controller.index()

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 200)
        body = args[2]
        self.assertIn("data", body)
        self.assertIsInstance(body["data"], list)
        self.assertEqual(len(body["data"]), 1)
        self.assertEqual(body["data"][0]["type"], "mb_policy")
        self.assertEqual(body["data"][0]["id"], "policy1")

    @patch(f"{MODULE}.MBPolicy")
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


class TestMBRefStateControllerShow(unittest.TestCase):
    """Test cases for MBRefStateController.show()."""

    def setUp(self):
        self.controller = _v2_controller()
        self.controller.respond = MagicMock()

    @patch(f"{MODULE}.session_context")
    def test_show_v2_found_returns_policy(self, mock_session_ctx):
        """Test that v2 show returns policy when found."""
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_policy = MagicMock()
        mock_policy.name = "test_policy"
        mock_policy.mb_policy = '{"key": "value"}'
        mock_session.query.return_value.filter_by.return_value.one.return_value = mock_policy

        self.controller.show("test_policy")

        self.controller.respond.assert_called_once_with(
            200, "Success", {"name": "test_policy", "mb_policy": '{"key": "value"}'}
        )

    @patch(f"{MODULE}.session_context")
    def test_show_v2_not_found_returns_404(self, mock_session_ctx):
        """Test that v2 show returns 404 when policy not found."""
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.filter_by.return_value.one.side_effect = NoResultFound

        self.controller.show("nonexistent")

        self.controller.respond.assert_called_once_with(404, "Measured boot policy nonexistent not found")

    @patch(f"{MODULE}.MBPolicy")
    def test_show_v3_found_returns_resource(self, mock_policy_cls):
        """Test that v3 show returns policy as JSON:API resource when found."""
        controller = _v3_controller()
        controller.action_handler.request.path = "/v3/refstates/uefi/test_policy"
        controller.send_response = MagicMock()

        mock_policy = MagicMock()
        mock_policy.name = "test_policy"
        mock_policy.render.return_value = {"name": "test_policy", "mb_policy": "{}"}
        mock_policy_cls.get.return_value = mock_policy

        with self.assertRaises(StopAction):
            controller.show("test_policy")

        mock_policy_cls.get.assert_called_once_with(name="test_policy")
        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 200)
        body = args[2]
        self.assertIn("data", body)
        self.assertEqual(body["data"]["type"], "mb_policy")
        self.assertEqual(body["data"]["id"], "test_policy")

    @patch(f"{MODULE}.MBPolicy")
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


class TestMBRefStateControllerCreate(unittest.TestCase):
    """Test cases for MBRefStateController.create()."""

    def setUp(self):
        self.controller = _v2_controller()
        self.controller.respond = MagicMock()

    @patch(f"{MODULE}.mba")
    @patch(f"{MODULE}.session_context")
    def test_create_v2_success(self, mock_session_ctx, mock_mba):
        """Test that v2 create succeeds and returns 201."""
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.filter_by.return_value.count.return_value = 0
        mock_mba.mb_policy_db_contents.return_value = {"name": "new_policy", "mb_policy": "{}"}
        self.controller.action_handler.request.body = b'{"mb_policy": {}}'
        self.controller.action_handler.matching_route.capture_params.return_value = {"name": "new_policy"}

        self.controller.create()

        self.controller.respond.assert_called_once_with(201)
        mock_session.add.assert_called_once()

    @patch(f"{MODULE}.mba")
    @patch(f"{MODULE}.session_context")
    def test_create_v2_duplicate_returns_409(self, mock_session_ctx, mock_mba):
        """Test that v2 create returns 409 when policy already exists."""
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.filter_by.return_value.count.return_value = 1
        mock_mba.mb_policy_db_contents.return_value = {"name": "existing", "mb_policy": "{}"}
        self.controller.action_handler.request.body = b'{"mb_policy": {}}'
        self.controller.action_handler.matching_route.capture_params.return_value = {"name": "existing"}

        self.controller.create()

        self.controller.respond.assert_called_once_with(409, "Measured boot policy with name existing already exists")

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

    @patch(f"{MODULE}._validate_and_format_mb_policy")
    @patch(f"{MODULE}.MBPolicy")
    def test_create_v3_success(self, mock_policy_cls, mock_validate):
        """Test that v3 create succeeds and returns resource with 201."""
        controller = _v3_controller()
        controller._api_request_body = MagicMock()
        controller.send_response = MagicMock()

        mock_policy_cls.get.return_value = None
        mock_validate.return_value = ({"name": "new_policy", "mb_policy": "{}"}, None)
        mock_policy = MagicMock()
        mock_policy.render.return_value = {"name": "new_policy", "mb_policy": "{}"}
        mock_policy_cls.return_value = mock_policy

        with self.assertRaises(StopAction):
            controller.create(
                mb_policy={
                    "name": "new_policy",
                    "mb_policy": '{"key": "value"}',
                }
            )

        mock_policy.commit_changes.assert_called_once()
        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 201)
        body = args[2]
        self.assertIn("data", body)
        self.assertEqual(body["data"]["type"], "mb_policy")

    @patch(f"{MODULE}.MBPolicy")
    def test_create_v3_duplicate_returns_409(self, mock_policy_cls):
        """Test that v3 create returns 409 when policy already exists."""
        controller = _v3_controller()
        controller._api_request_body = MagicMock()
        controller.send_response = MagicMock()

        mock_policy_cls.get.return_value = MagicMock()

        with self.assertRaises(StopAction):
            controller.create(
                mb_policy={
                    "name": "existing",
                    "mb_policy": '{"key": "value"}',
                }
            )

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 409)
        body = args[2]
        self.assertIn("errors", body)
        self.assertEqual(body["errors"][0]["code"], "conflict")

    @patch(f"{MODULE}._validate_and_format_mb_policy")
    @patch(f"{MODULE}.MBPolicy")
    def test_create_v3_invalid_policy_returns_error(self, mock_policy_cls, mock_validate):
        """Test that v3 create returns error when policy validation fails."""
        controller = _v3_controller()
        controller._api_request_body = MagicMock()
        controller.send_response = MagicMock()

        mock_policy_cls.get.return_value = None
        mock_validate.return_value = ({}, (400, "Measured boot policy is malformatted: bad data"))

        with self.assertRaises(StopAction):
            controller.create(
                mb_policy={
                    "name": "bad_policy",
                    "mb_policy": "invalid",
                }
            )

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 400)

    def test_create_v3_missing_data_returns_error(self):
        """Test that v3 create returns error when no mb_policy data provided."""
        controller = _v3_controller()
        controller._api_request_body = MagicMock()
        controller.send_response = MagicMock()

        with self.assertRaises(StopAction):
            controller.create()

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 400)


class TestMBRefStateControllerOverwrite(unittest.TestCase):
    """Test cases for MBRefStateController.overwrite()."""

    def setUp(self):
        self.controller = _v2_controller()
        self.controller.respond = MagicMock()

    @patch(f"{MODULE}.mba")
    @patch(f"{MODULE}.session_context")
    def test_overwrite_v2_success(self, mock_session_ctx, mock_mba):
        """Test that v2 overwrite succeeds and returns 201."""
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.filter_by.return_value.count.return_value = 1
        mock_mba.mb_policy_db_contents.return_value = {"name": "existing", "mb_policy": "{}"}
        self.controller.action_handler.request.body = b'{"mb_policy": {}}'

        self.controller.overwrite("existing")

        self.controller.respond.assert_called_once_with(201)
        mock_session.query.return_value.filter_by.return_value.update.assert_called_once()

    @patch(f"{MODULE}.mba")
    @patch(f"{MODULE}.session_context")
    def test_overwrite_v2_not_found_returns_409(self, mock_session_ctx, mock_mba):
        """Test that v2 overwrite returns 409 when policy doesn't exist."""
        mock_session = MagicMock()
        mock_session_ctx.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_session_ctx.return_value.__exit__ = MagicMock(return_value=False)
        mock_session.query.return_value.filter_by.return_value.count.return_value = 0
        mock_mba.mb_policy_db_contents.return_value = {"name": "nonexistent", "mb_policy": "{}"}
        self.controller.action_handler.request.body = b'{"mb_policy": {}}'

        self.controller.overwrite("nonexistent")

        self.controller.respond.assert_called_once_with(
            409, "Measured boot policy with name nonexistent does not already exist"
        )

    def test_overwrite_v2_empty_body_returns_400(self):
        """Test that v2 overwrite returns 400 when body is empty."""
        self.controller.action_handler.request.body = b""

        self.controller.overwrite("test")

        self.controller.respond.assert_called_once_with(400, "Expected non zero content length")


class TestMBRefStateControllerUpdate(unittest.TestCase):
    """Test cases for MBRefStateController.update() (v3 only)."""

    @patch(f"{MODULE}._validate_and_format_mb_policy")
    @patch(f"{MODULE}.MBPolicy")
    def test_update_v3_success(self, mock_policy_cls, mock_validate):
        """Test that v3 update succeeds and returns updated resource."""
        controller = _v3_controller()
        controller.action_handler.request.path = "/v3/refstates/uefi/test_policy"
        controller._api_request_body = MagicMock()
        controller.send_response = MagicMock()

        mock_existing = MagicMock()
        mock_existing.render.return_value = {"name": "test_policy", "mb_policy": '{"new": true}'}
        mock_policy_cls.get.return_value = mock_existing
        mock_validate.return_value = ({"name": "test_policy", "mb_policy": '{"new": true}'}, None)

        with self.assertRaises(StopAction):
            controller.update(
                "test_policy",
                mb_policy={
                    "mb_policy": '{"new": true}',
                },
            )

        mock_existing.commit_changes.assert_called_once()
        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 200)
        body = args[2]
        self.assertIn("data", body)
        self.assertEqual(body["data"]["type"], "mb_policy")

    @patch(f"{MODULE}.MBPolicy")
    def test_update_v3_not_found_returns_404(self, mock_policy_cls):
        """Test that v3 update returns 404 when policy not found."""
        controller = _v3_controller()
        controller._api_request_body = MagicMock()
        controller.send_response = MagicMock()

        mock_policy_cls.get.return_value = None

        with self.assertRaises(StopAction):
            controller.update(
                "nonexistent",
                mb_policy={
                    "mb_policy": '{"key": "value"}',
                },
            )

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 404)
        body = args[2]
        self.assertIn("errors", body)
        self.assertEqual(body["errors"][0]["code"], "not_found")

    @patch(f"{MODULE}.MBPolicy")
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


class TestMBRefStateControllerDelete(unittest.TestCase):
    """Test cases for MBRefStateController.delete()."""

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

        self.controller.respond.assert_called_once_with(404, "Measured boot policy nonexistent not found")

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

        # First query().filter_by().one() returns the policy
        # Second query().filter_by().one_or_none() returns the agent
        mock_session.query.return_value.filter_by.return_value.one.return_value = mock_policy
        mock_session.query.return_value.filter_by.return_value.one_or_none.return_value = mock_agent

        self.controller.delete("test_policy")

        self.controller.respond.assert_called_once_with(
            409, "Can't delete mb_policy as it's currently in use by agent agent-123"
        )

    @patch(f"{MODULE}.VerifierAgent")
    @patch(f"{MODULE}.MBPolicy")
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

    @patch(f"{MODULE}.MBPolicy")
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
    @patch(f"{MODULE}.MBPolicy")
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
