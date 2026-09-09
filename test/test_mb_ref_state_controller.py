"""Unit tests for TOCTOU race condition handling in MBRefStateController."""

import unittest
from typing import Any, cast
from unittest.mock import MagicMock, patch

from sqlalchemy.exc import IntegrityError

from keylime.web.base.action_handler import StopAction
from keylime.web.verifier.mb_ref_state_controller import MBRefStateController

MODULE = "keylime.web.verifier.mb_ref_state_controller"


def _v3_controller(body: bytes = b"") -> Any:
    """Create an MBRefStateController with a mocked action handler for v3."""
    mock_action_handler = MagicMock()
    mock_action_handler.request.path = "/v3.0/refstates/uefi/"
    mock_action_handler.request.query = ""
    mock_action_handler.request.body = body
    controller = cast(MBRefStateController, MBRefStateController(mock_action_handler))
    return controller


class TestMBRefStateControllerCreateRaceCondition(unittest.TestCase):
    """Test TOCTOU race condition handling in MBRefStateController._create_v3()."""

    @patch(f"{MODULE}.get_shared_memory")
    @patch(f"{MODULE}.mba")
    @patch(f"{MODULE}.MBPolicy")
    def test_create_integrity_error_returns_409(self, mock_mb_policy_cls, mock_mba, _mock_shared_mem):
        """Test that database constraint violation during concurrent create returns 409.

        Simulates two concurrent POST /refstates/uefi with the same name:
        both pass the MBPolicy.get() uniqueness check, but the second
        commit_changes() fails with IntegrityError from the DB unique constraint.
        """
        controller = _v3_controller()
        controller._api_request_body = MagicMock()  # pylint: disable=protected-access
        controller.send_response = MagicMock()

        # Uniqueness check passes (no existing policy)
        mock_mb_policy_cls.get.return_value = None

        mock_mba.mb_policy_db_contents.return_value = {"name": "test-policy", "mb_policy": "{}"}

        # Simulate IntegrityError on commit
        mock_policy = MagicMock()
        mock_mb_policy_cls.return_value = mock_policy
        orig_exception = Exception("UNIQUE constraint failed: mbpolicies.name")
        mock_policy.commit_changes.side_effect = IntegrityError("INSERT INTO mbpolicies ...", None, orig_exception)

        mb_policy_data = {
            "name": "test-policy",
            "mb_policy": "{}",
        }

        with self.assertRaises(StopAction):
            controller.create(mb_policy=mb_policy_data)

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 409)
        self.assertIn("already exists", args[2]["errors"][0]["detail"])


class TestMBRefStateControllerDeleteRaceCondition(unittest.TestCase):
    """Test TOCTOU race condition handling in MBRefStateController._delete_v3()."""

    @patch(f"{MODULE}.VerifierAgent")
    @patch(f"{MODULE}.MBPolicy")
    def test_delete_integrity_error_returns_409(self, mock_mb_policy_cls, mock_agent_cls):
        """Test that FK constraint violation during concurrent delete returns 409.

        Simulates the race where the agent-reference check passes (no agents
        reference this policy), but a concurrent enrollment adds one before
        delete() executes, causing an IntegrityError from the FK constraint.
        """
        controller = _v3_controller()
        controller.send_response = MagicMock()

        mock_policy = MagicMock()
        mock_policy.name = "test-policy"
        mock_mb_policy_cls.get.return_value = mock_policy

        # Reference check passes (no agents reference this policy)
        mock_agent_cls.all_ids.return_value = []

        # Simulate IntegrityError on delete (concurrent enrollment added a reference)
        orig_exception = Exception("FOREIGN KEY constraint failed")
        mock_policy.delete.side_effect = IntegrityError("DELETE FROM mbpolicies ...", None, orig_exception)

        with self.assertRaises(StopAction):
            controller.delete("test-policy")

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 409)
        self.assertIn("referenced by one or more agents", args[2]["errors"][0]["detail"])


if __name__ == "__main__":
    unittest.main()
