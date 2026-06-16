"""Unit tests for TOCTOU race condition handling in mb_policy_service."""

import unittest
from unittest.mock import MagicMock, patch

from sqlalchemy.exc import IntegrityError

from keylime.web.verifier.mb_policy_service import resolve_mb_policy_for_agent

MODULE = "keylime.web.verifier.mb_policy_service"


class TestResolveMBPolicyRaceCondition(unittest.TestCase):
    """Test TOCTOU race condition handling in resolve_mb_policy_for_agent()."""

    @patch(f"{MODULE}.mba")
    @patch(f"{MODULE}.MBPolicy")
    def test_integrity_error_fetches_existing(self, mock_mb_policy_cls, mock_mba):
        """Test that IntegrityError during policy creation falls back to fetching existing.

        Simulates the race where two concurrent agent enrollments both try to
        create the same MB policy (name defaults to agent_id). The second
        commit_changes() hits IntegrityError; the code should re-fetch the
        existing policy and return it.
        """

        mock_mba.mb_policy_db_contents.return_value = {"name": "agent-123", "mb_policy": "{}"}

        # First get() returns None (no existing), second get() returns the concurrent insert
        mock_existing = MagicMock()
        mock_existing.id = 42
        mock_mb_policy_cls.get.side_effect = [None, mock_existing]

        # commit_changes() raises IntegrityError
        mock_new_policy = MagicMock()
        orig_exception = Exception("UNIQUE constraint failed: mbpolicies.name")
        mock_new_policy.commit_changes.side_effect = IntegrityError("INSERT INTO mbpolicies ...", None, orig_exception)
        mock_mb_policy_cls.return_value = mock_new_policy

        policy, error = resolve_mb_policy_for_agent(
            mb_policy_name="",
            mb_policy="{}",
            agent_id="agent-123",
        )

        self.assertIsNone(error)
        self.assertEqual(policy, mock_existing)

    @patch(f"{MODULE}.mba")
    @patch(f"{MODULE}.MBPolicy")
    def test_integrity_error_refetch_fails_returns_500(self, mock_mb_policy_cls, mock_mba):
        """Test that if IntegrityError occurs and re-fetch also fails, return 500."""
        mock_mba.mb_policy_db_contents.return_value = {"name": "agent-123", "mb_policy": "{}"}

        # All get() calls return None
        mock_mb_policy_cls.get.return_value = None

        mock_new_policy = MagicMock()
        orig_exception = Exception("UNIQUE constraint failed: mbpolicies.name")
        mock_new_policy.commit_changes.side_effect = IntegrityError("INSERT INTO mbpolicies ...", None, orig_exception)
        mock_mb_policy_cls.return_value = mock_new_policy

        policy, error = resolve_mb_policy_for_agent(
            mb_policy_name="",
            mb_policy="{}",
            agent_id="agent-123",
        )

        self.assertIsNone(policy)
        assert error is not None
        self.assertEqual(error[0], 500)


if __name__ == "__main__":
    unittest.main()
