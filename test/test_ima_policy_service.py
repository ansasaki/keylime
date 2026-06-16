"""Unit tests for TOCTOU race condition handling in ima_policy_service."""

import unittest
from unittest.mock import MagicMock, patch

from sqlalchemy.exc import IntegrityError

from keylime.web.verifier.ima_policy_service import resolve_ima_policy_for_agent

MODULE = "keylime.web.verifier.ima_policy_service"


class TestResolveIMAPolicyRaceCondition(unittest.TestCase):
    """Test TOCTOU race condition handling in resolve_ima_policy_for_agent()."""

    @patch(f"{MODULE}.ima")
    @patch(f"{MODULE}.signing")
    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.IMAPolicy")
    def test_integrity_error_fetches_existing(self, mock_ima_policy_cls, mock_config, mock_signing, mock_ima):
        """Test that IntegrityError during policy creation falls back to fetching existing.

        Simulates the race where two concurrent agent enrollments both try to
        create the same IMA policy (name defaults to agent_id). The second
        commit_changes() hits IntegrityError; the code should re-fetch the
        existing policy and return it.
        """

        mock_config.getboolean.return_value = False
        mock_signing.get_runtime_policy_keys.return_value = None
        mock_ima.verify_runtime_policy.return_value = None
        mock_ima.runtime_policy_db_contents.return_value = {"name": "agent-123", "ima_policy": "{}"}
        mock_ima.EMPTY_RUNTIME_POLICY = {}
        mock_ima.ImaValidationError = type("ImaValidationError", (Exception,), {"message": "", "code": 400})

        # First get() (line 82) returns None (policy doesn't exist yet)
        # Second get() (line 90, re-fetch after IntegrityError) returns the concurrent insert
        mock_existing = MagicMock()
        mock_existing.id = 42
        mock_ima_policy_cls.get.side_effect = [None, mock_existing]

        # commit_changes() raises IntegrityError (concurrent request created it first)
        mock_new_policy = MagicMock()
        orig_exception = Exception("UNIQUE constraint failed: allowlists.name")
        mock_new_policy.commit_changes.side_effect = IntegrityError("INSERT INTO allowlists ...", None, orig_exception)
        mock_ima_policy_cls.return_value = mock_new_policy

        policy, error = resolve_ima_policy_for_agent(
            runtime_policy_name=None,
            runtime_policy="{}",
            runtime_policy_key=None,
            agent_id="agent-123",
        )

        self.assertIsNone(error)
        self.assertEqual(policy, mock_existing)

    @patch(f"{MODULE}.ima")
    @patch(f"{MODULE}.signing")
    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.IMAPolicy")
    def test_integrity_error_refetch_fails_returns_500(self, mock_ima_policy_cls, mock_config, mock_signing, mock_ima):
        """Test that if IntegrityError occurs and re-fetch also fails, return 500."""
        mock_config.getboolean.return_value = False
        mock_signing.get_runtime_policy_keys.return_value = None
        mock_ima.verify_runtime_policy.return_value = None
        mock_ima.runtime_policy_db_contents.return_value = {"name": "agent-123", "ima_policy": "{}"}
        mock_ima.EMPTY_RUNTIME_POLICY = {}
        mock_ima.ImaValidationError = type("ImaValidationError", (Exception,), {"message": "", "code": 400})

        # All get() calls return None
        mock_ima_policy_cls.get.return_value = None

        mock_new_policy = MagicMock()
        orig_exception = Exception("UNIQUE constraint failed: allowlists.name")
        mock_new_policy.commit_changes.side_effect = IntegrityError("INSERT INTO allowlists ...", None, orig_exception)
        mock_ima_policy_cls.return_value = mock_new_policy

        policy, error = resolve_ima_policy_for_agent(
            runtime_policy_name=None,
            runtime_policy="{}",
            runtime_policy_key=None,
            agent_id="agent-123",
        )

        self.assertIsNone(policy)
        assert error is not None
        self.assertEqual(error[0], 500)


if __name__ == "__main__":
    unittest.main()
