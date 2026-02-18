"""Unit tests for mb_policy_service module.

Tests the measured boot policy resolution service used during agent
enrollment, including policy lookup, creation, and conflict handling.
"""

import unittest
from unittest.mock import MagicMock, patch

from keylime.web.verifier.mb_policy_service import resolve_mb_policy_for_agent

MODULE = "keylime.web.verifier.mb_policy_service"


class TestResolveMbPolicyForAgent(unittest.TestCase):
    """Test cases for resolve_mb_policy_for_agent."""

    def test_named_policy_found_returns_stored(self):
        """Test that an existing named MB policy is returned directly."""
        session = MagicMock()
        stored_policy = MagicMock()
        session.query.return_value.filter_by.return_value.one_or_none.return_value = stored_policy

        policy, error = resolve_mb_policy_for_agent(session, "my_mb_policy", "", "agent-1")

        self.assertIs(policy, stored_policy)
        self.assertIsNone(error)

    def test_named_policy_conflict_returns_409(self):
        """Test that providing both name and inline policy when stored exists returns 409."""
        session = MagicMock()
        stored_policy = MagicMock()
        session.query.return_value.filter_by.return_value.one_or_none.return_value = stored_policy

        policy, error = resolve_mb_policy_for_agent(session, "my_mb_policy", '{"policy": "data"}', "agent-1")

        self.assertIsNone(policy)
        self.assertIsNotNone(error)
        assert error is not None
        self.assertEqual(error[0], 409)

    def test_named_policy_not_found_returns_404(self):
        """Test that referencing a non-existent named MB policy returns 404."""
        session = MagicMock()
        session.query.return_value.filter_by.return_value.one_or_none.return_value = None

        policy, error = resolve_mb_policy_for_agent(session, "missing_policy", "", "agent-1")

        self.assertIsNone(policy)
        self.assertIsNotNone(error)
        assert error is not None
        self.assertEqual(error[0], 404)

    def test_no_name_uses_agent_id(self):
        """Test that empty name falls back to agent_id as policy name."""
        session = MagicMock()
        session.query.return_value.filter_by.return_value.one_or_none.return_value = None

        with patch(f"{MODULE}.mba") as mock_mba, patch(f"{MODULE}.VerifierMbpolicy") as mock_mb_cls:
            mock_mba.mb_policy_db_contents.return_value = {"name": "agent-1"}
            mock_mb_cls.return_value = MagicMock()

            policy, error = resolve_mb_policy_for_agent(session, "", '{"policy": "data"}', "agent-1")

        self.assertIsNone(error)
        self.assertIsNotNone(policy)
        mock_mba.mb_policy_db_contents.assert_called_once_with("agent-1", '{"policy": "data"}')

    @patch(f"{MODULE}.VerifierMbpolicy")
    @patch(f"{MODULE}.mba")
    def test_policy_created_and_stored(self, mock_mba, mock_mb_cls):
        """Test that a new policy is created and stored in the database."""
        session = MagicMock()
        session.query.return_value.filter_by.return_value.one_or_none.return_value = None
        mock_mba.mb_policy_db_contents.return_value = {"name": "my_policy"}
        mock_mb_cls.return_value = MagicMock()

        policy, error = resolve_mb_policy_for_agent(session, "my_policy", '{"policy": "data"}', "agent-1")

        self.assertIsNone(error)
        self.assertIsNotNone(policy)
        session.add.assert_called_once()
        session.commit.assert_called_once()

    def test_no_name_conflict_with_existing_returns_409(self):
        """Test that unnamed policy with agent_id matching existing returns 409."""
        session = MagicMock()
        stored_policy = MagicMock()
        session.query.return_value.filter_by.return_value.one_or_none.return_value = stored_policy

        policy, error = resolve_mb_policy_for_agent(session, "", '{"policy": "data"}', "agent-1")

        self.assertIsNone(policy)
        self.assertIsNotNone(error)
        assert error is not None
        self.assertEqual(error[0], 409)


if __name__ == "__main__":
    unittest.main()
