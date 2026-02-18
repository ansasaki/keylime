"""Unit tests for ima_policy_service module.

Tests the IMA policy resolution service used during agent enrollment,
including policy lookup, creation, signature verification, and error handling.
"""

import unittest
from unittest.mock import MagicMock, patch

from keylime.web.verifier.ima_policy_service import resolve_ima_policy_for_agent

MODULE = "keylime.web.verifier.ima_policy_service"


class TestResolveImaPolicyForAgent(unittest.TestCase):
    """Test cases for resolve_ima_policy_for_agent."""

    def test_named_policy_found_returns_stored(self):
        """Test that an existing named policy is returned directly."""
        session = MagicMock()
        stored_policy = MagicMock()
        session.query.return_value.filter_by.return_value.one_or_none.return_value = stored_policy

        policy, error = resolve_ima_policy_for_agent(session, "my_policy", "", None, "agent-1")

        self.assertIs(policy, stored_policy)
        self.assertIsNone(error)

    def test_named_policy_conflict_returns_409(self):
        """Test that providing both name and inline policy when stored exists returns 409."""
        session = MagicMock()
        stored_policy = MagicMock()
        session.query.return_value.filter_by.return_value.one_or_none.return_value = stored_policy

        policy, error = resolve_ima_policy_for_agent(session, "my_policy", '{"key": "value"}', None, "agent-1")

        self.assertIsNone(policy)
        self.assertIsNotNone(error)
        assert error is not None
        self.assertEqual(error[0], 409)

    def test_named_policy_not_found_returns_404(self):
        """Test that referencing a non-existent named policy returns 404."""
        session = MagicMock()
        session.query.return_value.filter_by.return_value.one_or_none.return_value = None

        policy, error = resolve_ima_policy_for_agent(session, "missing_policy", "", None, "agent-1")

        self.assertIsNone(policy)
        self.assertIsNotNone(error)
        assert error is not None
        self.assertEqual(error[0], 404)

    @patch(f"{MODULE}.VerifierAllowlist")
    @patch(f"{MODULE}.ima")
    @patch(f"{MODULE}.signing")
    @patch(f"{MODULE}.config")
    def test_inline_policy_created(self, mock_config, mock_signing, mock_ima, mock_allowlist_cls):
        """Test that inline policy is verified, serialized, and stored."""
        session = MagicMock()
        # First query for named lookup returns None, second for after creation returns None
        session.query.return_value.filter_by.return_value.one_or_none.return_value = None
        mock_config.getboolean.return_value = False
        mock_signing.get_runtime_policy_keys.return_value = None
        mock_ima.runtime_policy_db_contents.return_value = {"name": "agent-1"}
        mock_allowlist_cls.return_value = MagicMock()

        policy, error = resolve_ima_policy_for_agent(session, None, '{"allow": []}', None, "agent-1")

        self.assertIsNone(error)
        self.assertIsNotNone(policy)
        session.add.assert_called_once()
        session.commit.assert_called_once()

    @patch(f"{MODULE}.VerifierAllowlist")
    @patch(f"{MODULE}.ima")
    def test_empty_policy_default(self, mock_ima, mock_allowlist_cls):
        """Test that missing policy uses EMPTY_RUNTIME_POLICY."""
        session = MagicMock()
        session.query.return_value.filter_by.return_value.one_or_none.return_value = None
        mock_ima.EMPTY_RUNTIME_POLICY = {"meta": {}, "release": 0, "digests": {}}
        mock_ima.runtime_policy_db_contents.return_value = {"name": "agent-1"}
        mock_ima.ImaValidationError = type("ImaValidationError", (Exception,), {"code": 400, "message": "err"})
        mock_allowlist_cls.return_value = MagicMock()

        with patch(f"{MODULE}.signing") as mock_signing, patch(f"{MODULE}.config") as mock_config:
            mock_config.getboolean.return_value = False
            mock_signing.get_runtime_policy_keys.return_value = None

            policy, error = resolve_ima_policy_for_agent(session, None, "", None, "agent-1")

        self.assertIsNone(error)
        self.assertIsNotNone(policy)

    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.signing")
    @patch(f"{MODULE}.ima")
    def test_invalid_signature_returns_error(self, mock_ima, mock_signing, mock_config):
        """Test that ImaValidationError from verify is returned as error tuple."""
        session = MagicMock()
        mock_config.getboolean.return_value = True
        mock_signing.get_runtime_policy_keys.return_value = b"key"
        error_cls = type("ImaValidationError", (Exception,), {"code": 401, "message": "bad signature"})
        mock_ima.ImaValidationError = error_cls
        mock_ima.verify_runtime_policy.side_effect = error_cls()

        policy, error = resolve_ima_policy_for_agent(session, None, '{"allow": []}', "key", "agent-1")

        self.assertIsNone(policy)
        self.assertIsNotNone(error)
        assert error is not None
        self.assertEqual(error[0], 401)

    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.signing")
    @patch(f"{MODULE}.ima")
    def test_malformed_policy_returns_error(self, mock_ima, mock_signing, mock_config):
        """Test that ImaValidationError from serialization is returned as error tuple."""
        session = MagicMock()
        mock_config.getboolean.return_value = False
        mock_signing.get_runtime_policy_keys.return_value = None
        error_cls = type("ImaValidationError", (Exception,), {"code": 400, "message": "bad format"})
        mock_ima.ImaValidationError = error_cls
        mock_ima.runtime_policy_db_contents.side_effect = error_cls()

        policy, error = resolve_ima_policy_for_agent(session, None, '{"allow": []}', None, "agent-1")

        self.assertIsNone(policy)
        self.assertIsNotNone(error)
        assert error is not None
        self.assertEqual(error[0], 400)
        self.assertIn("malformatted", error[1])


if __name__ == "__main__":
    unittest.main()
