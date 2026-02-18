"""Unit tests for agent_service module.

Tests the stateless service functions for agent enrollment data preparation
including build_agent_data, resolve_supported_version, and validate_mtls_cert.
"""

import unittest
from unittest.mock import patch

from keylime.common import states
from keylime.web.verifier.agent_service import build_agent_data, resolve_supported_version, validate_mtls_cert

MODULE = "keylime.web.verifier.agent_service"


def _minimal_json_body():
    """Return a minimal JSON body for agent enrollment."""
    return {
        "v": "1",
        "cloudagent_ip": "127.0.0.1",
        "cloudagent_port": "9002",
        "tpm_policy": "{}",
        "metadata": "{}",
        "ima_sign_verification_keys": "",
        "revocation_key": "",
        "accept_tpm_hash_algs": ["sha256"],
        "accept_tpm_encryption_algs": ["rsa"],
        "accept_tpm_signing_algs": ["rsassa"],
        "ak_tpm": "ak",
        "mtls_cert": "cert_data",
    }


class TestResolvedSupportedVersion(unittest.TestCase):
    """Test cases for resolve_supported_version."""

    @patch(f"{MODULE}.keylime_api_version")
    def test_valid_version_accepted(self, mock_api_version):
        """Test that a valid supported version is accepted as-is."""
        mock_api_version.is_supported_version.return_value = True
        body = {"supported_version": "2.1"}

        result = resolve_supported_version(body, "agent-1")

        self.assertEqual(result, "2.1")

    @patch(f"{MODULE}.keylime_api_version")
    def test_unsupported_version_falls_back(self, mock_api_version):
        """Test that unsupported version falls back to current."""
        mock_api_version.is_supported_version.return_value = False
        mock_api_version.current_version.return_value = "2.1"
        mock_api_version.all_versions.return_value = ["2.0", "2.1"]
        body = {"supported_version": "99.0"}

        result = resolve_supported_version(body, "agent-1")

        self.assertEqual(result, "2.1")

    @patch(f"{MODULE}.keylime_api_version")
    def test_missing_version_uses_current(self, mock_api_version):
        """Test that missing version uses current."""
        mock_api_version.current_version.return_value = "2.1"

        result = resolve_supported_version({}, "agent-1")

        self.assertEqual(result, "2.1")


class TestBuildAgentData(unittest.TestCase):
    """Test cases for build_agent_data."""

    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.cloud_verifier_common")
    @patch(f"{MODULE}.keylime_api_version")
    def test_pull_mode_uses_json_ip_port(self, mock_api_version, mock_cvc, mock_config):
        """Test that pull mode extracts IP/port from JSON body."""
        mock_api_version.current_version.return_value = "2.1"
        mock_cvc.DEFAULT_VERIFIER_ID = "default"
        mock_config.get.return_value = "fallback"

        body = _minimal_json_body()
        result = build_agent_data(body, "agent-1", "pull")

        self.assertEqual(result["ip"], "127.0.0.1")
        self.assertEqual(result["port"], 9002)
        self.assertEqual(result["agent_id"], "agent-1")

    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.cloud_verifier_common")
    @patch(f"{MODULE}.keylime_api_version")
    def test_push_mode_sets_ip_port_none(self, mock_api_version, mock_cvc, mock_config):
        """Test that push mode sets IP/port to None."""
        mock_api_version.current_version.return_value = "2.1"
        mock_cvc.DEFAULT_VERIFIER_ID = "default"
        mock_config.get.return_value = "fallback"

        body = _minimal_json_body()
        result = build_agent_data(body, "agent-1", "push")

        self.assertIsNone(result["ip"])
        self.assertIsNone(result["port"])

    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.cloud_verifier_common")
    @patch(f"{MODULE}.keylime_api_version")
    def test_push_mode_operational_state(self, mock_api_version, mock_cvc, mock_config):
        """Test that push mode sets GET_QUOTE state."""
        mock_api_version.current_version.return_value = "2.1"
        mock_cvc.DEFAULT_VERIFIER_ID = "default"
        mock_config.get.return_value = "fallback"

        body = _minimal_json_body()
        result = build_agent_data(body, "agent-1", "push")

        self.assertEqual(result["operational_state"], states.GET_QUOTE)

    @patch(f"{MODULE}.config")
    @patch(f"{MODULE}.cloud_verifier_common")
    @patch(f"{MODULE}.keylime_api_version")
    def test_pull_mode_operational_state(self, mock_api_version, mock_cvc, mock_config):
        """Test that pull mode sets START state."""
        mock_api_version.current_version.return_value = "2.1"
        mock_cvc.DEFAULT_VERIFIER_ID = "default"
        mock_config.get.return_value = "fallback"

        body = _minimal_json_body()
        result = build_agent_data(body, "agent-1", "pull")

        self.assertEqual(result["operational_state"], states.START)


class TestValidateMtlsCert(unittest.TestCase):
    """Test cases for validate_mtls_cert."""

    @patch(f"{MODULE}.config")
    def test_mtls_required_missing_returns_error(self, mock_config):
        """Test that missing mTLS cert returns error when required."""
        mock_config.getboolean.return_value = True
        agent_data = {"supported_version": "2.1", "mtls_cert": None}

        result = validate_mtls_cert(agent_data, "pull")

        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result[0], 400)

    @patch(f"{MODULE}.config")
    def test_mtls_not_required_returns_none(self, mock_config):
        """Test that disabled mTLS returns None."""
        mock_config.getboolean.return_value = False
        agent_data = {"supported_version": "2.1", "mtls_cert": None}

        result = validate_mtls_cert(agent_data, "pull")

        self.assertIsNone(result)

    @patch(f"{MODULE}.config")
    def test_mtls_push_mode_returns_none(self, mock_config):
        """Test that push mode always passes mTLS validation."""
        mock_config.getboolean.return_value = True
        agent_data = {"supported_version": "2.1", "mtls_cert": None}

        result = validate_mtls_cert(agent_data, "push")

        self.assertIsNone(result)

    @patch(f"{MODULE}.config")
    def test_mtls_cert_present_returns_none(self, mock_config):
        """Test that valid mTLS cert passes validation."""
        mock_config.getboolean.return_value = True
        agent_data = {"supported_version": "2.1", "mtls_cert": "valid_cert"}

        result = validate_mtls_cert(agent_data, "pull")

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
