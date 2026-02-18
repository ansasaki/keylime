"""Unit tests for EvidenceController (verifier).

Tests the verifier's evidence verification endpoint including parameter
validation, TPM verification, TEE verification, and error handling for v2 API.
"""

import unittest
from typing import Any, cast
from unittest.mock import MagicMock, patch

from keylime.web.base.action_handler import StopAction
from keylime.web.verifier.evidence_controller import EvidenceController

MODULE = "keylime.web.verifier.evidence_controller"


def _make_controller(body: bytes = b"") -> Any:
    """Create an EvidenceController with a mocked action handler."""
    mock_action_handler = MagicMock()
    mock_action_handler.request.path = "/v2.1/verify/evidence"
    mock_action_handler.request.body = body
    controller = cast(EvidenceController, EvidenceController(mock_action_handler))
    return controller


def _v3_controller() -> Any:
    """Create a controller with request path set to v3."""
    ctrl = _make_controller()
    ctrl.action_handler.request.path = "/v3.0/verify/evidence"
    return ctrl


class TestEvidenceControllerInputValidation(unittest.TestCase):
    """Test cases for input validation in process()."""

    def test_missing_type_returns_400(self):
        """Test that missing 'type' parameter returns 400."""
        controller = _make_controller(body=b'{"data": {"quote": "q"}}')
        controller.respond = MagicMock()

        controller.process()

        controller.respond.assert_called_once_with(400, "missing parameter 'type'")

    def test_empty_type_returns_400(self):
        """Test that empty 'type' parameter returns 400."""
        controller = _make_controller(body=b'{"type": "", "data": {"quote": "q"}}')
        controller.respond = MagicMock()

        controller.process()

        controller.respond.assert_called_once_with(400, "missing parameter 'type'")

    def test_missing_data_returns_400(self):
        """Test that missing 'data' parameter returns 400."""
        controller = _make_controller(body=b'{"type": "tpm"}')
        controller.respond = MagicMock()

        controller.process()

        controller.respond.assert_called_once_with(400, "missing parameter 'data'")

    def test_invalid_evidence_type_returns_400(self):
        """Test that invalid evidence type returns 400."""
        controller = _make_controller(body=b'{"type": "invalid", "data": {"foo": "bar"}}')
        controller.respond = MagicMock()

        controller.process()

        controller.respond.assert_called_once_with(400, "invalid evidence type")

    def test_invalid_json_returns_silently(self):
        """Test that invalid JSON body is handled gracefully."""
        controller = _make_controller(body=b"not valid json")
        controller.respond = MagicMock()

        controller.process()

        controller.respond.assert_not_called()


class TestEvidenceControllerTPMVerify(unittest.TestCase):
    """Test cases for TPM evidence verification."""

    @patch(f"{MODULE}.cloud_verifier_common")
    @patch(f"{MODULE}.ima")
    def test_tpm_verify_success(self, mock_ima, mock_cvc):
        """Test that TPM verification success returns 200 with valid=True."""
        data = {
            "quote": "q",
            "nonce": "n",
            "hash_alg": "sha256",
            "tpm_ek": "ek",
            "tpm_ak": "ak",
            "tpm_policy": "policy",
        }
        body = f'{{"type": "tpm", "data": {__import__("json").dumps(data)}}}'.encode()
        controller = _make_controller(body=body)
        controller.respond = MagicMock()

        mock_failure = MagicMock()
        mock_failure.__bool__ = MagicMock(return_value=False)
        mock_failure.events = []
        mock_cvc.process_verify_attestation.return_value = mock_failure
        mock_ima.deserialize_runtime_policy.return_value = None

        controller.process()

        call_args = controller.respond.call_args
        self.assertEqual(call_args[0][0], 200)
        self.assertEqual(call_args[0][1], "Success")
        self.assertTrue(call_args[0][2]["valid"])

    @patch(f"{MODULE}.cloud_verifier_common")
    @patch(f"{MODULE}.ima")
    def test_tpm_verify_attestation_failure(self, mock_ima, mock_cvc):
        """Test that TPM verification failure returns 200 with valid=False."""
        data = {
            "quote": "q",
            "nonce": "n",
            "hash_alg": "sha256",
            "tpm_ek": "ek",
            "tpm_ak": "ak",
            "tpm_policy": "policy",
        }
        body = f'{{"type": "tpm", "data": {__import__("json").dumps(data)}}}'.encode()
        controller = _make_controller(body=body)
        controller.respond = MagicMock()

        mock_event = MagicMock()
        mock_event.event_id = "tpm.quote_mismatch"
        mock_event.context = '{"message": "quote mismatch"}'
        mock_failure = MagicMock()
        mock_failure.__bool__ = MagicMock(return_value=True)
        mock_failure.events = [mock_event]
        mock_cvc.process_verify_attestation.return_value = mock_failure
        mock_ima.deserialize_runtime_policy.return_value = None

        controller.process()

        call_args = controller.respond.call_args
        self.assertEqual(call_args[0][0], 200)
        self.assertEqual(call_args[0][1], "Success")
        self.assertFalse(call_args[0][2]["valid"])
        self.assertEqual(len(call_args[0][2]["failures"]), 1)

    def test_tpm_verify_missing_quote_returns_400(self):
        """Test that TPM verify with missing quote returns 400."""
        data = {
            "nonce": "n",
            "hash_alg": "sha256",
            "tpm_ek": "ek",
            "tpm_ak": "ak",
            "tpm_policy": "policy",
        }
        body = f'{{"type": "tpm", "data": {__import__("json").dumps(data)}}}'.encode()
        controller = _make_controller(body=body)
        controller.respond = MagicMock()

        controller.process()

        call_args = controller.respond.call_args
        self.assertEqual(call_args[0][0], 400)
        self.assertEqual(call_args[0][1], "Bad Request")

    def test_tpm_verify_no_policy_returns_400(self):
        """Test that TPM verify with no policies returns 400."""
        data = {
            "quote": "q",
            "nonce": "n",
            "hash_alg": "sha256",
            "tpm_ek": "ek",
            "tpm_ak": "ak",
        }
        body = f'{{"type": "tpm", "data": {__import__("json").dumps(data)}}}'.encode()
        controller = _make_controller(body=body)
        controller.respond = MagicMock()

        controller.process()

        call_args = controller.respond.call_args
        self.assertEqual(call_args[0][0], 400)
        self.assertEqual(call_args[0][1], "Bad Request")

    @patch(f"{MODULE}.ima")
    def test_tpm_verify_internal_error_returns_500(self, mock_ima):
        """Test that internal error during TPM verify returns 500."""
        data = {
            "quote": "q",
            "nonce": "n",
            "hash_alg": "sha256",
            "tpm_ek": "ek",
            "tpm_ak": "ak",
            "tpm_policy": "policy",
        }
        body = f'{{"type": "tpm", "data": {__import__("json").dumps(data)}}}'.encode()
        controller = _make_controller(body=body)
        controller.respond = MagicMock()

        mock_ima.deserialize_runtime_policy.side_effect = RuntimeError("boom")

        controller.process()

        controller.respond.assert_called_once_with(500, "Internal Server Error: Failed to process attestation data")


class TestEvidenceControllerTEEVerify(unittest.TestCase):
    """Test cases for TEE evidence verification."""

    def test_tee_verify_missing_tee_evidence_returns_400(self):
        """Test that TEE verify with missing tee-evidence returns 400."""
        data = {"nonce": "bm9uY2U="}
        body = f'{{"type": "tee", "data": {__import__("json").dumps(data)}}}'.encode()
        controller = _make_controller(body=body)
        controller.respond = MagicMock()

        controller.process()

        call_args = controller.respond.call_args
        self.assertEqual(call_args[0][0], 400)
        self.assertEqual(call_args[0][1], "Bad Request")


class TestEvidenceControllerVersioning(unittest.TestCase):
    """Test cases for version handling."""

    @patch(f"{MODULE}.cloud_verifier_common")
    @patch(f"{MODULE}.ima")
    def test_process_v3_tpm_valid_returns_resource(self, mock_ima, mock_cvc):
        """Test that v3 TPM verification success returns JSON:API resource."""
        controller = _v3_controller()
        controller._api_request_body = MagicMock()  # Satisfy @require_json_api
        controller.send_response = MagicMock()

        mock_failure = MagicMock()
        mock_failure.__bool__ = MagicMock(return_value=False)
        mock_failure.events = []
        mock_cvc.process_verify_attestation.return_value = mock_failure
        mock_ima.deserialize_runtime_policy.return_value = None

        evidence_data = {
            "evidence_type": "tpm",
            "data": {
                "quote": "q",
                "nonce": "n",
                "hash_alg": "sha256",
                "tpm_ek": "ek",
                "tpm_ak": "ak",
                "tpm_policy": "policy",
            },
        }

        with self.assertRaises(StopAction):
            controller.process(evidence=evidence_data)

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 200)
        body = args[2]
        self.assertIn("data", body)
        self.assertEqual(body["data"]["type"], "evidence_result")
        self.assertTrue(body["data"]["attributes"]["valid"])

    @patch(f"{MODULE}.cloud_verifier_common")
    @patch(f"{MODULE}.ima")
    def test_process_v3_tpm_failure_returns_resource_with_failures(self, mock_ima, mock_cvc):
        """Test that v3 TPM verification failure returns resource with failures list."""
        controller = _v3_controller()
        controller._api_request_body = MagicMock()
        controller.send_response = MagicMock()

        mock_event = MagicMock()
        mock_event.event_id = "tpm.quote_mismatch"
        mock_event.context = '{"message": "quote mismatch"}'
        mock_failure = MagicMock()
        mock_failure.__bool__ = MagicMock(return_value=True)
        mock_failure.events = [mock_event]
        mock_cvc.process_verify_attestation.return_value = mock_failure
        mock_ima.deserialize_runtime_policy.return_value = None

        evidence_data = {
            "evidence_type": "tpm",
            "data": {
                "quote": "q",
                "nonce": "n",
                "hash_alg": "sha256",
                "tpm_ek": "ek",
                "tpm_ak": "ak",
                "tpm_policy": "policy",
            },
        }

        with self.assertRaises(StopAction):
            controller.process(evidence=evidence_data)

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 200)
        body = args[2]
        self.assertIn("data", body)
        self.assertFalse(body["data"]["attributes"]["valid"])
        self.assertEqual(len(body["data"]["attributes"]["failures"]), 1)

    def test_process_v3_missing_type_returns_error(self):
        """Test that v3 process returns error when evidence_type missing."""
        controller = _v3_controller()
        controller._api_request_body = MagicMock()
        controller.send_response = MagicMock()

        with self.assertRaises(StopAction):
            controller.process(evidence={"data": {"quote": "q"}})

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 422)

    def test_process_v3_invalid_evidence_type_returns_error(self):
        """Test that v3 process returns error for invalid evidence type."""
        controller = _v3_controller()
        controller._api_request_body = MagicMock()
        controller.send_response = MagicMock()

        with self.assertRaises(StopAction):
            controller.process(
                evidence={
                    "evidence_type": "invalid",
                    "data": {"foo": "bar"},
                }
            )

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 422)

    def test_process_v3_missing_data_returns_error(self):
        """Test that v3 process returns error when no evidence data provided."""
        controller = _v3_controller()
        controller._api_request_body = MagicMock()
        controller.send_response = MagicMock()

        with self.assertRaises(StopAction):
            controller.process()

        controller.send_response.assert_called_once()
        args = controller.send_response.call_args[0]
        self.assertEqual(args[0], 400)


if __name__ == "__main__":
    unittest.main()
