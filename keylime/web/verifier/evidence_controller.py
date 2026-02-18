"""Controller for on-demand verification of attestation evidence.

This controller handles evidence verification requests, which validate
that attestation evidence (quotes, logs, etc.) is valid and trustworthy.

For identity verification (verifying TPM genuineness), use IdentityController.

All actions in this controller are PUBLIC (no authentication required).
"""

import base64
from typing import Any, Dict, Optional, Tuple

from keylime import cloud_verifier_common, json, keylime_logging, web_util
from keylime.failure import Component, Failure
from keylime.ima import ima
from keylime.tee import snp
from keylime.web.base import Controller

logger = keylime_logging.init_logging("verifier")


def _extract_required(data: Dict[str, Any], key: str, failure: Failure) -> Optional[Any]:
    """Extract a required non-empty parameter from data.

    Returns the value if present and non-empty, or None after adding a
    failure event for the missing parameter.
    """
    if key in data and data[key] != "":
        return data[key]
    failure.add_event("missing_param", {"message": f'missing parameter "{key}"'}, False)
    logger.warning("POST returning 400 response. missing query parameter '%s'", key)
    return None


class EvidenceController(Controller):
    """Controller for on-demand verification of attestation evidence.

    This controller handles evidence verification requests, which validate
    that attestation evidence (quotes, logs, etc.) is valid and trustworthy.

    For identity verification (verifying TPM genuineness), use IdentityController.

    All actions in this controller are PUBLIC (no authentication required).
    """

    # POST /v2[.x]/verify/evidence
    def process(self, **_params):  # type: ignore[no-untyped-def]
        """Verify attestation evidence.

        This is a PUBLIC action - no authentication required.
        """
        if self.major_version and self.major_version <= 2:
            self._process_v2()
        else:
            self.respond(404)
            # TODO: Replace with v3 implementation

    def _process_v2(self) -> None:
        json_body: Dict[str, Any] = {}
        try:
            json_body = json.loads(self.request_body)
        except Exception as e:
            logger.warning("Failed to parse JSON body POST data: %s", e)
            return

        evidence_type = None
        data = None

        if "type" in json_body and json_body["type"] != "":
            evidence_type = json_body["type"]
        else:
            self.respond(400, "missing parameter 'type'")
            logger.warning("POST returning 400 response. missing query parameter 'type'")
            return

        if "data" in json_body and json_body["data"] != "":
            data = json_body["data"]
        else:
            self.respond(400, "missing parameter 'data'")
            logger.warning("POST returning 400 response. missing query parameter 'data'")
            return

        attestation_response: Dict[str, Any] = {}

        attestation_response["valid"] = False
        attestation_response["claims"] = {}
        attestation_response["failures"] = []

        try:
            if evidence_type == "tpm":
                claims, attestation_failure = self._tpm_verify(data)
                attestation_response["claims"] = claims
            elif evidence_type == "tee":
                claims, attestation_failure = self._tee_verify(data)
                attestation_response["claims"] = claims
            else:
                self.respond(400, "invalid evidence type")
                logger.warning("POST returning 400 response. invalid evidence type")
                return

            if attestation_failure:
                failures = []
                is_input_error = False
                for event in attestation_failure.events:
                    failures.append(
                        {
                            "type": event.event_id,
                            "context": json.loads(event.context),
                        }
                    )
                    # Check if this is an input validation error
                    if event.event_id.endswith(".missing_param") or event.event_id.endswith(".missing_policy"):
                        is_input_error = True
                attestation_response["failures"] = failures

                # Return 400 for input validation errors, 200 for attestation failures
                if is_input_error:
                    self.respond(400, "Bad Request", attestation_response)
                else:
                    self.respond(200, "Success", attestation_response)
            else:
                attestation_response["valid"] = True
                self.respond(200, "Success", attestation_response)
        except Exception:
            self.respond(500, "Internal Server Error: Failed to process attestation data")

    def _tpm_verify(self, data: Dict[str, Any]) -> Tuple[Dict[str, Any], Failure]:
        failure = Failure(Component.DEFAULT)

        # Required parameters
        quote = _extract_required(data, "quote", failure)
        if quote is None:
            return ({}, failure)

        nonce = _extract_required(data, "nonce", failure)
        if nonce is None:
            return ({}, failure)

        hash_alg = _extract_required(data, "hash_alg", failure)
        if hash_alg is None:
            return ({}, failure)

        tpm_ek = _extract_required(data, "tpm_ek", failure)
        if tpm_ek is None:
            return ({}, failure)

        tpm_ak = _extract_required(data, "tpm_ak", failure)
        if tpm_ak is None:
            return ({}, failure)

        # Optional parameters
        tpm_policy = data.get("tpm_policy") or ""
        runtime_policy = data.get("runtime_policy") or ""
        mb_policy = data.get("mb_policy") or ""

        # At least one policy must be provided for TPM verification to be meaningful
        if not tpm_policy and not runtime_policy and not mb_policy:
            failure.add_event(
                "missing_policy",
                {"message": "at least one policy (tpm_policy, runtime_policy, or mb_policy) must be provided"},
                False,
            )
            logger.warning("POST returning 400 response. no policy provided for verification")
            return ({}, failure)

        ima_measurement_list = data.get("ima_measurement_list") or ""
        mb_log = data.get("mb_log") or ""

        # process the request for attestation check
        try:
            # TODO - provide better error handling around bad runtime policy
            policy_obj = ima.deserialize_runtime_policy(runtime_policy)
            failure = cloud_verifier_common.process_verify_attestation(
                tpm_ek, tpm_ak, quote, nonce, hash_alg, tpm_policy, policy_obj, mb_policy, ima_measurement_list, mb_log
            )

            if len(failure.events) > 0:
                return ({}, failure)

            return (data, failure)
        except Exception as e:
            logger.warning("Failed to process /verify/evidence data in TPM verifier: %s", e)
            raise

    def _tee_verify(self, data: Dict[str, Any]) -> Tuple[Dict[str, Any], Failure]:
        claims: Dict[str, Any] = {}
        failure = Failure(Component.TEE)

        tee_evidence = _extract_required(data, "tee-evidence", failure)
        if tee_evidence is None:
            return (claims, failure)

        nonce_str = _extract_required(data, "nonce", failure)
        if nonce_str is None:
            return (claims, failure)
        nonce = base64.b64decode(nonce_str.encode("ascii"))

        x_str = _extract_required(data, "tee-pubkey-x-b64", failure)
        if x_str is None:
            return (claims, failure)
        x = web_util.urlsafe_nopad_b64decode(x_str.encode("ascii"))

        y_str = _extract_required(data, "tee-pubkey-y-b64", failure)
        if y_str is None:
            return (claims, failure)
        y = web_util.urlsafe_nopad_b64decode(y_str.encode("ascii"))

        tee = _extract_required(tee_evidence, "tee", failure)
        if tee is None:
            return (claims, failure)

        evidence = _extract_required(tee_evidence, "evidence", failure)
        if evidence is None:
            return (claims, failure)

        if tee == "snp":
            return self._sev_snp_verify(evidence, nonce, x, y)

        failure.add_event("invalid.tee", {"message": "invalid tee argument"}, False)
        logger.warning("POST returning 400 response. invalid tee argument")

        return (claims, failure)

    def _sev_snp_verify(
        self, data: Dict[str, Any], nonce: bytes, x_b64: bytes, y_b64: bytes
    ) -> Tuple[Dict[str, Any], Failure]:
        claims: Dict[str, Any] = {}
        failure = Failure(Component.TEE)

        report_str = _extract_required(data, "snp-report", failure)
        if report_str is None:
            return (claims, failure)
        report = base64.b64decode(report_str.encode("ascii"))

        try:
            claims, failure = snp.verify_attestation(report, nonce, x_b64, y_b64)

            return (claims, failure)
        except Exception as e:
            logger.warning("Failed to process /verify/evidence evidence in SEV-SNP verifier: %s", e)
            raise
