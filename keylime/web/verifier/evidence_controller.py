"""Controller for on-demand verification of attestation evidence.

This controller handles evidence verification requests, which validate
that attestation evidence (quotes, logs, etc.) is valid and trustworthy.

For identity verification (verifying TPM genuineness), use IdentityController.

All actions in this controller are PUBLIC (no authentication required).
"""

import base64
from typing import Any, Dict, Optional, Tuple

from keylime import cloud_verifier_common, config, json, keylime_logging, web_util
from keylime.failure import Component, Failure
from keylime.ima import ima
from keylime.tee import snp
from keylime.web.base import APIError, APILink, APIResource, Controller
from keylime.web.base.exceptions import StopAction

logger = keylime_logging.init_logging("verifier")


class EvidenceController(Controller):
    """Controller for on-demand verification of attestation evidence.

    This controller handles evidence verification requests, which validate
    that attestation evidence (quotes, logs, etc.) is valid and trustworthy.

    For identity verification (verifying TPM genuineness), use IdentityController.

    All actions in this controller are PUBLIC (no authentication required).
    """

    def _new_v2_handler(self):  # type: ignore[no-untyped-def]
        """Create a legacy v2 VerifyEvidenceHandler."""
        # pylint: disable=import-outside-toplevel  # Avoid circular import
        from keylime import cloud_verifier_tornado as v2

        tornado_app = self.action_handler.application
        tornado_req = self.action_handler.request
        return v2.VerifyEvidenceHandler(tornado_app, tornado_req, override=self.action_handler)  # type: ignore[no-untyped-call]

    # POST /v3[.x]/verify/evidence
    # POST /v2[.x]/verify/evidence
    def process(self, **_params):  # type: ignore[no-untyped-def]
        """Verify attestation evidence.

        This is a PUBLIC action - no authentication required.

        For API v2, delegates to the legacy VerifyEvidenceHandler.
        For API v3+, uses JSON:API format.
        """
        if self.major_version and self.major_version <= 2:
            self._new_v2_handler().post()  # type: ignore[no-untyped-call]
        else:
            self._process_v3(**_params)

    # ---- Shared verification helpers ----

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
            mb_policy_name = config.get("verifier", "measured_boot_policy_name", fallback="accept-all")
            failure = cloud_verifier_common.process_verify_attestation(
                tpm_ek,
                tpm_ak,
                quote,
                nonce,
                hash_alg,
                tpm_policy,
                policy_obj,
                mb_policy,
                ima_measurement_list,
                mb_log,
                mb_policy_name=mb_policy_name,
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

    # ---- v3 implementation ----

    @Controller.require_json_api  # type: ignore[misc, untyped-decorator]
    def _process_v3(self, evidence: Optional[Dict[str, Any]] = None, **_params: Any) -> None:
        if not evidence:
            APIError("invalid_request", 400).set_detail(  # type: ignore[no-untyped-call]
                "Request body must include evidence data with type 'evidence'."
            ).send_via(self)

        assert evidence is not None

        evidence_type = evidence.get("evidence_type")
        if not evidence_type:
            APIError("invalid_resource_data").set_detail(  # type: ignore[no-untyped-call]
                "Attribute 'evidence_type' is required."
            ).send_via(self)

        data = evidence.get("data")
        if not data:
            APIError("invalid_resource_data").set_detail(  # type: ignore[no-untyped-call]
                "Attribute 'data' is required."
            ).send_via(self)

        assert data is not None

        try:
            if evidence_type == "tpm":
                claims, attestation_failure = self._tpm_verify(data)
            elif evidence_type == "tee":
                claims, attestation_failure = self._tee_verify(data)
            else:
                APIError("invalid_resource_data").set_detail(  # type: ignore[no-untyped-call]
                    f"Invalid evidence type: {evidence_type}"
                ).send_via(self)
                return  # unreachable but satisfies type checker

            result_attrs: Dict[str, Any] = {
                "valid": False,
                "claims": {},
                "failures": [],
            }

            if attestation_failure and attestation_failure.events:
                failures = []
                is_input_error = False
                for event in attestation_failure.events:
                    failures.append(
                        {
                            "type": event.event_id,
                            "context": json.loads(event.context),
                        }
                    )
                    if event.event_id.endswith(".missing_param") or event.event_id.endswith(".missing_policy"):
                        is_input_error = True
                result_attrs["failures"] = failures

                if is_input_error:
                    APIError("invalid_resource_data", 400).set_detail(  # type: ignore[no-untyped-call]
                        "Missing required evidence parameters."
                    ).send_via(self)
            else:
                result_attrs["valid"] = True
                result_attrs["claims"] = claims

            APIResource(
                "evidence_result",
                result_attrs,
            ).include(APILink("self", f"/v{self.version}/verify/evidence")).send_via(
                self, code=200
            )  # type: ignore[no-untyped-call]

        except StopAction:
            raise
        except Exception:
            logger.exception("Failed to process attestation evidence")
            APIError("server_error", 500).set_detail(  # type: ignore[no-untyped-call]
                "Internal Server Error: Failed to process attestation data."
            ).send_via(self)


def _extract_required(data: Dict[str, Any], key: str, failure: Failure) -> Any:
    """Extract a required field from data, adding a failure event if missing."""
    value = data.get(key)
    if value is None or value == "":
        failure.add_event(
            f"{key}.missing_param",
            {"message": f"missing required parameter '{key}'"},
            False,
        )
        logger.warning("POST returning 400 response. missing parameter '%s'", key)
        return None
    return value
