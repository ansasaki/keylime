"""Stateless service functions for agent enrollment data preparation.

Handles agent data construction, API version negotiation, and mTLS
validation for the verifier's agent enrollment workflow.
"""

from typing import Any, Dict, Optional, Tuple

from keylime import api_version as keylime_api_version
from keylime import cloud_verifier_common, config, keylime_logging
from keylime.common import states

logger = keylime_logging.init_logging("verifier")


def resolve_supported_version(json_body: Dict[str, Any], agent_id: str) -> str:
    """Validate and resolve the API version for an agent.

    Returns the requested version if supported, otherwise falls back
    to the current version.
    """
    supported_version = json_body.get("supported_version")
    if supported_version:
        if not keylime_api_version.is_supported_version(supported_version):
            logger.warning(
                "Agent %s requested API version %s which is not supported by verifier. "
                "Verifier supports: %s. Will attempt version negotiation on first contact.",
                agent_id,
                supported_version,
                keylime_api_version.all_versions(),
            )
            supported_version = keylime_api_version.current_version()
    else:
        supported_version = keylime_api_version.current_version()
    return supported_version


def build_agent_data(json_body: Dict[str, Any], agent_id: str, mode: str) -> Dict[str, Any]:
    """Build the agent data dictionary for enrollment.

    Pure function that constructs the agent data from the JSON request body,
    agent ID, and operating mode (push/pull).
    """
    # For push-mode agents, ip/port should be None (agent pushes to verifier)
    # For pull-mode agents, ip/port are required (verifier pulls from agent)
    if mode == "push":
        agent_ip = None
        agent_port = None
    else:
        agent_ip = json_body.get("cloudagent_ip")
        agent_port = json_body.get("cloudagent_port")
        if agent_port is not None:
            agent_port = int(agent_port)

    supported_version = resolve_supported_version(json_body, agent_id)

    agent_data: Dict[str, Any] = {
        "v": json_body.get("v", None),
        "ip": agent_ip,
        "port": agent_port,
        "operational_state": states.GET_QUOTE if mode == "push" else states.START,
        "public_key": "",
        "tpm_policy": json_body["tpm_policy"],
        "meta_data": json_body["metadata"],
        "ima_sign_verification_keys": json_body["ima_sign_verification_keys"],
        "revocation_key": json_body["revocation_key"],
        "accept_tpm_hash_algs": json_body["accept_tpm_hash_algs"],
        "accept_tpm_encryption_algs": json_body["accept_tpm_encryption_algs"],
        "accept_tpm_signing_algs": json_body["accept_tpm_signing_algs"],
        "supported_version": supported_version,
        "ak_tpm": json_body["ak_tpm"],
        "mtls_cert": json_body.get("mtls_cert", None),
        "hash_alg": "",
        "enc_alg": "",
        "sign_alg": "",
        "agent_id": agent_id,
        "boottime": 0,
        "ima_pcrs": [],
        "pcr10": None,
        "next_ima_ml_entry": 0,
        "learned_ima_keyrings": {},
        "verifier_id": config.get("verifier", "uuid", fallback=cloud_verifier_common.DEFAULT_VERIFIER_ID),
        "attestation_count": 0,
        "last_received_quote": 0,
        "last_successful_attestation": 0,
        "accept_attestations": True,
    }

    if "verifier_ip" in json_body:
        agent_data["verifier_ip"] = json_body["verifier_ip"]
    else:
        agent_data["verifier_ip"] = config.get("verifier", "ip")

    if "verifier_port" in json_body:
        agent_data["verifier_port"] = json_body["verifier_port"]
    else:
        agent_data["verifier_port"] = config.get("verifier", "port")

    return agent_data


def validate_mtls_cert(agent_data: Dict[str, Any], mode: str) -> Optional[Tuple[int, str]]:
    """Validate mTLS certificate requirements for agent enrollment.

    Returns an error tuple (status_code, message) if validation fails,
    or None if validation passes.
    """
    agent_mtls_cert_enabled = config.getboolean("verifier", "enable_agent_mtls", fallback=False)

    if all(
        [
            agent_data["supported_version"] != "1.0",
            agent_mtls_cert_enabled,
            (agent_data["mtls_cert"] is None or agent_data["mtls_cert"] == "disabled"),
            mode == "pull",
        ]
    ):
        return (400, "mTLS certificate for agent is required!")

    return None
