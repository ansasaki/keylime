"""Stateless service for IMA policy resolution during agent enrollment.

Handles looking up, validating, and creating IMA runtime policies
in the verifier database.
"""

from typing import Any, Dict, Optional, Tuple, cast

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from keylime import config, json, keylime_logging, signing
from keylime.db.verifier_db import VerifierAllowlist
from keylime.ima import ima

logger = keylime_logging.init_logging("verifier")


def resolve_ima_policy_for_agent(
    session: Session,
    runtime_policy_name: Optional[str],
    runtime_policy: str,
    runtime_policy_key: Optional[str],
    agent_id: str,
) -> Tuple[Optional[VerifierAllowlist], Optional[Tuple[int, str]]]:
    """Resolve IMA runtime policy for agent enrollment.

    Looks up or creates the IMA policy based on the provided name and
    inline policy data. The session is managed by the caller.

    Returns:
        A tuple of (policy, error). On success, policy is the resolved
        VerifierAllowlist and error is None. On failure, policy is None
        and error is a (status_code, message) tuple.
    """
    runtime_policy_stored = None

    if runtime_policy_name:
        try:
            runtime_policy_stored = session.query(VerifierAllowlist).filter_by(name=runtime_policy_name).one_or_none()
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)
            raise

        # Prevent overwriting existing IMA policies with name provided in request
        if runtime_policy and runtime_policy_stored:
            logger.warning("IMA policy with name %s already exists", runtime_policy_name)
            return (
                None,
                (
                    409,
                    f"IMA policy with name {runtime_policy_name} already exists. "
                    "Please use a different name or delete the allowlist from the verifier.",
                ),
            )

        # Return an error code if the named allowlist does not exist in the database
        if not runtime_policy and not runtime_policy_stored:
            logger.warning("Could not find IMA policy with name %s", runtime_policy_name)
            return (None, (404, f"Could not find IMA policy with name {runtime_policy_name}!"))

    # Apply default empty policy if none provided
    if not runtime_policy_name and not runtime_policy:
        logger.info("IMA policy data not provided with request! Using default empty IMA policy.")
        runtime_policy = json.dumps(cast(Dict[str, Any], ima.EMPTY_RUNTIME_POLICY))

    if runtime_policy:
        runtime_policy_key_bytes = signing.get_runtime_policy_keys(
            runtime_policy.encode(),
            runtime_policy_key,
        )

        try:
            ima.verify_runtime_policy(
                runtime_policy.encode(),
                runtime_policy_key_bytes,
                verify_sig=config.getboolean("verifier", "require_allow_list_signatures", fallback=False),
            )
        except ima.ImaValidationError as e:
            logger.warning(e.message)
            return (None, (e.code, e.message))

        if not runtime_policy_name:
            runtime_policy_name = agent_id

        try:
            runtime_policy_db_format = ima.runtime_policy_db_contents(runtime_policy_name, runtime_policy)
        except ima.ImaValidationError as e:
            message = f"Runtime policy is malformatted: {e.message}"
            logger.warning(message)
            return (None, (e.code, message))

        try:
            runtime_policy_stored = session.query(VerifierAllowlist).filter_by(name=runtime_policy_name).one_or_none()
        except SQLAlchemyError as e:
            logger.error(
                "SQLAlchemy Error while retrieving stored ima policy for agent ID %s: %s",
                agent_id,
                e,
            )
            raise

        try:
            if runtime_policy_stored is None:
                runtime_policy_stored = VerifierAllowlist(**runtime_policy_db_format)
                session.add(runtime_policy_stored)
                session.commit()
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error while updating ima policy for agent ID %s: %s", agent_id, e)
            raise

    return (runtime_policy_stored, None)
