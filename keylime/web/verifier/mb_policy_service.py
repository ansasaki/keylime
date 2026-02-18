"""Stateless service for measured boot policy resolution during agent enrollment.

Handles looking up, validating, and creating MB reference state policies
in the verifier database.
"""

from typing import Optional, Tuple

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from keylime import keylime_logging
from keylime.db.verifier_db import VerifierMbpolicy
from keylime.mba import mba

logger = keylime_logging.init_logging("verifier")


def resolve_mb_policy_for_agent(
    session: Session,
    mb_policy_name: str,
    mb_policy: str,
    agent_id: str,
) -> Tuple[Optional[VerifierMbpolicy], Optional[Tuple[int, str]]]:
    """Resolve measured boot policy for agent enrollment.

    Looks up or creates the MB policy based on the provided name and
    inline policy data. The session is managed by the caller.

    Returns:
        A tuple of (policy, error). On success, policy is the resolved
        VerifierMbpolicy and error is None. On failure, policy is None
        and error is a (status_code, message) tuple.
    """
    mb_policy_stored = None

    if mb_policy_name:
        try:
            mb_policy_stored = session.query(VerifierMbpolicy).filter_by(name=mb_policy_name).one_or_none()
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)
            raise

        # Prevent overwriting existing mb_policy with name provided in request
        if mb_policy and mb_policy_stored:
            logger.warning("mb_policy with name %s already exists", mb_policy_name)
            return (
                None,
                (
                    409,
                    f"mb_policy with name {mb_policy_name} already exists. "
                    "Please use a different name or delete the mb_policy from the verifier.",
                ),
            )

        # Return error if the mb_policy is neither provided nor stored.
        if not mb_policy and not mb_policy_stored:
            logger.warning("Could not find mb_policy with name %s", mb_policy_name)
            return (None, (404, f"Could not find mb_policy with name {mb_policy_name}!"))

    else:
        # Use the UUID of the agent
        mb_policy_name = agent_id
        try:
            mb_policy_stored = session.query(VerifierMbpolicy).filter_by(name=mb_policy_name).one_or_none()
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)
            raise

        # Prevent overwriting existing mb_policy
        if mb_policy and mb_policy_stored:
            logger.warning("mb_policy with name %s already exists", mb_policy_name)
            return (
                None,
                (
                    409,
                    f"mb_policy with name {mb_policy_name} already exists. "
                    "You can delete the mb_policy from the verifier.",
                ),
            )

    # Store the policy into database if not stored
    if mb_policy_stored is None:
        try:
            mb_policy_db_format = mba.mb_policy_db_contents(mb_policy_name, mb_policy)
            mb_policy_stored = VerifierMbpolicy(**mb_policy_db_format)
            session.add(mb_policy_stored)
            session.commit()
        except SQLAlchemyError as e:
            logger.error("SQLAlchemy Error while updating mb_policy for agent ID %s: %s", agent_id, e)
            raise

    return (mb_policy_stored, None)
