"""Service for measured boot policy resolution during agent enrollment.

Handles looking up, validating, and creating MB reference state policies
using PersistableModel (MBPolicy). No legacy ORM or session management.
"""

from typing import Optional, Tuple

from keylime import keylime_logging
from keylime.mba import mba
from keylime.models.verifier.mb_policy import MBPolicy

logger = keylime_logging.init_logging("verifier")


def resolve_mb_policy_for_agent(
    mb_policy_name: str,
    mb_policy: str,
    agent_id: str,
) -> Tuple[Optional[MBPolicy], Optional[Tuple[int, str]]]:
    """Resolve measured boot policy for agent enrollment.

    Looks up or creates the MB policy based on the provided name and
    inline policy data. Uses PersistableModel for all DB operations.

    Returns:
        A tuple of (policy, error). On success, policy is the resolved
        MBPolicy and error is None. On failure, policy is None and
        error is a (status_code, message) tuple.
    """
    mb_policy_stored = None

    if mb_policy_name:
        mb_policy_stored = MBPolicy.get(name=mb_policy_name)

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

        if not mb_policy and not mb_policy_stored:
            logger.warning("Could not find mb_policy with name %s", mb_policy_name)
            return (None, (404, f"Could not find mb_policy with name {mb_policy_name}!"))

    else:
        mb_policy_name = agent_id
        mb_policy_stored = MBPolicy.get(name=mb_policy_name)

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

    if mb_policy_stored is None:
        mb_policy_db_format = mba.mb_policy_db_contents(mb_policy_name, mb_policy)
        mb_policy_stored = MBPolicy(mb_policy_db_format)
        mb_policy_stored.commit_changes()  # type: ignore[no-untyped-call]

    return (mb_policy_stored, None)
