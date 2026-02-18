"""Controller for on-demand identity verification.

This controller handles identity verification requests, which verify that a
TPM quote was produced by a genuine TPM. This is separate from evidence
verification which validates the actual attestation evidence.

Identity verification is a PUBLIC action - it allows any party to verify
that a TPM quote is genuine without requiring authentication.
"""

from typing import cast

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import joinedload

from keylime import cloud_verifier_common, keylime_logging
from keylime.db.verifier_db import VerfierMain, VerifierAllowlist
from keylime.verifier_db_manager import get_AgentAttestStates, session_context
from keylime.web.base import Controller

logger = keylime_logging.init_logging("verifier")


class IdentityController(Controller):
    """Controller for on-demand identity verification.

    This controller handles verification that a TPM quote was produced by a
    genuine TPM (identity verification). It does not verify the attestation
    evidence itself - for that, use EvidenceController.

    All actions in this controller are PUBLIC (no authentication required).
    """

    # GET /v2[.x]/verify/identity
    def verify(self, **_params):  # type: ignore[no-untyped-def]
        """Verify that a TPM quote was produced by a genuine TPM.

        This is a PUBLIC action - no authentication required.
        """
        if self.major_version and self.major_version <= 2:
            self._verify_v2()
        else:
            self.respond(404)
            # TODO: Replace with v3 implementation

    def _verify_v2(self) -> None:
        # make sure we have all of the necessary parameters: agent_uuid, quote, nonce, hash_alg
        agent_id = self.query_params.get("agent_uuid")
        if agent_id is None or agent_id == "":
            self.respond(400, "missing query parameter 'agent_uuid'")
            logger.warning("GET returning 400 response. missing query parameter 'agent_uuid'")
            return

        quote = self.query_params.get("quote")
        if quote is None or quote == "":
            self.respond(400, "missing query parameter 'quote'")
            logger.warning("GET returning 400 response. missing query parameter 'quote'")
            return

        nonce = self.query_params.get("nonce")
        if nonce is None or nonce == "":
            self.respond(400, "missing query parameter 'nonce'")
            logger.warning("GET returning 400 response. missing query parameter 'nonce'")
            return

        hash_alg = self.query_params.get("hash_alg")
        if hash_alg is None or hash_alg == "":
            self.respond(400, "missing query parameter 'hash_alg'")
            logger.warning("GET returning 400 response. missing query parameter 'hash_alg'")
            return

        # get the agent information from the DB
        with session_context() as session:
            agent = None
            try:
                agent = (
                    session.query(VerfierMain)
                    .options(  # type: ignore
                        joinedload(VerfierMain.ima_policy).load_only(
                            VerifierAllowlist.checksum, VerifierAllowlist.generator  # pyright: ignore
                        )
                    )
                    .filter_by(agent_id=agent_id)
                    .one_or_none()
                )
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)

        if agent is not None:
            agent_id_str = cast(str, agent_id)
            agentAttestState = get_AgentAttestStates().get_by_agent_id(agent_id_str)
            failure = cloud_verifier_common.process_verify_identity_quote(
                agent, cast(str, quote), cast(str, nonce), cast(str, hash_alg), agentAttestState
            )
            if failure:
                failure_contexts = "; ".join(x.context for x in failure.events)
                self.respond(200, "Success", {"valid": 0, "reason": failure_contexts})
                logger.info("GET returning 200, but validation failed")
            else:
                self.respond(200, "Success", {"valid": 1})
                logger.info("GET returning 200, validation successful")
        else:
            self.respond(404, "agent id not found")
            logger.info("GET returning 404, agaent not found")
