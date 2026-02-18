import asyncio
import base64
from typing import Any, Dict, cast

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import joinedload

from keylime import cloud_verifier_common, config, json, keylime_logging, web_util
from keylime.common import states, validators
from keylime.db.verifier_db import VerfierMain, VerifierAllowlist, VerifierMbpolicy
from keylime.shared_data import clear_agent_policy_cache
from keylime.verifier_db_manager import _from_db_obj, exclude_db, session_context, verifier_db_delete_agent
from keylime.web.base import Controller
from keylime.web.verifier.agent_service import build_agent_data, validate_mtls_cert
from keylime.web.verifier.ima_policy_service import resolve_ima_policy_for_agent
from keylime.web.verifier.mb_policy_service import resolve_mb_policy_for_agent

logger = keylime_logging.init_logging("verifier")


class AgentController(Controller):
    # GET /vx[.y]/agents/
    def index(self, **_params):  # type: ignore[no-untyped-def]
        if self.major_version and self.major_version <= 2:
            self._index_v2()
        else:
            self.respond(404)
            # TODO: Replace with v3 implementation

    def _index_v2(self) -> None:
        with session_context() as session:
            if "bulk" in self.query_params:
                verifier = self.query_params.get("verifier")

                query = (
                    session.query(VerfierMain)
                    .options(  # type: ignore
                        joinedload(VerfierMain.ima_policy).load_only(
                            VerifierAllowlist.checksum, VerifierAllowlist.generator  # pyright: ignore
                        )
                    )
                    .options(  # type: ignore
                        joinedload(VerfierMain.mb_policy).load_only(
                            VerifierMbpolicy.mb_policy  # type: ignore[arg-type]
                        )
                    )
                )

                if verifier and verifier != "":
                    agent_list = query.filter_by(verifier_id=verifier).all()
                else:
                    agent_list = query.all()

                json_response: Dict[str, Any] = {}
                for agent in agent_list:
                    # Refresh agent from database to ensure fresh consecutive_attestation_failures
                    session.refresh(agent)
                    json_response[cast(str, agent.agent_id)] = cloud_verifier_common.process_get_status(agent)

                self.respond(200, "Success", json_response)
            else:
                verifier = self.query_params.get("verifier")

                if verifier and verifier != "":
                    json_response_list = (
                        session.query(VerfierMain.agent_id).filter_by(verifier_id=cast(str, verifier)).all()
                    )
                else:
                    json_response_list = session.query(VerfierMain.agent_id).all()

                self.respond(200, "Success", {"uuids": json_response_list})

            logger.info("GET returning 200 response for agent_id list")

    # GET /vx[.y]/agents/:agent_id/
    def show(self, agent_id, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        if self.major_version and self.major_version <= 2:
            self._show_v2(agent_id)
        else:
            self.respond(404)
            # TODO: Replace with v3 implementation

    def _show_v2(self, agent_id: str) -> None:
        if not validators.valid_agent_id(agent_id):
            self.respond(400, "agent_id not not valid")
            logger.error("GET received an invalid agent ID: %s", agent_id)
            return

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
                    .options(  # type: ignore
                        joinedload(VerfierMain.mb_policy).load_only(VerifierMbpolicy.mb_policy)  # pyright: ignore
                    )
                    .filter_by(agent_id=agent_id)
                    .one_or_none()
                )
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)

            if agent is not None:
                # Refresh agent from database to ensure we have the latest consecutive_attestation_failures
                # This is critical for PUSH mode status detection when failures occur
                session.refresh(agent)
                response = cloud_verifier_common.process_get_status(agent)
                self.respond(200, "Success", response)
            else:
                self.respond(404, "agent id not found")

    # POST /v3[.x]/agents/
    # POST /v2[.x]/agents/:agent_id
    def create(self, **_params):  # type: ignore[no-untyped-def]
        if self.major_version and self.major_version <= 2:
            agent_id = self.path_params.get("agent_id")
            if not agent_id:
                self.respond(400, "uri not supported")
                logger.warning("POST returning 400 response. uri not supported")
                return
            if not validators.valid_agent_id(agent_id):
                self.respond(400, "agent_id not not valid")
                logger.error("POST received an invalid agent ID: %s", agent_id)
                return
            self._create_v2(agent_id)
        else:
            self.respond(404)
            # TODO: Replace with v3 implementation

    def _create_v2(self, agent_id: str) -> None:
        mode = config.get("verifier", "mode", fallback="pull")
        # Handle empty string as pull mode (regression from config template changes)
        if not mode:
            mode = "pull"

        try:
            content_length = len(self.request_body)
            if content_length == 0:
                self.respond(400, "Expected non zero content length")
                logger.warning("POST returning 400 response. Expected non zero content length.")
                return

            json_body = json.loads(self.request_body)
            agent_data = build_agent_data(json_body, agent_id, mode)

            mtls_error = validate_mtls_cert(agent_data, mode)
            if mtls_error:
                self.respond(*mtls_error)
                return

            runtime_policy_name = json_body.get("runtime_policy_name")
            runtime_policy = base64.b64decode(json_body.get("runtime_policy")).decode()
            runtime_policy_key = json_body.get("runtime_policy_key")

            with session_context() as session:
                # Prevent overwriting existing agents with UUID provided in request
                try:
                    new_agent_count = session.query(VerfierMain).filter_by(agent_id=agent_id).count()
                except SQLAlchemyError as e:
                    logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)
                    raise e

                if new_agent_count > 0:
                    self.respond(
                        409,
                        f"Agent of uuid {agent_id} already exists. Please use delete or update.",
                    )
                    logger.warning("Agent of uuid %s already exists", agent_id)
                    return

                # Resolve IMA policy
                runtime_policy_stored, ima_error = resolve_ima_policy_for_agent(
                    session, runtime_policy_name, runtime_policy, runtime_policy_key, agent_id
                )
                if ima_error:
                    self.respond(*ima_error)
                    return

                # Resolve MB policy
                mb_policy_stored, mb_error = resolve_mb_policy_for_agent(
                    session, json_body["mb_policy_name"], json_body["mb_policy"], agent_id
                )
                if mb_error:
                    self.respond(*mb_error)
                    return

                # Write the agent to the database, attaching associated stored ima_policy and mb_policy
                try:
                    assert runtime_policy_stored
                    assert mb_policy_stored
                    session.add(VerfierMain(**agent_data, ima_policy=runtime_policy_stored, mb_policy=mb_policy_stored))
                    session.commit()
                except SQLAlchemyError as e:
                    logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)
                    raise e

                # add default fields that are ephemeral
                for key, val in exclude_db.items():
                    agent_data[key] = val

                # Start event loop to periodically obtain quote from agent when operating in pull mode
                if mode == "pull":
                    # Prepare SSLContext for mTLS connections
                    agent_mtls_cert_enabled = config.getboolean("verifier", "enable_agent_mtls", fallback=False)
                    agent_data["ssl_context"] = None
                    if agent_mtls_cert_enabled:
                        agent_data["ssl_context"] = web_util.generate_agent_tls_context(
                            "verifier", agent_data["mtls_cert"], logger=logger
                        )

                    if agent_data["ssl_context"] is None:
                        logger.warning("Connecting to agent without mTLS: %s", agent_id)

                    # pylint: disable=import-outside-toplevel
                    from keylime.cloud_verifier_tornado import process_agent

                    asyncio.ensure_future(process_agent(agent_data, states.GET_QUOTE))

                self.respond(200, "Success")
                logger.info("POST returning 200 response for adding agent id: %s", agent_id)
        except Exception as e:
            self.respond(400, f"Exception error: {str(e)}")
            logger.exception("POST returning 400 response.")

    # PATCH /v3[.x]/agents/:agent_id/
    def update(self, agent_id, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        self.respond(404)
        # TODO: Replace with v3 implementation

    # DELETE /vx[.y]/agents/:agent_id/
    def delete(self, agent_id, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        if self.major_version and self.major_version <= 2:
            self._delete_v2(agent_id)
        else:
            self.respond(404)
            # TODO: Replace with v3 implementation

    def _delete_v2(self, agent_id: str) -> None:
        if not validators.valid_agent_id(agent_id):
            self.respond(400, "agent_id not not valid")
            logger.error("DELETE received an invalid agent ID: %s", agent_id)
            return

        with session_context() as session:
            agent = None
            try:
                agent = session.query(VerfierMain).filter_by(agent_id=agent_id).first()
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)

            if agent is None:
                self.respond(404, "agent id not found")
                logger.info("DELETE returning 404 response. agent id: %s not found.", agent_id)
                return

            verifier_id = config.get("verifier", "uuid", fallback=cloud_verifier_common.DEFAULT_VERIFIER_ID)
            if verifier_id != agent.verifier_id:
                self.respond(404, "agent id associated to this verifier")
                logger.info("DELETE returning 404 response. agent id: %s not associated to this verifer.", agent_id)
                return

            # Cleanup the cache when the agent is deleted. Do it early.
            clear_agent_policy_cache(agent_id)
            logger.debug(
                "Cleaned up policy cache from all entries used by agent %s",
                agent_id,
            )

            # Check verifier mode
            mode = config.get("verifier", "mode", fallback="pull")
            if not mode:
                mode = "pull"

            if mode == "push":
                # Push mode: Always delete immediately (synchronous deletion)
                try:
                    verifier_db_delete_agent(session, agent_id)
                    self.respond(200, "Success")
                    logger.info("DELETE (push mode) returning 200 response for agent id: %s", agent_id)
                except SQLAlchemyError as e:
                    logger.error("SQLAlchemy Error deleting agent in push mode: %s", e)
                    self.respond(500, "Internal Server Error")
            else:
                # Pull mode: Use operational_state to determine deletion behavior
                op_state = agent.operational_state
                if op_state in (
                    states.SAVED,
                    states.FAILED,
                    states.TERMINATED,
                    states.TENANT_FAILED,
                    states.INVALID_QUOTE,
                ):
                    try:
                        verifier_db_delete_agent(session, agent_id)
                        self.respond(200, "Success")
                        logger.info("DELETE (pull mode) returning 200 response for agent id: %s", agent_id)
                    except SQLAlchemyError as e:
                        logger.error("SQLAlchemy Error deleting agent in pull mode: %s", e)
                        self.respond(500, "Internal Server Error")
                else:
                    try:
                        update_agent = session.get(VerfierMain, agent_id)  # type: ignore[attr-defined]
                        assert update_agent
                        update_agent.operational_state = states.TERMINATED  # pyright: ignore
                        session.add(update_agent)
                        # session.commit() is automatically called by context manager
                        self.respond(202, "Accepted")
                        logger.info("DELETE (pull mode) returning 202 response for agent id: %s", agent_id)
                    except SQLAlchemyError as e:
                        logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)

    # PUT /v2[.x]/agents/:agent_id/reactivate/
    def reactivate(self, agent_id, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        if self.major_version and self.major_version <= 2:
            self._reactivate_v2(agent_id)

    def _reactivate_v2(self, agent_id: str) -> None:
        if not validators.valid_agent_id(agent_id):
            self.respond(400, "agent_id not not valid")
            logger.error("PUT received an invalid agent ID: %s", agent_id)
            return

        try:
            with session_context() as session:
                try:
                    verifier_id = config.get("verifier", "uuid", fallback=cloud_verifier_common.DEFAULT_VERIFIER_ID)
                    db_agent = session.query(VerfierMain).filter_by(agent_id=agent_id, verifier_id=verifier_id).one()
                except SQLAlchemyError as e:
                    logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)
                    raise e

                if db_agent is None:
                    self.respond(404, "agent id not found")
                    logger.info("PUT returning 404 response. agent id: %s not found.", agent_id)
                    return

                # Check if this is a push-mode agent (no ip/port) or pull-mode agent
                is_push_mode = db_agent.ip is None and db_agent.port is None

                if is_push_mode:
                    # For push-mode agents: just re-enable attestations
                    try:
                        session.query(VerfierMain).filter(VerfierMain.agent_id == agent_id).update(  # pyright: ignore
                            {"accept_attestations": True}
                        )
                        # session.commit() is automatically called by context manager
                        self.respond(200, "Success")
                        logger.info(
                            "PUT returning 200 response for push-mode agent id: %s (accept_attestations re-enabled)",
                            agent_id,
                        )
                    except SQLAlchemyError as e:
                        logger.error("SQLAlchemy Error during push-mode reactivate: %s", e)
                        self.respond(500, "Internal server error")
                else:
                    # For pull-mode agents: start polling thread
                    agent = _from_db_obj(db_agent)

                    if agent["mtls_cert"] and agent["mtls_cert"] != "disabled":
                        agent["ssl_context"] = web_util.generate_agent_tls_context(
                            "verifier", agent["mtls_cert"], logger=logger
                        )
                    if agent["ssl_context"] is None:
                        logger.warning("Connecting to agent without mTLS: %s", agent_id)

                    agent["operational_state"] = states.START

                    # pylint: disable=import-outside-toplevel
                    from keylime.cloud_verifier_tornado import process_agent

                    asyncio.ensure_future(process_agent(agent, states.GET_QUOTE))
                    self.respond(200, "Success")
                    logger.info("PUT returning 200 response for pull-mode agent id: %s", agent_id)
        except Exception as e:
            self.respond(400, f"Exception error: {str(e)}")
            logger.exception("PUT returning 400 response.")

    # PUT /v2[.x]/agents/:agent_id/stop/
    def stop(self, agent_id, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        if self.major_version and self.major_version <= 2:
            self._stop_v2(agent_id)

    def _stop_v2(self, agent_id: str) -> None:
        if not validators.valid_agent_id(agent_id):
            self.respond(400, "agent_id not not valid")
            logger.error("PUT received an invalid agent ID: %s", agent_id)
            return

        try:
            with session_context() as session:
                try:
                    verifier_id = config.get("verifier", "uuid", fallback=cloud_verifier_common.DEFAULT_VERIFIER_ID)
                    db_agent = session.query(VerfierMain).filter_by(agent_id=agent_id, verifier_id=verifier_id).one()
                except SQLAlchemyError as e:
                    logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)
                    raise e

                if db_agent is None:
                    self.respond(404, "agent id not found")
                    logger.info("PUT returning 404 response. agent id: %s not found.", agent_id)
                    return

                logger.debug("Stopping polling on %s", agent_id)
                try:
                    session.query(VerfierMain).filter(VerfierMain.agent_id == agent_id).update(  # pyright: ignore
                        {"operational_state": states.TENANT_FAILED}
                    )
                    # session.commit() is automatically called by context manager
                except SQLAlchemyError as e:
                    logger.error("SQLAlchemy Error: %s", e)

                self.respond(200, "Success")
                logger.info("PUT returning 200 response for agent id: %s", agent_id)
        except Exception as e:
            self.respond(400, f"Exception error: {str(e)}")
            logger.exception("PUT returning 400 response.")
