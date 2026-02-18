import asyncio
import base64
from typing import Any, Dict, Optional, cast

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import joinedload

from keylime import cloud_verifier_common, config, json, keylime_logging, web_util
from keylime.common import states, validators
from keylime.db.verifier_db import VerfierMain, VerifierAllowlist, VerifierMbpolicy
from keylime.models.verifier import IMAPolicy, MBPolicy
from keylime.models.verifier import VerifierAgent as VerifierAgentModel
from keylime.shared_data import clear_agent_policy_cache
from keylime.verifier_db_manager import _from_db_obj, exclude_db, session_context, verifier_db_delete_agent
from keylime.web.base import APIError, APILink, APIResource, Controller
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
            self._index_v3()

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
            self._show_v3(agent_id)

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
            self._create_v3(**_params)

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
        self._update_v3(agent_id, **_params)

    # DELETE /vx[.y]/agents/:agent_id/
    def delete(self, agent_id, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        if self.major_version and self.major_version <= 2:
            self._delete_v2(agent_id)
        else:
            self._delete_v3(agent_id)

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

    # ---- v3 implementations ----

    def _index_v3(self) -> None:
        verifier = self.query_params.get("verifier")
        if verifier:
            agents = VerifierAgentModel.all(verifier_id=verifier)
        else:
            agents = VerifierAgentModel.all()

        data = [
            APIResource(
                "agent",
                str(agent.agent_id),  # type: ignore[no-untyped-call]
                _render_agent_summary(agent),
            )
            .include(APILink("self", f"/v{self.version}/agents/{agent.agent_id}"))
            .render()  # type: ignore[no-untyped-call]
            for agent in agents
        ]

        self.send_response(200, None, {"data": data}, "application/vnd.api+json")

    def _show_v3(self, agent_id: str) -> None:
        if not validators.valid_agent_id(agent_id):
            APIError("invalid_request", 400).set_detail("Invalid agent ID.").send_via(  # type: ignore[no-untyped-call]
                self
            )

        agent = VerifierAgentModel.get(agent_id)
        if not agent:
            APIError("not_found", f"Agent '{agent_id}' not found.").send_via(self)

        assert agent is not None

        APIResource(
            "agent",
            str(agent.agent_id),
            _render_agent_attrs(agent),
        ).include(APILink("self", f"/v{self.version}/agents/{agent_id}")).send_via(
            self, code=200
        )  # type: ignore[no-untyped-call]

    @Controller.require_json_api
    def _create_v3(self, agent: Optional[Dict[str, Any]] = None, **_params: Any) -> None:
        if not agent:
            APIError("invalid_request", 400).set_detail(  # type: ignore[no-untyped-call]
                "Request body must include agent data with type 'agent'."
            ).send_via(self)

        assert agent is not None
        agent_id = agent.get("id")
        if not agent_id:
            APIError("invalid_resource_data").set_detail(  # type: ignore[no-untyped-call]
                "Resource 'id' (agent_id) is required."
            ).send_via(self)

        if not validators.valid_agent_id(agent_id):
            APIError("invalid_request", 400).set_detail(  # type: ignore[no-untyped-call]
                f"Invalid agent ID: {agent_id}"
            ).send_via(self)

        mode = config.get("verifier", "mode", fallback="pull")
        if not mode:
            mode = "pull"

        try:
            agent_data = build_agent_data(agent, agent_id, mode)
        except (KeyError, ValueError) as e:
            APIError("invalid_resource_data").set_detail(  # type: ignore[no-untyped-call]
                f"Missing or invalid enrollment field: {e}"
            ).send_via(self)
            return  # unreachable but satisfies type checker

        mtls_error = validate_mtls_cert(agent_data, mode)
        if mtls_error:
            APIError("invalid_request", mtls_error[0]).set_detail(  # type: ignore[no-untyped-call]
                mtls_error[1]
            ).send_via(self)

        runtime_policy_name = agent.get("runtime_policy_name")
        runtime_policy_b64 = agent.get("runtime_policy", "")
        runtime_policy = base64.b64decode(runtime_policy_b64).decode() if runtime_policy_b64 else ""
        runtime_policy_key = agent.get("runtime_policy_key")

        with session_context() as session:
            # Check for duplicate
            try:
                existing_count = session.query(VerfierMain).filter_by(agent_id=agent_id).count()
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)
                raise

            if existing_count > 0:
                APIError("conflict").set_detail(  # type: ignore[no-untyped-call]
                    f"Agent '{agent_id}' already exists. Use DELETE then POST to re-enroll."
                ).send_via(self)

            # Resolve IMA policy
            ima_policy_stored, ima_error = resolve_ima_policy_for_agent(
                session, runtime_policy_name, runtime_policy, runtime_policy_key, agent_id
            )
            if ima_error:
                APIError("invalid_resource_data", ima_error[0]).set_detail(  # type: ignore[no-untyped-call]
                    ima_error[1]
                ).send_via(self)

            # Resolve MB policy
            mb_policy_stored, mb_error = resolve_mb_policy_for_agent(
                session, agent.get("mb_policy_name", ""), agent.get("mb_policy", "{}"), agent_id
            )
            if mb_error:
                APIError("invalid_resource_data", mb_error[0]).set_detail(  # type: ignore[no-untyped-call]
                    mb_error[1]
                ).send_via(self)

            try:
                assert ima_policy_stored
                assert mb_policy_stored
                session.add(VerfierMain(**agent_data, ima_policy=ima_policy_stored, mb_policy=mb_policy_stored))
                session.commit()
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error for agent ID %s: %s", agent_id, e)
                raise

            # Add ephemeral fields
            for key, val in exclude_db.items():
                agent_data[key] = val

            # Start polling if pull mode
            if mode == "pull":
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

        # Return the created agent resource
        created_agent = VerifierAgentModel.get(agent_id)
        if created_agent:
            APIResource(
                "agent",
                str(agent_id),
                _render_agent_attrs(created_agent),
            ).include(APILink("self", f"/v{self.version}/agents/{agent_id}")).send_via(
                self
            )  # type: ignore[no-untyped-call]

        logger.info("POST returning 201 for agent: %s", agent_id)

    @Controller.require_json_api
    def _update_v3(self, agent_id: str, agent: Optional[Dict[str, Any]] = None, **_params: Any) -> None:
        existing = VerifierAgentModel.get(agent_id)
        if not existing:
            APIError("not_found", f"Agent '{agent_id}' not found.").send_via(self)

        if not agent:
            APIError("invalid_request", 400).set_detail(  # type: ignore[no-untyped-call]
                "Request body must include agent data with type 'agent'."
            ).send_via(self)

        assert agent is not None
        assert existing is not None

        mutable_fields = {
            "tpm_policy",
            "accept_tpm_hash_algs",
            "accept_tpm_encryption_algs",
            "accept_tpm_signing_algs",
            "meta_data",
            "ima_sign_verification_keys",
            "accept_attestations",
        }
        policy_name_fields = {"ima_policy_name", "mb_policy_name"}

        # Reject immutable fields
        for field in agent:
            if field not in mutable_fields and field not in policy_name_fields and field != "id":
                APIError("invalid_resource_data", 422).set_detail(  # type: ignore[no-untyped-call]
                    f"Field '{field}' is not modifiable via PATCH."
                ).send_via(self)

        # Handle policy reassignment by name
        ima_policy_name = agent.get("ima_policy_name")
        if ima_policy_name is not None:
            policy = IMAPolicy.get(name=ima_policy_name)
            if not policy:
                APIError("not_found").set_detail(  # type: ignore[no-untyped-call]
                    f"IMA policy '{ima_policy_name}' not found."
                ).send_via(self)
            assert policy is not None
            existing.change("ima_policy_id", policy.id)  # type: ignore[no-untyped-call]

        mb_policy_name = agent.get("mb_policy_name")
        if mb_policy_name is not None:
            policy = MBPolicy.get(name=mb_policy_name)
            if not policy:
                APIError("not_found").set_detail(  # type: ignore[no-untyped-call]
                    f"MB policy '{mb_policy_name}' not found."
                ).send_via(self)
            assert policy is not None
            existing.change("mb_policy_id", policy.id)  # type: ignore[no-untyped-call]

        # Handle accept_attestations with pull-mode state management
        accept_attestations = agent.get("accept_attestations")
        needs_reactivation = False

        if accept_attestations is not None:
            mode = config.get("verifier", "mode", fallback="pull")
            if not mode:
                mode = "pull"

            if mode == "pull":
                if not accept_attestations:
                    existing.change("operational_state", states.TENANT_FAILED)  # type: ignore[no-untyped-call]
                else:
                    existing.change("operational_state", states.START)  # type: ignore[no-untyped-call]
                    needs_reactivation = True

        # Apply mutable field changes
        for field in mutable_fields:
            if field in agent:
                existing.change(field, agent[field])  # type: ignore[no-untyped-call]

        existing.commit_changes()  # type: ignore[no-untyped-call]

        # For pull mode reactivation, start polling
        if needs_reactivation:
            with session_context() as session:
                db_agent = session.query(VerfierMain).filter_by(agent_id=agent_id).one()
                agent_dict = _from_db_obj(db_agent)

                if agent_dict["mtls_cert"] and agent_dict["mtls_cert"] != "disabled":
                    agent_dict["ssl_context"] = web_util.generate_agent_tls_context(
                        "verifier", agent_dict["mtls_cert"], logger=logger
                    )
                if agent_dict["ssl_context"] is None:
                    logger.warning("Connecting to agent without mTLS: %s", agent_id)

                agent_dict["operational_state"] = states.START

                # pylint: disable=import-outside-toplevel
                from keylime.cloud_verifier_tornado import process_agent

                asyncio.ensure_future(process_agent(agent_dict, states.GET_QUOTE))

        APIResource(
            "agent",
            str(agent_id),
            _render_agent_attrs(existing),
        ).include(APILink("self", f"/v{self.version}/agents/{agent_id}")).send_via(
            self, code=200
        )  # type: ignore[no-untyped-call]

        logger.info("PATCH returning 200 for agent: %s", agent_id)

    def _delete_v3(self, agent_id: str) -> None:
        if not validators.valid_agent_id(agent_id):
            APIError("invalid_request", 400).set_detail("Invalid agent ID.").send_via(  # type: ignore[no-untyped-call]
                self
            )

        agent = VerifierAgentModel.get(agent_id)
        if not agent:
            APIError("not_found", f"Agent '{agent_id}' not found.").send_via(self)

        assert agent is not None

        verifier_id = config.get("verifier", "uuid", fallback=cloud_verifier_common.DEFAULT_VERIFIER_ID)
        if verifier_id != agent.verifier_id:
            APIError("not_found", f"Agent '{agent_id}' not found on this verifier.").send_via(self)

        clear_agent_policy_cache(agent_id)

        mode = config.get("verifier", "mode", fallback="pull")
        if not mode:
            mode = "pull"

        with session_context() as session:
            if mode == "push":
                verifier_db_delete_agent(session, agent_id)
                self.send_response(204)
            else:
                op_state = agent.operational_state
                if op_state in (
                    states.SAVED,
                    states.FAILED,
                    states.TERMINATED,
                    states.TENANT_FAILED,
                    states.INVALID_QUOTE,
                ):
                    verifier_db_delete_agent(session, agent_id)
                    self.send_response(204)
                else:
                    update_agent = session.get(VerfierMain, agent_id)  # type: ignore[attr-defined]
                    assert update_agent
                    update_agent.operational_state = states.TERMINATED  # pyright: ignore
                    session.add(update_agent)
                    # session.commit() is automatically called by context manager
                    self.send_response(202)

        logger.info("DELETE returning response for agent: %s", agent_id)


_AGENT_SUMMARY_FIELDS = [
    "operational_state",
    "accept_attestations",
    "attestation_count",
    "verifier_id",
]

_AGENT_DETAIL_FIELDS = [
    "operational_state",
    "ip",
    "port",
    "tpm_policy",
    "meta_data",
    "accept_tpm_hash_algs",
    "accept_tpm_encryption_algs",
    "accept_tpm_signing_algs",
    "hash_alg",
    "enc_alg",
    "sign_alg",
    "verifier_id",
    "verifier_ip",
    "verifier_port",
    "severity_level",
    "last_event_id",
    "attestation_count",
    "last_received_quote",
    "last_successful_attestation",
    "accept_attestations",
    "ima_sign_verification_keys",
    "ima_policy_id",
    "mb_policy_id",
    "supported_version",
    "boottime",
]


def _render_agent_summary(agent: Any) -> Dict[str, Any]:
    """Render agent summary attributes for JSON:API list response."""
    rendered = agent.render(only=_AGENT_SUMMARY_FIELDS)
    return {k: v for k, v in rendered.items() if v is not None}


def _render_agent_attrs(agent: Any) -> Dict[str, Any]:
    """Render agent detail attributes for JSON:API response, excluding None values."""
    rendered = agent.render(only=_AGENT_DETAIL_FIELDS)
    return {k: v for k, v in rendered.items() if v is not None}
