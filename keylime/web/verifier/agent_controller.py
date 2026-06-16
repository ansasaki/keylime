import asyncio
import base64
from typing import Any, Dict, Optional, cast

from keylime import cloud_verifier_common, config, keylime_logging, push_agent_monitor, web_util
from keylime.agentstates import AgentAttestStates
from keylime.common import states, validators
from keylime.models.verifier import Attestation, EvidenceItem, IMAPolicy, MBPolicy
from keylime.models.verifier import VerifierAgent as VerifierAgentModel
from keylime.shared_data import clear_agent_policy_cache
from keylime.web.base import APIError, APILink, APIResource, Controller
from keylime.web.verifier.agent_service import build_agent_data, validate_mtls_cert
from keylime.web.verifier.ima_policy_service import resolve_ima_policy_for_agent
from keylime.web.verifier.mb_policy_service import resolve_mb_policy_for_agent

logger = keylime_logging.init_logging("verifier")


class AgentController(Controller):
    def _new_v2_handler(self) -> Any:
        # pylint: disable=import-outside-toplevel  # Avoid circular import
        from keylime import cloud_verifier_tornado as v2

        tornado_app = self.action_handler.application
        tornado_req = self.action_handler.request
        return v2.AgentsHandler(tornado_app, tornado_req, override=self.action_handler)  # type: ignore[no-untyped-call]

    # GET /v3[.x]/agents/
    # GET /v2[.x]/agents/
    def index(self, **_params):  # type: ignore[no-untyped-def]
        if self.major_version and self.major_version <= 2:
            self._new_v2_handler().get()  # type: ignore[no-untyped-call]
        else:
            self._index_v3()

    # GET /v3[.x]/agents/:id
    # GET /v2[.x]/agents/:id
    def show(self, agent_id, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        if self.major_version and self.major_version <= 2:
            self._new_v2_handler().get()  # type: ignore[no-untyped-call]
        else:
            self._show_v3(agent_id)

    # POST /v3[.x]/agents/
    # POST /v2[.x]/agents/:id
    def create(self, **_params):  # type: ignore[no-untyped-def]
        if self.major_version and self.major_version <= 2:
            self._new_v2_handler().post()  # type: ignore[no-untyped-call]
        else:
            self._create_v3(**_params)

    # PATCH /v3[.x]/agents/:id
    def update(self, agent_id, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        self._update_v3(agent_id, **_params)

    # DELETE /v3[.x]/agents/:id
    # DELETE /v2[.x]/agents/:id
    def delete(self, agent_id, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        if self.major_version and self.major_version <= 2:
            self._new_v2_handler().delete()  # type: ignore[no-untyped-call]
        else:
            self._delete_v3(agent_id)

    # PUT /v2[.x]/agents/:id/reactivate/
    def reactivate(self, agent_id, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        self._new_v2_handler().put()  # type: ignore[no-untyped-call]

    # PUT /v2[.x]/agents/:id/stop/
    def stop(self, agent_id, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        self._new_v2_handler().put()  # type: ignore[no-untyped-call]

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
                str(agent.agent_id),  # type: ignore[attr-defined]
                _render_agent_summary(agent),
            )
            .include(APILink("self", f"/v{self.version}/agents/{agent.agent_id}"))  # type: ignore[attr-defined]
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
            str(agent.agent_id),  # type: ignore[attr-defined]
            _render_agent_attrs(agent),
        ).include(APILink("self", f"/v{self.version}/agents/{agent_id}")).send_via(
            self, code=200
        )  # type: ignore[no-untyped-call]

    @Controller.require_json_api  # type: ignore[misc, untyped-decorator]
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

        agent_id = cast(str, agent_id)

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

        # Check for duplicate agent
        existing = VerifierAgentModel.get(agent_id)
        if existing:
            APIError("conflict").set_detail(  # type: ignore[no-untyped-call]
                f"Agent '{agent_id}' already exists. Use DELETE then POST to re-enroll."
            ).send_via(self)

        # Resolve IMA policy
        runtime_policy_name = agent.get("runtime_policy_name")
        runtime_policy_b64 = agent.get("runtime_policy", "")
        runtime_policy = base64.b64decode(runtime_policy_b64).decode() if runtime_policy_b64 else ""
        runtime_policy_key = agent.get("runtime_policy_key")

        ima_policy, ima_error = resolve_ima_policy_for_agent(
            runtime_policy_name, runtime_policy, runtime_policy_key, agent_id
        )
        if ima_error:
            APIError("invalid_resource_data", ima_error[0]).set_detail(  # type: ignore[no-untyped-call]
                ima_error[1]
            ).send_via(self)

        # Resolve MB policy
        mb_policy, mb_error = resolve_mb_policy_for_agent(
            agent.get("mb_policy_name", ""), agent.get("mb_policy", "{}"), agent_id
        )
        if mb_error:
            APIError("invalid_resource_data", mb_error[0]).set_detail(  # type: ignore[no-untyped-call]
                mb_error[1]
            ).send_via(self)

        # Set policy foreign keys
        assert ima_policy is not None
        assert mb_policy is not None
        agent_data["ima_policy_id"] = ima_policy.id  # type: ignore[attr-defined]
        agent_data["mb_policy_id"] = mb_policy.id  # type: ignore[attr-defined]

        # Create the agent via PersistableModel
        new_agent = VerifierAgentModel(agent_data)
        new_agent.commit_changes()  # type: ignore[no-untyped-call]

        # Start polling if pull mode
        if mode == "pull":
            _start_pull_polling(agent_data, agent_id)

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

    @Controller.require_json_api  # type: ignore[misc, untyped-decorator]
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
            existing.change("ima_policy_id", policy.id)  # type: ignore[no-untyped-call, attr-defined]

        mb_policy_name = agent.get("mb_policy_name")
        if mb_policy_name is not None:
            mb_pol = MBPolicy.get(name=mb_policy_name)
            if not mb_pol:
                APIError("not_found").set_detail(  # type: ignore[no-untyped-call]
                    f"MB policy '{mb_policy_name}' not found."
                ).send_via(self)
            assert mb_pol is not None
            existing.change("mb_policy_id", mb_pol.id)  # type: ignore[no-untyped-call, attr-defined]

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

        # For pull mode reactivation, rebuild agent dict and start polling
        if needs_reactivation:
            refreshed = VerifierAgentModel.get(agent_id)
            assert refreshed is not None
            agent_dict = _build_agent_dict_from_model(refreshed)
            agent_dict["operational_state"] = states.START
            _start_pull_polling(agent_dict, agent_id)

        APIResource(
            "agent",
            str(agent_id),
            _render_agent_attrs(existing),
        ).include(APILink("self", f"/v{self.version}/agents/{agent_id}")).send_via(
            self, code=200
        )  # type: ignore[no-untyped-call]

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
        if verifier_id != agent.verifier_id:  # type: ignore[attr-defined]
            APIError("not_found", f"Agent '{agent_id}' not found on this verifier.").send_via(self)

        clear_agent_policy_cache(agent_id)

        mode = config.get("verifier", "mode", fallback="pull")
        if not mode:
            mode = "pull"

        if mode == "push":
            _delete_agent_v3(agent, agent_id)
            self.send_response(204)
        else:
            op_state = agent.operational_state  # type: ignore[attr-defined]
            if op_state in (
                states.SAVED,
                states.FAILED,
                states.TERMINATED,
                states.TENANT_FAILED,
                states.INVALID_QUOTE,
            ):
                _delete_agent_v3(agent, agent_id)
                self.send_response(204)
            else:
                agent.change("operational_state", states.TERMINATED)  # type: ignore[no-untyped-call]
                agent.commit_changes()  # type: ignore[no-untyped-call]
                self.send_response(202)


def _delete_agent_v3(agent: VerifierAgentModel, agent_id: str) -> None:
    """Delete an agent and all associated data in a single transaction."""
    push_agent_monitor.cancel_agent_timeout(agent_id)
    AgentAttestStates.get_instance().delete_by_agent_id(agent_id)

    # pylint: disable=import-outside-toplevel
    from keylime.db.verifier_db import VerifierAttestations
    from keylime.models.base import db_manager

    with db_manager.session_context() as session:
        EvidenceItem.delete_all(agent_id=agent_id, session_=session)
        Attestation.delete_all(agent_id=agent_id, session_=session)
        session.query(VerifierAttestations).filter_by(agent_id=agent_id).delete()
        agent.delete(session=session, include_dependants=False)  # type: ignore[no-untyped-call]
        _cleanup_agent_named_policies(agent_id, session=session)


def _cleanup_agent_named_policies(agent_id: str, session: Any = None) -> None:
    """Remove policies named after the agent if no other agents reference them.

    When session is provided, deletes run within the caller's transaction.
    """
    ima = IMAPolicy.get(name=agent_id)
    if ima:
        refs = VerifierAgentModel.all_ids(ima_policy_id=ima.id)  # type: ignore[no-untyped-call, attr-defined]
        if not refs:
            ima.delete(session=session)  # type: ignore[no-untyped-call]

    mb = MBPolicy.get(name=agent_id)
    if mb:
        refs = VerifierAgentModel.all_ids(mb_policy_id=mb.id)  # type: ignore[no-untyped-call, attr-defined]
        if not refs:
            mb.delete(session=session)  # type: ignore[no-untyped-call]


def _start_pull_polling(agent_data: Dict[str, Any], agent_id: str) -> None:
    """Set up SSL context and start pull-mode polling for an agent."""
    # pylint: disable=import-outside-toplevel
    from keylime.verifier_db_manager import exclude_db

    # Add ephemeral fields needed by the polling engine
    for key, val in exclude_db.items():
        agent_data.setdefault(key, val)

    agent_mtls_cert_enabled = config.getboolean("verifier", "enable_agent_mtls", fallback=False)
    mtls_cert = agent_data.get("mtls_cert")
    agent_data["ssl_context"] = None
    if agent_mtls_cert_enabled and isinstance(mtls_cert, str) and mtls_cert != "disabled":
        agent_data["ssl_context"] = web_util.generate_agent_tls_context("verifier", mtls_cert, logger=logger)

    if agent_data["ssl_context"] is None:
        logger.warning("Connecting to agent without mTLS: %s", agent_id)

    from keylime.cloud_verifier_tornado import process_agent

    asyncio.ensure_future(process_agent(agent_data, states.GET_QUOTE))


def _build_agent_dict_from_model(agent: VerifierAgentModel) -> Dict[str, Any]:
    """Build the polling engine agent dict from a PersistableModel instance."""
    # pylint: disable=import-outside-toplevel
    from keylime.verifier_db_manager import exclude_db

    agent_dict = agent.render(only=_AGENT_POLLING_FIELDS)  # type: ignore[no-untyped-call]

    for key, val in exclude_db.items():
        agent_dict.setdefault(key, val)

    return agent_dict


_AGENT_POLLING_FIELDS = [
    "agent_id",
    "v",
    "ip",
    "port",
    "operational_state",
    "public_key",
    "tpm_policy",
    "meta_data",
    "ima_sign_verification_keys",
    "revocation_key",
    "accept_tpm_hash_algs",
    "accept_tpm_encryption_algs",
    "accept_tpm_signing_algs",
    "hash_alg",
    "enc_alg",
    "sign_alg",
    "boottime",
    "ima_pcrs",
    "pcr10",
    "next_ima_ml_entry",
    "learned_ima_keyrings",
    "supported_version",
    "mtls_cert",
    "ak_tpm",
    "attestation_count",
    "last_received_quote",
    "last_successful_attestation",
    "tpm_clockinfo",
    "accept_attestations",
]

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
