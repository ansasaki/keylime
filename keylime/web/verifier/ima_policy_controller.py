import base64
from typing import Any, Dict, Optional, Tuple

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm.exc import NoResultFound  # pyright: ignore

from keylime import config, json, keylime_logging, signing
from keylime.db.verifier_db import VerfierMain, VerifierAllowlist
from keylime.ima import ima
from keylime.models.verifier import VerifierAgent
from keylime.models.verifier.ima_policy import IMAPolicy
from keylime.verifier_db_manager import session_context
from keylime.web.base import APIError, APILink, APIResource, Controller

logger = keylime_logging.init_logging("verifier")


def _validate_and_format_ima_policy(
    name: str,
    runtime_policy: str,
    runtime_policy_key: Optional[str],
    tpm_policy: Optional[str] = None,
) -> Tuple[Dict[str, Any], Optional[Tuple[int, str]]]:
    """Validate and format an IMA runtime policy for DB storage.

    Returns (db_format_dict, error_tuple_or_none).
    """
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
        return ({}, (e.code, e.message))

    try:
        db_format = ima.runtime_policy_db_contents(name, runtime_policy, tpm_policy)
    except ima.ImaValidationError as e:
        message = f"Runtime policy is malformatted: {e.message}"
        return ({}, (e.code, message))

    return (db_format, None)


class IMAPolicyController(Controller):
    def _get_runtime_policy_db_format(self, runtime_policy_name: str) -> Dict[str, Any]:
        """Get the IMA policy from the request and return it in DB format."""
        content_length = len(self.request_body)
        if content_length == 0:
            self.respond(400, "Expected non zero content length")
            logger.warning("POST returning 400 response. Expected non zero content length.")
            return {}

        json_body = json.loads(self.request_body)

        runtime_policy = base64.b64decode(json_body.get("runtime_policy")).decode()
        tpm_policy = json_body.get("tpm_policy")

        db_format, error = _validate_and_format_ima_policy(
            runtime_policy_name, runtime_policy, json_body.get("runtime_policy_key"), tpm_policy
        )

        if error:
            self.respond(error[0], error[1])
            logger.warning(error[1])
            return {}

        return db_format

    # GET /v3[.x]/policies/ima/
    # GET /v2[.x]/allowlists/
    def index(self, **_params):  # type: ignore[no-untyped-def]
        if self.major_version and self.major_version <= 2:
            self._index_v2()
        else:
            self._index_v3()

    def _index_v2(self) -> None:
        with session_context() as session:
            try:
                names_allowlists = session.query(VerifierAllowlist.name).all()
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                self.respond(500, "Failed to get names of allowlists")
                raise

            names_response = []
            for name in names_allowlists:
                names_response.append(name[0])
            self.respond(200, "Success", {"runtimepolicy names": names_response})

    # GET /v3[.x]/policies/ima/:name
    # GET /v2[.x]/allowlists/:name
    def show(self, name, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        if self.major_version and self.major_version <= 2:
            self._show_v2(name)
        else:
            self._show_v3(name)

    def _show_v2(self, runtime_policy_name: str) -> None:
        with session_context() as session:
            try:
                allowlist = session.query(VerifierAllowlist).filter_by(name=runtime_policy_name).one()
            except NoResultFound:
                self.respond(404, f"Runtime policy {runtime_policy_name} not found")
                return
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                self.respond(500, "Failed to get allowlist")
                raise

            response = {}
            for field in ("name", "tmp_policy"):
                response[field] = getattr(allowlist, field, None)
            response["runtime_policy"] = getattr(allowlist, "ima_policy", None)
            self.respond(200, "Success", response)

    # POST /v3[.x]/policies/ima/
    # POST /v2[.x]/allowlists/:name
    def create(self, **_params):  # type: ignore[no-untyped-def]
        if self.major_version and self.major_version <= 2:
            name = self.path_params.get("name")
            if not name:
                self.respond(400, "Invalid URL")
                return
            self._create_v2(name)
        else:
            self._create_v3(**_params)

    def _create_v2(self, runtime_policy_name: str) -> None:
        runtime_policy_db_format = self._get_runtime_policy_db_format(runtime_policy_name)
        if not runtime_policy_db_format:
            return

        with session_context() as session:
            # don't allow overwriting
            try:
                runtime_policy_count = session.query(VerifierAllowlist).filter_by(name=runtime_policy_name).count()
                if runtime_policy_count > 0:
                    self.respond(409, f"Runtime policy with name {runtime_policy_name} already exists")
                    logger.warning("Runtime policy with name %s already exists", runtime_policy_name)
                    return
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                raise

            try:
                session.add(VerifierAllowlist(**runtime_policy_db_format))
                # session.commit() is automatically called by context manager
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                raise

        self.respond(201)
        logger.info("POST returning 201")

    # PATCH /v3[.x]/policies/ima/:name
    def update(self, name, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        self._update_v3(name, **_params)

    # PUT /v2[.x]/allowlists/:name
    def overwrite(self, name, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        self._overwrite_v2(name)

    def _overwrite_v2(self, runtime_policy_name: str) -> None:
        runtime_policy_db_format = self._get_runtime_policy_db_format(runtime_policy_name)
        if not runtime_policy_db_format:
            return

        with session_context() as session:
            # don't allow creating a new policy
            try:
                runtime_policy_count = session.query(VerifierAllowlist).filter_by(name=runtime_policy_name).count()
                if runtime_policy_count != 1:
                    self.respond(
                        404,
                        f"Runtime policy with name {runtime_policy_name} does not already exist, use POST to create",
                    )
                    logger.warning("Runtime policy with name %s does not already exist", runtime_policy_name)
                    return
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                raise

            try:
                session.query(VerifierAllowlist).filter_by(name=runtime_policy_name).update(
                    runtime_policy_db_format  # pyright: ignore
                )
                # session.commit() is automatically called by context manager
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                raise

        self.respond(201)
        logger.info("PUT returning 201")

    # DELETE /v3[.x]/policies/ima/:name
    # DELETE /v2[.x]/allowlists/:name
    def delete(self, name, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        if self.major_version and self.major_version <= 2:
            self._delete_v2(name)
        else:
            self._delete_v3(name)

    def _delete_v2(self, runtime_policy_name: str) -> None:
        with session_context() as session:
            try:
                runtime_policy = session.query(VerifierAllowlist).filter_by(name=runtime_policy_name).one()
            except NoResultFound:
                self.respond(404, f"Runtime policy {runtime_policy_name} not found")
                return
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                self.respond(500, "Failed to get allowlist")
                raise

            try:
                agent = session.query(VerfierMain).filter_by(ima_policy_id=runtime_policy.id).one_or_none()
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                raise
            if agent is not None:
                self.respond(409, f"Can't delete allowlist as it's currently in use by agent {agent.agent_id}")
                return

            try:
                session.query(VerifierAllowlist).filter_by(name=runtime_policy_name).delete()
                # session.commit() is automatically called by context manager
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                self.respond(500, f"Database error: {e}")
                raise

            self.send_response(204)
            logger.info("DELETE returning 204 response for allowlist: %s", runtime_policy_name)

    # ---- v3 implementations ----

    def _index_v3(self) -> None:
        policies = IMAPolicy.all()

        data = [
            APIResource(
                "ima_policy",
                str(policy.name),  # type: ignore[no-untyped-call]
                _render_ima_policy_attrs(policy),
            )
            .include(APILink("self", f"/v{self.version}/policies/ima/{policy.name}"))
            .render()  # type: ignore[no-untyped-call]
            for policy in policies
        ]

        self.send_response(200, None, {"data": data}, "application/vnd.api+json")

    def _show_v3(self, name: str) -> None:
        policy = IMAPolicy.get(name=name)

        if not policy:
            APIError("not_found", f"IMA policy '{name}' not found.").send_via(self)

        APIResource(
            "ima_policy",
            str(policy.name),  # type: ignore[union-attr]
            _render_ima_policy_attrs(policy),  # type: ignore[arg-type]
        ).include(APILink("self", f"/v{self.version}/policies/ima/{name}")).send_via(
            self, code=200
        )  # type: ignore[no-untyped-call]

    @Controller.require_json_api
    def _create_v3(self, ima_policy: Optional[Dict[str, Any]] = None, **_params: Any) -> None:
        if not ima_policy:
            APIError("invalid_request", 400).set_detail(  # type: ignore[no-untyped-call]
                "Request body must include IMA policy data with type 'ima_policy'."
            ).send_via(self)

        assert ima_policy is not None
        name = ima_policy.get("name")
        if not name:
            APIError("invalid_resource_data").set_detail(  # type: ignore[no-untyped-call]
                "Attribute 'name' is required."
            ).send_via(self)

        runtime_policy_b64 = ima_policy.get("runtime_policy", "")
        if not runtime_policy_b64:
            APIError("invalid_resource_data").set_detail(  # type: ignore[no-untyped-call]
                "Attribute 'runtime_policy' is required."
            ).send_via(self)

        runtime_policy = base64.b64decode(runtime_policy_b64).decode()
        runtime_policy_key = ima_policy.get("runtime_policy_key")
        tpm_policy = ima_policy.get("tpm_policy")

        # Check for duplicates
        existing = IMAPolicy.get(name=name)
        if existing:
            APIError("conflict").set_detail(  # type: ignore[no-untyped-call]
                f"IMA policy with name '{name}' already exists."
            ).send_via(self)

        db_format, error = _validate_and_format_ima_policy(name, runtime_policy, runtime_policy_key, tpm_policy)
        if error:
            APIError("invalid_resource_data", error[0]).set_detail(error[1]).send_via(self)  # type: ignore[no-untyped-call]

        policy = IMAPolicy(db_format)
        policy.commit_changes()  # type: ignore[no-untyped-call]

        APIResource(
            "ima_policy",
            str(name),
            _render_ima_policy_attrs(policy),
        ).include(APILink("self", f"/v{self.version}/policies/ima/{name}")).send_via(
            self
        )  # type: ignore[no-untyped-call]

        logger.info("POST returning 201 for IMA policy: %s", name)

    @Controller.require_json_api
    def _update_v3(self, name: str, ima_policy: Optional[Dict[str, Any]] = None, **_params: Any) -> None:
        existing = IMAPolicy.get(name=name)
        if not existing:
            APIError("not_found", f"IMA policy '{name}' not found.").send_via(self)

        if not ima_policy:
            APIError("invalid_request", 400).set_detail(  # type: ignore[no-untyped-call]
                "Request body must include IMA policy data with type 'ima_policy'."
            ).send_via(self)

        assert ima_policy is not None
        assert existing is not None

        runtime_policy_b64 = ima_policy.get("runtime_policy", "")
        if not runtime_policy_b64:
            APIError("invalid_resource_data").set_detail(  # type: ignore[no-untyped-call]
                "Attribute 'runtime_policy' is required for update."
            ).send_via(self)

        runtime_policy = base64.b64decode(runtime_policy_b64).decode()
        runtime_policy_key = ima_policy.get("runtime_policy_key")
        tpm_policy = ima_policy.get("tpm_policy")

        db_format, error = _validate_and_format_ima_policy(name, runtime_policy, runtime_policy_key, tpm_policy)
        if error:
            APIError("invalid_resource_data", error[0]).set_detail(error[1]).send_via(self)  # type: ignore[no-untyped-call]

        for field_name, value in db_format.items():
            if field_name != "name":
                existing.change(field_name, value)  # type: ignore[no-untyped-call]

        existing.commit_changes()  # type: ignore[no-untyped-call]

        APIResource(
            "ima_policy",
            str(name),
            _render_ima_policy_attrs(existing),
        ).include(APILink("self", f"/v{self.version}/policies/ima/{name}")).send_via(
            self, code=200
        )  # type: ignore[no-untyped-call]

        logger.info("PATCH returning 200 for IMA policy: %s", name)

    def _delete_v3(self, name: str) -> None:
        policy = IMAPolicy.get(name=name)
        if not policy:
            APIError("not_found", f"IMA policy '{name}' not found.").send_via(self)

        assert policy is not None

        # Check if any agents reference this policy
        agents = VerifierAgent.all_ids(ima_policy_id=policy.id)  # type: ignore[no-untyped-call]
        if agents:
            APIError("conflict").set_detail(  # type: ignore[no-untyped-call]
                f"Cannot delete IMA policy '{name}' as it is currently in use by agent(s)."
            ).send_via(self)

        policy.delete()  # type: ignore[no-untyped-call]

        self.send_response(204)
        logger.info("DELETE returning 204 for IMA policy: %s", name)


def _render_ima_policy_attrs(policy: IMAPolicy) -> Dict[str, Any]:
    """Render IMA policy attributes for JSON:API response, excluding None values."""
    rendered = policy.render()  # type: ignore[no-untyped-call]
    rendered.pop("id", None)
    return {k: v for k, v in rendered.items() if v is not None}
