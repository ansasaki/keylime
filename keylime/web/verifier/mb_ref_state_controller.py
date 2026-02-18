from typing import Any, Dict, Optional, Tuple

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm.exc import NoResultFound  # pyright: ignore

from keylime import json, keylime_logging
from keylime.db.verifier_db import VerfierMain, VerifierMbpolicy
from keylime.mba import mba
from keylime.models.verifier import VerifierAgent
from keylime.models.verifier.mb_policy import MBPolicy
from keylime.verifier_db_manager import session_context
from keylime.web.base import APIError, APILink, APIResource, Controller

logger = keylime_logging.init_logging("verifier")


def _validate_and_format_mb_policy(
    name: str,
    mb_policy: str,
) -> Tuple[Dict[str, Any], Optional[Tuple[int, str]]]:
    """Validate and format a measured boot policy for DB storage.

    Returns (db_format_dict, error_tuple_or_none).
    """
    try:
        db_format = mba.mb_policy_db_contents(name, mb_policy)
    except Exception as e:
        return ({}, (400, f"Measured boot policy is malformatted: {e}"))

    return (db_format, None)


class MBRefStateController(Controller):
    def _get_mb_policy_db_format(self, mb_policy_name: str) -> Dict[str, Any]:
        """Get the measured boot policy from the request and return it in DB format."""
        content_length = len(self.request_body)
        if content_length == 0:
            self.respond(400, "Expected non zero content length")
            logger.warning("POST returning 400 response. Expected non zero content length.")
            return {}

        json_body = json.loads(self.request_body)
        mb_policy_str = json_body.get("mb_policy")

        db_format, error = _validate_and_format_mb_policy(mb_policy_name, mb_policy_str)
        if error:
            self.respond(error[0], error[1])
            logger.warning(error[1])
            return {}

        return db_format

    # GET /v3[.x]/refstates/uefi/
    # GET /v2[.x]/mbpolicies/
    def index(self, **_params):  # type: ignore[no-untyped-def]
        if self.major_version and self.major_version <= 2:
            self._index_v2()
        else:
            self._index_v3()

    def _index_v2(self) -> None:
        with session_context() as session:
            try:
                names_mbpolicies = session.query(VerifierMbpolicy.name).all()
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                self.respond(500, "Failed to get names of mbpolicies")
                raise

            names_response = []
            for name in names_mbpolicies:
                names_response.append(name[0])
            self.respond(200, "Success", {"mbpolicy names": names_response})

    # GET /v3[.x]/refstates/uefi/:name
    # GET /v2[.x]/mbpolicies/:name
    def show(self, name, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        if self.major_version and self.major_version <= 2:
            self._show_v2(name)
        else:
            self._show_v3(name)

    def _show_v2(self, mb_policy_name: str) -> None:
        with session_context() as session:
            try:
                mbpolicy = session.query(VerifierMbpolicy).filter_by(name=mb_policy_name).one()
            except NoResultFound:
                self.respond(404, f"Measured boot policy {mb_policy_name} not found")
                return
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                self.respond(500, "Failed to get mb_policy")
                raise

            response = {}
            response["name"] = getattr(mbpolicy, "name", None)
            response["mb_policy"] = getattr(mbpolicy, "mb_policy", None)
            self.respond(200, "Success", response)

    # POST /v3[.x]/refstates/uefi/
    # POST /v2[.x]/mbpolicies/:name
    def create(self, **_params):  # type: ignore[no-untyped-def]
        if self.major_version and self.major_version <= 2:
            name = self.path_params.get("name")
            if not name:
                self.respond(400, "Invalid URL")
                return
            self._create_v2(name)
        else:
            self._create_v3(**_params)

    def _create_v2(self, mb_policy_name: str) -> None:
        mb_policy_db_format = self._get_mb_policy_db_format(mb_policy_name)
        if not mb_policy_db_format:
            return

        with session_context() as session:
            # don't allow overwriting
            try:
                mbpolicy_count = session.query(VerifierMbpolicy).filter_by(name=mb_policy_name).count()
                if mbpolicy_count > 0:
                    self.respond(409, f"Measured boot policy with name {mb_policy_name} already exists")
                    logger.warning("Measured boot policy with name %s already exists", mb_policy_name)
                    return
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                raise

            try:
                session.add(VerifierMbpolicy(**mb_policy_db_format))
                # session.commit() is automatically called by context manager
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                raise

        self.respond(201)
        logger.info("POST returning 201")

    # PATCH /v3[.x]/refstates/uefi/:name
    def update(self, name, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        self._update_v3(name, **_params)

    # PUT /v2[.x]/mbpolicies/:name
    def overwrite(self, name, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        self._overwrite_v2(name)

    def _overwrite_v2(self, mb_policy_name: str) -> None:
        mb_policy_db_format = self._get_mb_policy_db_format(mb_policy_name)
        if not mb_policy_db_format:
            return

        with session_context() as session:
            # don't allow creating a new policy
            try:
                mbpolicy_count = session.query(VerifierMbpolicy).filter_by(name=mb_policy_name).count()
                if mbpolicy_count != 1:
                    self.respond(409, f"Measured boot policy with name {mb_policy_name} does not already exist")
                    logger.warning("Measured boot policy with name %s does not already exist", mb_policy_name)
                    return
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                raise

            try:
                session.query(VerifierMbpolicy).filter_by(name=mb_policy_name).update(
                    mb_policy_db_format  # pyright: ignore
                )
                # session.commit() is automatically called by context manager
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                raise

        self.respond(201)
        logger.info("PUT returning 201")

    # DELETE /v3[.x]/refstates/uefi/:name
    # DELETE /v2[.x]/mbpolicies/:name
    def delete(self, name, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        if self.major_version and self.major_version <= 2:
            self._delete_v2(name)
        else:
            self._delete_v3(name)

    def _delete_v2(self, mb_policy_name: str) -> None:
        with session_context() as session:
            try:
                mbpolicy = session.query(VerifierMbpolicy).filter_by(name=mb_policy_name).one()
            except NoResultFound:
                self.respond(404, f"Measured boot policy {mb_policy_name} not found")
                return
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                self.respond(500, "Failed to get mb_policy")
                raise

            try:
                agent = session.query(VerfierMain).filter_by(mb_policy_id=mbpolicy.id).one_or_none()
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                raise
            if agent is not None:
                self.respond(409, f"Can't delete mb_policy as it's currently in use by agent {agent.agent_id}")
                return

            try:
                session.query(VerifierMbpolicy).filter_by(name=mb_policy_name).delete()
                # session.commit() is automatically called by context manager
            except SQLAlchemyError as e:
                logger.error("SQLAlchemy Error: %s", e)
                self.respond(500, f"Database error: {e}")
                raise

            self.send_response(204)
            logger.info("DELETE returning 204 response for mb_policy: %s", mb_policy_name)

    # ---- v3 implementations ----

    def _index_v3(self) -> None:
        policies = MBPolicy.all()

        data = [
            APIResource(
                "mb_policy",
                str(policy.name),  # type: ignore[no-untyped-call]
                _render_mb_policy_attrs(policy),
            )
            .include(APILink("self", f"/v{self.version}/refstates/uefi/{policy.name}"))
            .render()  # type: ignore[no-untyped-call]
            for policy in policies
        ]

        self.send_response(200, None, {"data": data}, "application/vnd.api+json")

    def _show_v3(self, name: str) -> None:
        policy = MBPolicy.get(name=name)

        if not policy:
            APIError("not_found", f"Measured boot policy '{name}' not found.").send_via(self)

        APIResource(
            "mb_policy",
            str(policy.name),  # type: ignore[union-attr]
            _render_mb_policy_attrs(policy),  # type: ignore[arg-type]
        ).include(APILink("self", f"/v{self.version}/refstates/uefi/{name}")).send_via(
            self, code=200
        )  # type: ignore[no-untyped-call]

    @Controller.require_json_api
    def _create_v3(self, mb_policy: Optional[Dict[str, Any]] = None, **_params: Any) -> None:
        if not mb_policy:
            APIError("invalid_request", 400).set_detail(  # type: ignore[no-untyped-call]
                "Request body must include MB policy data with type 'mb_policy'."
            ).send_via(self)

        assert mb_policy is not None
        name = mb_policy.get("name")
        if not name:
            APIError("invalid_resource_data").set_detail(  # type: ignore[no-untyped-call]
                "Attribute 'name' is required."
            ).send_via(self)

        mb_policy_str = mb_policy.get("mb_policy", "")
        if not mb_policy_str:
            APIError("invalid_resource_data").set_detail(  # type: ignore[no-untyped-call]
                "Attribute 'mb_policy' is required."
            ).send_via(self)

        # Check for duplicates
        existing = MBPolicy.get(name=name)
        if existing:
            APIError("conflict").set_detail(  # type: ignore[no-untyped-call]
                f"Measured boot policy with name '{name}' already exists."
            ).send_via(self)

        db_format, error = _validate_and_format_mb_policy(name, mb_policy_str)
        if error:
            APIError("invalid_resource_data", error[0]).set_detail(error[1]).send_via(self)  # type: ignore[no-untyped-call]

        policy = MBPolicy(db_format)
        policy.commit_changes()  # type: ignore[no-untyped-call]

        APIResource(
            "mb_policy",
            str(name),
            _render_mb_policy_attrs(policy),
        ).include(APILink("self", f"/v{self.version}/refstates/uefi/{name}")).send_via(
            self
        )  # type: ignore[no-untyped-call]

        logger.info("POST returning 201 for MB policy: %s", name)

    @Controller.require_json_api
    def _update_v3(self, name: str, mb_policy: Optional[Dict[str, Any]] = None, **_params: Any) -> None:
        existing = MBPolicy.get(name=name)
        if not existing:
            APIError("not_found", f"Measured boot policy '{name}' not found.").send_via(self)

        if not mb_policy:
            APIError("invalid_request", 400).set_detail(  # type: ignore[no-untyped-call]
                "Request body must include MB policy data with type 'mb_policy'."
            ).send_via(self)

        assert mb_policy is not None
        assert existing is not None

        mb_policy_str = mb_policy.get("mb_policy", "")
        if not mb_policy_str:
            APIError("invalid_resource_data").set_detail(  # type: ignore[no-untyped-call]
                "Attribute 'mb_policy' is required for update."
            ).send_via(self)

        db_format, error = _validate_and_format_mb_policy(name, mb_policy_str)
        if error:
            APIError("invalid_resource_data", error[0]).set_detail(error[1]).send_via(self)  # type: ignore[no-untyped-call]

        for field_name, value in db_format.items():
            if field_name != "name":
                existing.change(field_name, value)  # type: ignore[no-untyped-call]

        existing.commit_changes()  # type: ignore[no-untyped-call]

        APIResource(
            "mb_policy",
            str(name),
            _render_mb_policy_attrs(existing),
        ).include(APILink("self", f"/v{self.version}/refstates/uefi/{name}")).send_via(
            self, code=200
        )  # type: ignore[no-untyped-call]

        logger.info("PATCH returning 200 for MB policy: %s", name)

    def _delete_v3(self, name: str) -> None:
        policy = MBPolicy.get(name=name)
        if not policy:
            APIError("not_found", f"Measured boot policy '{name}' not found.").send_via(self)

        assert policy is not None

        # Check if any agents reference this policy
        agents = VerifierAgent.all_ids(mb_policy_id=policy.id)  # type: ignore[no-untyped-call]
        if agents:
            APIError("conflict").set_detail(  # type: ignore[no-untyped-call]
                f"Cannot delete measured boot policy '{name}' as it is currently in use by agent(s)."
            ).send_via(self)

        policy.delete()  # type: ignore[no-untyped-call]

        self.send_response(204)
        logger.info("DELETE returning 204 for MB policy: %s", name)


def _render_mb_policy_attrs(policy: MBPolicy) -> Dict[str, Any]:
    """Render MB policy attributes for JSON:API response, excluding None values."""
    rendered = policy.render()  # type: ignore[no-untyped-call]
    rendered.pop("id", None)
    return {k: v for k, v in rendered.items() if v is not None}
