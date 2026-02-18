import base64
from typing import Any, Dict

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm.exc import NoResultFound  # pyright: ignore

from keylime import config, json, keylime_logging, signing
from keylime.db.verifier_db import VerfierMain, VerifierAllowlist
from keylime.ima import ima
from keylime.verifier_db_manager import session_context
from keylime.web.base import Controller

logger = keylime_logging.init_logging("verifier")


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
        runtime_policy_key_bytes = signing.get_runtime_policy_keys(
            runtime_policy.encode(),
            json_body.get("runtime_policy_key"),
        )

        try:
            ima.verify_runtime_policy(
                runtime_policy.encode(),
                runtime_policy_key_bytes,
                verify_sig=config.getboolean("verifier", "require_allow_list_signatures", fallback=False),
            )
        except ima.ImaValidationError as e:
            self.respond(e.code, e.message)
            logger.warning(e.message)
            return {}

        tpm_policy = json_body.get("tpm_policy")

        try:
            runtime_policy_db_format = ima.runtime_policy_db_contents(runtime_policy_name, runtime_policy, tpm_policy)
        except ima.ImaValidationError as e:
            message = f"Runtime policy is malformatted: {e.message}"
            self.respond(e.code, message)
            logger.warning(message)
            return {}

        return runtime_policy_db_format

    # GET /v3[.x]/policies/ima/
    # GET /v2[.x]/allowlists/
    def index(self, **_params):  # type: ignore[no-untyped-def]
        if self.major_version and self.major_version <= 2:
            self._index_v2()
        else:
            self.respond(404)
            # TODO: Replace with v3 implementation

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
            self.respond(404)
            # TODO: Replace with v3 implementation

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
            self.respond(404)
            # TODO: Replace with v3 implementation

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
        self.respond(404)
        # TODO: Replace with v3 implementation

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
            self.respond(404)
            # TODO: Replace with v3 implementation

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
