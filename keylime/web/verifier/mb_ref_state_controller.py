from typing import Any, Dict

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm.exc import NoResultFound  # pyright: ignore

from keylime import json, keylime_logging
from keylime.db.verifier_db import VerfierMain, VerifierMbpolicy
from keylime.mba import mba
from keylime.verifier_db_manager import session_context
from keylime.web.base import Controller

logger = keylime_logging.init_logging("verifier")


class MBRefStateController(Controller):
    def _get_mb_policy_db_format(self, mb_policy_name: str) -> Dict[str, Any]:
        """Get the measured boot policy from the request and return it in DB format."""
        content_length = len(self.request_body)
        if content_length == 0:
            self.respond(400, "Expected non zero content length")
            logger.warning("POST returning 400 response. Expected non zero content length.")
            return {}

        json_body = json.loads(self.request_body)
        mb_policy = json_body.get("mb_policy")
        return mba.mb_policy_db_contents(mb_policy_name, mb_policy)

    # GET /v3[.x]/refstates/uefi/
    # GET /v2[.x]/mbpolicies/
    def index(self, **_params):  # type: ignore[no-untyped-def]
        if self.major_version and self.major_version <= 2:
            self._index_v2()
        else:
            self.respond(404)
            # TODO: Replace with v3 implementation

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
            self.respond(404)
            # TODO: Replace with v3 implementation

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
            self.respond(404)
            # TODO: Replace with v3 implementation

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
        self.respond(404)
        # TODO: Replace with v3 implementation

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
            self.respond(404)
            # TODO: Replace with v3 implementation

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
