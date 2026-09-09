from typing import Any, Dict, Optional

from sqlalchemy.exc import IntegrityError

from keylime import keylime_logging
from keylime.mba import mba
from keylime.models.verifier import MBPolicy, VerifierAgent
from keylime.shared_data import get_shared_memory
from keylime.web.base import APIError, APILink, APIMessageBody, APIResource, Controller

logger = keylime_logging.init_logging("verifier")


class MBRefStateController(Controller):
    def _new_v2_handler(self) -> Any:
        # pylint: disable=import-outside-toplevel  # Avoid circular import
        from keylime import cloud_verifier_tornado as v2

        tornado_app = self.action_handler.application
        tornado_req = self.action_handler.request
        return v2.MbpolicyHandler(tornado_app, tornado_req, override=self.action_handler)  # type: ignore[no-untyped-call]

    # GET /v3[.x]/refstates/uefi/
    # GET /v2[.x]/mbpolicies/
    def index(self, **_params):  # type: ignore[no-untyped-def]
        if self.major_version and self.major_version <= 2:
            self._new_v2_handler().get()  # type: ignore[no-untyped-call]
        else:
            self._index_v3()

    # GET /v3[.x]/refstates/uefi/:name
    # GET /v2[.x]/mbpolicies/:name
    def show(self, name, **_params):  # type: ignore[no-untyped-def]
        if self.major_version and self.major_version <= 2:
            self._new_v2_handler().get()  # type: ignore[no-untyped-call]
        else:
            self._show_v3(name)

    # POST /v3[.x]/refstates/uefi/
    # POST /v2[.x]/mbpolicies/:name
    def create(self, **_params):  # type: ignore[no-untyped-def]
        if self.major_version and self.major_version <= 2:
            self._new_v2_handler().post()  # type: ignore[no-untyped-call]
        else:
            self._create_v3(**_params)

    # PATCH /v3[.x]/refstates/uefi/:name
    def update(self, name, **_params):  # type: ignore[no-untyped-def]
        self._update_v3(name, **_params)

    # PUT /v2[.x]/mbpolicies/:name
    def overwrite(self, name, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        self._new_v2_handler().put()  # type: ignore[no-untyped-call]

    # DELETE /v3[.x]/refstates/uefi/:name
    # DELETE /v2[.x]/mbpolicies/:name
    def delete(self, name, **_params):  # type: ignore[no-untyped-def]
        if self.major_version and self.major_version <= 2:
            self._new_v2_handler().delete()  # type: ignore[no-untyped-call]
        else:
            self._delete_v3(name)

    def _index_v3(self) -> None:
        policies = MBPolicy.all()
        resources = [
            APIResource("mb_policy", str(p.id), p.render(["name"])).include(  # type: ignore[attr-defined]
                APILink("self", f"/v{self.version}/refstates/uefi/{p.name}")  # type: ignore[attr-defined]
            )
            for p in policies
        ]
        body = APIMessageBody(*resources)
        if not resources:
            body._data = []  # pylint: disable=protected-access
        body.send_via(self)

    def _show_v3(self, name: str) -> None:
        policy = MBPolicy.get(name=name)
        if not policy:
            APIError("not_found", f"No MB ref state with name '{name}'.").send_via(self)
            return
        APIResource("mb_policy", str(policy.id), policy.render(["name", "mb_policy"])).include(  # type: ignore[attr-defined]
            APILink("self", f"/v{self.version}/refstates/uefi/{policy.name}")  # type: ignore[attr-defined]
        ).send_via(
            self
        )

    @Controller.require_json_api  # type: ignore[misc, untyped-decorator]
    def _create_v3(self, mb_policy: Optional[Dict[str, Any]] = None, **_params: Any) -> None:
        if not mb_policy:
            APIError("invalid_resource_data", "Request body must include an 'mb_policy' resource.").send_via(self)
            return

        name = mb_policy.get("name")
        mb_policy_str = mb_policy.get("mb_policy")

        if not name or mb_policy_str is None:
            APIError("invalid_resource_data", "Attributes 'name' and 'mb_policy' are required.").send_via(self)
            return

        shared_mem = get_shared_memory()
        mb_policy_locks = shared_mem.get_or_create_dict("mb_policy_create_locks")
        if name not in mb_policy_locks:
            mb_policy_locks[name] = shared_mem.manager.Lock()
        policy_lock = mb_policy_locks[name]

        with policy_lock:
            if MBPolicy.get(name=name):
                APIError("conflict", f"An MB ref state named '{name}' already exists.").send_via(self)
                return

            db_format = mba.mb_policy_db_contents(name, mb_policy_str)
            policy = MBPolicy(db_format)
            try:
                policy.commit_changes()
            except IntegrityError as e:
                logger.warning("MB policy creation failed due to database constraint for name '%s': %s", name, e)
                APIError("conflict", f"An MB ref state named '{name}' already exists.").send_via(self)
                return

            APIResource("mb_policy", str(policy.id), policy.render(["name", "mb_policy"])).include(  # type: ignore[attr-defined]
                APILink("self", f"/v{self.version}/refstates/uefi/{policy.name}")  # type: ignore[attr-defined]
            ).send_via(
                self, code=201
            )

    @Controller.require_json_api  # type: ignore[misc, untyped-decorator]
    def _update_v3(self, name: str, mb_policy: Optional[Dict[str, Any]] = None, **_params: Any) -> None:
        policy = MBPolicy.get(name=name)
        if not policy:
            APIError("not_found", f"No MB ref state with name '{name}'.").send_via(self)
            return

        mb_policy_str = mb_policy.get("mb_policy") if mb_policy else None

        if mb_policy_str is not None:
            db_format = mba.mb_policy_db_contents(name, mb_policy_str)
            for field, value in db_format.items():
                if field != "name":
                    policy.change(field, value)  # type: ignore[no-untyped-call]

        if not policy.changes_valid:
            APIMessageBody.from_record_errors(policy).send_via(self)
            return

        policy.commit_changes()
        APIResource("mb_policy", str(policy.id), policy.render(["name", "mb_policy"])).include(  # type: ignore[attr-defined]
            APILink("self", f"/v{self.version}/refstates/uefi/{policy.name}")  # type: ignore[attr-defined]
        ).send_via(
            self, code=200
        )

    def _delete_v3(self, name: str) -> None:
        policy = MBPolicy.get(name=name)
        if not policy:
            APIError("not_found", f"No MB ref state with name '{name}'.").send_via(self)
            return
        if VerifierAgent.all_ids(mb_policy_id=policy.id):  # type: ignore[attr-defined]
            APIError("conflict", f"MB ref state '{name}' is referenced by one or more agents.").send_via(self)
            return
        try:
            policy.delete(include_dependants=False)
        except IntegrityError as e:
            logger.warning("MB policy deletion failed due to FK constraint for '%s': %s", name, e)
            APIError("conflict", f"MB ref state '{name}' is referenced by one or more agents.").send_via(self)
            return
        self.send_response(204)
