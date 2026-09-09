import base64
from typing import Any, Dict, Optional

from sqlalchemy.exc import IntegrityError

from keylime import config, keylime_logging, signing
from keylime.ima import ima
from keylime.models.verifier import IMAPolicy, VerifierAgent
from keylime.shared_data import get_shared_memory
from keylime.web.base import APIError, APILink, APIMessageBody, APIResource, Controller

logger = keylime_logging.init_logging("verifier")


class IMAPolicyController(Controller):
    def _new_v2_handler(self) -> Any:
        # pylint: disable=import-outside-toplevel  # Avoid circular import
        from keylime import cloud_verifier_tornado as v2

        tornado_app = self.action_handler.application
        tornado_req = self.action_handler.request
        return v2.AllowlistHandler(tornado_app, tornado_req, override=self.action_handler)  # type: ignore[no-untyped-call]

    # GET /v3[.x]/policies/ima/
    # GET /v2[.x]/allowlists/
    def index(self, **_params):  # type: ignore[no-untyped-def]
        if self.major_version and self.major_version <= 2:
            self._new_v2_handler().get()  # type: ignore[no-untyped-call]
        else:
            self._index_v3()

    # GET /v3[.x]/policies/ima/:name
    # GET /v2[.x]/allowlists/:name
    def show(self, name, **_params):  # type: ignore[no-untyped-def]
        if self.major_version and self.major_version <= 2:
            self._new_v2_handler().get()  # type: ignore[no-untyped-call]
        else:
            self._show_v3(name)

    # POST /v3[.x]/policies/ima/
    # POST /v2[.x]/allowlists/:name
    def create(self, **_params):  # type: ignore[no-untyped-def]
        if self.major_version and self.major_version <= 2:
            self._new_v2_handler().post()  # type: ignore[no-untyped-call]
        else:
            self._create_v3(**_params)

    # PATCH /v3[.x]/policies/ima/:name
    def update(self, name, **_params):  # type: ignore[no-untyped-def]
        self._update_v3(name, **_params)

    # PUT /v2[.x]/allowlists/:name
    def overwrite(self, name, **_params):  # type: ignore[no-untyped-def]  # pylint: disable=unused-argument  # Required by URL route pattern
        self._new_v2_handler().put()  # type: ignore[no-untyped-call]

    # DELETE /v3[.x]/policies/ima/:name
    # DELETE /v2[.x]/allowlists/:name
    def delete(self, name, **_params):  # type: ignore[no-untyped-def]
        if self.major_version and self.major_version <= 2:
            self._new_v2_handler().delete()  # type: ignore[no-untyped-call]
        else:
            self._delete_v3(name)

    def _index_v3(self) -> None:
        policies = IMAPolicy.all()
        resources = [
            APIResource(
                "ima_policy", str(p.id), p.render(["name", "checksum", "generator"])  # type: ignore[attr-defined]
            ).include(  # type: ignore[attr-defined]
                APILink("self", f"/v{self.version}/policies/ima/{p.name}")  # type: ignore[attr-defined]
            )
            for p in policies
        ]
        body = APIMessageBody(*resources)
        if not resources:
            body._data = []  # pylint: disable=protected-access
        body.send_via(self)

    def _show_v3(self, name: str) -> None:
        policy = IMAPolicy.get(name=name)
        if not policy:
            APIError("not_found", f"No IMA policy with name '{name}'.").send_via(self)
            return
        APIResource("ima_policy", str(policy.id), policy.render(["name", "ima_policy", "tpm_policy", "checksum", "generator"])).include(  # type: ignore[attr-defined]
            APILink("self", f"/v{self.version}/policies/ima/{policy.name}")  # type: ignore[attr-defined]
        ).send_via(
            self
        )

    @Controller.require_json_api  # type: ignore[misc, untyped-decorator]
    def _create_v3(self, ima_policy: Optional[Dict[str, Any]] = None, **_params: Any) -> None:
        if not ima_policy:
            APIError("invalid_resource_data", "Request body must include an 'ima_policy' resource.").send_via(self)
            return

        name = ima_policy.get("name")
        runtime_policy_b64 = ima_policy.get("runtime_policy")
        tpm_policy = ima_policy.get("tpm_policy", "")

        if not name or not runtime_policy_b64:
            APIError("invalid_resource_data", "Attributes 'name' and 'runtime_policy' are required.").send_via(self)
            return

        shared_mem = get_shared_memory()
        ima_policy_locks = shared_mem.get_or_create_dict("ima_policy_create_locks")
        if name not in ima_policy_locks:
            ima_policy_locks[name] = shared_mem.manager.Lock()
        policy_lock = ima_policy_locks[name]

        with policy_lock:
            if IMAPolicy.get(name=name):
                APIError("conflict", f"An IMA policy named '{name}' already exists.").send_via(self)
                return

            try:
                runtime_policy_bytes = base64.b64decode(runtime_policy_b64)
            except Exception:  # pylint: disable=broad-except
                APIError("invalid_resource_data", "Attribute 'runtime_policy' must be valid base64.").send_via(self)
                return

            runtime_policy_key_bytes = signing.get_runtime_policy_keys(
                runtime_policy_bytes, ima_policy.get("runtime_policy_key")
            )
            verify_sig = config.getboolean("verifier", "require_allow_list_signatures", fallback=False)

            try:
                ima.verify_runtime_policy(runtime_policy_bytes, runtime_policy_key_bytes, verify_sig=verify_sig)
            except ima.ImaValidationError as e:
                APIError("invalid_resource_data", str(e.message)).send_via(self)
                return

            runtime_policy_str = runtime_policy_bytes.decode("utf-8")
            db_format = ima.runtime_policy_db_contents(name, runtime_policy_str, tpm_policy or "")
            policy = IMAPolicy(db_format)
            try:
                policy.commit_changes()
            except IntegrityError as e:
                logger.warning("IMA policy creation failed due to database constraint for name '%s': %s", name, e)
                APIError("conflict", f"An IMA policy named '{name}' already exists.").send_via(self)
                return

            APIResource("ima_policy", str(policy.id), policy.render(["name", "ima_policy", "tpm_policy", "checksum", "generator"])).include(  # type: ignore[attr-defined]
                APILink("self", f"/v{self.version}/policies/ima/{policy.name}")  # type: ignore[attr-defined]
            ).send_via(
                self, code=201
            )

    @Controller.require_json_api  # type: ignore[misc, untyped-decorator]
    def _update_v3(self, name: str, ima_policy: Optional[Dict[str, Any]] = None, **_params: Any) -> None:
        policy = IMAPolicy.get(name=name)
        if not policy:
            APIError("not_found", f"No IMA policy with name '{name}'.").send_via(self)
            return

        runtime_policy_b64 = ima_policy.get("runtime_policy") if ima_policy else None
        tpm_policy = ima_policy.get("tpm_policy", "") if ima_policy else None

        if runtime_policy_b64:
            try:
                runtime_policy_bytes = base64.b64decode(runtime_policy_b64)
            except Exception:  # pylint: disable=broad-except
                APIError("invalid_resource_data", "Attribute 'runtime_policy' must be valid base64.").send_via(self)
                return

            runtime_policy_key_bytes = signing.get_runtime_policy_keys(
                runtime_policy_bytes, ima_policy.get("runtime_policy_key") if ima_policy else None
            )
            verify_sig = config.getboolean("verifier", "require_allow_list_signatures", fallback=False)

            try:
                ima.verify_runtime_policy(runtime_policy_bytes, runtime_policy_key_bytes, verify_sig=verify_sig)
            except ima.ImaValidationError as e:
                APIError("invalid_resource_data", str(e.message)).send_via(self)
                return

            runtime_policy_str = runtime_policy_bytes.decode("utf-8")
            db_format = ima.runtime_policy_db_contents(name, runtime_policy_str, tpm_policy or "")
            for field, value in db_format.items():
                if field != "name":
                    policy.change(field, value)  # type: ignore[no-untyped-call]

        if not policy.changes_valid:
            APIMessageBody.from_record_errors(policy).send_via(self)
            return

        policy.commit_changes()
        APIResource("ima_policy", str(policy.id), policy.render(["name", "ima_policy", "tpm_policy", "checksum", "generator"])).include(  # type: ignore[attr-defined]
            APILink("self", f"/v{self.version}/policies/ima/{policy.name}")  # type: ignore[attr-defined]
        ).send_via(
            self, code=200
        )

    def _delete_v3(self, name: str) -> None:
        policy = IMAPolicy.get(name=name)
        if not policy:
            APIError("not_found", f"No IMA policy with name '{name}'.").send_via(self)
            return
        if VerifierAgent.all_ids(ima_policy_id=policy.id):  # type: ignore[attr-defined]
            APIError("conflict", f"Policy '{name}' is referenced by one or more agents.").send_via(self)
            return
        try:
            policy.delete(include_dependants=False)
        except IntegrityError as e:
            logger.warning("IMA policy deletion failed due to FK constraint for '%s': %s", name, e)
            APIError("conflict", f"Policy '{name}' is referenced by one or more agents.").send_via(self)
            return
        self.send_response(204)
