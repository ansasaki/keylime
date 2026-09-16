from keylime import api_version as keylime_api_version
from keylime import keylime_logging
from keylime.web.base import APIResource, Controller

logger = keylime_logging.init_logging("registrar")


class VersionController(Controller):
    # GET /version
    def version(self, **_params):  # type: ignore[override]  # pylint: disable=invalid-overridden-method  # Route handler, not property
        version_info = {
            "current_version": keylime_api_version.current_version(),
            "supported_versions": keylime_api_version.all_versions(),
        }
        self.respond(200, "Success", version_info)

    # GET /v3[.0]/
    def show_version_root(self, **_params):
        """A request to the top-level path of a given API version returns 200 when supported,
        along with a JSON:API document containing registrar metadata.
        """
        APIResource(
            "registrar",
            {"supported_versions": keylime_api_version.all_versions()},
        ).send_via(self)
