from keylime import api_version, config
from keylime.web.base import Controller


class ServerInfoController(Controller):
    def show_root(self, **_params):
        """The root endpoint may be used by clients which understand API v3+ to determine the current API version of the
        server by way of standard HTTP redirect. As v2 clients do not use this mechanism, it always redirects to a v3
        path, even when the deprecated /versions endpoint indicates an older version is most current.
        """
        version = api_version.current_version()
        major = api_version.major(version)

        if major > 3:
            self.redirect(f"/v{version}/")
        else:
            self.redirect(f"/v{api_version.latest_minor_version(3)}/")

    def show_version_root(self, **_params):
        """A request issued for the top-level path of a given API version results in a 200 response when the server
        supports that version.
        """
        if self.major_version and self.major_version <= 2:
            self.respond(405, "Not Implemented: Use /agents/ interface instead")
        else:
            self.respond(200)

    # GET /version[s]
    def show_versions(self, **_params):
        """This endpoint is used by v2 clients (and earlier) to obtain a list of API versions supported by the server.
        Because this endpoint is itself not scoped to a particular API version, it is difficult/impossible to change
        without breaking existing clients. It is therefore deprecated for new clients and not supported in push mode.
        API clients should instead query the top-level path for the latest version supported by the client (e.g.,
        "/v3.0/") to determine whether it is available on the server or not.
        """
        if config.get("verifier", "mode", fallback="pull") == "pull":
            version_info = {
                "current_version": api_version.current_version(),
                "supported_versions": api_version.all_versions(),
            }
            self.respond(200, "Success", version_info)
        else:
            self.respond(410, "Gone")
