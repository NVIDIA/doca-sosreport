import json
from sos.report.plugins import IndependentPlugin, Plugin
from sos.utilities import is_executable

SERVICE_NAME = "doca-xplane"
CLIENT_COMMAND = "doca-xplane-client"


class DocaXPlane(Plugin, IndependentPlugin):
    """Collect DOCA XPlane service data and, when available, CLI state."""

    short_desc = "DOCA XPlane service"
    plugin_name = "doca_xplane"
    profiles = ("doca",)
    packages = (SERVICE_NAME, CLIENT_COMMAND)
    services = (SERVICE_NAME,)
    containers = (SERVICE_NAME,)
    commands = (CLIENT_COMMAND,)

    def setup(self):
        self.add_copy_spec(
            [
                "/opt/mellanox/doca/services/xplane",
                "/var/log/xplane",
            ]
        )

        if is_executable(CLIENT_COMMAND, self.sysroot):
            self._collect_client()

    def _collect_client(self):
        self.add_cmd_output(
            [
                f"{CLIENT_COMMAND} --version",
                f"{CLIENT_COMMAND} get-planes-summary",
                f"{CLIENT_COMMAND} get-topology",
            ]
        )

        res = self.collect_cmd_output(f"{CLIENT_COMMAND} get-status")

        if res["status"] != 0:
            self._log_error("Failed to get status")
            return

        try:
            status = json.loads(res["output"])
            num_planes = status["topologySummary"]["planes"]
        except Exception as e:
            self._log_error(f"Failed to parse status: {e}")
            return

        subcommands = (
            "get-plane-failures-local",
            "get-plane-failures-remote",
            "get-plane-traffic-diverted-from",
            "get-plane-traffic-diverted-to",
            "get-plane-traffic-summary",
        )

        self.add_cmd_output(
            [
                f"{CLIENT_COMMAND} {sub} --plane_id {i}"
                for i in range(num_planes)
                for sub in subcommands
            ]
        )
