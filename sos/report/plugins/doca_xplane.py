import json

from sos.report.plugins import IndependentPlugin, Plugin
from sos.utilities import is_executable

SERVICE_NAME = "doca-xplane"
CORE_SERVICE_NAME = "doca-xplane-core"
TRANSPORT_SERVICE_NAME = "doca-xplane-transport"
CLIENT_COMMAND = "doca-xplane-client"


class DocaXPlane(Plugin, IndependentPlugin):
    """Collect DOCA XPlane service data and, when available, CLI state."""

    short_desc = "DOCA XPlane service"
    plugin_name = "doca_xplane"
    profiles = ("doca",)
    packages = (SERVICE_NAME, CLIENT_COMMAND)
    services = (SERVICE_NAME, CORE_SERVICE_NAME, TRANSPORT_SERVICE_NAME)
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
                f"{CLIENT_COMMAND} get-status",
                f"{CLIENT_COMMAND} get-planes-summary",
            ]
        )

        res = self.collect_cmd_output(f"{CLIENT_COMMAND} get-topology")

        if res["status"] != 0:
            self._log_error("Failed to get topology")
            return

        try:
            pfs = json.loads(res["output"])["pfs"]
            plane_ids = sorted({pf["plane"] for pf in pfs})
            pf_names = sorted({pf["pfName"] for pf in pfs})
        except (json.JSONDecodeError, KeyError, TypeError) as e:
            self._log_error(f"Failed to parse topology: {e}")
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
                for i in plane_ids
                for sub in subcommands
            ]
        )

        maintenance_help = self.exec_cmd(
            f"{CLIENT_COMMAND} maintenance get-link-maintenance --help"
        )
        if maintenance_help["status"] == 0:
            self.add_cmd_output(
                [
                    f"{CLIENT_COMMAND} maintenance get-link-maintenance "
                    f"--pf_name {pf_name}"
                    for pf_name in pf_names
                ]
            )
