
# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
# This file is part of the sos project: https://github.com/sosreport/sos
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# version 2 of the GNU General Public License.
#
# See the LICENSE file in the source distribution for further information.

import json

from sos.report.plugins import IndependentPlugin, Plugin, PluginOpt

# vpcctl is shipped inside the weave image at / and is not on the host PATH.
VPCCTL = "/vpcctl"
GRPC_SOCKET_DIR = "/var/run/dpf/weave/grpc"
DHCP_SOCKET = f"{GRPC_SOCKET_DIR}/dhcp.sock"
UNDERLAY_CONFIG = "/var/lib/dpf/weave/flow-controller/underlay-config.yaml"
# DHCP state is bind mounted to this host path (chart default) and persists
# even when the pod is down, which is the usual case when a report is taken.
DHCP_HOST_DIR = "/var/run/dpf/weave/dhcp"
DHCP_STATE_FILES = ("last-applied-state.json", "leases.json", "dnsmasq.conf")
FLOW_CONTROLLER_CONTAINER = "weave-flow-controller"
DHCP_AGENT_CONTAINER = "weave-dhcp-agent"
WEAVE_CONTAINERS = (FLOW_CONTROLLER_CONTAINER, DHCP_AGENT_CONTAINER)


class DocaWeave(Plugin, IndependentPlugin):
    """
    Collect DOCA Weave (east-west VPC) runtime state from a DPU node.

    This plugin captures:
    - Virtual network and attachment state via the vpcctl gRPC client
    - The flow-controller underlay config (read from the container) and the
      host-side DHCP state files
    - Container stdout/stderr logs for weave-flow-controller and
      weave-dhcp-agent

    Note: Weave runs on the DPU (arm64 BlueField) and vpcctl only exists
    inside the weave containers, so run sos report on the DPU. This plugin
    execs vpcctl in the local weave-flow-controller container via the node
    runtime (crictl/podman), which keeps collection scoped to this node with
    no kubeconfig needed.
    """

    short_desc = "DOCA Weave east-west VPC runtime state"
    plugin_name = "doca_weave"
    profiles = ("doca",)
    plugin_timeout = 300

    containers = WEAVE_CONTAINERS
    # Trigger-only (we override setup and never copy self.files), these are
    # persistent host dirs so the plugin still runs, and collects host state
    # plus stopped-container logs, when the pod is down. Do not call
    # super().setup(), GRPC_SOCKET_DIR holds live unix sockets.
    files = (GRPC_SOCKET_DIR, DHCP_HOST_DIR)

    option_list = [
        PluginOpt("describe", default=False, val_type=bool,
                  desc="collect get-vnet/get-attachment for each listed "
                       "resource"),
    ]

    def setup(self):
        self._collect_config()
        # get_all so logs are still collected from crashed/exited containers,
        # which is the common state when a report is taken.
        self.add_container_logs(list(WEAVE_CONTAINERS), get_all=True)
        self._collect_client()

    def _collect_config(self):
        # The underlay config is a ConfigMap mount inside the container with no
        # host equivalent, so read it through the container when it is up.
        self.add_cmd_output(
            f"cat {UNDERLAY_CONFIG}",
            container=FLOW_CONTROLLER_CONTAINER,
            suggest_filename="underlay-config.yaml",
            subdir="config",
        )
        # DHCP state is bind mounted from the host, collect it there so it
        # survives a downed pod.
        self.add_copy_spec([f"{DHCP_HOST_DIR}/{f}" for f in DHCP_STATE_FILES])
        if self.path_exists(GRPC_SOCKET_DIR):
            self.add_cmd_output(f"ls -la {GRPC_SOCKET_DIR}/", subdir="runtime")

    def _collect_client(self):
        self.add_cmd_output(
            [f"{VPCCTL} list-vnet", f"{VPCCTL} list-attachment"],
            container=FLOW_CONTROLLER_CONTAINER,
            subdir="client",
        )

        # get-dhcp-config talks to dhcp.sock, owned by the dhcp-agent, so run
        # it there to stay available if the flow-controller alone is down.
        if self.path_exists(DHCP_SOCKET):
            self.add_cmd_output(f"{VPCCTL} get-dhcp-config",
                                container=DHCP_AGENT_CONTAINER,
                                subdir="client")

        if self.get_option("describe"):
            self._collect_describe()

    def _collect_describe(self):
        # exec_cmd falls back to running on the host when the container is
        # missing, so skip the fan-out entirely if it is not present.
        if not self.container_exists(FLOW_CONTROLLER_CONTAINER):
            return
        self._describe_resources("list-vnet", "virtualNetworks", "get-vnet")
        self._describe_resources(
            "list-attachment", "virtualNetworkAttachments", "get-attachment"
        )

    def _describe_resources(self, list_cmd, list_key, get_cmd):
        res = self.exec_cmd(f"{VPCCTL} {list_cmd}",
                            container=FLOW_CONTROLLER_CONTAINER)
        if res["status"] != 0:
            self._log_error(f"Failed to run {VPCCTL} {list_cmd}")
            return

        try:
            items = json.loads(res["output"]).get(list_key, [])
        except json.JSONDecodeError as e:
            self._log_error(f"Failed to parse {list_cmd} output: {e}")
            return

        # The resource id lives in metadata, the spec has no id field.
        ids = [item["metadata"]["id"] for item in items
               if item.get("metadata", {}).get("id")]
        self.add_cmd_output(
            [f"{VPCCTL} {get_cmd} --id {rid}" for rid in ids],
            container=FLOW_CONTROLLER_CONTAINER,
            subdir="client",
        )
