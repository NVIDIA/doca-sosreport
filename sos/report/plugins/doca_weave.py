# Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES.
# This file is part of the sos project: https://github.com/sosreport/sos
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# version 2 of the GNU General Public License.
#
# See the LICENSE file in the source distribution for further information.

from sos.report.plugins import IndependentPlugin, Plugin


class DocaWeave(Plugin, IndependentPlugin):
    """
    Collect DOCA Weave (east-west VPC) runtime state from a DPU node:
    vnet/attachment state, the flow-controller underlay config, and host-side
    DHCP state. Container logs are collected by the container_log plugin.

    This needs to run on the DPU (arm64 BlueField) because vpcctl only exists
    inside the weave containers on the DPU.
    """

    short_desc = "DOCA Weave east-west VPC runtime state"
    plugin_name = "doca_weave"
    profiles = ("doca",)

    # vpcctl ships inside the weave image at / and is not on the host PATH.
    VPCCTL = "/vpcctl"
    GRPC_SOCKET_DIR = "/var/run/dpf/weave/grpc"
    DHCP_SOCKET = f"{GRPC_SOCKET_DIR}/dhcp.sock"
    # Bind-mounted host path (chart default), persists when the pod is down.
    DHCP_HOST_DIR = "/var/run/dpf/weave/dhcp"
    FLOW_CONTROLLER_CONTAINER = "weave-flow-controller"
    DHCP_AGENT_CONTAINER = "weave-dhcp-agent"
    WEAVE_CONTAINERS = (FLOW_CONTROLLER_CONTAINER, DHCP_AGENT_CONTAINER)

    containers = WEAVE_CONTAINERS
    files = (GRPC_SOCKET_DIR, DHCP_HOST_DIR)

    def setup(self):
        self._collect_config()
        self._collect_client()

    def _collect_config(self):
        # ConfigMap mount with no host equivalent, read it via the container.
        self.add_cmd_output(
            "cat /var/lib/dpf/weave/flow-controller/underlay-config.yaml",
            container=self.FLOW_CONTROLLER_CONTAINER,
            suggest_filename="underlay-config.yaml",
            subdir="config",
        )
        self.add_copy_spec([
            f"{self.DHCP_HOST_DIR}/last-applied-state.json",
            f"{self.DHCP_HOST_DIR}/leases.json",
            f"{self.DHCP_HOST_DIR}/dnsmasq.conf",
        ])

    def _collect_client(self):
        self.add_cmd_output(
            [f"{self.VPCCTL} list-vnet",
             f"{self.VPCCTL} list-attachment"],
            container=self.FLOW_CONTROLLER_CONTAINER,
            subdir="client",
        )

        # get-dhcp-config talks to dhcp.sock, owned by the dhcp-agent.
        if self.path_exists(self.DHCP_SOCKET):
            self.add_cmd_output(f"{self.VPCCTL} get-dhcp-config",
                                container=self.DHCP_AGENT_CONTAINER,
                                subdir="client")

# vim: set et ts=4 sw=4
