# Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES.
# This file is part of the sos project: https://github.com/sosreport/sos
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# version 2 of the GNU General Public License.
#
# See the LICENSE file in the source distribution for further information.

from sos.report.plugins import Plugin, IndependentPlugin


class SnapRpc(Plugin, IndependentPlugin):
    """
    Collects snap service information and logs.
    This plugin captures:
    - snap service logs
    - snap service configuration
    - runtime snap service information
    - runtime spdk information
    """

    short_desc = "NVIDIA DOCA SNAP-4"
    plugin_name = "snap_service"
    packages = ("cri-o", "cri-tools")
    services = ("crio",)

    def check_enabled(self):
        return self._get_snap_container_id() is not None

    def setup(self):
        self.collect_snap_rpc_logs()
        self.collect_snap_config()
        commands = self.get_running_snap_rpc_commands()
        self.add_cmd_output(commands, timeout=30)

    def get_running_snap_rpc_commands(self):
        container_id = self._get_snap_container_id()
        if not container_id:
            return None
        CONTAINER_CMD = f"crictl exec {container_id}"
        return [
            f"{CONTAINER_CMD} snap_rpc.py snap_global_param_list",
            f"{CONTAINER_CMD} snap_rpc.py emulation_function_list",
            f"{CONTAINER_CMD} spdk_rpc.py bdev_get_bdevs",
            f"{CONTAINER_CMD} snap_rpc.py nvme_subsystem_list",
            f"{CONTAINER_CMD} snap_rpc.py virtio_blk_controller_list",
        ]

    def collect_snap_rpc_logs(self):
        self.add_copy_spec(
            [
                "/var/log/snap-log/rpc-log",
            ]
        )

    def collect_snap_config(self):
        self.add_copy_spec(
            [
                "/opt/nvidia/nvda_snap/bin/spdk_config.json",
                "/opt/nvidia/nvda_snap/bin/snap_rpc_init.conf",
                "/opt/nvidia/nvda_snap/bin/set_environment_variables.sh",
                "/etc/nvda_snap/snap_rpc_init.conf",
                "/etc/nvda_snap/spdk_rpc_init.conf",
            ]
        )

    def _get_snap_container_id(self):
        snap_container_cmd = "crictl ps -s running -q --name snap"
        container_result = self.exec_cmd(snap_container_cmd)
        if container_result and container_result.get("output"):
            return container_result["output"].strip()
        return None
