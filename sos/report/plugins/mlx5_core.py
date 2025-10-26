# Copyright (C) 2024 Nvidia Corporation,
# This file is part of the sos project: https://github.com/sosreport/sos
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# version 2 of the GNU General Public License.
#
# See the LICENSE file in the source distribution for further information.

from sos.report.plugins import Plugin, IndependentPlugin, PluginOpt


class Mlx5_core(Plugin, IndependentPlugin):
    """The mlx5_core plugin is aimed at collecting debug information related to
    Mellanox 5th generation network adapters core driver
    """
    short_desc = 'Mellanox 5th generation network adapters (ConnectX series)\
    core driver'
    plugin_name = 'mlx5_core'
    profiles = ('hardware', )

    option_list = [
        PluginOpt("firmware-dump", default=False,
                  desc="collect firmware dump data (ethtool -w) for mlx5 devices")
    ]

    def setup(self):
        self.add_copy_spec([
            # Debug and kernel information
            '/sys/kernel/debug/mlx5/0000:*/*',
            # Network device settings and statistics
            '/sys/class/net/*/hp_oob_cnt',
            '/sys/class/net/*/hp_oob_cnt_mode',
            '/sys/class/net/*/hp_queues/*/rate',
            '/sys/class/net/*/rep_config/miss_rl_cfg',
            '/sys/class/net/*/rep_config/miss_rl_dropped_packets',
            '/sys/class/net/*/rep_config/miss_rl_dropped_bytes',
            '/sys/class/net/*/rep_config/miss_rl_stats_clr',
            '/sys/devices/*/*/*/net/*/settings/force_local_lb_disable',
            # SR-IOV and VF configurations
            '/sys/class/net/*/device/sriov/*/meters/*/*/*',
            '/sys/class/infiniband/*/device/sriov/*/vlan',
            '/sys/class/infiniband/*/device/sriov/*/config',
            # InfiniBand
            '/sys/class/infiniband/*/ttl/*/ttl',
            '/sys/class/infiniband/*/tc/*/traffic_class',
            # devlink
            '/sys/devices/*/*/*/net/*/compat/devlink/*',
        ])

        # Collect RSS hash indirection table information for all ethernet devices
        self.add_device_cmd([
            "ethtool -x %(dev)s"
        ], devices='ethernet')

        # Collect firmware dump information for all ethernet devices
        # This shows dump flag, version, and length of dump data
        # NOTE: ethtool -w is deprecated and only shows results for kernels below 6.1
        self.add_device_cmd([
            "ethtool -w %(dev)s"
        ], devices='ethernet')

        # Collect actual firmware dump data if option is enabled
        if self.get_option("firmware-dump"):
            self._log_warn("WARNING: collecting firmware dump data may take "
                           "time and generate large files")
            self.add_device_cmd([
                "ethtool -w %(dev)s data %(dev)s_firmware_dump.bin"
            ], devices='ethernet')

# vim: set et ts=4 sw=4 :
