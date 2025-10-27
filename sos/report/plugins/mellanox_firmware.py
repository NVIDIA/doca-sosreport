# Copyright (C) 2023 Nvidia Corporation
# Author: Alin Serdean <aserdean@nvidia.com>
#
# This file is part of the sos project: https://github.com/sosreport/sos
#
# Licensed under the GNU General Public License v2.
# See the LICENSE file in the source distribution for details.

import os
import re
import shutil
from sos.report.plugins import Plugin, IndependentPlugin


class MellanoxFirmware(Plugin, IndependentPlugin):
    """
    SOSReport plugin for gathering Mellanox firmware information
    using either MFT (flint) or MSTFlint utilities.
    """

    # Estimate: ~3 minutes per device × 9 devices (largest known system)
    plugin_timeout = 1650
    plugin_name = "mellanox_firmware"
    MLNX_STRING = "Mellanox Technologies"
    short_desc = "Nvidia (Mellanox) firmware tools output"

    packages = ("mst", "mstflint")
    profiles = ("hardware", "system")

    def __init__(self, commons):
        """
        Initialize the plugin.

        Args:
            commons: SOSReport commons object.
        """
        super().__init__(commons=commons)

        self.tool_type = None
        self.devices_tools = []

        self.MFT_TOOL = "mft"
        self.MSTFLINT_TOOL = "mstflint"

    def detect_tool(self):
        """
        Detect which firmware tool is available on the system.

        Returns:
            One of 'mft', 'mstflint', or None.
        """
        if shutil.which("flint"):
            return self.MFT_TOOL

        if shutil.which("mstflint"):
            return self.MSTFLINT_TOOL

        return None

    def get_mst_status(self):
        """
        Check if the MST PCI configuration module is loaded (MFT only).

        Returns:
            True if MST is loaded, False otherwise.
        """
        if self.tool_type != self.MFT_TOOL:
            return False

        result = self.exec_cmd("mst status")

        return (
            result.get("status") == 0 and
            "MST PCI configuration module loaded" in result.get("output", "")
        )

    def detect_devices(self):
        """
        Detect Mellanox devices in the system.

        This function collects all Mellanox PCI devices, filtering out
        bridges and DMA engines. If MST is running, it maps PCI devices
        to their corresponding /dev/mst nodes. Otherwise, PCI addresses
        are returned directly.

        Returns:
            list of tuples: Each tuple contains:
                - device path (/dev/mst/*) or PCI address (str)
                - PCI address (str)
                - primary function flag (bool)
                    true for the first function of the device
        """
        pci_devices = []
        devices_info = []

        # Get all Mellanox PCI devices (filter out bridges and DMA engines)
        result = self.exec_cmd("lspci -D -d 15b3:")

        pci_pattern = re.compile(
            r"^[\da-fA-F]{1,4}:[\da-fA-F]{1,2}:[\da-fA-F]{1,2}\.[0-7]$"
        )

        for line in sorted(result.get("output", "").splitlines()):
            fields = line.split()

            if not fields:
                continue

            if "bridge" in line or "DMA" in line:
                continue

            pci_addr = fields[0]

            if pci_pattern.match(pci_addr):
                prefix = pci_addr.rsplit(":", 1)[0]

                is_primary = not any(
                    d[0].startswith(prefix) for d in pci_devices
                )

                pci_devices.append((pci_addr, is_primary))

        # If MST is running, map PCI devices to /dev/mst nodes
        if pci_devices and self.get_mst_status():
            result = self.exec_cmd("mst status -v")

            if result.get("status") == 0:
                for line in sorted(result.get("output", "").splitlines()):
                    parts = line.split()

                    if len(parts) < 3:
                        continue

                    pci_addr, is_primary = next(
                        (dev for dev in pci_devices if parts[2] in dev[0]),
                        (None, None)
                    )

                    if pci_addr:
                        devices_info.append((
                            parts[1],
                            pci_addr,
                            is_primary
                        ))

        else:
            for (pci_addr, is_primary) in pci_devices:
                devices_info.append((
                    pci_addr,
                    pci_addr,
                    is_primary
                ))

        return devices_info

    def check_enabled(self):
        """
        Determine whether this plugin should be enabled.

        Returns:
            True if Mellanox devices are present in the system, False
            otherwise.
        """
        try:
            lspci = self.exec_cmd("lspci -D -d 15b3:")

            return (
                lspci.get("status") == 0 and
                self.MLNX_STRING in lspci.get("output", "")
            )

        except Exception:
            return False

    @property
    def timeout(self):
        """
        Override the plugin timeout.
        - Uses the base Plugin timeout.
        - Warns if the configured timeout may be insufficient
            (based on ~3 minutes per device).
        """
        base_timeout = super().timeout
        device_count = len(
            [dev for dev in getattr(self, "devices_tools", []) if dev.primary]
        )
        expected_timeout = device_count * 180  # ~3 min per device

        if base_timeout < expected_timeout:
            self._log_warn(
                f"Plugin timeout {base_timeout}s may be too low for "
                f"{device_count} device(s). Expected ~{expected_timeout}s "
                f"(~3 minutes per device)."
            )

        return base_timeout

    def setup(self):
        """
        Set up the plugin: detect the available tool and initialize
        firmware tool instances for each detected device.
        """
        self.tool_type = self.detect_tool()

        if not self.tool_type:
            self._log_warn("No Mellanox tool found. Skipping plugin.")
            return

        devices_info = self.detect_devices()

        if not devices_info:
            self._log_warn("No Mellanox devices found. Skipping plugin.")
            return

        for idx, (dev, pci, primary) in enumerate(devices_info):
            global_collector = idx == 0

            if self.tool_type == self.MFT_TOOL:
                self.devices_tools.append(
                    MFTFirmwareTool(
                        self,
                        device=dev,
                        pci=pci,
                        primary=primary,
                        global_collector=global_collector
                    )
                )
            else:
                self.devices_tools.append(
                    MSTFlintFirmwareTool(
                        self,
                        device=dev,
                        pci=pci,
                        primary=primary,
                        global_collector=global_collector
                    )
                )

        self._log_info(
            f"Mellanox plugin setup complete. Tool={self.tool_type}, "
            f"Devices={[dev_info[0] for dev_info in devices_info]}"
        )

    def collect(self):
        """
        Run firmware collection across all detected devices and priorities.
        """
        all_priorities = set()

        for tool in self.devices_tools:
            all_priorities.update(tool.commands.keys())

        for priority in sorted(all_priorities):
            for tool in self.devices_tools:
                if priority in tool.commands:
                    tool.collect(priority)


class BaseFirmwareTool:
    """
    Base class for Mellanox firmware tools.

    Provides a common structure for device-specific command generation,
    firmware collection, and secure firmware detection.
    """

    def __init__(self, plugin, device, pci, primary, global_collector):
        """
        Initialize a firmware tool instance.

        Args:
            plugin: SOSReport plugin used for running commands and logging.
            device: Device identifier, either a PCI address or an mst device.
            pci: PCI address, used to standardize output file naming when the
                device is an mst device.
            primary (bool): True for the first function of the device,
                used to run device-specific queries.
            global_collector (bool): True for the single device responsible
                for running global system-level commands once per system.
        """
        self.plugin = plugin
        self.device = device
        self.primary = primary
        self.pci_address = pci
        self.global_collector = global_collector
        self._commands = None

    @staticmethod
    def parse_security_attributes(output):
        """
        Extract security attributes from firmware query output.

        Args:
            output: Raw string output from a firmware query command.

        Returns:
            List of security attributes as strings.
        """
        match = re.search(
            r"^Security Attributes:\s*(.+)$",
            output,
            re.MULTILINE
        )

        if match:
            return [attr.strip() for attr in match.group(1).split(",")]

        return []

    def is_secured_fw(self):
        """
        Determine if the firmware is marked as secure.

        Returns:
            Boolean indicating whether the firmware is secure.

        Raises:
            NotImplementedError: Must be implemented by subclasses.
        """
        raise NotImplementedError

    @property
    def commands(self):
        """
        Return the set of commands required for firmware data collection,
        organized by priority.

        Raises:
            NotImplementedError: Must be implemented by subclasses.
        """
        raise NotImplementedError

    def __generate_archive_file_path(self, file_name):
        return os.path.join(
            self.plugin.archive.get_archive_path(),
            self.plugin._make_command_filename(exe=file_name)
        )

    def get_cable_commands(self, tool_name: str):
        """
        Generate cable-related commands for the given tool.

        Args:
            tool_name (str): Tool executable name ("mstlink" or "mlxlink").

        Returns:
            list[dict]: [ { 'cmd': str, 'file': str }, ... ].
        """
        bdf = self.pci_address.replace(":", "").replace(".", "")

        commands = [
            {
                "priority": 3,
                "cmd": f"{tool_name} -d {self.device} --show_module",
                "file": f"{tool_name}_{bdf}_--show_module",
            },
            {
                "priority": 3,
                "cmd": f"{tool_name} -d {self.device} --cable --dump",
                "file": f"{tool_name}_{bdf}_--cable_--dump",
            },
            {
                "priority": 3,
                "cmd": f"{tool_name} -d {self.device} --cable --ddm",
                "file": f"{tool_name}_{bdf}_--cable_--ddm",
            },
            {
                "priority": 3,
                "cmd": f"{tool_name} -d {self.device} --show_counters",
                "file": f"{tool_name}_{bdf}_--show_counters",
            },
            {
                "priority": 3,
                "cmd": f"{tool_name} -d {self.device} --show_eye",
                "file": f"{tool_name}_{bdf}_--show_eye",
            },
            {
                "priority": 3,
                "cmd": f"{tool_name} -d {self.device} --show_fec",
                "file": f"{tool_name}_{bdf}_--show_fec",
            },
            {
                "priority": 3,
                "cmd": f"{tool_name} -d {self.device} --show_serdes_tx",
                "file": f"{tool_name}_{bdf}_--show_serdes_tx",
            },
            {
                "priority": 3,
                "cmd": (
                    f"{tool_name} -d {self.device} "
                    "--rx_fec_histogram --show_histogram"
                ),
                "file": (
                    f"{tool_name}_{bdf}_--rx_fec_histogram_--show_histogram"
                ),
            },
        ]

        if self.primary:
            amber_file_name = f"{tool_name}_{bdf}_--amber_collect"
            amber_csv_path = self.__generate_archive_file_path(
                file_name=f'{amber_file_name}.csv'
            )

            amber_pci_file_name = f"{amber_file_name}_--pci"
            amber_pci_csv_path = self.__generate_archive_file_path(
                file_name=f'{amber_pci_file_name}.csv'
            )

            commands.extend([
                {
                    "priority": 3,
                    "cmd": (
                        f"{tool_name} -d {self.device} "
                        "--show_links --port_type PCIE"
                    ),
                    "file": (
                        f"{tool_name}_{bdf}_--show_links_--port_type_PCIE"
                    ),
                },
                {
                    "priority": 3,
                    "cmd": (
                        f"{tool_name} -d {self.device} "
                        f"--amber_collect {amber_csv_path}"
                    ),
                    "file": amber_file_name,
                },
                {
                    "priority": 3,
                    "cmd": (
                        f"{tool_name} -d {self.device} --amber_collect "
                        f"{amber_pci_csv_path} --port_type PCIE"
                    ),
                    "file": amber_pci_file_name,
                },
            ])

        return commands

    def collect(self, priority=None):
        """
        Run all commands for this device, either for a specific priority
        or for all priorities if none is specified.

        Args:
            priority: Integer priority level to collect, or None to collect
                      all.
        """
        if priority is not None:
            self.plugin._log_info(
                f"[{self.device}] Starting collection for "
                f"priority {priority}"
            )

            for entry in self.commands.get(priority, []):
                self.plugin.collect_cmd_output(
                    cmd=entry["cmd"],
                    suggest_filename=entry["file"]
                )

            self.plugin._log_info(
                f"[{self.device}] Completed collection for "
                f"priority {priority}"
            )

        else:
            self.plugin._log_info(
                f"[{self.device}] Starting full firmware collection"
            )

            for priority in sorted(self.commands):
                for entry in self.commands[priority]:
                    self.plugin.collect_cmd_output(
                        cmd=entry["cmd"],
                        suggest_filename=entry["file"]
                    )

            self.plugin._log_info(
                f"[{self.device}] Finished full firmware collection"
            )


class MFTFirmwareTool(BaseFirmwareTool):
    """
    Firmware tool implementation for Mellanox MFT (flint) utilities.
    """

    def is_secured_fw(self):
        """
        Check if the firmware is secure using the flint query command.

        Returns:
            Boolean indicating secure firmware status.
        """
        result = self.plugin.exec_cmd(
            f"flint -d {self.device} q full",
        )

        attrs = self.parse_security_attributes(
            result.get("output", "")
        ) if result.get("status") == 0 else []

        return "secure-fw" in attrs and "dev" not in attrs

    @property
    def commands(self):
        """
        Build and return all commands for MFT firmware collection.

        Behavior:
        - Global commands run only once on the system-level collector device.
        - Primary commands run only on the first function of each device.
        - Extra commands are included only when firmware is not secured.
        - Cable-related commands run on every PCI function of every device.

        Returns:
            dict: { priority: [ { 'cmd': str, 'file': str }, ... ] }
        """
        if self._commands is not None:
            return self._commands

        bdf = self.pci_address.replace(":", "").replace(".", "")

        COMMANDS = []

        # Global system-level commands
        # Executed only for the first function of the first device
        if self.global_collector:
            COMMANDS.extend([
                {
                    "priority": 2,
                    "cmd": "flint --version",
                    "file": "flint_--version",
                },
                {
                    "priority": 2,
                    "cmd": "mst status -v",
                    "file": "mst_status_-v",
                },
            ])

        # Primary-function commands
        # Executed only on the first function of each device
        if self.primary:
            COMMANDS.extend([
                {
                    "priority": 0,
                    "cmd": f"flint -d {self.device} q full",
                    "file": f"flint_{bdf}_q_full",
                },
                {  # Repeated intentionally for diagnostic sampling
                    "priority": 0,
                    "cmd": f"mstdump {self.device}",
                    "file": f"mstdump_{bdf}_run_1",
                },
                {
                    "priority": 0,
                    "cmd": f"mstdump {self.device}",
                    "file": f"mstdump_{bdf}_run_2",
                },
                {
                    "priority": 0,
                    "cmd": f"mstdump {self.device}",
                    "file": f"mstdump_{bdf}_run_3",
                },
                {
                    "priority": 1,
                    "cmd": (
                        f"resourcedump dump -d {self.device} "
                        "--segment BASIC_DEBUG"
                    ),
                    "file": (
                        f"resourcedump_dump_{bdf}_--segment_BASIC_DEBUG"
                    ),
                },
                {
                    "priority": 2,
                    "cmd": (
                        f"mlxdump -d {self.device} "
                        "pcie_uc --all"
                    ),
                    "file": (
                        f"mlxdump_{bdf}_pcie_uc_--all"
                    ),
                },
                {
                    "priority": 2,
                    "cmd": (
                        f"mlxconfig -d {self.device} -e q"
                    ),
                    "file": (
                        f"mlxconfig_{bdf}_-e_q"
                    ),
                },
                {
                    "priority": 2,
                    "cmd": (
                        f"mlxreg -d {self.device} "
                        "--reg_name ROCE_ACCL --get"
                    ),
                    "file": (
                        f"mlxreg_{bdf}_--reg_name_ROCE_ACCL_--get"
                    ),
                },
                {
                    "priority": 3,
                    "cmd": f"mget_temp -d {self.device}",
                    "file": f"mget_temp_{bdf}",
                },
            ])

            # Additional commands applied only when firmware is unsecured
            if not self.is_secured_fw():
                COMMANDS.extend([
                    {
                        "priority": 2,
                        "cmd": f"flint -d {self.device} dc",
                        "file": f"flint_{bdf}_dc",
                    },
                ])

        # Cable-related commands executed for every function of each device
        COMMANDS.extend(
            self.get_cable_commands(tool_name="mlxlink")
        )

        self._commands = {}

        for entry in COMMANDS:
            self._commands.setdefault(entry["priority"], []).append(
                {"cmd": entry["cmd"], "file": entry["file"]}
            )

        return self._commands


class MSTFlintFirmwareTool(BaseFirmwareTool):
    """
    Firmware tool implementation for Mellanox MSTFlint utilities.
    """

    def is_secured_fw(self):
        """
        Check if the firmware is secure using the mstflint query command.

        Returns:
            Boolean indicating secure firmware status.
        """
        result = self.plugin.exec_cmd(
            f"mstflint -d {self.device} q full",
        )

        attrs = self.parse_security_attributes(
            result.get("output", "")
        ) if result.get("status") == 0 else []

        return "secure-fw" in attrs and "dev" not in attrs

    @property
    def commands(self):
        """
        Build and return all commands for MSTFlint firmware collection.

        Behavior:
        - Global commands run only once on the system-level collector device.
        - Primary commands run only on the first function of each device.
        - Extra commands are included only when firmware is not secured.
        - Cable-related commands run on every PCI function of every device.

        Returns:
            dict: { priority: [ { 'cmd': str, 'file': str }, ... ] }
        """
        if self._commands is not None:
            return self._commands

        bdf = self.pci_address.replace(":", "").replace(".", "")

        COMMANDS = []

        # Global system-level commands
        # Executed only for the first function of the first device
        if self.global_collector:
            COMMANDS.extend([
                {
                    "priority": 2,
                    "cmd": "mstflint --version",
                    "file": "mstflint--version",
                },
                {
                    "priority": 2,
                    "cmd": "mstdevices_info",
                    "file": "mstdevices_info",
                },
            ])

        # Primary-function commands
        # Executed only on the first function of each device
        if self.primary:
            COMMANDS.extend([
                {
                    "priority": 0,
                    "cmd": f"mstflint -d {self.device} q full",
                    "file": f"mstflint_{bdf}_q_full",
                },
                {  # Repeated intentionally for diagnostic sampling
                    "priority": 0,
                    "cmd": f"mstregdump {self.device}",
                    "file": f"mstregdump_{bdf}_run_1",
                },
                {
                    "priority": 0,
                    "cmd": f"mstregdump {self.device}",
                    "file": f"mstregdump_{bdf}_run_2",
                },
                {
                    "priority": 0,
                    "cmd": f"mstregdump {self.device}",
                    "file": f"mstregdump_{bdf}_run_3",
                },
                {
                    "priority": 1,
                    "cmd": (
                        f"mstresourcedump dump -d {self.device} "
                        "--segment BASIC_DEBUG"
                    ),
                    "file": (
                        f"mstresourcedump_dump_{bdf}_--segment_BASIC_DEBUG"
                    ),
                },
                {
                    "priority": 2,
                    "cmd": (
                        f"mstconfig -d {self.device} -e q"
                    ),
                    "file": (
                        f"mstconfig_{bdf}_-e_q"
                    ),
                },
                {
                    "priority": 2,
                    "cmd": (
                        f"mstreg -d {self.device} "
                        "--reg_name ROCE_ACCL --get"
                    ),
                    "file": (
                        f"mstreg_{bdf}_--reg_name_ROCE_ACCL_--get"
                    ),
                },
                {
                    "priority": 3,
                    "cmd": f"mstmget_temp -d {self.device}",
                    "file": f"mstmget_temp_{bdf}",
                },
            ])

            # Additional commands applied only when firmware is unsecured
            if not self.is_secured_fw():
                COMMANDS.extend([
                    {
                        "priority": 2,
                        "cmd": f"mstflint -d {self.device} dc",
                        "file": f"mstflint_{bdf}_dc",
                    },
                ])

        # Cable-related commands executed for every function of each device
        COMMANDS.extend(
            self.get_cable_commands(tool_name="mstlink")
        )

        self._commands = {}

        for entry in COMMANDS:
            self._commands.setdefault(entry["priority"], []).append(
                {
                    "cmd": entry["cmd"],
                    "file": entry["file"],
                }
            )

        return self._commands

# vim: set et ts=4 sw=4 :
