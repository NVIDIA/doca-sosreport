# Copyright (C) 2023 Nvidia Corporation
# Author: Alin Serdean <aserdean@nvidia.com>
#
# This file is part of the sos project: https://github.com/sosreport/sos
#
# Licensed under the GNU General Public License v2.
# See the LICENSE file in the source distribution for details.

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

        Returns:
            dict: Mapping of device paths (/dev/mst/*) to PCI addresses,
                or PCI addresses directly if mst is not running.
        """
        all_devices = []
        pci_devices = []
        device_to_pci = {}

        # Get all Mellanox PCI devices (filter out bridges and DMA engines)
        result = self.exec_cmd("lspci -D -d 15b3:")

        pci_pattern = re.compile(
            r"^[\da-fA-F]{1,4}:[\da-fA-F]{1,2}:[\da-fA-F]{1,2}\.[0-7]$"
        )

        for line in result.get("output", "").splitlines():
            fields = line.split()

            if not fields:
                continue

            if "bridge" in line or "DMA" in line:
                continue

            if pci_pattern.match(fields[0]):
                all_devices.append(fields[0])

        # Deduplicate: keep only one device per PCI root prefix
        for dev in sorted(all_devices):
            prefix = dev.rsplit(":", 1)[0]

            if not any(d.startswith(prefix) for d in pci_devices):
                pci_devices.append(dev)

        # If MST is running, map PCI devices to /dev/mst nodes
        if pci_devices and self.get_mst_status():
            result = self.exec_cmd("mst status -v")

            if result.get("status") == 0:
                for line in result.get("output", "").splitlines():
                    parts = line.split()

                    if len(parts) < 3:
                        continue

                    pci_address = next(
                        (dev for dev in pci_devices if parts[2] in dev),
                        None
                    )

                    if pci_address:
                        device_to_pci[parts[1]] = pci_address

        else:
            device_to_pci = {dev: dev for dev in pci_devices}

        return device_to_pci

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
        device_count = len(getattr(self, "devices_tools", []))
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

        device_to_pci = self.detect_devices()

        if not device_to_pci:
            self._log_warn("No Mellanox devices found. Skipping plugin.")
            return

        for idx, (dev, pci) in enumerate(device_to_pci.items()):
            primary = idx == 0

            if self.tool_type == self.MFT_TOOL:
                self.devices_tools.append(
                    MFTFirmwareTool(
                        self, device=dev,
                        pci_address=pci,
                        primary=primary
                    )
                )
            else:
                self.devices_tools.append(
                    MSTFlintFirmwareTool(
                        self, device=dev,
                        pci_address=pci,
                        primary=primary
                    )
                )

        self._log_info(
            f"Mellanox plugin setup complete. Tool={self.tool_type}, "
            f"Devices={list(device_to_pci.keys())}"
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

    def __init__(self, plugin, device, pci_address, primary):
        """
        Initialize a firmware tool instance.

        Args:
            plugin: SOSReport plugin used for running commands and logging.
            device: Device identifier, either a PCI address or a /dev/mst path.
            pci_address: PCI address, required to standardize output file
                naming when the device is an mst device.
            primary: True if this is the first detected device; ensures global
                commands are executed once per system.
        """
        self.plugin = plugin
        self.device = device
        self.primary = primary
        self.pci_address = pci_address
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

        Commands are grouped by priority:
        - 0: High-priority queries and repeated diagnostic commands.
        - 1: Medium-priority debug commands.
        - 2: Extended diagnostic, global, and optional commands
            for unsecured firmware.

        This property automatically generates the commands for the current
        device, including device-specific file names. Global commands are
        added only for the first/primary device, and additional commands
        are included if the firmware is not secured.

        Returns:
            dict: Map priority -> list of commands with 'cmd' and 'file'
        """
        if self._commands is not None:
            return self._commands

        bdf = self.pci_address.replace(":", "").replace(".", "")

        COMMANDS = [
            {
                "priority": 0,
                "cmd": f"flint -d {self.device} q full",
                "file": f"flint_{bdf}_q_full",
            },
            {  # 'mstdump' repeated intentionally for diagnostic purposes
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
                "cmd": f"resourcedump dump -d {self.device} --segment "
                       "BASIC_DEBUG",
                "file": f"resourcedump_dump_{bdf}_--segment_BASIC_DEBUG",
            },
            {
                "priority": 2,
                "cmd": f"mlxdump -d {self.device} pcie_uc --all",
                "file": f"mlxdump_{bdf}_pcie_uc_--all",
            },
            {
                "priority": 2,
                "cmd": f"mlxconfig -d {self.device} -e q",
                "file": f"mlxconfig_{bdf}_-e_q",
            },
            {
                "priority": 2,
                "cmd": f"mlxreg -d {self.device} --reg_name ROCE_ACCL --get",
                "file": f"mlxreg_{bdf}_--reg_name_ROCE_ACCL_--get",
            },
        ]

        # Global commands should only run once (on the first/primary device)
        if self.primary:
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

        # Add additional commands only if firmware is not secure
        if not self.is_secured_fw():
            COMMANDS.extend([
                {
                    "priority": 2,
                    "cmd": f"flint -d {self.device} dc",
                    "file": f"flint_{bdf}_dc",
                },
            ])

        self._commands = {}

        for entry in COMMANDS:
            self._commands.setdefault(entry["priority"], []).append(
                {
                    "cmd": entry["cmd"],
                    "file": entry["file"],
                }
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

        Commands are grouped by priority:
        - 0: High-priority queries and repeated diagnostic commands.
        - 1: Medium-priority debug commands.
        - 2: Extended diagnostic, global, and optional commands
            for unsecured firmware.

        This property automatically generates the commands for the current
        device, including device-specific file names. Global commands are
        added only for the first/primary device, and additional commands
        are included if the firmware is not secured.

        Returns:
            dict: Map priority -> list of commands with 'cmd' and 'file'
        """
        if self._commands is not None:
            return self._commands

        bdf = self.pci_address.replace(":", "").replace(".", "")

        COMMANDS = [
            {
                "priority": 0,
                "cmd": f"mstflint -d {self.device} q full",
                "file": f"mstflint_{bdf}_q_full",
            },
            {  # 'mstregdump' repeated intentionally for diagnostic purposes
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
                "cmd": f"mstresourcedump dump -d {self.device} --segment "
                       "BASIC_DEBUG",
                "file": f"mstresourcedump_dump_{bdf}_--segment_BASIC_DEBUG",
            },
            {
                "priority": 2,
                "cmd": f"mstconfig -d {self.device} -e q",
                "file": f"mstconfig_{bdf}_-e_q",
            },
            {
                "priority": 2,
                "cmd": f"mstreg -d {self.device} --reg_name ROCE_ACCL --get",
                "file": f"mstreg_{bdf}_--reg_name_ROCE_ACCL_--get",
            },
        ]

        # Global commands should only run once (on the first/primary device)
        if self.primary:
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

        # Add additional commands only if firmware is not secure
        if not self.is_secured_fw():
            COMMANDS.extend([
                {
                    "priority": 2,
                    "cmd": f"mstflint -d {self.device} dc",
                    "file": f"mstflint_{bdf}_dc",
                },
            ])

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
