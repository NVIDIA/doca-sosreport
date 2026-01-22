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
from sos.report.mellanox_firmware_suite.tools import FirmwareTools
from sos.report.mellanox_firmware_suite.device_context import DeviceContext
from sos.report.mellanox_firmware_suite.collectors.collector_manager import (
    CollectorManager
)


class MellanoxFirmware(Plugin, IndependentPlugin):
    """
    SOSReport plugin for gathering Mellanox firmware information
    using either MFT (flint) or MSTFlint utilities.
    """

    # Estimate: ~3 minutes per device × 9 devices (largest known system)
    plugin_timeout = 1650
    plugin_name = "mellanox_firmware"
    short_desc = "Nvidia (Mellanox) firmware tools output"

    MLNX_STRING = "Mellanox Technologies"
    PCI_VENDOR_CMD = "lspci -D -d 15b3:"

    packages = ("mst", "mstflint")
    profiles = ("hardware", "system")

    def __init__(self, commons):
        super().__init__(commons=commons)

        self.tool_type = None
        self.device_contexts = []

    def detect_tool(self):
        if shutil.which("flint"):
            return FirmwareTools.MFT_TOOL

        if shutil.which("mstflint"):
            return FirmwareTools.MSTFLINT_TOOL

        return None

    def check_enabled(self):
        try:
            lspci = self.exec_cmd(self.PCI_VENDOR_CMD)

            return (
                lspci.get("status") == 0 and
                self.MLNX_STRING in lspci.get("output", "")
            )

        except Exception:
            return False

    @property
    def timeout(self):
        base_timeout = super().timeout
        device_count = len([d for d in self.device_contexts if d.primary])
        expected_timeout = device_count * 180  # ~3 min per device

        if base_timeout < expected_timeout:
            self._log_warn(
                f"Plugin timeout {base_timeout}s may be too low for "
                f"{device_count} device(s). Expected ~{expected_timeout}s "
                f"(~3 minutes per device)."
            )

        return base_timeout

    def _list_mellanox_pci(self):
        """
        Return (pci_addr, is_primary) tuples detected via lspci.

        The first function per physical device (matched by BDF prefix) is
        marked as primary to reduce duplicate device-level work.
        """
        devices = []
        seen_prefixes = set()
        pci_addr_regex = re.compile(
            r"^[\da-fA-F]{1,4}:[\da-fA-F]{1,2}:[\da-fA-F]{1,2}\.[0-7]$"
        )

        result = self.exec_cmd(self.PCI_VENDOR_CMD)

        if result.get("status") != 0:
            self._log_warn(
                "Failed to list Mellanox devices; skipping plugin."
            )
            return []

        for line in sorted(result.get("output", "").splitlines()):
            fields = line.split()

            if not fields or "bridge" in line or "DMA" in line:
                continue

            pci_addr = fields[0]

            if not pci_addr_regex.match(pci_addr):
                continue

            prefix = pci_addr.rsplit(":", 1)[0]
            devices.append((pci_addr, prefix not in seen_prefixes))
            seen_prefixes.add(prefix)

        return devices

    def _map_mst_nodes(self, pci_devices):
        """
        Map mst device nodes to PCI addresses, if mst status is available.
        """
        if not pci_devices:
            return []

        result = self.exec_cmd("mst status -v")

        if result.get("status") != 0:
            self._log_warn(
                "mst status failed; falling back to PCI addresses."
            )
            return []

        devices_info = []

        for line in sorted(result.get("output", "").splitlines()):
            parts = line.split()

            if len(parts) < 3:
                continue

            for pci_addr, is_primary in pci_devices:
                if parts[2] in pci_addr:
                    devices_info.append((parts[1], pci_addr, is_primary))
                    break

        return devices_info

    def detect_devices(self):
        pci_devices = self._list_mellanox_pci()

        if not pci_devices:
            return []

        if self.tool_type == FirmwareTools.MFT_TOOL:
            mst_devices = self._map_mst_nodes(pci_devices)

            if mst_devices:
                return mst_devices

        return [
            (pci_addr, pci_addr, is_primary)
            for pci_addr, is_primary in pci_devices
        ]

    def setup(self):
        self.tool_type = self.detect_tool()

        if not self.tool_type:
            self._log_warn("No Mellanox tool found. Skipping plugin.")
            return

        devices_info = self.detect_devices()

        if not devices_info:
            self._log_warn("No Mellanox devices found. Skipping plugin.")
            return

        self.device_contexts = []

        for idx, (dev, pci, primary) in enumerate(devices_info):
            global_collector = idx == 0

            self.device_contexts.append(DeviceContext(
                device=dev,
                pci=pci,
                primary=primary,
                global_collector=global_collector,
                provider=self.tool_type
            ))

        self._log_info(
            f"Mellanox plugin setup complete. Tool={self.tool_type}, "
            f"Devices={[ctx.device for ctx in self.device_contexts]}"
        )

    def collect(self):
        CollectorManager(self, self.device_contexts).collect_all()
