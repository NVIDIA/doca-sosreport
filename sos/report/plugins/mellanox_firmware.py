# Copyright (C) 2023 Nvidia Corporation
# Author: Alin Serdean <aserdean@nvidia.com>
#
# This file is part of the sos project: https://github.com/sosreport/sos
#
# Licensed under the GNU General Public License v2.
# See the LICENSE file in the source distribution for details.

import re
import shutil

from sos.report.plugins import Plugin, IndependentPlugin, PluginOpt
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

    plugin_timeout = 1650
    plugin_name = "mellanox_firmware"
    short_desc = "Nvidia (Mellanox) firmware tools output"

    MLNX_STRING = "Mellanox Technologies"
    PCI_VENDOR_CMD = "lspci -D -d 15b3:"

    _LONG_PCI_RE = re.compile(
        r"^[\da-fA-F]{1,4}:[\da-fA-F]{1,2}:[\da-fA-F]{1,2}\.[0-7]$"
    )
    _SHORT_PCI_RE = re.compile(r"[\da-fA-F]{1,2}:[\da-fA-F]{1,2}\.[0-7]")
    _FWCTL_RE = re.compile(r"/dev/fwctl/\S+")
    _MST_RE = re.compile(r"/dev/mst/\S+")

    packages = ("mst", "mstflint")
    profiles = ("hardware", "system")

    option_list = [
        PluginOpt(
            "pcc",
            default=False,
            desc=(
                "Collect PPCC (mlxreg/mstreg) register dumps; can be slow on "
                "large systems"
            ),
        ),
    ]

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
        expected_timeout = device_count * 180

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

            pci_addr = fields[0].lower()

            if not self._LONG_PCI_RE.match(pci_addr):
                continue

            prefix = pci_addr.rsplit(":", 1)[0]
            devices.append((pci_addr, prefix not in seen_prefixes))
            seen_prefixes.add(prefix)

        return devices

    def _parse_device_table(self, output):
        """
        Parse device table from 'mst status -v' or 'mstdevices_info -v'.

        Scans each line after the column header for distinctive regex
        patterns rather than relying on fixed column positions.

        Returns dict mapping short PCI address to (mst_device, fwctl).
        Values are None when the field is not present in the line.
        """
        result = {}
        in_table = False

        for line in output.splitlines():
            if "DEVICE_TYPE" in line and "PCI" in line:
                in_table = True
                continue

            if not in_table or not line.strip():
                continue

            pci_match = self._SHORT_PCI_RE.search(line)

            if not pci_match:
                continue

            pci = pci_match.group().lower()

            mst_match = self._MST_RE.search(line)
            mst = mst_match.group() if mst_match else None

            fwctl_match = self._FWCTL_RE.search(line)
            fwctl = fwctl_match.group() if fwctl_match else None

            result[pci] = (mst, fwctl)

        return result

    def _enrich_from_mst_status(self):
        """
        Run 'mst status -v' and parse MST device / FWCTL paths.

        Works whether the MST PCI module is loaded or not -- when
        unloaded the MST column is 'NA' (parsed as None) but PCI
        and FWCTL are still present.
        """
        result = self.exec_cmd("mst status -v")

        if result.get("status") != 0:
            self._log_warn(
                "mst status failed; using lspci only."
            )
            return {}

        return self._parse_device_table(result.get("output", ""))

    def _enrich_from_mstdevices_info(self):
        """
        Run 'mstdevices_info -v' and parse FWCTL paths.

        Returns empty dict when the command is unavailable (older
        MSTFlint versions), causing detect_devices to fall back
        to lspci-only results.
        """
        result = self.exec_cmd("mstdevices_info -v")

        if result.get("status") != 0:
            self._log_info(
                "mstdevices_info failed; using lspci only."
            )
            return {}

        return self._parse_device_table(result.get("output", ""))

    def detect_devices(self):
        """
        Detect Mellanox devices and enrich with MST / FWCTL paths.

        1. lspci provides canonical PCI addresses and primary marking.
        2. 'mst status -v' or 'mstdevices_info -v' provides MST device
           names and FWCTL paths (when available).
        3. Cross-references by checking short PCI in long PCI addresses.
        """
        pci_devices = self._list_mellanox_pci()

        if not pci_devices:
            return []

        enrichment = {}

        if self.tool_type == FirmwareTools.MFT_TOOL:
            enrichment = self._enrich_from_mst_status()

        elif self.tool_type == FirmwareTools.MSTFLINT_TOOL:
            enrichment = self._enrich_from_mstdevices_info()

        results = []

        for pci_addr, is_primary in pci_devices:
            mst, fwctl = None, None

            for short_pci, (m, f) in enrichment.items():
                if pci_addr.endswith(short_pci):
                    mst, fwctl = m, f
                    break

            results.append((mst, pci_addr, fwctl, is_primary))

        return results

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

        for idx, (mst_dev, pci, fwctl, primary) in enumerate(devices_info):
            global_collector = idx == 0

            self.device_contexts.append(DeviceContext(
                pci=pci,
                primary=primary,
                global_collector=global_collector,
                provider=self.tool_type,
                mst_device=mst_dev,
                fwctl=fwctl
            ))

        self._log_info(
            f"Mellanox plugin setup complete. Tool={self.tool_type}, "
            f"Devices={[ctx.effective_device for ctx in self.device_contexts]}"
        )

    def collect(self):
        CollectorManager(self, self.device_contexts).collect_all()
