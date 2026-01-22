import os
import re

from .base_collector import Collector
from ..tools import (
    MftTools,
    MstFlintTools,
    get_tool,
)


class CableCollector(Collector):
    @staticmethod
    def __generate_archive_file_path(plugin, file_name):
        return os.path.join(
            plugin.archive.get_archive_path(),
            plugin._make_command_filename(exe=file_name)
        )

    def _collect_pcie_link_details(self, plugin, tool, file_base, ctx):
        rc, output = tool.show_links_pcie(
            filename=f"{file_base}--show_links_--port_type_PCIE"
        )

        if rc != 0 or not output:
            plugin._log_info(
                f"Skipping PCIe link details for {ctx.device} (rc={rc})"
            )
            return

        pattern = re.compile(
            r":\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)",
            re.IGNORECASE,
        )

        for line in output.splitlines():
            match = pattern.search(line.strip())

            if not match:
                continue

            depth, pcie_index, node = (int(m) for m in match.groups())

            tool.show_links_pcie_details(
                depth=depth,
                pcie_index=pcie_index,
                node=node,
                filename=(
                    f"{file_base}--show_links_--port_type_PCIE_"
                    f"depth_{depth}_pcie_index_{pcie_index}_node_{node}_-c_-e"
                )
            )

    def _collect_link_data(self, plugin, tool, prefix, ctx):
        file_base = f"{prefix}_{ctx.bdf}_"

        tool.show_module(
            filename=f"{file_base}--show_module"
        )

        tool.cable_dump(
            filename=f"{file_base}--cable_--dump"
        )

        tool.cable_ddm(
            filename=f"{file_base}--cable_--ddm"
        )

        tool.show_counters(
            filename=f"{file_base}--show_counters"
        )

        tool.show_eye(
            filename=f"{file_base}--show_eye"
        )

        tool.show_fec(
            filename=f"{file_base}--show_fec"
        )

        tool.show_serdes_tx(
            filename=f"{file_base}--show_serdes_tx"
        )

        tool.show_rx_fec_histogram(
            filename=f"{file_base}--rx_fec_histogram_--show_histogram"
        )

        if ctx.primary:
            self._collect_pcie_link_details(plugin, tool, file_base, ctx)

            amber_file_name = f"{file_base}--amber_collect"
            amber_csv_path = self.__generate_archive_file_path(
                plugin,
                file_name=f"{amber_file_name}.csv"
            )

            tool.amber_collect(
                path=amber_csv_path, filename=amber_file_name
            )

            amber_pci_file_name = f"{file_base}--amber_collect_--pci"
            amber_pci_csv_path = self.__generate_archive_file_path(
                plugin,
                file_name=f"{amber_pci_file_name}.csv"
            )

            tool.amber_collect_pcie(
                path=amber_pci_csv_path,
                filename=amber_pci_file_name
            )

    def _collect_with_mft(self, plugin, ctx):
        mlxlink_tool = get_tool(MftTools.MLXLINK, plugin, ctx)
        self._collect_link_data(plugin, mlxlink_tool, "mlxlink", ctx)

    def _collect_with_mstflint(self, plugin, ctx):
        mstlink_tool = get_tool(MstFlintTools.MSTLINK, plugin, ctx)
        self._collect_link_data(plugin, mstlink_tool, "mstlink", ctx)
