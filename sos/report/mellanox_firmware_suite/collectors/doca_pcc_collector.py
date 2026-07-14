import os
import re


class DocaPccCollector(object):
    _TOOL_PATH = "/opt/mellanox/doca/tools/pcc_counters.sh"
    _OUTPUT_SUBDIR = "pcc_info/doca_pcc_counters"

    # sw_dev_id values embedded in MST device names for supported devices:
    #   ConnectX6DX: 4125  (/dev/mst/mt4125_*)
    #   ConnectX7:   4129  (/dev/mst/mt4129_*)
    #   BlueField3:  41692 (/dev/mst/mt41692_*)
    _SUPPORTED_DEV_IDS = frozenset({"4125", "4129", "41692"})
    _MST_DEV_ID_RE = re.compile(r"/dev/mst/mt(\d+)_")

    def _is_supported_device(self, mst_device):
        match = self._MST_DEV_ID_RE.search(mst_device)
        return match is not None and match.group(1) in self._SUPPORTED_DEV_IDS

    def run(self, plugin, ctx):
        if not ctx.primary:
            return

        if ctx.mst_device is None:
            plugin._log_info(
                f"doca_pcc: skipping {ctx.pci} — no MST device path available"
            )
            return

        if not self._is_supported_device(ctx.mst_device):
            plugin._log_info(
                f"doca_pcc: skipping {ctx.pci} — "
                f"{ctx.mst_device!r} is not a supported device"
            )
            return

        if not os.path.isfile(self._TOOL_PATH):
            plugin._log_info(
                f"doca_pcc: {self._TOOL_PATH} not found; skipping collection"
            )
            return

        self._collect(plugin, ctx)

    def _collect(self, plugin, ctx):
        mst_dev = ctx.mst_device

        result = plugin.exec_cmd(cmd=f"{self._TOOL_PATH} set {mst_dev}")
        rc = result.get("status", 1)

        if rc != 0:
            plugin._log_info(
                f"doca_pcc: setting counters failed for {mst_dev} (rc={rc}); "
                "skipping query"
            )
            return

        filename = f"pcc_counters_{ctx.bdf}_query"

        plugin._collect_cmd_output(
            cmd=f"{self._TOOL_PATH} query {mst_dev}",
            suggest_filename=filename,
            subdir=self._OUTPUT_SUBDIR,
            stderr=True,
        )
