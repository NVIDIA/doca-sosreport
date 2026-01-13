from .base_collector import Collector
from ..tools import (
    MftTools,
    MstFlintTools,
    get_tool,
)


class SystemCollector(Collector):
    def run(self, plugin, ctx):
        if not ctx.global_collector:
            return

        super().run(plugin, ctx)

    def _collect_with_mft(self, plugin, ctx):
        get_tool(MftTools.FLINT, plugin, ctx).flint_version(
            filename="flint_--version"
        )

        get_tool(MftTools.MST, plugin, ctx).mst_status_verbose(
            filename="mst_status_-v"
        )

    def _collect_with_mstflint(self, plugin, ctx):
        get_tool(MstFlintTools.MSTFLINT, plugin, ctx).mstflint_version(
            filename="mstflint_--version"
        )

        device_info_tool = get_tool(MstFlintTools.DEVICES_INFO, plugin, ctx)

        device_info_tool.mstdevices_info_verbose(
            filename="mstdevices_info_-v"
        )
