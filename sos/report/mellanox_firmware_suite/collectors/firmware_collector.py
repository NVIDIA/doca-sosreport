from .base_collector import Collector
from ..tools import (
    MftTools,
    MstFlintTools,
    get_tool,
)


class FirmwareCollector(Collector):
    def run(self, plugin, ctx):
        if not ctx.primary:
            return

        super().run(plugin, ctx)

    def _collect_with_mft(self, plugin, ctx):
        flint_tool = get_tool(MftTools.FLINT, plugin, ctx)
        mstdump_tool = get_tool(MftTools.MSTDUMP, plugin, ctx)

        flint_tool.flint_query_full(
            filename=f"flint_{ctx.bdf}_q_full"
        )

        for idx in (1, 2, 3):
            mstdump_tool.mstdump_run(
                idx,
                filename=f"mstdump_{ctx.bdf}_run_{idx}"
            )

        if not flint_tool.is_secured_fw:
            flint_tool.flint_dump_config(
                filename=f"flint_{ctx.bdf}_dc"
            )

        get_tool(MftTools.RESOURCEDUMP, plugin, ctx).resourcedump_basic_debug(
            filename=f"resourcedump_dump_{ctx.bdf}_--segment_BASIC_DEBUG"
        )

        get_tool(MftTools.MLXDUMP, plugin, ctx).mlxdump_pcie_uc_all(
            filename=f"mlxdump_{ctx.bdf}_pcie_uc_--all"
        )

        get_tool(MftTools.MLXCONFIG, plugin, ctx).mlxconfig_query(
            filename=f"mlxconfig_{ctx.bdf}_-e_q"
        )

        get_tool(MftTools.MLXREG, plugin, ctx).mlxreg_roce_accl_query(
            filename=f"mlxreg_{ctx.bdf}_--reg_name_ROCE_ACCL_--get"
        )

        get_tool(MftTools.MGET_TEMP, plugin, ctx).mget_temp(
            filename=f"mget_temp_{ctx.bdf}"
        )

    def _collect_with_mstflint(self, plugin, ctx):
        mstflint_tool = get_tool(MstFlintTools.MSTFLINT, plugin, ctx)
        mstregdump_tool = get_tool(MstFlintTools.MSTREGDUMP, plugin, ctx)

        mstflint_tool.mstflint_query_full(
            filename=f"mstflint_{ctx.bdf}_q_full"
        )

        for idx in (1, 2, 3):
            mstregdump_tool.mstregdump_run(
                idx,
                filename=f"mstregdump_{ctx.bdf}_run_{idx}"
            )

        if not mstflint_tool.is_secured_fw:
            mstflint_tool.mstflint_dump_config(
                filename=f"mstflint_{ctx.bdf}_dc"
            )

        resourcedump = get_tool(
            MstFlintTools.MSTRESOURCEDUMP,
            plugin,
            ctx
        )

        resourcedump.mstresourcedump_basic_debug(
            filename=f"mstresourcedump_dump_{ctx.bdf}_--segment_BASIC_DEBUG"
        )

        get_tool(MstFlintTools.MSTCONFIG, plugin, ctx).mstconfig_query(
            filename=f"mstconfig_{ctx.bdf}_-e_q"
        )

        get_tool(MstFlintTools.MSTREG, plugin, ctx).mstreg_roce_accl_query(
            filename=f"mstreg_{ctx.bdf}_--reg_name_ROCE_ACCL_--get"
        )

        get_tool(MstFlintTools.MSTMGET_TEMP, plugin, ctx).mstmget_temp(
            filename=f"mstmget_temp_{ctx.bdf}"
        )
