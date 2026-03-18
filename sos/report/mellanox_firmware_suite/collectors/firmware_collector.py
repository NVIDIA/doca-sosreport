import os
from .base_collector import Collector
from ..tools import (
    MftTools,
    MstFlintTools,
    FirmwareTools,
    get_tool,
)


class FirmwareCollector(Collector):
    def run(self, plugin, ctx):
        if not ctx.primary:
            return

        super().run(plugin, ctx)

    def _collect_with_mft(self, plugin, ctx):
        flint_tool = get_tool(MftTools.FLINT, plugin, ctx)

        flint_tool.flint_query_full(
            filename=f"flint_{ctx.bdf}_q_full"
        )

        self._collect_device_dumps(plugin, ctx)

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
        mstresourcedump = get_tool(MstFlintTools.MSTRESOURCEDUMP, plugin, ctx)

        mstflint_tool.mstflint_query_full(
            filename=f"mstflint_{ctx.bdf}_q_full"
        )

        self._collect_device_dumps(plugin, ctx)

        if not mstflint_tool.is_secured_fw:
            mstflint_tool.mstflint_dump_config(
                filename=f"mstflint_{ctx.bdf}_dc"
            )

        mstresourcedump.mstresourcedump_basic_debug(
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

    def _collect_device_dumps(self, plugin, ctx):
        """
        Collect three dump iterations, preferring resourcedump
        over the legacy mstdump/mstregdump fallback.

        When fwctl is available, probes with a single resourcedump run.
        If the probe succeeds, the remaining two runs use resourcedump;

        If it fails, the probe's output file is cleaned up and
        all three runs use the legacy tool instead.

        MFT:      resourcedump crspace → fallback mstdump
        MSTFlint: mstresourcedump crspace → fallback mstregdump
        """

        if ctx.provider == FirmwareTools.MFT_TOOL:
            resourcedump_tool = get_tool(MftTools.RESOURCEDUMP, plugin, ctx)
            fallback_tool = get_tool(MftTools.MSTDUMP, plugin, ctx)
            resourcedump_fn = resourcedump_tool.resourcedump_crspace_map
            fallback_fn = fallback_tool.mstdump_run
            resourcedump_prefix = "resourcedump_crspace_map"
            fallback_prefix = "mstdump"

        else:
            resourcedump_tool = get_tool(
                MstFlintTools.MSTRESOURCEDUMP, plugin, ctx
            )
            fallback_tool = get_tool(
                MstFlintTools.MSTREGDUMP, plugin, ctx
            )
            resourcedump_fn = resourcedump_tool.mstresourcedump_crspace_map
            fallback_fn = fallback_tool.mstregdump_run
            resourcedump_prefix = "mstresourcedump_crspace_map"
            fallback_prefix = "mstregdump"

        collect_with_resourcedump = ctx.fwctl is not None

        if collect_with_resourcedump:
            file_name = f"{resourcedump_prefix}_{ctx.bdf}_run_1"
            file_path = self._generate_archive_file_path(plugin, file_name)

            rc, _ = resourcedump_fn(idx=1, filename=file_name)

            if rc != 0:
                collect_with_resourcedump = False

                if os.path.exists(file_path):
                    os.remove(file_path)

        if collect_with_resourcedump:
            for idx in range(2, 4):
                resourcedump_fn(
                    idx=idx,
                    filename=f"{resourcedump_prefix}_{ctx.bdf}_run_{idx}"
                )

        else:
            for idx in range(1, 4):
                fallback_fn(
                    idx,
                    filename=f"{fallback_prefix}_{ctx.bdf}_run_{idx}"
                )
