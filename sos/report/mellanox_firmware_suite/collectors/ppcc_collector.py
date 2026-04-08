import re
from enum import Enum
from typing import Dict, List, Optional, Tuple

from .base_collector import Collector
from ..tools import (
    MftTools,
    MstFlintTools,
    get_tool,
)

# mlxreg/mstreg --op uses string cmd_type values from the PPCC PRM.
PpccCommandOptions = Dict[str, str]


class PpccCommand(str, Enum):
    GET_ALGO_STATUS = "0x3"
    GET_NUM_PARAMS = "0x4"
    GET_PARAM_INFO = "0x5"
    GET_PARAM = "0x6"
    BULK_GET_PARAMS = "0xA"
    BULK_GET_COUNTERS = "0xC"
    GET_NUM_COUNTERS = "0xE"
    GET_COUNTER_INFO = "0xF"
    ALGO_INFO_ARRAY = "0x10"


class PPCCCollector(Collector):
    _BASE_REGISTER_INDEXES = "local_port=1,pnat=0,lp_msb=0"
    _ALGO_SLOT_TEXT_INDEX_COUNT = 16
    _COMMAND_OUTPUT_LOG_MAX_CHARS = 4000

    _TEXT_TABLE_LINE_PATTERN = re.compile(
        r"^\s*text\[(\d+)\]\s*\|\s*0x([0-9a-fA-F]+)",
        re.MULTILINE | re.IGNORECASE,
    )
    _VALUE_FIELD_PATTERN = re.compile(
        r"^\s*value\s*\|\s*0x([0-9a-fA-F]+)",
        re.MULTILINE | re.IGNORECASE,
    )

    @staticmethod
    def _op_for_cmd_type(command: PpccCommand) -> PpccCommandOptions:
        return {"cmd_type": command.value}

    @staticmethod
    def _register_indexes_for_algo_slot(algo_slot_index: int) -> str:
        return (
            f"{PPCCCollector._BASE_REGISTER_INDEXES},"
            f"algo_slot={algo_slot_index}"
        )

    @staticmethod
    def _make_filename_for_ppcc_get(
        collection_file_prefix: str,
        command_options: PpccCommandOptions,
        register_indexes: str,
    ) -> str:
        op_part = "_".join(
            f"{key}_{value}" for key, value in command_options.items()
        )
        index_part = register_indexes.replace("=", "_").replace(",", "_")
        return (
            f"{collection_file_prefix}--reg_name_PPCC_--get_"
            f"--op_{op_part}_--indexes_{index_part}"
        )

    @classmethod
    def _get_algo_slot_indices(cls, mlxreg_output: str) -> List[int]:
        slot_count = cls._ALGO_SLOT_TEXT_INDEX_COUNT
        values_per_slot = [0] * slot_count
        for match in cls._TEXT_TABLE_LINE_PATTERN.finditer(mlxreg_output):
            text_index = int(match.group(1))
            if text_index >= slot_count:
                continue
            values_per_slot[text_index] = int(match.group(2), 16)
        return [
            text_index
            for text_index, value in enumerate(values_per_slot)
            if value != 0
        ]

    @classmethod
    def _extract_value_field(cls, mlxreg_output: str) -> Optional[int]:
        match = cls._VALUE_FIELD_PATTERN.search(mlxreg_output)
        if not match:
            return None
        return int(match.group(1), 16)

    @classmethod
    def _clip_command_output(cls, text: str) -> str:
        raw = (text or "").strip()
        if not raw:
            return "(empty)"
        limit = cls._COMMAND_OUTPUT_LOG_MAX_CHARS
        if len(raw) <= limit:
            return raw
        return raw[:limit]

    def _ppcc_get(
        self,
        plugin,
        device_label: str,
        tool,
        collection_file_prefix: str,
        output_subdir: str,
        command_options: PpccCommandOptions,
        register_indexes: str,
    ) -> Tuple[int, str]:
        return_code, output = tool.ppcc_get(
            command_options,
            register_indexes,
            filename=self._make_filename_for_ppcc_get(
                collection_file_prefix,
                command_options,
                register_indexes,
            ),
            subdir=output_subdir,
        )
        if return_code != 0:
            op = command_options.get("cmd_type", "?")
            plugin._log_info(
                "PPCC command failed "
                f"device={device_label} cmd_type={op} "
                f"indexes={register_indexes!r} rc={return_code} "
                f"output:\n{self._clip_command_output(output)}"
            )
        return return_code, output

    def _collect_counters_for_algo_slot(
        self,
        plugin,
        tool,
        collection_file_prefix: str,
        output_subdir: str,
        ctx,
        algo_slot_index: int,
        register_indexes: str,
    ) -> None:
        device_label = ctx.device

        return_code, output = self._ppcc_get(
            plugin,
            device_label,
            tool,
            collection_file_prefix,
            output_subdir,
            self._op_for_cmd_type(PpccCommand.GET_NUM_COUNTERS),
            register_indexes,
        )
        if return_code != 0:
            return

        counter_count = self._extract_value_field(output)
        if counter_count is None:
            return

        counter_info_op = self._op_for_cmd_type(
            PpccCommand.GET_COUNTER_INFO
        )
        for counter_index in range(counter_count):
            counter_indexes = (
                f"{register_indexes},algo_counter_index={counter_index}"
            )
            self._ppcc_get(
                plugin,
                device_label,
                tool,
                collection_file_prefix,
                output_subdir,
                counter_info_op,
                counter_indexes,
            )

        if counter_count == 0:
            return

        self._ppcc_get(
            plugin,
            device_label,
            tool,
            collection_file_prefix,
            output_subdir,
            self._op_for_cmd_type(PpccCommand.BULK_GET_COUNTERS),
            register_indexes,
        )

    def _collect_params_for_algo_slot(
        self,
        plugin,
        tool,
        collection_file_prefix: str,
        output_subdir: str,
        ctx,
        algo_slot_index: int,
        register_indexes: str,
    ) -> None:
        device_label = ctx.device

        return_code, output = self._ppcc_get(
            plugin,
            device_label,
            tool,
            collection_file_prefix,
            output_subdir,
            self._op_for_cmd_type(PpccCommand.GET_NUM_PARAMS),
            register_indexes,
        )
        if return_code != 0:
            return

        param_count = self._extract_value_field(output)
        if param_count is None:
            return

        param_info_op = self._op_for_cmd_type(
            PpccCommand.GET_PARAM_INFO
        )
        for param_index in range(param_count):
            param_indexes = (
                f"{register_indexes},algo_param_index={param_index}"
            )
            self._ppcc_get(
                plugin,
                device_label,
                tool,
                collection_file_prefix,
                output_subdir,
                param_info_op,
                param_indexes,
            )

        if param_count == 0:
            return

        return_code, _ = self._ppcc_get(
            plugin,
            device_label,
            tool,
            collection_file_prefix,
            output_subdir,
            self._op_for_cmd_type(PpccCommand.BULK_GET_PARAMS),
            register_indexes,
        )

        if return_code == 0:
            return

        get_param_op = self._op_for_cmd_type(PpccCommand.GET_PARAM)
        for param_index in range(param_count):
            param_indexes = (
                f"{register_indexes},algo_param_index={param_index}"
            )
            self._ppcc_get(
                plugin,
                device_label,
                tool,
                collection_file_prefix,
                output_subdir,
                get_param_op,
                param_indexes,
            )

    def _collect_single_algo_slot(
        self,
        plugin,
        tool,
        collection_file_prefix: str,
        output_subdir: str,
        ctx,
        algo_slot_index: int,
    ) -> None:
        register_indexes = self._register_indexes_for_algo_slot(
            algo_slot_index
        )
        device_label = ctx.device

        return_code, output = self._ppcc_get(
            plugin,
            device_label,
            tool,
            collection_file_prefix,
            output_subdir,
            self._op_for_cmd_type(PpccCommand.GET_ALGO_STATUS),
            register_indexes,
        )
        if return_code != 0:
            return

        algo_status = self._extract_value_field(output)
        if algo_status is not None and algo_status != 1:
            return

        self._collect_counters_for_algo_slot(
            plugin,
            tool,
            collection_file_prefix,
            output_subdir,
            ctx,
            algo_slot_index,
            register_indexes,
        )
        self._collect_params_for_algo_slot(
            plugin,
            tool,
            collection_file_prefix,
            output_subdir,
            ctx,
            algo_slot_index,
            register_indexes,
        )

    def _collect_ppcc_data(self, plugin, tool, tool_name: str, ctx) -> None:
        collection_file_prefix = f"{tool_name}_{ctx.bdf}_"
        output_subdir = f"{tool_name}_pcc"
        device_label = ctx.device

        return_code, output = self._ppcc_get(
            plugin,
            device_label,
            tool,
            collection_file_prefix,
            output_subdir,
            self._op_for_cmd_type(PpccCommand.ALGO_INFO_ARRAY),
            self._BASE_REGISTER_INDEXES,
        )
        if return_code != 0:
            return

        present_algo_slots = self._get_algo_slot_indices(output)
        if not present_algo_slots:
            return

        for algo_slot_index in present_algo_slots:
            self._collect_single_algo_slot(
                plugin,
                tool,
                collection_file_prefix,
                output_subdir,
                ctx,
                algo_slot_index,
            )

    def _collect_with_mft(self, plugin, ctx):
        mlxreg_tool = get_tool(MftTools.MLXREG, plugin, ctx)
        self._collect_ppcc_data(plugin, mlxreg_tool, "mlxreg", ctx)

    def _collect_with_mstflint(self, plugin, ctx):
        mstreg_tool = get_tool(MstFlintTools.MSTREG, plugin, ctx)
        self._collect_ppcc_data(plugin, mstreg_tool, "mstreg", ctx)
