import re
from enum import Enum

from .base_collector import Collector
from ..tools import (
    MftTools,
    MstFlintTools,
    get_tool,
)


class PpccCommand(str, Enum):
    """
    Values passed as ``--op cmd_type`` to the PPCC register.
    """

    GET_ALGO_INFO = "0x0"
    GET_ALGO_STATUS = "0x3"
    GET_NUM_PARAMS = "0x4"
    GET_PARAM_INFO = "0x5"
    GET_PARAM = "0x6"
    BULK_GET_PARAMS = "0xA"
    BULK_GET_COUNTERS = "0xC"
    GET_NUM_COUNTERS = "0xE"
    GET_COUNTER_INFO = "0xF"
    ALGO_INFO_ARRAY = "0x10"


class PccCollector(Collector):
    _BASE_REGISTER_INDEXES = "local_port=1,pnat=0,lp_msb=0"

    # Number of text[] entries ALGO_INFO_ARRAY reports slot presence in.
    _ALGO_SLOT_TEXT_INDEX_COUNT = 16

    # Slots queried for GET_ALGO_STATUS only, whether or not the
    # ALGO_INFO_ARRAY read reports them as present. No algorithm info,
    # parameters or counters are collected for them.
    _STATUS_ONLY_ALGO_SLOTS = frozenset({15})

    _TEXT_TABLE_LINE_PATTERN = re.compile(
        r"^\s*text\[(\d+)\]\s*\|\s*0x([0-9a-fA-F]+)",
        re.MULTILINE | re.IGNORECASE,
    )
    _VALUE_FIELD_PATTERN = re.compile(
        r"^\s*value\s*\|\s*0x([0-9a-fA-F]+)",
        re.MULTILINE | re.IGNORECASE,
    )
    _COUNTER_EN_FIELD_PATTERN = re.compile(
        r"^\s*counter_en\s*\|\s*0x([0-9a-fA-F]+)",
        re.MULTILINE | re.IGNORECASE,
    )
    _TOOL_ERROR_LINE_PATTERN = re.compile(r"^\s*-E-\s*(.+)$", re.MULTILINE)

    @staticmethod
    def _op_for_cmd_type(command):
        return {"cmd_type": command.value}

    @staticmethod
    def _register_indexes_for_algo_slot(algo_slot_index):
        return (
            f"{PccCollector._BASE_REGISTER_INDEXES},"
            f"algo_slot={algo_slot_index}"
        )

    @staticmethod
    def _make_filename_for_ppcc_get(
        collection_file_prefix,
        command_options,
        register_indexes,
    ):
        op_part = "_".join(
            f"{key}_{value}" for key, value in command_options.items()
        )
        index_part = register_indexes.replace("=", "_").replace(",", "_")

        return (
            f"{collection_file_prefix}--reg_name_PPCC_--get_"
            f"--op_{op_part}_--indexes_{index_part}"
        )

    @classmethod
    def _get_algo_slot_indices(cls, mlxreg_output):
        """
        Algorithm slots reported as present by ALGO_INFO_ARRAY.

        A slot is present when its text[] entry holds a non-zero value.
        """

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
    def _extract_hex_field(cls, pattern, mlxreg_output):
        match = pattern.search(mlxreg_output)

        if not match:
            return None

        return int(match.group(1), 16)

    @classmethod
    def _counter_en_enabled(cls, mlxreg_output):
        """
        Whether the counter_en LSB is set, or None if the field is absent.
        """

        value = cls._extract_hex_field(
            cls._COUNTER_EN_FIELD_PATTERN,
            mlxreg_output,
        )

        if value is None:
            return None

        return (value & 1) != 0

    @classmethod
    def _tool_error_reason(cls, output):
        """
        The tool's ``-E-`` line, used to report why PPCC is unavailable.
        """

        match = cls._TOOL_ERROR_LINE_PATTERN.search(output or "")

        if not match:
            return "no error reported"

        return match.group(1).strip()

    def _ppcc_get(
        self,
        tool,
        collection_file_prefix,
        output_subdir,
        command,
        register_indexes,
    ):
        """
        Run one PPCC read and store its output in the report.

        Failures are not logged here: the tool layer already logs the
        command and return code, and the output is kept in the report.
        """

        command_options = self._op_for_cmd_type(command)
        filename = self._make_filename_for_ppcc_get(
            collection_file_prefix,
            command_options,
            register_indexes,
        )

        return tool.ppcc_get(
            command_options,
            register_indexes,
            filename=filename,
            subdir=output_subdir,
        )

    def _ppcc_get_for_each_algo_param(
        self,
        tool,
        collection_file_prefix,
        output_subdir,
        command,
        register_indexes,
        algo_param_count,
    ):
        for algo_param_index in range(algo_param_count):
            param_indexes = (
                f"{register_indexes},algo_param_index={algo_param_index}"
            )
            self._ppcc_get(
                tool,
                collection_file_prefix,
                output_subdir,
                command,
                param_indexes,
            )

    def _count_from_command(
        self,
        tool,
        collection_file_prefix,
        output_subdir,
        command,
        register_indexes,
    ):
        """
        Run a PPCC command that reports a count in its ``value`` field.

        Returns None when the command failed or the field is absent.
        """

        return_code, output = self._ppcc_get(
            tool,
            collection_file_prefix,
            output_subdir,
            command,
            register_indexes,
        )

        if return_code != 0:
            return None

        return self._extract_hex_field(self._VALUE_FIELD_PATTERN, output)

    def _collect_params_individually(
        self,
        tool,
        collection_file_prefix,
        output_subdir,
        register_indexes,
        param_count,
    ):
        """
        Fallback for firmware that rejects BULK_GET_PARAMS.

        Issues GET_PARAM once per parameter index instead.
        """

        self._ppcc_get_for_each_algo_param(
            tool,
            collection_file_prefix,
            output_subdir,
            PpccCommand.GET_PARAM,
            register_indexes,
            param_count,
        )

    def _collect_counters_for_algo_slot(
        self,
        tool,
        collection_file_prefix,
        output_subdir,
        register_indexes,
    ):
        counter_count = self._count_from_command(
            tool,
            collection_file_prefix,
            output_subdir,
            PpccCommand.GET_NUM_COUNTERS,
            register_indexes,
        )

        if counter_count is None:
            return

        self._ppcc_get_for_each_algo_param(
            tool,
            collection_file_prefix,
            output_subdir,
            PpccCommand.GET_COUNTER_INFO,
            register_indexes,
            counter_count,
        )

        if counter_count == 0:
            return

        self._ppcc_get(
            tool,
            collection_file_prefix,
            output_subdir,
            PpccCommand.BULK_GET_COUNTERS,
            register_indexes,
        )

    def _collect_params_for_algo_slot(
        self,
        tool,
        collection_file_prefix,
        output_subdir,
        register_indexes,
    ):
        param_count = self._count_from_command(
            tool,
            collection_file_prefix,
            output_subdir,
            PpccCommand.GET_NUM_PARAMS,
            register_indexes,
        )

        if param_count is None:
            return

        self._ppcc_get_for_each_algo_param(
            tool,
            collection_file_prefix,
            output_subdir,
            PpccCommand.GET_PARAM_INFO,
            register_indexes,
            param_count,
        )

        if param_count == 0:
            return

        return_code, _ = self._ppcc_get(
            tool,
            collection_file_prefix,
            output_subdir,
            PpccCommand.BULK_GET_PARAMS,
            register_indexes,
        )

        if return_code != 0:
            self._collect_params_individually(
                tool,
                collection_file_prefix,
                output_subdir,
                register_indexes,
                param_count,
            )

    def _collect_status_only_algo_slot(
        self,
        tool,
        collection_file_prefix,
        output_subdir,
        register_indexes,
    ):
        self._ppcc_get(
            tool,
            collection_file_prefix,
            output_subdir,
            PpccCommand.GET_ALGO_STATUS,
            register_indexes,
        )

    def _collect_single_algo_slot(
        self,
        tool,
        collection_file_prefix,
        output_subdir,
        algo_slot_index,
    ):
        """
        Collect algorithm info, parameters and counters for one slot.

        Slots whose GET_ALGO_STATUS value is not 1 are inactive and are
        skipped. Counters are collected only when counter_en is set.
        """

        register_indexes = self._register_indexes_for_algo_slot(
            algo_slot_index
        )

        if algo_slot_index in self._STATUS_ONLY_ALGO_SLOTS:
            self._collect_status_only_algo_slot(
                tool,
                collection_file_prefix,
                output_subdir,
                register_indexes,
            )

            return

        self._ppcc_get(
            tool,
            collection_file_prefix,
            output_subdir,
            PpccCommand.GET_ALGO_INFO,
            register_indexes,
        )

        return_code, output = self._ppcc_get(
            tool,
            collection_file_prefix,
            output_subdir,
            PpccCommand.GET_ALGO_STATUS,
            register_indexes,
        )

        if return_code != 0:
            return

        algo_status = self._extract_hex_field(
            self._VALUE_FIELD_PATTERN,
            output,
        )

        if algo_status is not None and algo_status != 1:
            return

        counter_en_on = self._counter_en_enabled(output)

        if counter_en_on:
            self._collect_counters_for_algo_slot(
                tool,
                collection_file_prefix,
                output_subdir,
                register_indexes,
            )

        self._collect_params_for_algo_slot(
            tool,
            collection_file_prefix,
            output_subdir,
            register_indexes,
        )

    def _algo_slots_to_collect(self, mlxreg_output):
        present_slots = self._get_algo_slot_indices(mlxreg_output)

        return sorted(
            frozenset(present_slots) | self._STATUS_ONLY_ALGO_SLOTS,
        )

    def _collect_ppcc_data(self, plugin, tool, tool_name, ctx):
        """
        Collect PPCC data for every algorithm slot of one device.

        The ALGO_INFO_ARRAY read doubles as the PCC support check, so a
        failure means the device exposes no PCC data and is skipped.
        """

        collection_file_prefix = f"{tool_name}_{ctx.bdf}_"
        output_subdir = "pcc_info"
        return_code, output = self._ppcc_get(
            tool,
            collection_file_prefix,
            output_subdir,
            PpccCommand.ALGO_INFO_ARRAY,
            self._BASE_REGISTER_INDEXES,
        )

        if return_code != 0:
            plugin._log_info(
                f"Skipping PCC collection for {ctx.pci}: "
                f"{self._tool_error_reason(output)}"
            )

            return

        for algo_slot_index in self._algo_slots_to_collect(output):
            self._collect_single_algo_slot(
                tool,
                collection_file_prefix,
                output_subdir,
                algo_slot_index,
            )

    def _collect_with_mft(self, plugin, ctx):
        mlxreg_tool = get_tool(MftTools.MLXREG, plugin, ctx)
        self._collect_ppcc_data(plugin, mlxreg_tool, "mlxreg", ctx)

    def _collect_with_mstflint(self, plugin, ctx):
        mstreg_tool = get_tool(MstFlintTools.MSTREG, plugin, ctx)
        self._collect_ppcc_data(plugin, mstreg_tool, "mstreg", ctx)
