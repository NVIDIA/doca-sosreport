from ..base_tool import BaseTool, supports_fwctl


class MlxregTool(BaseTool):
    @supports_fwctl
    def mlxreg_roce_accl_query(self, filename=None):
        return self.execute_cmd(
            f"mlxreg -d {self.ctx.effective_device} --reg_name ROCE_ACCL "
            "--get",
            filename=filename
        )

    def ppcc_get(self, op, indexes, filename=None, subdir=None):
        op_str = ",".join(f"{k}={v}" for k, v in op.items())
        return self.execute_cmd(
            f'mlxreg -d {self.ctx.device} --reg_name PPCC --get '
            f'--op "{op_str}" --indexes "{indexes}"',
            filename=filename,
            subdir=subdir,
        )
