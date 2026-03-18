from ..base_tool import BaseTool, supports_fwctl


class MlxregTool(BaseTool):
    @supports_fwctl
    def mlxreg_roce_accl_query(self, filename=None):
        return self.execute_cmd(
            f"mlxreg -d {self.ctx.effective_device} --reg_name ROCE_ACCL "
            "--get",
            filename=filename
        )
