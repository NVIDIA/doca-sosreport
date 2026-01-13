from ..base_tool import BaseTool


class MlxregTool(BaseTool):
    def mlxreg_roce_accl_query(self, filename=None):
        return self.execute_cmd(
            f"mlxreg -d {self.ctx.device} --reg_name ROCE_ACCL --get",
            filename=filename
        )
