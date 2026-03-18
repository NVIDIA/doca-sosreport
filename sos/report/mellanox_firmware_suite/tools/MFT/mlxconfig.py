from ..base_tool import BaseTool, supports_fwctl


class MlxconfigTool(BaseTool):
    @supports_fwctl
    def mlxconfig_query(self, filename=None):
        return self.execute_cmd(
            f"mlxconfig -d {self.ctx.effective_device} -e q",
            filename=filename
        )
