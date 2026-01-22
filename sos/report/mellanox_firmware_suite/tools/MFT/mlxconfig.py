from ..base_tool import BaseTool


class MlxconfigTool(BaseTool):
    def mlxconfig_query(self, filename=None):
        return self.execute_cmd(
            f"mlxconfig -d {self.ctx.device} -e q",
            filename=filename
        )
