from ..base_tool import BaseTool


class MstconfigTool(BaseTool):
    def mstconfig_query(self, filename=None):
        return self.execute_cmd(
            f"mstconfig -d {self.ctx.device} -e q",
            filename=filename
        )
