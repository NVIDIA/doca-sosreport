from ..base_tool import BaseTool


class MgetTempTool(BaseTool):
    def mget_temp(self, filename=None):
        return self.execute_cmd(
            f"mget_temp -d {self.ctx.device}",
            filename=filename
        )
