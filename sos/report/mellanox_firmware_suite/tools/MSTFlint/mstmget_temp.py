from ..base_tool import BaseTool


class MstmgetTempTool(BaseTool):
    def mstmget_temp(self, filename=None):
        return self.execute_cmd(
            f"mstmget_temp -d {self.ctx.device}",
            filename=filename
        )
