from ..base_tool import BaseTool, supports_fwctl


class MstmgetTempTool(BaseTool):
    @supports_fwctl
    def mstmget_temp(self, filename=None):
        return self.execute_cmd(
            f"mstmget_temp -d {self.ctx.effective_device}",
            filename=filename
        )
