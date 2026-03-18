from ..base_tool import BaseTool, supports_fwctl


class MgetTempTool(BaseTool):
    @supports_fwctl
    def mget_temp(self, filename=None):
        return self.execute_cmd(
            f"mget_temp -d {self.ctx.effective_device}",
            filename=filename
        )
