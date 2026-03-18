from ..base_tool import BaseTool, supports_fwctl


class MstconfigTool(BaseTool):
    @supports_fwctl
    def mstconfig_query(self, filename=None):
        return self.execute_cmd(
            f"mstconfig -d {self.ctx.effective_device} -e q",
            filename=filename
        )
