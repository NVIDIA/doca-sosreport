from ..base_tool import BaseTool


class MstdumpTool(BaseTool):
    def mstdump_run(self, idx, filename=None):
        return self.execute_cmd(
            cmd=f"mstdump {self.ctx.effective_device}",
            key=f"mstdump_{self.ctx.effective_device}_{idx}",
            filename=filename
        )
