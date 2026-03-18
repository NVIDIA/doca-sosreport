from ..base_tool import BaseTool


class MstregdumpTool(BaseTool):
    def mstregdump_run(self, idx, filename=None):
        return self.execute_cmd(
            cmd=f"mstregdump {self.ctx.effective_device}",
            key=f"mstregdump_{self.ctx.effective_device}_{idx}",
            filename=filename
        )
