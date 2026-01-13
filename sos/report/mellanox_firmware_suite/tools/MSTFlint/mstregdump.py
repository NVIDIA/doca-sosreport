from ..base_tool import BaseTool


class MstregdumpTool(BaseTool):
    def mstregdump_run(self, idx, filename=None):
        return self.execute_cmd(
            cmd=f"mstregdump {self.ctx.device}",
            key=f"mstregdump_{self.ctx.device}_{idx}",
            filename=filename
        )
