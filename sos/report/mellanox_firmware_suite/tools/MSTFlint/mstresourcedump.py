from ..base_tool import BaseTool


class MstresourcedumpTool(BaseTool):
    def mstresourcedump_basic_debug(self, filename=None):
        return self.execute_cmd(
            f"mstresourcedump dump -d {self.ctx.device} "
            "--segment BASIC_DEBUG",
            filename=filename
        )
