from ..base_tool import BaseTool


class ResourcedumpTool(BaseTool):
    def resourcedump_basic_debug(self, filename=None):
        return self.execute_cmd(
            f"resourcedump dump -d {self.ctx.device} --segment BASIC_DEBUG",
            filename=filename
        )
