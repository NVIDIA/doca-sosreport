from ..base_tool import BaseTool, supports_fwctl


class ResourcedumpTool(BaseTool):
    @supports_fwctl
    def resourcedump_basic_debug(self, filename=None):
        return self.execute_cmd(
            f"resourcedump dump -d {self.ctx.effective_device} "
            "--segment BASIC_DEBUG",
            filename=filename
        )

    @supports_fwctl
    def resourcedump_crspace_map(self, idx, filename=None):
        return self.execute_cmd(
            f"resourcedump dump -d {self.ctx.effective_device} "
            "-s CRSPACE -p map",
            key=f"resourcedump_crspace_map_{self.ctx.effective_device}"
            f"_{idx}",
            filename=filename
        )
