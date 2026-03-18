from ..base_tool import BaseTool, supports_fwctl


class MstresourcedumpTool(BaseTool):
    @supports_fwctl
    def mstresourcedump_basic_debug(self, filename=None):
        return self.execute_cmd(
            f"mstresourcedump dump -d {self.ctx.effective_device} "
            "--segment BASIC_DEBUG",
            filename=filename
        )

    @supports_fwctl
    def mstresourcedump_crspace_map(self, idx, filename=None):
        return self.execute_cmd(
            f"mstresourcedump dump -d {self.ctx.effective_device} "
            "-s CRSPACE -p map",
            key=f"mstresourcedump_crspace_map_{self.ctx.effective_device}"
            f"_{idx}",
            filename=filename
        )
