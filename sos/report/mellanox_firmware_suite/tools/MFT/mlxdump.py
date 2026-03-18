from ..base_tool import BaseTool, supports_fwctl


class MlxdumpTool(BaseTool):
    @supports_fwctl
    def mlxdump_pcie_uc_all(self, filename=None):
        return self.execute_cmd(
            f"mlxdump -d {self.ctx.effective_device} pcie_uc --all",
            filename=filename
        )
