from ..base_tool import BaseTool


class MlxdumpTool(BaseTool):
    def mlxdump_pcie_uc_all(self, filename=None):
        return self.execute_cmd(
            f"mlxdump -d {self.ctx.device} pcie_uc --all",
            filename=filename
        )
