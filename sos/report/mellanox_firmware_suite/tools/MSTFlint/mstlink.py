from ..base_tool import BaseTool, supports_fwctl


class MstLinkTool(BaseTool):
    @supports_fwctl
    def show_module(self, filename=None):
        return self.execute_cmd(
            f"mstlink -d {self.ctx.effective_device} --show_module",
            filename=filename
        )

    @supports_fwctl
    def cable_dump(self, filename=None):
        return self.execute_cmd(
            f"mstlink -d {self.ctx.effective_device} --cable --dump",
            filename=filename
        )

    @supports_fwctl
    def cable_ddm(self, filename=None):
        return self.execute_cmd(
            f"mstlink -d {self.ctx.effective_device} --cable --ddm",
            filename=filename
        )

    @supports_fwctl
    def show_counters(self, filename=None):
        return self.execute_cmd(
            f"mstlink -d {self.ctx.effective_device} --show_counters",
            filename=filename
        )

    @supports_fwctl
    def show_eye(self, filename=None):
        return self.execute_cmd(
            f"mstlink -d {self.ctx.effective_device} --show_eye",
            filename=filename
        )

    @supports_fwctl
    def show_fec(self, filename=None):
        return self.execute_cmd(
            f"mstlink -d {self.ctx.effective_device} --show_fec",
            filename=filename
        )

    @supports_fwctl
    def show_serdes_tx(self, filename=None):
        return self.execute_cmd(
            f"mstlink -d {self.ctx.effective_device} --show_serdes_tx",
            filename=filename
        )

    @supports_fwctl
    def show_rx_fec_histogram(self, filename=None):
        return self.execute_cmd(
            f"mstlink -d {self.ctx.effective_device} "
            "--rx_fec_histogram --show_histogram",
            filename=filename
        )

    @supports_fwctl
    def show_links_pcie(self, filename=None):
        return self.execute_cmd(
            f"mstlink -d {self.ctx.effective_device} --show_links "
            "--port_type PCIE",
            filename=filename
        )

    @supports_fwctl
    def show_links_pcie_details(self, depth, pcie_index, node, filename=None):
        return self.execute_cmd(
            f"mstlink -d {self.ctx.effective_device} --port_type PCIE "
            f"--depth {depth} --pcie_index {pcie_index} --node {node} -c -e",
            filename=filename
        )

    @supports_fwctl
    def amber_collect(self, path, filename=None):
        return self.execute_cmd(
            f"mstlink -d {self.ctx.effective_device} --amber_collect {path}",
            filename=filename
        )

    @supports_fwctl
    def amber_collect_pcie(self, path, filename=None):
        return self.execute_cmd(
            f"mstlink -d {self.ctx.effective_device} --amber_collect {path} "
            "--port_type PCIE",
            filename=filename
        )
