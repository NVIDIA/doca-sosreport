from ..base_tool import BaseTool


class MstLinkTool(BaseTool):
    def show_module(self, filename=None):
        return self.execute_cmd(
            f"mstlink -d {self.ctx.device} --show_module",
            filename=filename
        )

    def cable_dump(self, filename=None):
        return self.execute_cmd(
            f"mstlink -d {self.ctx.device} --cable --dump",
            filename=filename
        )

    def cable_ddm(self, filename=None):
        return self.execute_cmd(
            f"mstlink -d {self.ctx.device} --cable --ddm",
            filename=filename
        )

    def show_counters(self, filename=None):
        return self.execute_cmd(
            f"mstlink -d {self.ctx.device} --show_counters",
            filename=filename
        )

    def show_eye(self, filename=None):
        return self.execute_cmd(
            f"mstlink -d {self.ctx.device} --show_eye",
            filename=filename
        )

    def show_fec(self, filename=None):
        return self.execute_cmd(
            f"mstlink -d {self.ctx.device} --show_fec",
            filename=filename
        )

    def show_serdes_tx(self, filename=None):
        return self.execute_cmd(
            f"mstlink -d {self.ctx.device} --show_serdes_tx",
            filename=filename
        )

    def show_rx_fec_histogram(self, filename=None):
        return self.execute_cmd(
            f"mstlink -d {self.ctx.device} "
            "--rx_fec_histogram --show_histogram",
            filename=filename
        )

    def show_links_pcie(self, filename=None):
        return self.execute_cmd(
            f"mstlink -d {self.ctx.device} --show_links --port_type PCIE",
            filename=filename
        )

    def show_links_pcie_details(self, depth, pcie_index, node, filename=None):
        return self.execute_cmd(
            f"mstlink -d {self.ctx.device} --port_type PCIE "
            f"--depth {depth} --pcie_index {pcie_index} --node {node} -c -e",
            filename=filename
        )

    def amber_collect(self, path, filename=None):
        return self.execute_cmd(
            f"mstlink -d {self.ctx.device} --amber_collect {path}",
            filename=filename
        )

    def amber_collect_pcie(self, path, filename=None):
        return self.execute_cmd(
            f"mstlink -d {self.ctx.device} --amber_collect {path} "
            "--port_type PCIE",
            filename=filename
        )
