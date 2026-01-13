from ..base_tool import BaseTool


class MstTool(BaseTool):
    def mst_status_verbose(self, filename=None):
        return self.execute_cmd(
            "mst status -v",
            filename=filename
        )
