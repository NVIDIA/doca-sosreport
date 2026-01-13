from ..base_tool import BaseTool


class MstregTool(BaseTool):
    def mstreg_roce_accl_query(self, filename=None):
        return self.execute_cmd(
            f"mstreg -d {self.ctx.device} --reg_name ROCE_ACCL --get",
            filename=filename
        )
