from ..base_tool import BaseTool, supports_fwctl


class MstregTool(BaseTool):
    @supports_fwctl
    def mstreg_roce_accl_query(self, filename=None):
        return self.execute_cmd(
            f"mstreg -d {self.ctx.effective_device} --reg_name ROCE_ACCL "
            "--get",
            filename=filename
        )
