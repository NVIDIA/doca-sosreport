from ..base_tool import BaseTool


class MstDevicesInfoTool(BaseTool):
    def mstdevices_info_verbose(self, filename=None):
        return self.execute_cmd(
            "mstdevices_info -v",
            filename=filename
        )
