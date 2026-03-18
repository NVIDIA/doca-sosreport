from ..base_tool import BaseTool, supports_fwctl


class MstFlintTool(BaseTool):
    @property
    @supports_fwctl
    def is_secured_fw(self):
        if getattr(self, "_is_secured_cache", None) is None:
            rc, output = self.execute_cmd(
                f"mstflint -d {self.ctx.effective_device} q full",
                cache=False,
                get_cached=True
            )

            attrs = self._parse_security_attributes(
                output if rc == 0 else ""
            )

            self._is_secured_cache = (
                "secure-fw" in attrs and "dev" not in attrs
            )

        return self._is_secured_cache

    def mstflint_version(self, filename=None):
        return self.execute_cmd(
            "mstflint --version",
            filename=filename
        )

    @supports_fwctl
    def mstflint_query_full(self, filename=None):
        return self.execute_cmd(
            f"mstflint -d {self.ctx.effective_device} q full",
            filename=filename
        )

    @supports_fwctl
    def mstflint_dump_config(self, filename=None):
        return self.execute_cmd(
            f"mstflint -d {self.ctx.effective_device} dc",
            filename=filename
        )
