from ..base_tool import BaseTool


class FlintTool(BaseTool):
    @property
    def is_secured_fw(self):
        if getattr(self, "_is_secured_cache", None) is None:
            rc, output = self.execute_cmd(
                f"flint -d {self.ctx.device} q full",
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

    def flint_version(self, filename=None):
        return self.execute_cmd(
            "flint --version",
            filename=filename
        )

    def flint_query_full(self, filename=None):
        return self.execute_cmd(
            f"flint -d {self.ctx.device} q full",
            filename=filename
        )

    def flint_dump_config(self, filename=None):
        return self.execute_cmd(
            f"flint -d {self.ctx.device} dc",
            filename=filename
        )
