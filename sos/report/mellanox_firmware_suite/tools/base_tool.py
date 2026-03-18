import re
import functools

from ..device_context import DeviceContext


def supports_fwctl(func):
    """
    Temporarily override effective_device with fwctl.

    When ctx.fwctl is set, effective_device resolves to
    fwctl for the duration of the decorated call.
    Apply to methods that pass ctx.effective_device as
    the -d argument to CLI tools.
    """

    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        if getattr(self.ctx, "fwctl", None) is not None:
            self.ctx._effective_device = self.ctx.fwctl

        try:
            return func(self, *args, **kwargs)

        finally:
            if hasattr(self.ctx, "_effective_device"):
                del self.ctx._effective_device

    return wrapper


class BaseTool(object):
    def __init__(self, plugin, ctx: DeviceContext):
        self.plugin = plugin
        self.ctx = ctx

    def execute_cmd(
        self,
        cmd,
        timeout=None,
        cache=True,
        get_cached=True,
        key=None,
        filename=None
    ):
        cache_key = key or cmd

        if get_cached and cache_key in self.ctx.cache:
            return self.ctx.cache[cache_key]

        rc, output = self._run_command(cmd, timeout, filename)

        if rc != 0:
            self.plugin._log_info(
                f"{cmd} failed for {self.ctx.effective_device} (rc={rc})"
            )

        if rc == 0 and cache:
            self.ctx.cache[cache_key] = (rc, output)

        return (rc, output)

    def _run_command(self, cmd, timeout, filename):
        if filename is None:
            res = self.plugin.exec_cmd(cmd=cmd, timeout=timeout)

        else:
            res = self.plugin._collect_cmd_output(
                cmd=cmd,
                suggest_filename=filename,
                timeout=timeout,
                stderr=True,
            )

        return res.get("status", 1), res.get("output", "")

    @staticmethod
    def _parse_security_attributes(output):
        match = re.search(
            r"^Security Attributes:\s*(.+)$", output, re.MULTILINE
        )

        if not match:
            return []

        return [attr.strip() for attr in match.group(1).split(",")]
