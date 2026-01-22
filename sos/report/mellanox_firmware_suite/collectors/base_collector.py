from abc import ABC, abstractmethod
from ..tools import FirmwareTools


class Collector(ABC):
    def run(self, plugin, ctx):
        if ctx.provider == FirmwareTools.MFT_TOOL:
            self._collect_with_mft(plugin, ctx)

        elif ctx.provider == FirmwareTools.MSTFLINT_TOOL:
            self._collect_with_mstflint(plugin, ctx)

        else:
            raise ValueError(f"Unknown tools provider: '{ctx.provider}'")

    @abstractmethod
    def _collect_with_mft(self, plugin, ctx):
        pass

    @abstractmethod
    def _collect_with_mstflint(self, plugin, ctx):
        pass
