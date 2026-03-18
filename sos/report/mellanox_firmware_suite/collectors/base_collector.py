import os
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

    @staticmethod
    def _generate_archive_file_path(plugin, file_name):
        """
        Build the absolute path where a command output file will be
        stored in the sosreport archive.

        _make_command_filename turns file_name into a relative path
        under the plugin's command directory by mangling the name
        into a filesystem-safe form and appending a numeric suffix
        if a collision is detected.

        Resulting path:
             <archive_root>/<cmddir>/<plugin_name>/<mangled_file_name>
        e.g. /tmp/sos.abc123/sos_commands/mellanox_firmware/file_name
        """

        return os.path.join(
            plugin.archive.get_archive_path(),
            plugin._make_command_filename(exe=file_name)
        )
