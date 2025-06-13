# Copyright (C) 2025 Nvidia Corporation,
# This file is part of the sos project: https://github.com/sosreport/sos
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# version 2 of the GNU General Public License.
#
# See the LICENSE file in the source distribution for further information.

from sos.report.plugins import Plugin, IndependentPlugin
import os


class Doca(Plugin, IndependentPlugin):
    """The DOCA plugin is aimed at collecting debug information related to
    DOCA package and libraries
    """
    short_desc = 'NVIDIA DOCA package and libraries'
    plugin_name = 'doca'
    profiles = ('hardware', )
    packages = ('doca-caps',)

    def setup(self):
        doca_caps = '/opt/mellanox/doca/tools/doca_caps'
        self.add_cmd_output([
            f'{doca_caps} -v',
            f'{doca_caps} --list-devs',
            f'{doca_caps} --list-rep-devs',
            f'{doca_caps} --list-libs',
            f'{doca_caps}',
        ])

        doca_script = '/opt/mellanox/doca/scripts/sos_script.sh'
        self.exec_cmd(doca_script)

        doca_commands_file = '/var/tmp/sos_commands'
        if os.path.isfile(doca_commands_file):
            try:
                with open(doca_commands_file, 'r', encoding='UTF-8') as f:
                    lines = f.readlines()
                    for line in lines:
                        self.add_cmd_output(line.strip())
            except Exception as e:
                self._log_warn(f'Error reading {doca_commands_file}: {e}')

        doca_logs = '/opt/mellanox/doca/scripts/sos_logs'
        if os.path.isfile(doca_logs):
            try:
                with open(doca_logs, 'r', encoding='UTF-8') as f:
                    lines = f.readlines()
                    for line in lines:
                        self.add_copy_spec(line.strip())
            except Exception as e:
                self._log_warn(f'Error reading {doca_logs}: {e}')

# vim: set et ts=4 sw=4 :
