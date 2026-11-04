# Copyright (C) 2026 NVIDIA Corporation
# This file is part of the sos project: https://github.com/sosreport/sos
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# version 2 of the GNU General Public License.
#
# See the LICENSE file in the source distribution for further information.

from sos.report.plugins import Plugin, IndependentPlugin


class DpuAgent(Plugin, IndependentPlugin):
    """Collect journald logs for the DPF dpu-agent service.

    dpu-agent writes stdout and stderr to the journal
    (StandardOutput=journal+console). This plugin captures that journal,
    the unit status, and the unit file.
    """

    short_desc = 'DPF dpu-agent service journal logs'
    plugin_name = 'dpu_agent'
    profiles = ('services', 'doca')

    # Enable when the unit is installed. `services` is intentionally not
    # used: sos already journals every service listed there, and setup()
    # collects the journal explicitly.
    files = (
        '/usr/lib/systemd/system/dpu-agent.service',
        '/lib/systemd/system/dpu-agent.service',
        '/etc/systemd/system/dpu-agent.service',
    )

    def setup(self):
        self.add_journal(units='dpu-agent')
        self.add_service_status('dpu-agent')
        self.add_copy_spec([
            '/usr/lib/systemd/system/dpu-agent.service',
            '/lib/systemd/system/dpu-agent.service',
            '/etc/systemd/system/dpu-agent.service',
            '/etc/systemd/system/multi-user.target.wants/dpu-agent.service',
        ])

# vim: set et ts=4 sw=4 :
