# Copyright (C) 2024 Nvidia Corporation

# This file is part of the sos project: https://github.com/sosreport/sos
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# version 2 of the GNU General Public License.
#
# See the LICENSE file in the source distribution for further information.

from sos.report.plugins import Plugin, IndependentPlugin
import json


class DevlinkHealth(Plugin, IndependentPlugin):
    """
    This plugin collects information about devlink health reporters and their
    status. It gathers the output of diagnostics and dumps for each reporter.
    """
    short_desc = 'Devlink health reporting and recovery information'
    plugin_name = "devlink_health"
    profiles = ('network', 'hardware')
    packages = ('iproute2', 'iproute', 'mlnx-iproute2')

    def setup(self):
        # Get list of all devices and reporters
        result = self.collect_cmd_output("devlink health -jp")
        if result['status'] != 0:
            return

        # Parse the output to identify devices, ports and their reporters
        reporters = self._parse_devlink_health_json(result['output'])

        # Run commands for each reporter
        for reporter_info in reporters:
            dev = reporter_info['dev']
            reporter = reporter_info['reporter']

            # Run diagnose command for each reporter
            self.add_cmd_output(f"devlink health diagnose {dev} reporter "
                                f"{reporter}")

            # Get dump for each reporter
            self.add_cmd_output(f"devlink health dump show {dev} reporter "
                                f"{reporter}", foreground=True)

    def _parse_devlink_health_json(self, output):
        """
        Parse the JSON output of 'devlink health -j' command to extract devices
        and reporters.
        """
        out_reporters = []

        try:
            # Parse JSON output
            data = json.loads(output)

            # Check if the JSON has the expected structure
            if 'health' not in data:
                self.log_warn("Unexpected JSON format: 'health' key not found")
                return out_reporters

            # Iterate through each device/port in the health data
            for dev_name, reporters in data['health'].items():
                for reporter_data in reporters:
                    if 'reporter' not in reporter_data:
                        continue

                    reporter_info = {
                        'dev': dev_name,
                        'reporter': reporter_data['reporter']
                    }
                    out_reporters.append(reporter_info)

        except json.JSONDecodeError as e:
            self.log_error(f"Failed to parse JSON: {e}")
        except Exception as e:
            self.log_error(f"Error processing devlink health data: {e}")

        return out_reporters
