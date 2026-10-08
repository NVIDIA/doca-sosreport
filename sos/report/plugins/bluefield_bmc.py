# Copyright (C) 2026 NVIDIA Corporation
# This file is part of the sos project: https://github.com/sosreport/sos
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# version 2 of the GNU General Public License.
#
# See the LICENSE file in the source distribution for further information.

import ipaddress
import json
import os
import re
import shutil
import tempfile
import time
from pathlib import Path
from sos.report.plugins import Plugin, IndependentPlugin, PluginOpt


class BluefieldBmc(Plugin, IndependentPlugin):
    """
    Collects Bluefield BMC diagnostic data

    Triggers the dumps supported by the installed card, downloads and
    extracts them into the sosreport. Dump creation typically takes
    several minutes per dump.

    The BlueField generation is detected from the builtin FRU device, and
    determines both the Redfish resource names and which dumps are taken:
    Bluefield-3 (BF3) provides a BMC dump only, while Bluefield-4 (BF4)
    additionally provides a Grace (CPU diagnostics) system dump.

    BMC IP is always extracted from ipmitool.

    Credentials must be provided via plugin options or environment
    variables:
      -k bluefield_bmc.bmc_user=USER -k bluefield_bmc.bmc_password=PASS
      or set BMC_USER and BMC_PASSWORD environment variables.
    """

    short_desc = 'Bluefield BMC dump collection'
    plugin_name = 'bluefield_bmc'
    profiles = ('hardware',)
    packages = ('curl', 'ipmitool')

    option_list = [
        PluginOpt('bmc_user', val_type=str,
                  desc='BMC username (required)'),
        PluginOpt('bmc_password', val_type=str,
                  desc='BMC password (required)'),
    ]

    # FRU product names used to identify the BlueField generation.
    _CARD_NAMES = {
        'bf3': 'BlueField-3',
        'bf4': 'BlueField-4',
    }

    _BMC_DUMP_PAYLOAD = '{"DiagnosticDataType": "Manager"}'

    _GRACE_DUMP_PAYLOAD = (
        '{"DiagnosticDataType": "OEM", "OEMDiagnosticDataType": '
        '"DiagnosticType=CPUDiagnosticsData"}'
    )

    # Dumps to collect per generation, as (label, Redfish resource holding
    # the dump LogService, CollectDiagnosticData payload). The System
    # resource is named differently on each generation.
    _CARD_DUMPS = {
        'bf3': (
            ('bmc', 'Managers/Bluefield_BMC', _BMC_DUMP_PAYLOAD),
        ),
        'bf4': (
            ('bmc', 'Managers/BlueField_BMC_0', _BMC_DUMP_PAYLOAD),
            ('grace', 'Systems/BlueField_0', _GRACE_DUMP_PAYLOAD),
        ),
    }

    @staticmethod
    def _brief(output, limit=500):
        """Condense a Redfish response for inclusion in a log message."""
        text = ' '.join(output.split())
        return text[:limit] if text else '<empty response>'

    def _parse_dump_ids(self, output):
        """Parse dump entry IDs from Redfish response."""
        try:
            dumps_json = json.loads(output)
            members = dumps_json.get('Members', [])
            dump_ids = [m.get('@odata.id', '').split('/')[-1]
                        for m in members if '@odata.id' in m]
            return sorted(set(dump_ids))
        except (json.JSONDecodeError, KeyError) as e:
            self._log_warn(f"Could not parse dump entries: {e}")
            return []

    def _get_card_generation(self):
        """Identify the BlueField generation from the builtin FRU device.

        The FRU device with ID 0 describes the Bluefield.
        """
        result = self.exec_cmd("ipmitool fru", timeout=60)
        if result['status'] != 0:
            self._log_warn("Could not read FRU data via ipmitool")
            return None

        builtin = False
        for line in result['output'].split('\n'):
            key, _, value = line.partition(':')
            key = key.strip()
            value = value.strip()
            if key == 'FRU Device Description':
                builtin = '(ID 0)' in value
            elif builtin and key == 'Product Name':
                for card, name in self._CARD_NAMES.items():
                    if name.lower() in value.lower():
                        return card
                self._log_warn(f"Unrecognized FRU product name: {value}")
                return None
        self._log_warn("No builtin FRU device (ID 0) found")
        return None

    def _get_bmc_ip_from_ipmitool(self):
        """Extract BMC IP address from ipmitool."""
        # ipmitool lan print uses the default channel (1), where the BMC is.
        cmd = "ipmitool lan print"
        result = self.exec_cmd(cmd, timeout=30)
        if result['status'] == 0:
            # Look for "IP Address" line
            for line in result['output'].split('\n'):
                if 'IP Address' in line and 'Source' not in line:
                    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        candidate = match.group(1)
                        try:
                            parsed = ipaddress.ip_address(candidate)
                        except ValueError:
                            continue
                        if parsed.is_unspecified:
                            continue
                        return candidate
        return None

    def _get_credentials(self):
        """Resolve BMC credentials from plugin options or environment."""
        bmc_user = (self.get_option('bmc_user') or
                    os.environ.get('BMC_USER', ''))
        bmc_password = (self.get_option('bmc_password') or
                        os.environ.get('BMC_PASSWORD', ''))

        if not bmc_user or not bmc_password:
            self._log_warn(
                "BMC credentials not provided. Use: "
                "-k bluefield_bmc.bmc_user=USER "
                "-k bluefield_bmc.bmc_password=PASSWORD or set "
                "BMC_USER and BMC_PASSWORD env vars"
            )
            return None, None

        return bmc_user, bmc_password

    def _wait_for_task(self, netrc_path, bmc_ip, task_url, label):
        """Poll a Redfish task until it completes. Returns True on success."""
        poll_interval = 5
        max_attempts = 120

        for _attempt in range(max_attempts):
            poll_cmd = (
                f"curl -k -s --netrc-file {netrc_path} "
                f"-X GET https://{bmc_ip}{task_url}"
            )
            poll_result = self.exec_cmd(poll_cmd)

            if poll_result['status'] == 0:
                try:
                    task_json = json.loads(poll_result['output'])
                    task_state = task_json.get('TaskState', '')

                    if task_state == 'Completed':
                        self._log_info(f"{label} dump creation completed")
                        return True
                    if task_state in ['Exception', 'Killed', 'Cancelled']:
                        self._log_error(
                            f"{label} dump creation failed: {task_state}"
                        )
                        return False

                except (json.JSONDecodeError, KeyError) as e:
                    self._log_warn(f"Failed to parse task status: {e}")

            time.sleep(poll_interval)

        timeout = max_attempts * poll_interval
        self._log_error(
            f"Timeout waiting for {label} dump (max {timeout}s)"
        )
        return False

    def _collect_dump(self, netrc_path, bmc_ip, label, resource, payload):
        """Trigger one Redfish dump, then download and extract it.

        :param label:    short name for the dump, used in logs and paths
        :param resource: Redfish resource holding the dump LogService,
                         e.g. ``Managers/Bluefield_BMC``
        :param payload:  JSON body for the CollectDiagnosticData action
        """
        dump_service = (
            f"https://{bmc_ip}/redfish/v1/{resource}/LogServices/Dump"
        )
        entries_url = f"{dump_service}/Entries"
        list_cmd = (
            f"curl -k -s --netrc-file {netrc_path} -X GET {entries_url}"
        )

        list_result = self.exec_cmd(list_cmd)
        existing_ids = []
        if list_result['status'] == 0:
            existing_ids = self._parse_dump_ids(list_result['output'])

        self._log_info(f"Triggering {label} dump via Redfish...")
        create_cmd = (
            f"curl -k -s --netrc-file {netrc_path} "
            f"-H 'Content-Type: application/json' "
            f"-d '{payload}' "
            f"-X POST {dump_service}/Actions/"
            "LogService.CollectDiagnosticData"
        )

        create_result = self.exec_cmd(create_cmd)
        if create_result['status'] != 0:
            self._log_error(f"Failed to trigger {label} dump: "
                            f"{self._brief(create_result['output'])}")
            return False

        try:
            response_json = json.loads(create_result['output'])
            task_url = response_json.get('@odata.id', '')
            if not task_url:
                # curl -s exits 0 on HTTP errors, so an auth or path
                # failure arrives here as a Redfish error body
                self._log_error(f"No task URL in {label} dump response: "
                                f"{self._brief(create_result['output'])}")
                return False
            self._log_info(f"{label} dump task started")
        except (json.JSONDecodeError, KeyError) as e:
            self._log_error(f"Failed to parse {label} task response: {e}: "
                            f"{self._brief(create_result['output'])}")
            return False

        if not self._wait_for_task(netrc_path, bmc_ip, task_url, label):
            return False

        list_result2 = self.exec_cmd(list_cmd)
        if list_result2['status'] != 0:
            self._log_error(f"Failed to list {label} dump entries: "
                            f"{self._brief(list_result2['output'])}")
            return False

        current_ids = self._parse_dump_ids(list_result2['output'])
        if not current_ids:
            self._log_error(f"Failed to parse {label} dump entries: "
                            f"{self._brief(list_result2['output'])}")
            return False

        new_ids = [cid for cid in current_ids if cid not in existing_ids]
        if not new_ids:
            self._log_error(f"No new {label} dump entry found")
            return False

        dump_id = new_ids[0]
        self._log_info(f"Found {label} dump entry ID: {dump_id}")

        dump_fd, local_dump = tempfile.mkstemp(prefix=f'bmc_dump_{label}_')
        os.close(dump_fd)  # Close FD, curl will create the file
        download_cmd = (
            f"curl -k -s --fail --netrc-file {netrc_path} "
            f"-X GET {entries_url}/{dump_id}/attachment "
            f"--output {local_dump}"
        )

        download_result = self.exec_cmd(download_cmd)
        if download_result['status'] != 0:
            self._log_error(f"Failed to download {label} dump")
            return False

        if not self.path_exists(local_dump):
            self._log_error(f"{label} dump file not found after download")
            return False

        dump_dir = Path(tempfile.mkdtemp(prefix=f'bmc_sos_{label}_'))
        extract_result = self.exec_cmd(
            f"tar -xf {local_dump} -C {str(dump_dir)}"
        )
        if extract_result['status'] == 0:
            Path(local_dump).unlink(missing_ok=True)
        else:
            # Keep the archive rather than discarding the dump entirely;
            # BF4 dumps are zstd compressed and need tar zstd support.
            self._log_warn(
                f"Failed to extract {label} dump, collecting it as-is"
            )
            shutil.move(local_dump, str(dump_dir / f'{label}_dump'))

        self.add_copy_spec(str(dump_dir), sizelimit=0)
        return True

    def setup(self):
        """Detect the card, then collect every dump it supports."""
        card = self._get_card_generation()
        if not card:
            self._log_warn("No Bluefield card detected. Cannot proceed.")
            return
        self._log_info(f"Detected card generation: {card}")

        bmc_ip = self._get_bmc_ip_from_ipmitool()
        if not bmc_ip:
            self._log_warn("BMC IP not found via ipmitool. Cannot proceed.")
            return
        self._log_info(f"Extracted BMC IP from ipmitool: {bmc_ip}")

        bmc_user, bmc_password = self._get_credentials()
        if not bmc_user or not bmc_password:
            return

        # Create temporary .netrc file to avoid credentials in ps output
        netrc_fd, netrc_path = tempfile.mkstemp(prefix='bmc_netrc_')
        try:
            with os.fdopen(netrc_fd, 'w') as netrc_file:
                netrc_file.write(f"machine {bmc_ip}\n")
                netrc_file.write(f"login {bmc_user}\n")
                netrc_file.write(f"password {bmc_password}\n")
            os.chmod(netrc_path, 0o600)

            # A failed dump should not prevent the others being collected
            for label, resource, payload in self._CARD_DUMPS[card]:
                self._collect_dump(netrc_path, bmc_ip, label, resource,
                                   payload)

        finally:
            # Always clean up the .netrc file
            try:
                os.unlink(netrc_path)
            except OSError:
                pass

# vim: set et ts=4 sw=4 :
