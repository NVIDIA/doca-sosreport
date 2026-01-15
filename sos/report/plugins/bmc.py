# Copyright (C) 2026 NVIDIA Corporation
# This file is part of the sos project: https://github.com/sosreport/sos
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# version 2 of the GNU General Public License.
#
# See the LICENSE file in the source distribution for further information.

import json
import os
import shutil
import tempfile
import time
from pathlib import Path
from sos.report.plugins import Plugin, IndependentPlugin, PluginOpt


class Bmc(Plugin, IndependentPlugin):
    """
    Collects BMC diagnostic data

    Triggers a BMC dump, downloads and extracts it into the sosreport.
    BMC dump creation typically takes 5-10 minutes.

    Credentials must be provided via plugin options:
      -k bmc.bmc_ip=IP -k bmc.bmc_user=USER -k bmc.bmc_password=PASS
    """

    short_desc = 'BMC dump collection'
    plugin_name = 'bmc'
    profiles = ('hardware',)
    packages = ('curl',)

    option_list = [
        PluginOpt('bmc_ip', val_type=str,
                  desc='BMC IP address (required)'),
        PluginOpt('bmc_user', val_type=str,
                  desc='BMC username (required)'),
        PluginOpt('bmc_password', val_type=str,
                  desc='BMC password (required)'),
    ]

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

    def setup(self):
        """Trigger BMC dump via Redfish, poll for completion, and collect."""
        bmc_ip = self.get_option('bmc_ip')
        bmc_user = self.get_option('bmc_user')
        bmc_password = self.get_option('bmc_password')

        has_any = any([bmc_ip, bmc_user, bmc_password])
        has_all = all([bmc_ip, bmc_user, bmc_password])

        if has_any and not has_all:
            if not bmc_ip:
                self._log_warn(
                    "BMC IP not provided. Use: -k bmc.bmc_ip=X.X.X.X"
                )
            if not bmc_user:
                self._log_warn(
                    "BMC user not provided. Use: -k bmc.bmc_user=USER"
                )
            if not bmc_password:
                self._log_warn(
                    "BMC password not provided. "
                    "Use: -k bmc.bmc_password=SECRET"
                )
            return

        if not has_all:
            return

        # Create temporary .netrc file to avoid credentials in ps output
        netrc_fd, netrc_path = tempfile.mkstemp(prefix='bmc_netrc_')
        try:
            with os.fdopen(netrc_fd, 'w') as netrc_file:
                netrc_file.write(f"machine {bmc_ip}\n")
                netrc_file.write(f"login {bmc_user}\n")
                netrc_file.write(f"password {bmc_password}\n")
            os.chmod(netrc_path, 0o600)

            dump_dir = Path('/tmp/bmc_sos')
            if dump_dir.exists():
                shutil.rmtree(dump_dir)
            dump_dir.mkdir(parents=True, exist_ok=True)

            redfish_base = f"https://{bmc_ip}/redfish/v1"

            list_dumps_cmd = (
                f"curl -k -s --netrc-file {netrc_path} -X GET "
                f"{redfish_base}/Managers/Bluefield_BMC/LogServices/"
                "Dump/Entries"
            )
            list_result = self.exec_cmd(list_dumps_cmd)

            existing_ids = []
            if list_result['status'] == 0:
                existing_ids = self._parse_dump_ids(list_result['output'])

            self._log_info("Triggering BMC dump via Redfish...")
            base_path = (
                f"{redfish_base}/Managers/Bluefield_BMC/LogServices/"
                "Dump/Actions/LogService.CollectDiagnosticData"
            )
            create_dump_cmd = (
                f"curl -k -s --netrc-file {netrc_path} "
                f"-H 'Content-Type: application/json' "
                f'-d \'{{\"DiagnosticDataType\": \"Manager\"}}\' '
                f"-X POST {base_path}"
            )

            create_result = self.exec_cmd(create_dump_cmd)
            if create_result['status'] != 0:
                self._log_error("Failed to trigger BMC dump")
                return

            try:
                response_json = json.loads(create_result['output'])
                task_url = response_json.get('@odata.id', '')
                if not task_url:
                    self._log_error("No task URL in response")
                    return

                self._log_info("BMC dump task started")
            except (json.JSONDecodeError, KeyError) as e:
                self._log_error(f"Failed to parse task response: {e}")
                return

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
                            self._log_info("BMC dump creation completed")
                            break
                        elif task_state in ['Exception', 'Killed',
                                            'Cancelled']:
                            self._log_error(
                                f"BMC dump creation failed: {task_state}"
                            )
                            return

                    except (json.JSONDecodeError, KeyError) as e:
                        self._log_warn(f"Failed to parse task status: {e}")

                time.sleep(poll_interval)
            else:
                timeout = max_attempts * poll_interval
                self._log_error(
                    f"Timeout waiting for BMC dump (max {timeout}s)"
                )
                return

            list_dumps_cmd2 = (
                f"curl -k -s --netrc-file {netrc_path} -X GET "
                f"{redfish_base}/Managers/Bluefield_BMC/LogServices/"
                "Dump/Entries"
            )
            list_result2 = self.exec_cmd(list_dumps_cmd2)

            if list_result2['status'] != 0:
                self._log_error("Failed to list dump entries")
                return

            current_ids = self._parse_dump_ids(list_result2['output'])
            if not current_ids:
                self._log_error("Failed to parse dump entries")
                return

            new_ids = [cid for cid in current_ids
                       if cid not in existing_ids]

            if not new_ids:
                self._log_error("No new dump entry found")
                return

            dump_id = new_ids[0]
            self._log_info(f"Found dump entry ID: {dump_id}")

            local_dump = f"/tmp/bmc_dump_{dump_id}.tar.xz"
            download_url = (
                f"{redfish_base}/Managers/Bluefield_BMC/LogServices/"
                f"Dump/Entries/{dump_id}/attachment"
            )
            download_cmd = (
                f"curl -k -s --fail --netrc-file {netrc_path} "
                f"-X GET {download_url} --output {local_dump}"
            )

            download_result = self.exec_cmd(download_cmd)
            if download_result['status'] != 0:
                self._log_error("Failed to download BMC dump")
                return

            if not self.path_exists(local_dump):
                self._log_error("BMC dump file not found after download")
                return

            extract_result = self.exec_cmd(
                f"tar -xf {local_dump} -C {str(dump_dir)}"
            )
            if extract_result['status'] != 0:
                self._log_error("Failed to extract BMC dump")
                return

            Path(local_dump).unlink(missing_ok=True)
            self.add_copy_spec(str(dump_dir), sizelimit=0)

        finally:
            # Always clean up the .netrc file
            try:
                os.unlink(netrc_path)
            except OSError:
                pass

# vim: set et ts=4 sw=4 :
