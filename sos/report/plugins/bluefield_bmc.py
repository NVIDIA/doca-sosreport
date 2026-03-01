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
import tempfile
import time
from pathlib import Path
from sos.report.plugins import Plugin, IndependentPlugin, PluginOpt


class BluefieldBmc(Plugin, IndependentPlugin):
    """
    Collects Bluefield BMC diagnostic data

    Triggers a BMC dump, downloads and extracts it into the sosreport.
    BMC dump creation typically takes 5-10 minutes.

    BMC IP is always extracted from ipmitool.

    Credentials can be extracted from EFI variables on the Bluefield when
    enabled, or provided via plugin options or environment variables:
      -k bluefield_bmc.bmc_user=USER -k bluefield_bmc.bmc_password=PASS
      or set BMC_USER and BMC_PASSWORD environment variables.

    EFI credential extraction is supported only on Bluefield-3 (BF3); on
    other Bluefield versions credentials must be provided via options or
    environment variables.
    """

    short_desc = 'Bluefield BMC dump collection'
    plugin_name = 'bluefield_bmc'
    profiles = ('hardware',)
    packages = ('curl', 'ipmitool')

    option_list = [
        PluginOpt('bmc_user', val_type=str,
                  desc='BMC username (required if not extracted from '
                       'EFI variables)'),
        PluginOpt('bmc_password', val_type=str,
                  desc='BMC password (required if not extracted from '
                       'EFI variables)'),
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

    def _get_efi_credentials(self):
        """Extract BMC credentials from EFI variables."""
        efi_base = Path('/sys/firmware/efi/efivars')
        if not efi_base.exists():
            return None, None

        # Find EFI variables by searching for BMC-related files
        creds_flag = None
        username_file = None
        password_file = None

        try:
            for efi_var in efi_base.iterdir():
                var_name = efi_var.name
                if 'DPUBMCRfshCrdntlsFnd' in var_name:
                    creds_flag = efi_var
                elif 'DPUBMCUsername' in var_name:
                    username_file = efi_var
                elif 'DPUBMCPassword' in var_name:
                    password_file = efi_var
        except OSError:
            return None, None

        # Check if credentials flag is set
        if not creds_flag or not creds_flag.exists():
            return None, None

        # Check flag value (skip 4-byte header, check if 5th byte is 0x01)
        try:
            with open(creds_flag, 'rb') as f:
                flag_data = f.read()
                if len(flag_data) < 5 or flag_data[4] != 0x01:
                    return None, None
        except (OSError, IndexError):
            return None, None

        username = None
        if username_file and username_file.exists():
            try:
                with open(username_file, 'rb') as f:
                    data = f.read()
                    username = data[4:].decode('utf-8').rstrip('\0')
            except (OSError, UnicodeDecodeError):
                # EFI var unreadable or not valid UTF-8; skip username
                pass

        if username is None:
            return None, None  # need both from EFI; skip if username failed

        password = None
        if password_file and password_file.exists():
            try:
                with open(password_file, 'rb') as f:
                    data = f.read()
                    password_bytes = data[4:]
                    password = password_bytes.rstrip(b'\0').decode('utf-8')
            except (OSError, UnicodeDecodeError):
                # EFI var unreadable or not valid UTF-8; skip password
                pass

        if username and password:
            return username, password
        return None, None

    def setup(self):
        """Trigger BMC dump via Redfish, poll for completion, and collect."""
        bmc_ip = self._get_bmc_ip_from_ipmitool()
        if not bmc_ip:
            self._log_warn("BMC IP not found via ipmitool. Cannot proceed.")
            return
        self._log_info(f"Extracted BMC IP from ipmitool: {bmc_ip}")

        # Credentials: either both from EFI or both from options/env vars
        efi_user, efi_password = self._get_efi_credentials()
        if efi_user and efi_password:
            bmc_user = efi_user
            bmc_password = efi_password
            self._log_info("Extracted BMC credentials from EFI variables")
        else:
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
            return

        # Create temporary .netrc file to avoid credentials in ps output
        netrc_fd, netrc_path = tempfile.mkstemp(prefix='bmc_netrc_')
        try:
            with os.fdopen(netrc_fd, 'w') as netrc_file:
                netrc_file.write(f"machine {bmc_ip}\n")
                netrc_file.write(f"login {bmc_user}\n")
                netrc_file.write(f"password {bmc_password}\n")
            os.chmod(netrc_path, 0o600)

            dump_dir = Path(tempfile.mkdtemp(prefix='bmc_sos_'))

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

            dump_fd, local_dump = tempfile.mkstemp(
                prefix='bmc_dump_', suffix='.tar.xz'
            )
            os.close(dump_fd)  # Close FD, curl will create the file
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
