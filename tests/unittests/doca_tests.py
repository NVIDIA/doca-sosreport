# This file is part of the sos project: https://github.com/sosreport/sos
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# version 2 of the GNU General Public License.
#
# See the LICENSE file in the source distribution for further information.
import os
import shutil
import tempfile
import unittest
from unittest import mock

from sos.policies.distros import LinuxPolicy
from sos.policies.init_systems import InitSystem
from sos.report.plugins import doca


class MockOptions:
    all_logs = False
    dry_run = False
    since = None
    log_size = 25
    allow_system_changes = False
    no_postproc = False
    skip_files = []
    skip_commands = []
    sysroot = None


class DocaSysrootTests(unittest.TestCase):
    """The doca plugin looks for DOCA files in the sysroot, which is the
    host's root file system when sos runs in a container.
    """

    def setUp(self):
        self.sysroot = tempfile.mkdtemp()
        self.local = tempfile.mkdtemp()
        self.plugin = doca.Doca({
            'sysroot': self.sysroot,
            'policy': LinuxPolicy(init=InitSystem(), probe_runtime=False),
            'cmdlineopts': MockOptions(),
            'devices': {}
        })
        self.plugin.doca_version = os.path.join(self.local, 'VERSION')
        self.plugin.mlnx_release = os.path.join(self.local, 'mlnx-release')

    def tearDown(self):
        shutil.rmtree(self.sysroot)
        shutil.rmtree(self.local)

    def _write(self, path, content=''):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)

    def test_not_enabled_without_doca(self):
        self.assertFalse(self.plugin.check_enabled())

    def test_not_enabled_by_local_files(self):
        # e.g. present in the sos container, but not on the host
        self._write(self.plugin.doca_version)
        self._write(self.plugin.mlnx_release)
        self.assertFalse(self.plugin.check_enabled())

    def test_enabled_by_sysroot_doca_version(self):
        self._write(self.sysroot + self.plugin.doca_version)
        self.assertTrue(self.plugin.check_enabled())

    def test_enabled_by_sysroot_mlnx_release(self):
        self._write(self.sysroot + self.plugin.mlnx_release)
        self.assertTrue(self.plugin.check_enabled())

    @mock.patch.object(doca.Doca, 'exec_cmd')
    @mock.patch.object(doca.Doca, 'add_copy_spec')
    @mock.patch.object(doca.Doca, 'add_cmd_output')
    def test_setup_reads_lists_from_sysroot(self, add_cmd_output,
                                            add_copy_spec, _exec_cmd):
        self._write(self.sysroot + '/var/tmp/sos_commands', 'doca-cmd\n')
        self._write(self.sysroot + '/opt/mellanox/doca/tools/sos_logs',
                    '/var/log/doca.log\n')
        self.plugin.setup()
        add_cmd_output.assert_any_call('doca-cmd')
        add_copy_spec.assert_any_call('/var/log/doca.log')


# vim: set et ts=4 sw=4 :
