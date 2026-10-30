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
from sos.report.plugins import doca_dpf


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
    chroot = 'auto'


class DocaDpfKubeconfigTests(unittest.TestCase):
    """Kubeconfig lookup of the doca_dpf plugin, which runs kubectl from the
    sos environment and not chrooted into the sysroot.
    """

    def setUp(self):
        self.sysroot = tempfile.mkdtemp()
        self.local = tempfile.mkdtemp()
        self.kconf = os.path.join(self.local, 'admin.conf')
        self.kconf2 = os.path.join(self.local, 'client.config')
        self.plugin = doca_dpf.UbuntuKubernetes({
            'sysroot': self.sysroot,
            'policy': LinuxPolicy(init=InitSystem(), probe_runtime=False),
            'cmdlineopts': MockOptions(),
            'devices': {}
        })
        self.plugin.files = (self.kconf,)
        self.plugin.packages = ()
        self.plugin.services = ()

    def tearDown(self):
        shutil.rmtree(self.sysroot)
        shutil.rmtree(self.local)

    def _touch(self, path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8'):
            pass

    def test_no_kubeconfig(self):
        self.assertIsNone(self.plugin.find_kubeconfig())
        self.assertFalse(self.plugin.check_is_master())
        self.assertFalse(self.plugin.check_enabled())

    def test_local_kubeconfig(self):
        # e.g. mounted into the sos container, but not present on the host
        self._touch(self.kconf)
        self.assertEqual(self.plugin.find_kubeconfig(), self.kconf)
        self.assertTrue(self.plugin.check_is_master())
        self.assertTrue(self.plugin.check_enabled())

    def test_sysroot_kubeconfig(self):
        sysroot_kconf = self.sysroot + self.kconf
        self._touch(sysroot_kconf)
        # kubectl is not chrooted, so the path must point into the sysroot
        self.assertEqual(self.plugin.find_kubeconfig(), sysroot_kconf)
        self.assertTrue(self.plugin.check_is_master())
        self.assertTrue(self.plugin.check_enabled())

    def test_local_kubeconfig_preferred(self):
        self._touch(self.kconf)
        self._touch(self.sysroot + self.kconf)
        self.assertEqual(self.plugin.find_kubeconfig(), self.kconf)

    def test_any_local_kubeconfig_preferred(self):
        # a later local candidate wins over an earlier one in the sysroot
        self.plugin.files = (self.kconf, self.kconf2)
        self._touch(self.sysroot + self.kconf)
        self._touch(self.kconf2)
        self.assertEqual(self.plugin.find_kubeconfig(), self.kconf2)

    def test_chroot_always_uses_sysroot_path(self):
        # kubectl runs in the sysroot, so local kubeconfigs are not usable
        # and the sysroot one is passed by its path in the sysroot
        self.plugin.commons['cmdlineopts'].chroot = 'always'
        self._touch(self.kconf)
        self.assertIsNone(self.plugin.find_kubeconfig())
        self._touch(self.sysroot + self.kconf)
        self.assertEqual(self.plugin.find_kubeconfig(), self.kconf)

    @mock.patch.dict(os.environ, clear=True)
    def test_set_kubeconfig_quotes_path(self):
        self.plugin.files = (os.path.join(self.local, 'my admin.conf'),)
        self._touch(self.plugin.files[0])
        self.plugin.set_kubeconfig()
        self.assertEqual(self.plugin.kube_cmd,
                         f"kubectl --kubeconfig='{self.plugin.files[0]}'")

    @mock.patch.dict(os.environ, clear=True)
    def test_set_kubeconfig(self):
        self._touch(self.kconf)
        self.plugin.set_kubeconfig()
        self.assertEqual(self.plugin.kube_cmd,
                         f'kubectl --kubeconfig={self.kconf}')
        self.assertFalse(self.plugin.kube_chroot)


# vim: set et ts=4 sw=4 :
