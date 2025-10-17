# Copyright (C) 2024 Nvidia Corporation, Soule BA <souleb@nvidia.com>

# This file is part of the sos project: https://github.com/sosreport/sos
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions of
# version 2 of the GNU General Public License.
#
# See the LICENSE file in the source distribution for further information.

import base64
import json
import os
from sos.report.plugins import (Plugin, RedHatPlugin, DebianPlugin,
                                UbuntuPlugin, PluginOpt)

KUBE_PACKAGES = (
    'kubelet',
    'kubernetes',
)

KUBE_SVCS = (
    'kubelet',
    'kube-apiserver',
    'kube-proxy',
    'kube-scheduler',
    'kube-controller-manager',
)

KUBECONFIGS = (
    '/etc/kubernetes/admin.conf',
)


class DocaDpf(Plugin):
    """
    This plugin will capture information related to the DOCA Platform Framework
    resources and configurations in the system.

    By default, it collects resources from the host Kubernetes cluster.

    When the 'collect-dpu-clusters' option is enabled, it will automatically
    detect all DPU clusters (dpucluster resources) in the host cluster,
    retrieve their kubeconfigs from Kubernetes secrets, and collect resources
    from each child DPU cluster. The collected data is organized in a directory
    structure: dpu-clusters/{namespace}/{cluster-name}/
    """
    short_desc = 'DOCA Platform Framework resources and configurations'
    plugin_name = "doca_dpf"
    profiles = ('doca',)
    plugin_timeout = 900

    # DOCA Platform Framework related configuration files to collect
    config_files = []
    resources = [
        'pod',
        'bfb',
        'dpfoperatorconfig',
        'dpudeployment',
        'dpuflavor',
        'dpuservice',
        'dpuservicechain',
        'dpuserviceconfiguration',
        'dpuservicecredentialrequest',
        'dpuserviceinterface',
        'dpuserviceipam',
        'dpuservicetemplate',
        'dpuset',
        'dpu',
        'dpucluster',
        'dpudevice',
        'dpudiscovery',
        'dpunodemaintenance',
        'dpunode',
        'servicechain',
        'servicechainset',
        'serviceinterface',
        'serviceinterfaceset',
        # storage related custom resources
        'dpustoragepolicy',
        'dpustoragevendor',
        'dpuvolumeattachment',
        'dpuvolume',
        # vpc related custom resources
        'dpuvirtualnetwork',
        'dpuvpc',
        'isolationclass',
        # nv-ipam custom resources
        'cidrpool',
        'ippool',
        # argocd custom resources
        'application',
        'appproject',
        # kamaji custom resources
        'tenantcontrolplane',
    ]

    option_list = [
        PluginOpt('all', default=True,
                  desc='collect all namespace output separately'),
        PluginOpt('describe', default=False,
                  desc='collect describe output of all resources'),
        PluginOpt('collect-dpu-clusters', default=True,
                  desc='collect resources from DPU child clusters')
    ]

    kube_cmd = "kubectl"

    def set_kubeconfig(self):
        if os.environ.get('KUBECONFIG'):
            return
        for _kconf in self.files:
            if self.path_exists(_kconf):
                self.kube_cmd += f" --kubeconfig={_kconf}"
                break

    def check_is_master(self):
        """ Check if this is the master node """
        return any(self.path_exists(f) for f in self.files)

    def setup(self):
        # Copy the specified configuration files
        self.add_copy_spec(self.config_files)

        # We can only grab kubectl output from the master
        if not self.check_is_master():
            return

        # Collect host cluster resources
        self.collect_per_resource_details()

        # Collect DPU cluster resources if enabled
        if self.get_option('collect-dpu-clusters'):
            self._collect_all_dpu_clusters()

    def collect_per_resource_details(self):
        """ Collect details about each resource in all namespaces """
        # get all namespaces in use
        kns = self.collect_cmd_output(f'{self.kube_cmd} get namespaces',
                                      subdir='cluster-info')
        # namespace is the 1st word on line, until the line has spaces only
        kn_output = kns['output'].splitlines()[1:]
        knsps = [n.split()[0] for n in kn_output if n and len(n.split())]

        for nspace in knsps:
            knsp = f'--namespace={nspace}'
            if self.get_option('all'):
                k_cmd = f'{self.kube_cmd} get -o json {knsp}'

                for res in self.resources:
                    self.add_cmd_output(
                        f'{k_cmd} {res}',
                        subdir=f'cluster-info/{nspace}'
                    )

            if self.get_option('describe'):
                # need to drop json formatting for this
                k_cmd = f'{self.kube_cmd} {knsp}'
                for res in self.resources:
                    ret = self.exec_cmd(f'{k_cmd} get {res}')
                    if ret['status'] == 0:
                        k_list = [k.split()[0] for k in
                                  ret['output'].splitlines()[1:]]
                        for item in k_list:
                            k_cmd = f'{self.kube_cmd} {knsp}'
                            self.add_cmd_output(
                                f'{k_cmd} describe {res} {item}',
                                subdir=f'cluster-info/{nspace}/{res}'
                            )

    def _discover_dpu_clusters(self):
        """Discover all dpucluster objects in the host cluster.

        Returns a list of dicts with cluster name, namespace, and
        kubeconfig secret name.
        """
        result = self.collect_cmd_output(
            f"{self.kube_cmd} get dpucluster -A -o json",
            subdir='cluster-info'
        )

        if result['status'] != 0:
            return []

        try:
            data = json.loads(result['output'])
            clusters = []
            for item in data.get('items', []):
                cluster_name = item['metadata']['name']
                namespace = item['metadata']['namespace']
                kubeconfig = item.get('spec', {}).get('kubeconfig')

                # Skip clusters without kubeconfig specified
                if not kubeconfig:
                    continue

                clusters.append({
                    'name': cluster_name,
                    'namespace': namespace,
                    'kubeconfig': kubeconfig
                })

            return clusters
        except (json.JSONDecodeError, KeyError) as e:
            self._log_error(f"Failed to parse dpucluster data: {e}")
            return []

    def _collect_dpu_cluster_resources(self, cluster_info):
        """Collect resources from a single DPU cluster.

        cluster_info: Dict with 'name', 'namespace', and 'kubeconfig' keys
        """
        cluster_name = cluster_info['name']
        namespace = cluster_info['namespace']
        # Get secret name from dpucluster spec.kubeconfig
        secret_name = cluster_info['kubeconfig']
        subdir_base = f'dpu-clusters/{namespace}/{cluster_name}'

        # Create unique temp kubeconfig path
        mktemp_ret = self.exec_cmd('mktemp /tmp/sos-dpu-kc.XXXXXX')
        if mktemp_ret['status'] != 0:
            self._log_error(
                f"Failed to create temp kubeconfig for {cluster_name}"
            )
            return
        kc_path = mktemp_ret['output'].strip()
        self._log_debug(f"Created temp kubeconfig at: {kc_path}")

        # Extract base64-encoded kubeconfig from secret
        extract_cmd = (
            f"{self.kube_cmd} get secret {secret_name} -n {namespace} "
            f"-o jsonpath='{{.data.admin\\.conf}}'"
        )
        extract_result = self.exec_cmd(extract_cmd)
        kubeconfig_b64 = extract_result['output'].strip()

        if extract_result['status'] != 0 or not kubeconfig_b64:
            self._log_error(
                f"Failed to extract kubeconfig from secret "
                f"{secret_name} in namespace {namespace}"
            )
            self._log_error(
                f"Command output: {extract_result.get('output', 'N/A')}"
            )
            return

        # Decode base64 data
        try:
            kubeconfig_content = base64.b64decode(
                kubeconfig_b64
            ).decode('utf-8')
        except Exception as e:
            self._log_error(f"Failed to decode kubeconfig base64 data: {e}")
            return

        # Write kubeconfig to temp file
        try:
            with open(kc_path, 'w') as f:
                f.write(kubeconfig_content)
        except IOError as e:
            self._log_error(f"Failed to write kubeconfig to {kc_path}: {e}")
            return

        dpu_kube_cmd = (
            f"kubectl --kubeconfig={kc_path} --request-timeout=10s"
        )
        self._log_debug(
            f"Fetching namespaces from DPU cluster {cluster_name}"
        )
        kns_result = self.collect_cmd_output(
            f"{dpu_kube_cmd} get namespaces -o json",
            subdir=subdir_base
        )

        if kns_result['status'] != 0:
            self._log_error(
                f"Failed to get namespaces from DPU cluster {cluster_name}"
            )
            self._log_error(
                f"Command output: {kns_result.get('output', 'N/A')}"
            )
            return

        try:
            ns_data = json.loads(kns_result['output'])
            namespaces = [
                n['metadata']['name'] for n in ns_data.get('items', [])
            ]
        except (json.JSONDecodeError, KeyError) as e:
            self._log_error(
                f"Failed to parse namespaces from DPU cluster "
                f"{cluster_name}: {e}"
            )
            return

        # Collect resources from each namespace
        for nspace in namespaces:
            self._log_debug(
                f"Collecting resources from namespace {nspace} "
                f"in DPU cluster {cluster_name}"
            )
            nspace_arg = f'--namespace={nspace}'
            if self.get_option('all'):
                k_cmd = (
                    f"{dpu_kube_cmd} get -o json {nspace_arg} "
                    f"--ignore-not-found"
                )
                for res in self.resources:
                    self.add_cmd_output(
                        f"{k_cmd} {res}",
                        subdir=f"{subdir_base}/{nspace}"
                    )

            if self.get_option('describe'):
                k_base = (
                    f"{dpu_kube_cmd} {nspace_arg} --ignore-not-found"
                )
                for res in self.resources:
                    ret = self.exec_cmd(f"{k_base} get {res}")
                    if ret['status'] == 0:
                        items = [
                            line.split()[0]
                            for line in ret['output'].splitlines()[1:]
                            if line.strip()
                        ]
                        for item in items:
                            self.add_cmd_output(
                                f"{k_base} describe {res} {item}",
                                subdir=f"{subdir_base}/{nspace}/{res}"
                            )

    def _collect_all_dpu_clusters(self):
        """Main orchestration method for DPU cluster collection."""
        clusters = self._discover_dpu_clusters()

        if not clusters:
            return

        for cluster in clusters:
            self._collect_dpu_cluster_resources(cluster)


class RedHatKubernetes(DocaDpf, RedHatPlugin):

    packages = KUBE_PACKAGES

    files = KUBECONFIGS

    services = KUBE_SVCS

    def check_enabled(self):
        # do not run at the same time as the openshift plugin
        if self.is_installed("openshift-hyperkube"):
            return False
        return super().check_enabled()

    def setup(self):
        self.set_kubeconfig()
        super().setup()


class UbuntuKubernetes(DocaDpf, UbuntuPlugin, DebianPlugin):

    packages = KUBE_PACKAGES

    files = KUBECONFIGS + (
        '/root/cdk/cdk_addons_kubectl_config',
        '/var/snap/microk8s/current/credentials/client.config',
    )

    services = KUBE_SVCS + (
        'snap.kubelet.daemon',
        'snap.kube-apiserver.daemon',
        'snap.kube-proxy.daemon',
        'snap.kube-scheduler.daemon',
        'snap.kube-controller-manager.daemon',
        # CDK
        'cdk.master.auth-webhook',
    )

    def setup(self):
        self.set_kubeconfig()

        if self.is_installed('microk8s'):
            self.kube_cmd = 'microk8s kubectl'

        self.config_files.extend([
            '/root/cdk/kubelet/config.yaml',
            '/root/cdk/audit/audit-policy.yaml',
        ])
        super().setup()


# vim: et ts=5 sw=4
