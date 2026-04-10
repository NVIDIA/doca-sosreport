from .system_collector import SystemCollector
from .firmware_collector import FirmwareCollector
from .cable_collector import CableCollector
from .pcc_collector import PccCollector


class CollectorManager(object):
    def __init__(self, plugin, device_contexts):
        self.plugin = plugin
        self.device_contexts = device_contexts

    def collect_all(self):
        self.collect_system_info()
        self.collect_firmware_info()
        self.collect_cable_info()
        self.collect_pcc_info()

    def collect_system_info(self):
        for ctx in self.device_contexts:
            if ctx.global_collector:
                SystemCollector().run(self.plugin, ctx)

    def collect_firmware_info(self):
        for ctx in self.device_contexts:
            if ctx.primary:
                FirmwareCollector().run(self.plugin, ctx)

    def collect_cable_info(self):
        for ctx in self.device_contexts:
            CableCollector().run(self.plugin, ctx)

    def collect_pcc_info(self):
        if not self.plugin.get_option("pcc", default=False):
            return
        for ctx in self.device_contexts:
            PccCollector().run(self.plugin, ctx)
