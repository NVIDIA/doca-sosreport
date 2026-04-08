from .system_collector import SystemCollector
from .firmware_collector import FirmwareCollector
from .cable_collector import CableCollector
from .ppcc_collector import PPCCCollector


class CollectorManager(object):
    def __init__(self, plugin, device_contexts):
        self.plugin = plugin
        self.device_contexts = device_contexts

    def collect_all(self):
        self.collect_system_info()
        self.collect_firmware_info()
        self.collect_cable_info()
        self.collect_ppcc_info()

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

    def collect_ppcc_info(self):
        for ctx in self.device_contexts:
            PPCCCollector().run(self.plugin, ctx)
