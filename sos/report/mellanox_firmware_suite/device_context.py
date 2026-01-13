class DeviceContext(object):
    def __init__(self, device, pci, primary, global_collector, provider):
        self._device = device
        self._pci = pci
        self._primary = primary
        self._global_collector = global_collector
        self._provider = provider
        self._bdf = pci.replace(":", "").replace(".", "")
        self.cache = {}

    @property
    def device(self):
        return self._device

    @property
    def pci(self):
        return self._pci

    @property
    def primary(self):
        return self._primary

    @property
    def global_collector(self):
        return self._global_collector

    @property
    def provider(self):
        return self._provider

    @property
    def bdf(self):
        return self._bdf
