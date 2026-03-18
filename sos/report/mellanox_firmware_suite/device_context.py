class DeviceContext(object):
    def __init__(
        self,
        pci,
        primary,
        global_collector,
        provider,
        mst_device=None,
        fwctl=None
    ):
        self._mst_device = mst_device
        self._pci = pci
        self._fwctl = fwctl
        self._primary = primary
        self._global_collector = global_collector
        self._provider = provider
        self._bdf = pci.replace(":", "").replace(".", "")
        self.cache = {}

    @property
    def mst_device(self):
        return self._mst_device

    @property
    def fwctl(self):
        return self._fwctl

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

    @property
    def effective_device(self):
        """
        Device path for CLI ``-d`` arguments.

        Resolution order:
            - fwctl (set by @supports_fwctl),
            - mst_device,
            - pci
        """

        if hasattr(self, "_effective_device"):
            return self._effective_device

        if self.mst_device is not None:
            return self.mst_device

        return self.pci
