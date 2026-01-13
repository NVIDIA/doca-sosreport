"""
Factory and enums for firmware-collection wrappers.

The collectors choose between MFT and MSTFlint providers based on the
`DeviceContext.provider` value.

Each wrapper is instantiated once per device context via `get_tool`,
so command results can leverage the shared `BaseTool` caching and the
plugin instance (which supplies `exec_cmd` and `_collect_cmd_output`).

If you add a new tool, register it in `TOOLS_MAP` to make it available
to the collectors.
"""

from enum import Enum

from .MFT.mst import MstTool
from .MFT.flint import FlintTool
from .MFT.mstdump import MstdumpTool
from .MFT.resourcedump import ResourcedumpTool
from .MFT.mlxdump import MlxdumpTool
from .MFT.mlxconfig import MlxconfigTool
from .MFT.mlxreg import MlxregTool
from .MFT.mget_temp import MgetTempTool
from .MFT.mlxlink import MlxlinkTool

from .MSTFlint.mstdevices_info import MstDevicesInfoTool
from .MSTFlint.mstflint import MstFlintTool
from .MSTFlint.mstregdump import MstregdumpTool
from .MSTFlint.mstresourcedump import MstresourcedumpTool
from .MSTFlint.mstconfig import MstconfigTool
from .MSTFlint.mstreg import MstregTool
from .MSTFlint.mstmget_temp import MstmgetTempTool
from .MSTFlint.mstlink import MstLinkTool


class FirmwareTools(str, Enum):
    MFT_TOOL = "mft"
    MSTFLINT_TOOL = "mstflint"


class MftTools(str, Enum):
    MST = MstTool.__name__
    FLINT = FlintTool.__name__
    MSTDUMP = MstdumpTool.__name__
    RESOURCEDUMP = ResourcedumpTool.__name__
    MLXDUMP = MlxdumpTool.__name__
    MLXCONFIG = MlxconfigTool.__name__
    MLXREG = MlxregTool.__name__
    MGET_TEMP = MgetTempTool.__name__
    MLXLINK = MlxlinkTool.__name__


class MstFlintTools(str, Enum):
    DEVICES_INFO = MstDevicesInfoTool.__name__
    MSTFLINT = MstFlintTool.__name__
    MSTREGDUMP = MstregdumpTool.__name__
    MSTRESOURCEDUMP = MstresourcedumpTool.__name__
    MSTCONFIG = MstconfigTool.__name__
    MSTREG = MstregTool.__name__
    MSTMGET_TEMP = MstmgetTempTool.__name__
    MSTLINK = MstLinkTool.__name__


TOOLS_MAP = {
    MftTools.MST: MstTool,
    MftTools.FLINT: FlintTool,
    MftTools.MSTDUMP: MstdumpTool,
    MftTools.RESOURCEDUMP: ResourcedumpTool,
    MftTools.MLXDUMP: MlxdumpTool,
    MftTools.MLXCONFIG: MlxconfigTool,
    MftTools.MLXREG: MlxregTool,
    MftTools.MGET_TEMP: MgetTempTool,
    MftTools.MLXLINK: MlxlinkTool,
    MstFlintTools.DEVICES_INFO: MstDevicesInfoTool,
    MstFlintTools.MSTFLINT: MstFlintTool,
    MstFlintTools.MSTREGDUMP: MstregdumpTool,
    MstFlintTools.MSTRESOURCEDUMP: MstresourcedumpTool,
    MstFlintTools.MSTCONFIG: MstconfigTool,
    MstFlintTools.MSTREG: MstregTool,
    MstFlintTools.MSTMGET_TEMP: MstmgetTempTool,
    MstFlintTools.MSTLINK: MstLinkTool,
}

_TOOL_CACHE = {}


def get_tool(name, plugin, ctx):
    cache_key = f"{id(ctx)}_{name}"

    if name not in TOOLS_MAP:
        raise ValueError(f"Unknown tool: '{name}'")

    if cache_key not in _TOOL_CACHE:
        _TOOL_CACHE[cache_key] = TOOLS_MAP[name](plugin, ctx)

    return _TOOL_CACHE[cache_key]
