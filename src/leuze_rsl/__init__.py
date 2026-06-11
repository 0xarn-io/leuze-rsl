"""leuze_rsl -- Python driver for the Leuze RSL 235 measurement data output.

Reads the scanner's UDP data telegrams ("UDT" / MDI packets) and exposes
them as :class:`Scan` objects, plus the full TCP command interface for
configuration and status.  Protocol reverse engineered from Leuze's official
ROD x08 ROS2 driver (the RSL 235 data output speaks the same
"ROD-300-500 communication protocol").
"""

from .driver import RSL235, ErrorLogEntry, ScannerConfig, ScannerStatus
from .errors import (
    CommandError,
    CommandTimeoutError,
    NotConnectedError,
    ProtocolError,
    RSL235Error,
    ScannerConnectionError,
)
from .parser import AssemblerStats, Scan, ScanAssembler
from .protocol import (
    DEFAULT_PORT,
    INTENSITY_MIN_VALID,
    FilterType,
    MdiHeader,
    MdiPacket,
    MdiPacketType,
    MdiProtocol,
    Resolution,
    ScanDirection,
    WindowCalibration,
)
from .udt import (
    DEFAULT_UDT_PORT,
    NO_ECHO_DISTANCE_MM,
    MeasurementContour,
    RSL235Udt,
    StatusProfile,
    UdtAssembler,
    UdtFrame,
    UdtScan,
    UdtStats,
)

__version__ = "0.2.0"

__all__ = [
    # UDP data telegrams ("UDT") -- what RSL 235 hardware pushes
    "RSL235Udt",
    "UdtScan",
    "UdtAssembler",
    "UdtFrame",
    "UdtStats",
    "StatusProfile",
    "MeasurementContour",
    "DEFAULT_UDT_PORT",
    "NO_ECHO_DISTANCE_MM",
    # ROD-300-500 protocol (TCP command interface + LEUZ MDI packets)
    "RSL235",
    "Scan",
    "ScanAssembler",
    "AssemblerStats",
    "ScannerConfig",
    "ScannerStatus",
    "ErrorLogEntry",
    "MdiHeader",
    "MdiPacket",
    "MdiProtocol",
    "MdiPacketType",
    "Resolution",
    "ScanDirection",
    "FilterType",
    "WindowCalibration",
    "DEFAULT_PORT",
    "INTENSITY_MIN_VALID",
    # errors
    "RSL235Error",
    "ScannerConnectionError",
    "NotConnectedError",
    "CommandTimeoutError",
    "CommandError",
    "ProtocolError",
    "__version__",
]
