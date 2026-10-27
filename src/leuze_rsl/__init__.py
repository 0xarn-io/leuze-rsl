"""leuze_rsl -- Python driver for Leuze laser scanner measurement data.

Two independent halves:

* :class:`RSL235Udt` receives the **UDP data telegrams** that RSL 200 / RSL
  400 safety laser scanners (e.g. the RSL 235) push to a configured
  destination -- distances, signal strengths, beam geometry and the safety
  status profile, decoded per the Leuze "RSL 200 / RSL 400 UDP
  specification" (50130122).  This is the verified RSL 235 interface.
* :class:`RodScanner` is a client for the **ROD-300-500 protocol** (TCP
  command interface + ``LEUZ`` MDI packets) of Leuze ROD 308/508 navigation
  scanners, reverse engineered from Leuze's ROD x08 ROS2 driver.  (``RSL235``
  is a deprecated alias of this class.)

Both ship with protocol simulators (:mod:`leuze_rsl.simulator`).
"""

from .driver import RSL235, ErrorLogEntry, RodScanner, ScannerConfig, ScannerStatus
from .errors import (
    CommandError,
    CommandTimeoutError,
    NotConnectedError,
    ProtocolError,
    ReceiverStoppedError,
    RSL235Error,
    ScannerConnectionError,
    ScanTimeoutError,
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
    DEFAULT_GEOMETRY,
    DEFAULT_UDT_PORT,
    GEOMETRY,
    NO_ECHO_DISTANCE_MM,
    BeamGeometry,
    MeasurementContour,
    RSL235Udt,
    ScannerFamily,
    StatusProfile,
    UdtAssembler,
    UdtFrame,
    UdtScan,
    UdtStats,
)

__version__ = "0.4.0"

__all__ = [
    # UDP data telegrams ("UDT") -- what RSL 200 / RSL 400 hardware pushes
    "RSL235Udt",
    "UdtScan",
    "UdtAssembler",
    "UdtFrame",
    "UdtStats",
    "StatusProfile",
    "MeasurementContour",
    "ScannerFamily",
    "BeamGeometry",
    "GEOMETRY",
    "DEFAULT_GEOMETRY",
    "DEFAULT_UDT_PORT",
    "NO_ECHO_DISTANCE_MM",
    # ROD-300-500 protocol (TCP command interface + LEUZ MDI packets)
    "RodScanner",
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
    "ReceiverStoppedError",
    "ScanTimeoutError",
    "CommandTimeoutError",
    "CommandError",
    "ProtocolError",
    "__version__",
]
