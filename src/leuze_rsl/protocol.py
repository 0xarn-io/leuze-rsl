"""Wire-protocol definitions of the Leuze ROD-300-500 communication protocol.

This is the protocol of the Leuze **ROD 308 / ROD 508** navigation scanners
(ROD x08).  It is *not* what an RSL 235 speaks -- the RSL safety scanners
push UDP data telegrams, see :mod:`leuze_rsl.udt`.  Everything in this
module was reverse engineered from Leuze's official ROD x08 ROS2 driver
(``leuze_rod_ros2_drivers``, Apache-2.0, https://github.com/thesensorpeople/
leuze_rod_ros2_drivers); no Leuze code is included in this package.

The protocol has two parts:

* A TCP **command interface** (default port 3050).  Commands are short ASCII
  strings framed by STX (0x02) and ETX (0x03), e.g. ``<STX>cWN SendMDI<ETX>``.
  Replies use ``cWA``/``cRA`` followed by space separated decimal values.

* **MDI packets** ("measurement data interface") carrying distances and
  optionally signal strengths.  They are pushed by the scanner either as UDP
  datagrams (to the command client's IP, same port number) or interleaved on
  the TCP command socket.  All multi-byte fields are big-endian.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import List, Optional, Sequence, Tuple, Union

from .errors import ProtocolError

__all__ = [
    "STX", "ETX", "DEFAULT_PORT", "MAX_RESPONSE_LENGTH",
    "VERB_WRITE", "VERB_READ", "ACK_WRITE", "ACK_READ",
    "CommandResponse", "frame_command", "parse_response", "find_response_start",
    "MdiProtocol", "MdiPacketType", "ScanDirection", "Resolution", "FilterType",
    "WindowCalibration", "ANGLE_MIN_CDEG", "ANGLE_MAX_CDEG",
    "INTENSITY_MIN_VALID", "INTENSITY_MAX",
    "SYNC", "HEADER_FORMAT", "HEADER_SIZE", "MdiHeader", "MdiPacket",
    "parse_packet", "build_packet", "expected_spots",
]

# ---------------------------------------------------------------------------
# Command interface framing
# ---------------------------------------------------------------------------

STX = b"\x02"
ETX = b"\x03"

#: Default TCP command port; the same port number is used for the UDP
#: measurement data (the scanner sends datagrams to <client ip>:<port>).
DEFAULT_PORT = 3050

#: Maximum sensible length of a command-interface message before we declare
#: a framing error.  Must comfortably hold a GetELog reply (21 values); the
#: reference driver's 128-byte TX limit does not apply to responses.
MAX_RESPONSE_LENGTH = 1024

# Write commands (request verb "cWN", acknowledged with "cWA <name>").
CMD_SEND_MDI = "SendMDI"
CMD_STOP_MDI = "StopMDI"

# Read commands (request verb "cRN", answered with "cRA <name> <values...>").
CMD_GET_PROTO = "GetProto"
CMD_GET_PTYPE = "GetPType"
CMD_GET_RESOL = "GetResol"
CMD_GET_DIR = "GetDir"
CMD_GET_RANGE = "GetRange"
CMD_GET_SKIP = "GetSkip"
CMD_GET_CONT = "GetCont"
CMD_GET_WINSTAT = "GetWinStat"
CMD_GET_VER = "GetVer"
CMD_GET_TEM = "GetTem"
CMD_GET_ELOG = "GetELog"
CMD_GET_HOURS = "GetHours"
CMD_GET_WCALIB = "GetWCalib"
CMD_GET_FILTER = "GetFilter"
CMD_GET_ECODE = "GetECode"
CMD_GET_TXMDI = "GetTxMDI"

VERB_WRITE = "cWN"
VERB_READ = "cRN"
ACK_WRITE = "cWA"
ACK_READ = "cRA"

_COMMAND_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")
_DECIMAL = re.compile(r"^-?[0-9]+$")


def frame_command(verb: str, name: str) -> bytes:
    """Frame a command for the TCP command interface.

    >>> frame_command("cWN", "SendMDI")
    b'\\x02cWN SendMDI\\x03'
    """
    if verb not in (VERB_WRITE, VERB_READ):
        raise ValueError("unknown command verb %r" % verb)
    if not _COMMAND_NAME.match(name):
        raise ValueError("invalid command name %r" % name)
    return STX + verb.encode("ascii") + b" " + name.encode("ascii") + ETX


@dataclass(frozen=True)
class CommandResponse:
    """A parsed command-interface response (``cWA``/``cRA`` message)."""

    kind: str               #: "cWA" for write acks, "cRA" for read replies
    name: str               #: echoed command name, e.g. "GetRange"
    values: Tuple[int, ...]  #: decimal values following the name
    raw: str                #: the full response body (without STX/ETX)


def parse_response(body: Union[bytes, bytearray]) -> CommandResponse:
    """Parse the body of a response (the bytes between STX and ETX).

    The body is ``<kind> <name>[ <value>...]``: whitespace-separated tokens
    (the reference driver splits on single spaces; surrounding or repeated
    whitespace is tolerated here) whose values are plain decimal integers
    with an optional leading minus.  Raises :class:`ProtocolError` (a
    ``ValueError``) otherwise.
    """
    try:
        text = bytes(body).decode("ascii")
    except UnicodeDecodeError:
        raise ProtocolError("non-ASCII response body: %r" % (bytes(body),)) from None
    tokens = text.split()
    if len(tokens) < 2 or tokens[0] not in (ACK_READ, ACK_WRITE) or not _COMMAND_NAME.match(tokens[1]):
        raise ProtocolError("not a command interface response: %r" % text)
    values: List[int] = []
    for tok in tokens[2:]:
        if not _DECIMAL.match(tok):
            raise ProtocolError("non-numeric value in response: %r" % text)
        values.append(int(tok))
    return CommandResponse(kind=tokens[0], name=tokens[1], values=tuple(values), raw=text)


#: Byte values allowed in position 2 of a response signature ("R" or "W").
_RESPONSE_KINDS = frozenset(b"RW")


def find_response_start(buf: Union[bytes, bytearray], start: int = 0) -> int:
    """Find the next command-interface response signature in ``buf``.

    The signature is the 5-byte sequence ``STX 'c' ('R'|'W') 'A' ' '``.
    Returns the index of the STX byte, or -1 if no *complete* signature is
    present (a partially received signature at the very end of the buffer
    does not count -- callers keep a small tail for that case).
    """
    i = buf.find(STX, start)
    while i != -1:
        if i + 5 > len(buf):
            return -1
        if (buf[i + 1] == 0x63            # 'c'
                and buf[i + 2] in _RESPONSE_KINDS
                and buf[i + 3] == 0x41    # 'A'
                and buf[i + 4] == 0x20):  # ' '
            return i
        i = buf.find(STX, i + 1)
    return -1


# ---------------------------------------------------------------------------
# Enumerations (values as used on the wire)
# ---------------------------------------------------------------------------


class MdiProtocol(IntEnum):
    """Transport used by the scanner to push measurement data (GetProto)."""

    UDP = 0
    TCP = 1


class MdiPacketType(IntEnum):
    """Payload layout of the measurement packets (GetPType / header field)."""

    DISTANCE = 0
    DISTANCE_AND_INTENSITY = 1


class ScanDirection(IntEnum):
    """Data output direction (GetDir)."""

    CLOCKWISE = 0
    COUNTERCLOCKWISE = 1


class Resolution(IntEnum):
    """Angular resolution / scan frequency setting (GetResol)."""

    RES_0200_AT_80HZ = 0
    RES_0100_AT_40HZ = 1
    RES_0050_AT_20HZ = 2
    RES_0025_AT_10HZ = 3
    RES_0200_AT_50HZ = 4

    @property
    def degrees(self) -> float:
        """Angular spacing between two native scan spots in degrees."""
        return _RESOLUTION_TABLE[self][0]

    @property
    def frequency_hz(self) -> float:
        """Scan (head rotation) frequency in Hz."""
        return _RESOLUTION_TABLE[self][1]

    @property
    def scan_time_s(self) -> float:
        """Duration of one full scan in seconds."""
        return 1.0 / self.frequency_hz


_RESOLUTION_TABLE = {
    Resolution.RES_0200_AT_80HZ: (0.200, 80.0),
    Resolution.RES_0100_AT_40HZ: (0.100, 40.0),
    Resolution.RES_0050_AT_20HZ: (0.050, 20.0),
    Resolution.RES_0025_AT_10HZ: (0.025, 10.0),
    Resolution.RES_0200_AT_50HZ: (0.200, 50.0),
}


class FilterType(IntEnum):
    """Measurement filter type (GetFilter)."""

    MEDIAN = 0
    AVERAGE = 1
    MAX = 2
    COMBO = 3


class WindowCalibration(IntEnum):
    """Window calibration state (GetWCalib)."""

    PROCESSING = 0
    DONE = 1
    FAILED = 3


# Valid range of the configured scan angles, in 0.01 degree units.
ANGLE_MIN_CDEG = -13760
ANGLE_MAX_CDEG = 13760

# Intensity (signal strength) values below this indicate an invalid /
# undefined measurement (reference driver: "valid range is 32 - 4095").
INTENSITY_MIN_VALID = 32
INTENSITY_MAX = 4095


def expected_spots(angle_min_cdeg: int, angle_max_cdeg: int,
                   resolution_deg: float, skip_spots: int = 0) -> int:
    """Spots per scan implied by the settings (shared by driver and simulator).

    ``1 + floor(span / (resolution * (skip_spots + 1)))``: the spots at
    ``angle_min + k * step`` that lie within the configured range, computed
    in integer thousandths of a degree so that both sides agree exactly.
    """
    if angle_max_cdeg <= angle_min_cdeg:
        raise ValueError("angle_max must be greater than angle_min")
    if skip_spots < 0:
        raise ValueError("skip_spots must be >= 0")
    step_mdeg = round(resolution_deg * 1000) * (skip_spots + 1)
    if step_mdeg <= 0:
        raise ValueError("resolution must be > 0")
    span_mdeg = (angle_max_cdeg - angle_min_cdeg) * 10
    return 1 + span_mdeg // step_mdeg


# ---------------------------------------------------------------------------
# MDI measurement packets
# ---------------------------------------------------------------------------

#: Synchronisation pattern at the start of every MDI packet.
SYNC = b"LEUZ"

#: Packed big-endian header layout (31 bytes), matching ``PacketHeader`` in
#: the reference driver's common.h.
HEADER_FORMAT = ">4sBHHHHHBBHHiiH"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
assert HEADER_SIZE == 31

_HEADER_STRUCT = struct.Struct(HEADER_FORMAT)

Buffer = Union[bytes, bytearray, memoryview]


@dataclass(frozen=True)
class MdiHeader:
    """Header of one MDI measurement packet."""

    packet_type: int     #: 0 = distances only, 1 = distances + intensities
    packet_size: int     #: total packet size in bytes, including this header
    reserve_a: int
    reserve_b: int
    reserve_c: int
    packet_number: int   #: sequence number since scanner power-up (wraps at 2**16)
    total_number: int    #: number of packets that make up one full scan
    sub_number: int      #: 1-based index of this packet within the scan
    scan_freq: int       #: scan frequency [Hz]
    scan_spots: int      #: number of measurement spots in *this* packet
    first_angle: int     #: absolute angle of the first spot [1/1000 deg]
    delta_angle: int     #: angle between consecutive spots [1/1000 deg]
    timestamp: int       #: packet timestamp [ms] (wraps at 2**16)

    @classmethod
    def from_bytes(cls, data: Buffer, offset: int = 0) -> "MdiHeader":
        """Decode a header; raises :class:`ProtocolError` on short data or bad sync."""
        if len(data) - offset < HEADER_SIZE:
            raise ProtocolError("MDI header needs %d bytes, got %d"
                                % (HEADER_SIZE, max(0, len(data) - offset)))
        (sync, packet_type, packet_size, res_a, res_b, res_c, packet_number,
         total_number, sub_number, scan_freq, scan_spots, first_angle,
         delta_angle, timestamp) = _HEADER_STRUCT.unpack_from(data, offset)
        if sync != SYNC:
            raise ProtocolError("bad sync pattern: %r" % (sync,))
        return cls(packet_type, packet_size, res_a, res_b, res_c,
                   packet_number, total_number, sub_number, scan_freq,
                   scan_spots, first_angle, delta_angle, timestamp)

    def to_bytes(self) -> bytes:
        try:
            return _HEADER_STRUCT.pack(
                SYNC, self.packet_type, self.packet_size, self.reserve_a,
                self.reserve_b, self.reserve_c, self.packet_number,
                self.total_number, self.sub_number, self.scan_freq,
                self.scan_spots, self.first_angle, self.delta_angle,
                self.timestamp)
        except struct.error as exc:
            raise ValueError("header field out of range: %s" % exc) from None

    def expected_size(self) -> int:
        """Packet size implied by ``scan_spots`` and ``packet_type``."""
        per_spot = 4 if self.packet_type == MdiPacketType.DISTANCE_AND_INTENSITY else 2
        return HEADER_SIZE + self.scan_spots * per_spot


@dataclass(frozen=True)
class MdiPacket:
    """One parsed MDI measurement packet (header + payload)."""

    header: MdiHeader
    distances_mm: Tuple[int, ...]            #: distances [mm]; 0 = no valid echo
    intensities: Optional[Tuple[int, ...]]   #: signal strengths, or None

    def angles_mdeg(self) -> List[int]:
        """Absolute angle of every spot in this packet [1/1000 deg]."""
        first, delta = self.header.first_angle, self.header.delta_angle
        return [first + i * delta for i in range(self.header.scan_spots)]


def parse_packet(data: Buffer, offset: int = 0) -> MdiPacket:
    """Parse one complete MDI packet starting at ``offset``.

    Raises :class:`ProtocolError` if the header is invalid, its size field
    disagrees with ``scan_spots``/``packet_type``, or ``data`` is too short.
    """
    header = MdiHeader.from_bytes(data, offset)
    if header.packet_size != header.expected_size():
        raise ProtocolError("packet_size %d does not match %d spots of type %d"
                            % (header.packet_size, header.scan_spots, header.packet_type))
    if len(data) - offset < header.packet_size:
        raise ProtocolError("MDI packet needs %d bytes, got %d"
                            % (header.packet_size, len(data) - offset))
    n = header.scan_spots
    distances = struct.unpack_from(">%dH" % n, data, offset + HEADER_SIZE)
    intensities: Optional[Tuple[int, ...]] = None
    if header.packet_type == MdiPacketType.DISTANCE_AND_INTENSITY:
        intensities = struct.unpack_from(
            ">%dH" % n, data, offset + HEADER_SIZE + 2 * n)
    return MdiPacket(header=header, distances_mm=distances, intensities=intensities)


def build_packet(*,
                 packet_type: int,
                 packet_number: int,
                 total_number: int,
                 sub_number: int,
                 scan_freq: int,
                 first_angle_mdeg: int,
                 delta_angle_mdeg: int,
                 timestamp_ms: int,
                 distances_mm: Sequence[int],
                 intensities: Optional[Sequence[int]] = None) -> bytes:
    """Serialise one MDI packet (used by the simulator and the tests).

    Raises ``ValueError`` for values the header cannot represent.
    """
    n = len(distances_mm)
    if not 1 <= total_number <= 255:
        raise ValueError("total_number must be in 1..255")
    if not 1 <= sub_number <= total_number:
        raise ValueError("sub_number must be in 1..total_number")
    if HEADER_SIZE + 4 * n > 0xFFFF:
        raise ValueError("too many spots for one packet: %d" % n)
    try:
        if packet_type == MdiPacketType.DISTANCE_AND_INTENSITY:
            if intensities is None or len(intensities) != n:
                raise ValueError("intensities must match distances for packet type 1")
            payload = struct.pack(">%dH" % n, *distances_mm) + \
                struct.pack(">%dH" % n, *intensities)
        else:
            payload = struct.pack(">%dH" % n, *distances_mm)
    except struct.error as exc:
        raise ValueError("distances/intensities must be integers in 0..65535: %s" % exc) from None
    header = MdiHeader(
        packet_type=packet_type,
        packet_size=HEADER_SIZE + len(payload),
        reserve_a=0, reserve_b=0, reserve_c=0,
        packet_number=packet_number & 0xFFFF,
        total_number=total_number,
        sub_number=sub_number,
        scan_freq=scan_freq,
        scan_spots=n,
        first_angle=first_angle_mdeg,
        delta_angle=delta_angle_mdeg,
        timestamp=timestamp_ms & 0xFFFF,
    )
    return header.to_bytes() + payload
