"""Passive receiver for Leuze RSL UDP data telegrams ("UDT").

This is the protocol the RSL 235 (and the whole RSL 200 / RSL 400 family)
speaks on the wire: the safety sensor *pushes* UDP datagrams to a
destination IP/port configured in Sensor Studio (SETTINGS > Data
telegrams) -- there is no TCP command channel and nothing to request.  The
format is documented in the Leuze "RSL 200 / RSL 400 UDP specification",
document 50130122 (EN 2024/10/01), and has been verified against RSL 235
hardware.

Every datagram starts with a 20-byte frame (all fields little-endian)::

    offset  size  field
    0       4     total_length   -- length of the whole datagram
    4       1     h1_size        -- 8
    5       1     follow_flag
    6       2     request_id
    8       4     header2        -- internal
    12      2     telegram_id    -- 1: extended status profile,
                                    6: distances, 3: distances + signal strength
    14      2     block          -- fragment number within the scan (0..65535)
    16      4     scan_number    -- scan cycle counter (wraps at 2**32)

* ID 1 (extended status profile), sent once per scan cycle before the
  measurement data: a status profile followed by the 8-byte *measurement
  contour description* (start index, stop index, index interval) which
  defines the beam count and angles of the measurement data.  The status
  profile layout depends on the device family and is identified by its
  first byte (spec tables 3.3 and 3.5):

  - type 21, **RSL 200** series (RSL 235): 28-byte profile, contour at
    payload offset 28 -> 56-byte datagram (exactly what RSL 235 hardware
    sends);
  - type 1, **RSL 400** series: 20-byte profile, contour at payload offset
    20, optionally followed by a 12-byte configuration signature.

* ID 6: n x u16 distance [mm].
* ID 3: n x (u16 distance [mm] + u16 signal strength [digits]).

A scan cycle's measurement data may span multiple datagrams ("blocks");
:class:`UdtAssembler` reassembles them and :class:`RSL235Udt` wraps the
whole thing in a background receiver thread.

Typical use::

    from leuze_rsl import RSL235Udt

    with RSL235Udt(port=3050) as receiver:        # the port configured in Sensor Studio
        scan = receiver.get_scan(timeout=5.0)
        print(scan.scan_number, scan.distances_mm[:5], scan.angles_deg()[:5])
"""

from __future__ import annotations

import logging
import math
import queue
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass
from enum import IntEnum
from functools import cached_property
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple, Union

from .errors import (
    ProtocolError,
    ReceiverStoppedError,
    ScannerConnectionError,
    ScanTimeoutError,
)

__all__ = [
    "UdtFrame",
    "ScannerFamily",
    "BeamGeometry",
    "StatusProfile",
    "MeasurementContour",
    "UdtScan",
    "UdtAssembler",
    "UdtStats",
    "RSL235Udt",
    "locate_contour",
    "FRAME_SIZE",
    "TELEGRAM_ID_STATUS",
    "TELEGRAM_ID_DISTANCE",
    "TELEGRAM_ID_DISTANCE_SIGNAL",
    "STATUS_PROFILE_TYPE_RSL200",
    "STATUS_PROFILE_TYPE_RSL400",
    "GEOMETRY",
    "DEFAULT_GEOMETRY",
    "DEFAULT_UDT_PORT",
    "NO_ECHO_DISTANCE_MM",
    "INDEX_RESOLUTION_DEG",
    "DEFAULT_ANGLE_AT_INDEX0_DEG",
]

log = logging.getLogger("leuze_rsl.udt")

#: Default local port to listen on (the destination port you enter in Sensor
#: Studio; the specification prescribes no particular number).
DEFAULT_UDT_PORT = 3050

TELEGRAM_ID_STATUS = 1            #: extended status profile
TELEGRAM_ID_DISTANCE_SIGNAL = 3   #: distance + signal strength per beam
TELEGRAM_ID_DISTANCE = 6          #: distance per beam

FRAME_SIZE = 20
_FRAME_STRUCT = struct.Struct("<IBBH4sHHI")
assert _FRAME_STRUCT.size == FRAME_SIZE

#: Status profile type byte (spec tables 3.3 / 3.5) per device family.
STATUS_PROFILE_TYPE_RSL200 = 21
STATUS_PROFILE_TYPE_RSL400 = 1

#: Length of the status profile (bytes) per profile type; the measurement
#: contour description follows immediately after it.
_PROFILE_LENGTH = {STATUS_PROFILE_TYPE_RSL200: 28, STATUS_PROFILE_TYPE_RSL400: 20}

CONTOUR_SIZE = 8
_CONTOUR_STRUCT = struct.Struct("<HHHH")

#: Distance value RSL 235 hardware sends for beams without a valid echo:
#: 65535 (0xFFFF, with a signal strength of 0xFFFF), observed in a capture
#: of 2026-10-27.  Earlier releases documented 32767, the top of the spec's
#: RSL 200 distance range; that value never occurred on hardware but is
#: still treated as invalid by :meth:`UdtScan.valid_mask`.
NO_ECHO_DISTANCE_MM = 65535


class ScannerFamily(IntEnum):
    """Device family, identified by the status profile type byte."""

    RSL400 = STATUS_PROFILE_TYPE_RSL400
    RSL200 = STATUS_PROFILE_TYPE_RSL200


@dataclass(frozen=True)
class BeamGeometry:
    """How measurement-contour beam *indices* map onto angles.

    ``angle_deg(index) = angle_at_index0_deg + index * index_step_deg``.

    The UDP specification only defines the index range (RSL 200: 0..1350,
    RSL 400: 0..2699); the angular step follows from the device's angular
    resolution (RSL 200: 0.2 deg, RSL 400: 0.1 deg) and the sign/offset from
    Leuze's own RSL 400 ROS driver, which maps index 0 to the counter-
    clockwise edge of a 270 deg field of view centred on the device front
    (indices increase clockwise; angles are counter-clockwise positive, as
    in a right-handed x-forward / y-left frame).  Verify the mapping once
    against a known target and override via :meth:`UdtScan.angles_deg` if
    your mounting differs.
    """

    index_step_deg: float      #: signed angular step per beam index (negative = clockwise)
    angle_at_index0_deg: float  #: angle of beam index 0
    max_index: int             #: highest beam index the device can transmit
    no_echo_mm: int            #: distance value the device sends for "no valid echo"
    max_valid_mm: int          #: largest distance that is a real measurement (spec range top - 1)

    # Leuze's RSL 400 ROS driver maps the reversed 2700 beams onto exactly
    # -135.0 .. +134.9 deg (index 2699 at -135.0); the defaults below centre
    # the beams symmetrically instead (+/-134.95), half a step apart from it.

    def angle_deg(self, index: int) -> float:
        return self.angle_at_index0_deg + index * self.index_step_deg


#: Per-family default beam geometry (see :class:`BeamGeometry`).  The RSL 200
#: no-echo value (65535) was observed on an RSL 235; the RSL 400 is assumed
#: to send the same (the top of its 0..65535 mm range).  ``max_valid_mm`` is
#: one below the spec's distance range top (RSL 200: 0..32767 mm, RSL 400:
#: 0..65535 mm), so both the no-echo value and the range top are invalid.
GEOMETRY: Dict[ScannerFamily, BeamGeometry] = {
    ScannerFamily.RSL200: BeamGeometry(index_step_deg=-0.2, angle_at_index0_deg=135.0,
                                       max_index=1350, no_echo_mm=65535, max_valid_mm=32766),
    ScannerFamily.RSL400: BeamGeometry(index_step_deg=-0.1, angle_at_index0_deg=134.95,
                                       max_index=2699, no_echo_mm=65535, max_valid_mm=65534),
}
#: Geometry assumed when the device family is not known (RSL 200 / RSL 235).
DEFAULT_GEOMETRY = GEOMETRY[ScannerFamily.RSL200]

#: Backwards-compatible aliases of the RSL 200 defaults: the *signed* angular
#: step per index (negative = clockwise) and the angle of index 0, i.e.
#: ``angles_deg(DEFAULT_ANGLE_AT_INDEX0_DEG, INDEX_RESOLUTION_DEG)`` equals
#: ``angles_deg()`` for an RSL 200 scan.
INDEX_RESOLUTION_DEG = DEFAULT_GEOMETRY.index_step_deg
DEFAULT_ANGLE_AT_INDEX0_DEG = DEFAULT_GEOMETRY.angle_at_index0_deg


@dataclass(frozen=True)
class UdtFrame:
    """The 20-byte frame preceding every UDP data telegram."""

    total_length: int
    h1_size: int
    follow_flag: int
    request_id: int
    header2: bytes
    telegram_id: int
    block: int
    scan_number: int

    @classmethod
    def from_bytes(cls, data: Union[bytes, bytearray, memoryview]) -> "UdtFrame":
        if len(data) < FRAME_SIZE:
            raise ProtocolError("UDT frame needs %d bytes, got %d" % (FRAME_SIZE, len(data)))
        (total_length, h1_size, follow_flag, request_id, header2,
         telegram_id, block, scan_number) = _FRAME_STRUCT.unpack_from(data, 0)
        return cls(total_length, h1_size, follow_flag, request_id, header2,
                   telegram_id, block, scan_number)

    def to_bytes(self) -> bytes:
        return _FRAME_STRUCT.pack(
            self.total_length, self.h1_size, self.follow_flag,
            self.request_id, self.header2, self.telegram_id, self.block,
            self.scan_number)


@dataclass(frozen=True)
class StatusProfile:
    """Decoded status profile of an ID 1 telegram.

    The layout is selected by :attr:`profile_type` (byte 0): 21 = RSL 200
    series (spec table 3.3, 28 bytes), 1 = RSL 400 series (table 3.5, 20
    bytes).  Fields that do not exist for a family are ``None``.  The
    "protective function A" view is unified: on the RSL 200 (which has one
    OSSD pair and one protective field) ``ossd_a`` / ``a_protective_violated``
    / ``a_warning_violated`` report its OSSD, protective field and warning
    field 1, and ``ossd_b`` / ``b_*`` are ``None``.

    ``raw`` always holds the full data block of the datagram (status profile
    + measurement contour + any trailer) for your own decoding.
    """

    profile_type: int                     #: byte 0: 21 = RSL 200, 1 = RSL 400
    family: Optional[ScannerFamily]       #: None for an unknown profile type
    profile_length: int                   #: 28 / 20; 0 if unknown
    operating_mode: int                   #: 0 not configured, 1 safety mode, 2 simulation mode
    error: bool                           #: collective message: error with switch-off
    alarm: bool                           #: collective message: warning without switch-off
    screen_contaminated: bool             #: optics cover contamination warning or error
    edm_error: bool                       #: EDM collection error
    field_selection_error: bool           #: field triple (RSL 200) / field pair (RSL 400) selection error
    ossd_a: bool                          #: OSSD state (RSL 200: the OSSD pair; RSL 400: function A)
    ossd_b: Optional[bool]                #: OSSD state, protective function B (RSL 400 only)
    parked: bool                          #: park request fulfilled
    scan_number: int                      #: scan counter embedded in the profile
    a_active: bool                        #: protective function A active/configured (RSL 200: always True)
    a_protective_violated: bool           #: active protective field (A) violated (False while inactive)
    a_warning_violated: bool              #: active warning field (A / RSL 200 warning field 1) violated
    b_active: Optional[bool]              #: RSL 400 only
    b_protective_violated: Optional[bool]  #: RSL 400 only
    b_warning_violated: Optional[bool]    #: RSL 400 only
    # -- RSL 200 specifics ------------------------------------------------
    screen_error: Optional[bool]          #: contamination error (switch-off)
    screen_warning: Optional[bool]        #: contamination warning
    warning_field_2_violated: Optional[bool]
    restart_interlock: Optional[bool]     #: start/restart interlock active
    field_triple: Optional[int]           #: selected field triple (1..32)
    inputs: Optional[int]                 #: control inputs IN1..IN8 as a bit mask (bit 0 = IN1)
    outputs: Optional[int]                #: outputs OUT1..OUT8 as a bit mask (bit 0 = OUT1)
    supply_voltage_raw: Optional[int]     #: VOLT field as sent, in 0.1 V (see :attr:`supply_voltage_v`)
    temperature_c: Optional[float]        #: device temperature [deg C]
    signature: Optional[int]              #: SAFE_SIG
    error_class: Optional[int]
    error_number: Optional[int]
    # -- RSL 400 specifics ------------------------------------------------
    estop_active: Optional[bool]          #: status of the inputs SE1/SE2 (E-STOP)
    estop_error: Optional[bool]           #: error with OSSD linkage / emergency stop monitoring
    a_bank: Optional[int]                 #: selected bank A (1..10)
    a_field_pair: Optional[int]           #: first selected field pair A (1..10)
    b_bank: Optional[int]
    b_field_pair: Optional[int]
    configuration_signature: Optional[bytes]  #: 8-byte signature trailer, when transmitted
    raw: bytes                            #: complete data block (status + contour + trailer)

    @property
    def supply_voltage_v(self) -> Optional[float]:
        """Supply voltage [V] (RSL 200 only; ``None`` for other profiles).

        The specification states the VOLT unit as 0.1 mV, which a 16-bit
        field cannot hold for a 24 V device; an RSL 235 on a 24 V supply
        sends 234, so the unit is 0.1 V (23.4 V behind the input diode).
        """
        return None if self.supply_voltage_raw is None else self.supply_voltage_raw / 10.0

    @classmethod
    def from_bytes(cls, data: Union[bytes, bytearray, memoryview]) -> "StatusProfile":
        """Decode the data block of an ID 1 telegram (everything after the frame)."""
        data = bytes(data)
        if len(data) < 3:
            raise ProtocolError("status profile needs at least 3 bytes, got %d" % len(data))
        profile_type = data[0]
        family: Optional[ScannerFamily]
        try:
            family = ScannerFamily(profile_type)
        except ValueError:
            family = None
        profile_length = _PROFILE_LENGTH.get(profile_type, 0)
        if profile_length and len(data) < profile_length:
            raise ProtocolError("status profile type %d needs %d bytes, got %d"
                                % (profile_type, profile_length, len(data)))
        b2 = data[2]
        common: Dict[str, Any] = dict(
            profile_type=profile_type, family=family, profile_length=profile_length,
            operating_mode=data[1],
            error=bool(b2 & 0x80), alarm=bool(b2 & 0x40),
            screen_contaminated=bool(b2 & 0x20), edm_error=bool(b2 & 0x10),
            field_selection_error=bool(b2 & 0x08),
            raw=data,
        )
        none200: Dict[str, Any] = dict(
            screen_error=None, screen_warning=None, warning_field_2_violated=None,
            restart_interlock=None, field_triple=None, inputs=None, outputs=None,
            supply_voltage_raw=None, temperature_c=None, signature=None,
            error_class=None, error_number=None)
        none400: Dict[str, Any] = dict(
            estop_active=None, estop_error=None, a_bank=None, a_field_pair=None,
            b_bank=None, b_field_pair=None, configuration_signature=None)

        if family is ScannerFamily.RSL200:
            # Spec table 3.3.  Field bits: value 0 = violated, 1 = free.
            b3 = data[3]
            voltage, temperature = struct.unpack_from("<HH", data, 8)
            scan_number, signature = struct.unpack_from("<II", data, 16)
            error_number = struct.unpack_from("<H", data, 25)[0]
            return cls(
                **common, **none400,
                ossd_a=bool(b3 & 0x80), ossd_b=None,
                parked=bool(b3 & 0x02),
                scan_number=scan_number,
                a_active=True,
                a_protective_violated=not (b3 & 0x40),
                a_warning_violated=not (b3 & 0x20),
                b_active=None, b_protective_violated=None, b_warning_violated=None,
                screen_error=bool(b2 & 0x04), screen_warning=bool(b2 & 0x02),
                warning_field_2_violated=not (b3 & 0x10),
                restart_interlock=bool(b3 & 0x08),
                field_triple=data[4], inputs=data[6], outputs=data[7],
                supply_voltage_raw=voltage,
                temperature_c=temperature / 10.0,         # [0.1 degC]
                signature=signature, error_class=data[24], error_number=error_number,
            )
        if family is ScannerFamily.RSL400:
            # Spec table 3.5.  Field bits: value 0 = violation, 1 = free.
            b3, b12, b13, b16, b17 = data[3], data[12], data[13], data[16], data[17]
            config_sig: Optional[bytes] = None
            trailer = data[20 + CONTOUR_SIZE:]
            if len(trailer) >= 12 and trailer[:4] == b"\x01\x00\x08\x00":
                config_sig = trailer[4:12]
            return cls(
                **common, **none200,
                ossd_a=bool(b2 & 0x02), ossd_b=bool(b2 & 0x01),
                parked=bool(b3 & 0x40),
                scan_number=struct.unpack_from("<I", data, 8)[0],
                a_active=bool(b12 & 0x80),
                a_protective_violated=bool(b12 & 0x80) and not (b12 & 0x20),
                a_warning_violated=bool(b12 & 0x80) and not (b12 & 0x40),
                b_active=bool(b16 & 0x80),
                b_protective_violated=bool(b16 & 0x80) and not (b16 & 0x20),
                b_warning_violated=bool(b16 & 0x80) and not (b16 & 0x40),
                estop_active=bool(b3 & 0x80), estop_error=bool(b2 & 0x04),
                a_bank=b13 >> 4, a_field_pair=b13 & 0x0F,
                b_bank=b17 >> 4, b_field_pair=b17 & 0x0F,
                configuration_signature=config_sig,
            )
        # Unknown profile type: only the bytes both known layouts agree on.
        return cls(
            **common, **none200, **none400,
            ossd_a=False, ossd_b=None, parked=False, scan_number=0,
            a_active=False, a_protective_violated=False, a_warning_violated=False,
            b_active=None, b_protective_violated=None, b_warning_violated=None,
        )

    @property
    def contour_offset(self) -> Optional[int]:
        """Offset of the measurement contour inside ``raw`` (None if unknown)."""
        return self.profile_length or None


@dataclass(frozen=True)
class MeasurementContour:
    """Measurement contour description: which beams the scanner transmits.

    Beam ``i`` (0-based) of a scan has index ``start_index + i * index_interval``.
    """

    start_index: int     #: first transmitted beam index
    stop_index: int      #: last beam index (spec: start < stop <= max index)
    index_interval: int  #: every n-th beam (spec: 1..8)
    reserved: int = 0

    def __post_init__(self) -> None:
        if not (0 <= self.start_index <= 0xFFFF and 0 <= self.stop_index <= 0xFFFF):
            raise ProtocolError("contour indices out of range: %r" % (self,))
        if self.index_interval < 1:
            raise ProtocolError("contour index interval must be >= 1: %r" % (self,))
        if self.start_index > self.stop_index:
            raise ProtocolError("contour start index > stop index: %r" % (self,))

    @classmethod
    def from_bytes(cls, data: Union[bytes, bytearray, memoryview],
                   offset: int = 0) -> Optional["MeasurementContour"]:
        """Decode 8 bytes; ``None`` if all zero (measurement transmission inactive)."""
        if len(data) < offset + CONTOUR_SIZE:
            raise ProtocolError("measurement contour needs %d bytes at offset %d, got %d"
                                % (CONTOUR_SIZE, offset, len(data)))
        start, stop, interval, reserved = _CONTOUR_STRUCT.unpack_from(data, offset)
        if start == stop == interval == 0:
            return None
        return cls(start, stop, interval, reserved)

    @property
    def num_beams(self) -> int:
        """Total beams per scan: 1 + ceil((stop - start) / interval) (spec)."""
        span = self.stop_index - self.start_index
        return 1 + -(-span // self.index_interval)

    def beam_indices(self) -> List[int]:
        return [self.start_index + i * self.index_interval
                for i in range(self.num_beams)]

    def plausible(self, family: Optional[ScannerFamily] = None) -> bool:
        """True if the values are within the specification's ranges."""
        max_index = GEOMETRY[family].max_index if family is not None else 2699
        return (1 <= self.index_interval <= 8
                and self.start_index < self.stop_index <= max_index)


def locate_contour(data: bytes, expected_beams: Optional[int]) -> Optional[Tuple[int, MeasurementContour]]:
    """Heuristically find a measurement contour inside an unknown status block.

    Only used for status profile types the specification does not describe
    (known types carry the contour at a fixed offset).  Candidates must be
    within the spec's ranges and, when ``expected_beams`` is given, yield
    exactly that beam count.  Returns ``(offset, contour)`` or ``None``.
    """
    candidates: List[Tuple[int, MeasurementContour]] = []
    for offset in range(0, len(data) - CONTOUR_SIZE + 1, 2):
        try:
            contour = MeasurementContour.from_bytes(data, offset)
        except ProtocolError:
            continue
        if contour is None or not contour.plausible():
            continue
        if expected_beams is not None and contour.num_beams != expected_beams:
            continue
        candidates.append((offset, contour))
    if not candidates:
        return None
    # Prefer offsets right after a known profile length, then zero reserved
    # field (as the spec prescribes), then the earliest offset.
    candidates.sort(key=lambda c: (c[0] not in (28, 20), c[1].reserved != 0, c[0]))
    return candidates[0]


@dataclass(frozen=True)
class UdtScan:
    """One assembled scan cycle of measurement data."""

    scan_number: int
    telegram_id: int                          #: 3 or 6
    distances_mm: Tuple[int, ...]             #: distance per beam [mm]
    signal_strengths: Optional[Tuple[int, ...]]  #: [digits], None for ID 6
    blocks: Tuple[int, ...]                   #: block numbers received, ascending
    block_beams: Tuple[int, ...]              #: beams per received block
    complete: bool                            #: all blocks present and beam count matches the contour
    contour: Optional[MeasurementContour]     #: beam geometry, if known
    status: Optional[StatusProfile]           #: status profile of this scan cycle (None if its telegram was lost)
    family: Optional[ScannerFamily]           #: device family, once a status telegram was seen
    received_at: float                        #: host time.time() of completion

    @property
    def num_beams(self) -> int:
        return len(self.distances_mm)

    @property
    def num_blocks(self) -> int:
        """Datagrams this scan arrived in."""
        return len(self.blocks)

    @property
    def geometry(self) -> BeamGeometry:
        """Beam geometry defaults for this scan's device family."""
        family = self.family
        return GEOMETRY[family] if family is not None else DEFAULT_GEOMETRY

    @property
    def no_echo_mm(self) -> int:
        """Distance value this device reports for beams without a valid echo."""
        return self.geometry.no_echo_mm

    @cached_property
    def distances_m(self) -> Tuple[float, ...]:
        return tuple(d / 1000.0 for d in self.distances_mm)

    def valid_mask(self, max_valid_mm: Optional[int] = None) -> List[bool]:
        """Per beam: True if the distance is a real measurement.

        0 mm, the no-echo value (65535 on RSL 235 hardware, sent with a
        signal strength of 65535) and anything above the family's distance
        range (RSL 200: 32767 mm, RSL 400: 65535 mm) count as invalid, as
        does anything above ``max_valid_mm`` when given.
        """
        limit = self.geometry.max_valid_mm if max_valid_mm is None else max_valid_mm
        return [0 < d <= limit for d in self.distances_mm]

    def beam_indices(self) -> List[int]:
        """Measurement-contour index of every beam in :attr:`distances_mm`.

        For a complete scan this is exactly the contour's index list.  For
        an incomplete scan (``strict=False``) the indices are reconstructed
        from the received block numbers, assuming the device's uniform
        fragmentation (every block but the last carries the same number of
        beams); if no full-size block was received the indices fall back to
        the beam positions and the geometry is unreliable.
        """
        if self.contour is None:
            return list(range(self.num_beams))
        indices = self.contour.beam_indices()
        if self.complete and len(indices) == self.num_beams:
            return indices
        if not self.blocks or (len(self.blocks) == 1 and self.blocks[0] != 0):
            # a lone block other than block 0 may be the short last one:
            # the fragment size is unknown, so the positions cannot be mapped
            return list(range(self.num_beams))
        full_block = max(self.block_beams)
        out: List[int] = []
        for block, n in zip(self.blocks, self.block_beams):
            first = block * full_block
            out.extend(indices[first:first + n])
        if len(out) != self.num_beams:
            return list(range(self.num_beams))
        return out

    def angles_deg(self,
                   angle_at_index0: Optional[float] = None,
                   index_resolution: Optional[float] = None) -> List[float]:
        """Beam angles in degrees: ``angle_at_index0 + index * index_resolution``.

        Defaults come from :attr:`geometry` (RSL 200: index 0 at +135 deg,
        -0.2 deg per index; RSL 400: +134.95 deg, -0.1 deg per index).
        Verify the mapping against a known target and pass your own values
        if your mounting differs.
        """
        geometry = self.geometry
        a0 = geometry.angle_at_index0_deg if angle_at_index0 is None else angle_at_index0
        step = geometry.index_step_deg if index_resolution is None else index_resolution
        return [a0 + i * step for i in self.beam_indices()]

    def to_cartesian(self,
                     angle_at_index0: Optional[float] = None,
                     index_resolution: Optional[float] = None,
                     skip_invalid: bool = True,
                     max_valid_mm: Optional[int] = None) -> List[Tuple[float, float]]:
        """(x, y) points in meters (x along 0 deg, y along +90 deg).

        Beams without a valid echo (see :meth:`valid_mask`) are omitted
        unless ``skip_invalid`` is False.
        """
        valid = self.valid_mask(max_valid_mm)
        points: List[Tuple[float, float]] = []
        for dist, angle, ok in zip(self.distances_mm,
                                   self.angles_deg(angle_at_index0, index_resolution),
                                   valid):
            if skip_invalid and not ok:
                continue
            a = math.radians(angle)
            d = dist / 1000.0
            points.append((d * math.cos(a), d * math.sin(a)))
        return points


@dataclass
class UdtStats:
    """Counters describing the health of the incoming datagram stream."""

    datagrams: int = 0                 #: datagrams fed
    bad_frames: int = 0                #: too short, inconsistent length or undecodable
    unknown_ids: int = 0               #: telegram IDs other than 1, 3, 6
    status_received: int = 0           #: ID 1 telegrams decoded
    scans_completed: int = 0           #: scans emitted
    scans_dropped_incomplete: int = 0  #: scans dropped (missing blocks / no contour) in strict mode
    scans_incomplete: int = 0          #: incomplete scans emitted (strict=False)
    scans_dropped_oversize: int = 0    #: scans discarded for exceeding the fragment/byte bounds
    stale_datagrams: int = 0           #: datagrams of an already finished scan (late/duplicate)
    outlier_datagrams: int = 0         #: datagrams far ahead of the stream, awaiting confirmation
    sequence_resets: int = 0           #: scan counter jumped backwards (scanner restarted)
    sequence_jumps: int = 0            #: scan counter jumped forwards (receiver offline / cycles lost)
    cycles_missed: int = 0             #: scan numbers never seen between consecutive cycles (skipped by the device or lost)
    bytes_discarded: int = 0           #: partial trailing beam bytes dropped


def _scan_newer(a: int, b: int) -> bool:
    """True if scan number ``a`` is newer than ``b`` (wrap-aware, 32 bit)."""
    return ((a - b) & 0xFFFFFFFF) < 0x80000000 and a != b


#: A datagram carrying an older scan number than the newest finished scan is
#: late/duplicated only when it arrives right behind the stream (a LAN
#: reorders by milliseconds, i.e. by a few cycles at most).  After a silence
#: longer than ``_RESTART_GAP_S`` or a jump back by more than
#: ``_STALE_WINDOW`` cycles the scanner has evidently restarted and its
#: counter begins anew; treating that as "stale" would silence the receiver
#: for hours, so it is never done.
_RESTART_GAP_S = 1.0
_STALE_WINDOW = 256

#: A scan number more than this many cycles ahead of the stream does not move
#: the stream position by itself: a single forged or foreign datagram must
#: not make the genuine cycles behind it look stale.  It is kept as a
#: candidate and adopted once a second datagram at or just after it arrives
#: (the receiver was really offline or the scanner skipped cycles).
_FORWARD_WINDOW = 8

#: Bounds for one scan cycle in flight (an RSL 400 cycle is at most 2700
#: beams x 4 bytes = 10.8 KB; the RSL 200 half that).  Exceeding them means
#: the input is not a scanner's and the cycle is discarded.
_MAX_FRAGMENTS_PER_SCAN = 64
_MAX_BYTES_PER_SCAN = 256 * 1024


class _PendingScan:
    __slots__ = ("telegram_id", "fragments", "nbytes", "status", "contour", "family")

    def __init__(self, telegram_id: int, status: Optional[StatusProfile],
                 contour: Optional[MeasurementContour],
                 family: Optional[ScannerFamily]) -> None:
        self.telegram_id = telegram_id
        self.fragments: Dict[int, bytes] = {}     # block -> payload
        self.nbytes = 0
        self.status = status
        self.contour = contour
        self.family = family


class UdtAssembler:
    """Reassemble UDP data telegrams into :class:`UdtScan` objects.

    Not thread safe; feed it from one thread.

    ``strict`` (default True) guarantees that every emitted scan is complete:
    all blocks from 0 upwards were received and the beam count equals the
    one announced by the measurement contour of the status telegram.  Scans
    that cannot be verified -- missing blocks, or no contour known yet (the
    first cycle after joining a stream mid-cycle) -- are dropped and counted
    in ``stats.scans_dropped_incomplete``.  With ``strict=False`` such scans
    are emitted with ``complete=False``.

    ``max_pending`` bounds the number of scan cycles kept in flight (the
    scanner sends strictly in order, so normally at most two).
    """

    def __init__(self, strict: bool = True, max_pending: int = 4) -> None:
        if max_pending < 1:
            raise ValueError("max_pending must be >= 1")
        self.strict = strict
        self.max_pending = max_pending
        self.stats = UdtStats()
        self.latest_status: Optional[StatusProfile] = None
        self.contour: Optional[MeasurementContour] = None
        self._contour_offset: Optional[int] = None   # heuristic location (unknown profile types)
        self._last_status_block: Optional[bytes] = None
        self._status_scan_number: Optional[int] = None  # frame scan number of latest_status
        self._observed_beams: Optional[int] = None
        self._pending: Dict[int, _PendingScan] = {}
        self._last_finished: Optional[int] = None    # newest scan number finalized
        self._newest_seen: Optional[int] = None      # stream position: newest confirmed scan number
        self._candidate: Optional[int] = None        # unconfirmed scan number far ahead of the stream
        self._last_activity: Optional[float] = None  # monotonic time of the last accepted datagram

    @property
    def family(self) -> Optional[ScannerFamily]:
        return self.latest_status.family if self.latest_status is not None else None

    def feed_datagram(self, data: bytes) -> List[UdtScan]:
        """Consume one UDP datagram; return any scans completed by it."""
        self.stats.datagrams += 1
        if len(data) < FRAME_SIZE:
            self.stats.bad_frames += 1
            return []
        frame = UdtFrame.from_bytes(data)
        if frame.total_length != len(data):
            # Tolerate trailing padding; reject truncated datagrams.
            if frame.total_length > len(data) or frame.total_length < FRAME_SIZE:
                self.stats.bad_frames += 1
                return []
        payload = data[FRAME_SIZE:frame.total_length]

        if frame.telegram_id == TELEGRAM_ID_STATUS:
            # Anything older than this cycle is finished; build it with the
            # status/contour of *its* cycle before adopting the new ones.
            tracked = self._track_sequence(frame.scan_number, status=True)
            if tracked is None:
                return []
            advance, scans = tracked
            if not advance:
                # Far ahead of the stream and unconfirmed: do not let it
                # replace the status/contour the genuine cycles rely on.
                return scans
            scans += self._finalize_older_than(frame.scan_number)
            self._handle_status(frame.scan_number, payload)
            return scans
        if frame.telegram_id in (TELEGRAM_ID_DISTANCE, TELEGRAM_ID_DISTANCE_SIGNAL):
            return self._handle_measurement(frame, payload)
        self.stats.unknown_ids += 1
        return []

    # -- internals -----------------------------------------------------------

    def _track_sequence(self, scan_number: int, status: bool
                        ) -> Optional[Tuple[bool, List[UdtScan]]]:
        """Classify ``scan_number`` against the stream position.

        Returns ``None`` for a late/duplicated measurement datagram of a
        finished scan (a scan number at or close behind the newest one);
        status telegrams are never stale (a device may send them after the
        data).  Otherwise returns ``(advance, flushed)``: ``advance`` is False
        for a datagram far ahead of the stream that is not yet confirmed by a
        second one (see :data:`_FORWARD_WINDOW`), so callers must not
        finalize older scans or adopt its status for it.  An older scan
        number arriving after a pause of :data:`_RESTART_GAP_S`, or more than
        :data:`_STALE_WINDOW` cycles back, means the scanner's counter
        restarted: pending scans are finalized and returned in ``flushed``
        and the sequence starts over.
        """
        now = time.monotonic()
        last_activity = self._last_activity
        newest = self._newest_seen
        if newest is None:
            self._newest_seen = scan_number
            self._last_activity = now
            return True, []
        if _scan_newer(scan_number, newest):
            ahead = (scan_number - newest) & 0xFFFFFFFF
            candidate = self._candidate
            confirmed = candidate is not None and (
                scan_number == candidate
                or (_scan_newer(scan_number, candidate)
                    and ((scan_number - candidate) & 0xFFFFFFFF) <= _FORWARD_WINDOW))
            if ahead <= _FORWARD_WINDOW or confirmed:
                self.stats.cycles_missed += ahead - 1
                if ahead > _FORWARD_WINDOW:
                    self.stats.sequence_jumps += 1
                    log.info("scan counter jumped from %d to %d: receiver offline or cycles lost?",
                             newest, scan_number)
                self._newest_seen = scan_number
                self._candidate = None
                self._last_activity = now
                return True, []
            self._candidate = scan_number
            self.stats.outlier_datagrams += 1
            return False, []
        if scan_number == newest:
            if status or self._last_finished != scan_number:
                self._last_activity = now
                return True, []               # another datagram of the current cycle
            return None                       # late fragment of the finished current cycle
        if (last_activity is not None and now - last_activity < _RESTART_GAP_S
                and ((newest - scan_number) & 0xFFFFFFFF) <= _STALE_WINDOW):
            return (True, []) if status else None
        self._last_activity = now
        self.stats.sequence_resets += 1
        if self.stats.sequence_resets <= 3:
            log.info("scan counter went back from %d to %d after %.1f s: scanner restarted?",
                     newest, scan_number, now - (last_activity or now))
        else:
            log.debug("scan counter went back from %d to %d", newest, scan_number)
        flushed: List[UdtScan] = []
        for number in list(self._pending):
            scan = self._build(number, self._pending.pop(number))
            if scan is not None:
                flushed.append(scan)
        self._last_finished = None
        self._newest_seen = scan_number
        self._candidate = None
        return True, flushed

    def _handle_status(self, scan_number: int, payload: bytes) -> None:
        try:
            status = StatusProfile.from_bytes(payload)
        except ProtocolError:
            self.stats.bad_frames += 1
            return
        self.stats.status_received += 1
        self.latest_status = status
        self._status_scan_number = scan_number
        self._last_status_block = payload
        self._update_contour(status, payload)

    def _update_contour(self, status: StatusProfile, payload: bytes) -> None:
        offset = status.contour_offset
        if offset is not None:
            # Known layout: the contour sits at a fixed, spec-defined offset.
            try:
                self.contour = MeasurementContour.from_bytes(payload, offset)
            except ProtocolError:
                self.stats.bad_frames += 1
                self.contour = None
            self._contour_offset = offset
            return
        # Unknown profile type: locate heuristically, verified against the
        # beam count observed in the measurement data whenever possible.
        if self._contour_offset is not None:
            try:
                contour = MeasurementContour.from_bytes(payload, self._contour_offset)
            except ProtocolError:
                contour = None
            if (contour is not None and contour.plausible()
                    and (self._observed_beams is None
                         or contour.num_beams == self._observed_beams)):
                self.contour = contour
                return
        located = locate_contour(payload, self._observed_beams)
        if located is None:
            self.contour = None
            self._contour_offset = None
            return
        self._contour_offset, self.contour = located
        log.debug("measurement contour located heuristically at offset %d: %s",
                  self._contour_offset, self.contour)

    def _handle_measurement(self, frame: UdtFrame, payload: bytes) -> List[UdtScan]:
        per_beam = 4 if frame.telegram_id == TELEGRAM_ID_DISTANCE_SIGNAL else 2
        usable = len(payload) - (len(payload) % per_beam)
        if usable == 0:
            # A measurement datagram without a single beam is not something a
            # scanner sends; it must not finish or disturb scans in flight.
            self.stats.bad_frames += 1
            return []
        if usable != len(payload):
            self.stats.bytes_discarded += len(payload) - usable
        tracked = self._track_sequence(frame.scan_number, status=False)
        if tracked is None:
            # Late or duplicated datagram of a scan that was already emitted
            # or dropped: never resurrect it.
            self.stats.stale_datagrams += 1
            return []
        advance, scans = tracked
        if advance:
            scans += self._finalize_older_than(frame.scan_number)

        pending = self._pending.get(frame.scan_number)
        if pending is None:
            if len(self._pending) >= self.max_pending:
                # Make room: drop an unconfirmed outlier first, else the oldest.
                outliers = [n for n in self._pending
                            if self._newest_seen is not None and _scan_newer(n, self._newest_seen)]
                victim = outliers[-1] if outliers else next(iter(self._pending))
                scan = self._build(victim, self._pending.pop(victim))
                if scan is not None:
                    scans.append(scan)
            # The status telegram of this cycle carries the same frame scan
            # number; anything else is an older cycle's (this one's was lost).
            status = self.latest_status if self._status_scan_number == frame.scan_number else None
            pending = _PendingScan(frame.telegram_id, status, self.contour, self.family)
            self._pending[frame.scan_number] = pending
        if frame.telegram_id != pending.telegram_id:
            # Mixed data types under one scan number cannot be assembled.
            self.stats.bad_frames += 1
            return scans
        if frame.block not in pending.fragments:
            pending.nbytes += usable
        else:
            pending.nbytes += usable - len(pending.fragments[frame.block])
        pending.fragments[frame.block] = payload[:usable]
        if (len(pending.fragments) > _MAX_FRAGMENTS_PER_SCAN
                or pending.nbytes > _MAX_BYTES_PER_SCAN):
            del self._pending[frame.scan_number]
            self.stats.scans_dropped_oversize += 1
            self._mark_finished(frame.scan_number)
            log.debug("dropping oversize scan %d (%d fragments, %d bytes)",
                      frame.scan_number, len(pending.fragments), pending.nbytes)
            return scans

        # Early completion: all beams announced by the contour have arrived.
        if pending.contour is not None:
            if pending.nbytes // per_beam >= pending.contour.num_beams:
                del self._pending[frame.scan_number]
                scan = self._build(frame.scan_number, pending)
                if scan is not None:
                    scans.append(scan)
        return scans

    def _finalize_older_than(self, scan_number: int) -> List[UdtScan]:
        """The scanner sends strictly in order: anything older is finished."""
        done: List[UdtScan] = []
        for number in [n for n in self._pending if _scan_newer(scan_number, n)]:
            scan = self._build(number, self._pending.pop(number))
            if scan is not None:
                done.append(scan)
        return done

    def _mark_finished(self, scan_number: int) -> None:
        if self._last_finished is None or _scan_newer(scan_number, self._last_finished):
            self._last_finished = scan_number

    def _build(self, scan_number: int, pending: _PendingScan) -> Optional[UdtScan]:
        self._mark_finished(scan_number)
        blocks = sorted(pending.fragments)
        per_beam = 4 if pending.telegram_id == TELEGRAM_ID_DISTANCE_SIGNAL else 2
        block_beams = [len(pending.fragments[b]) // per_beam for b in blocks]
        num_beams = sum(block_beams)

        # The spec sends the status telegram before the measurement data of a
        # cycle, but tolerate the opposite order: adopt the status/contour that
        # arrived while the scan was pending if none was known at its start.
        status = pending.status
        contour = pending.contour
        if status is None and self._status_scan_number == scan_number:
            status = self.latest_status
        if contour is None:
            contour = self.contour
        contiguous = blocks[0] == 0 and blocks == list(range(len(blocks)))
        if contiguous and num_beams:
            self._observed_beams = num_beams
        complete = contiguous and contour is not None and num_beams == contour.num_beams
        if num_beams == 0:
            self.stats.scans_dropped_incomplete += 1
            return None
        if not complete:
            if self.strict:
                self.stats.scans_dropped_incomplete += 1
                log.debug("dropping incomplete scan %d (%d beams, blocks %s, contour %s)",
                          scan_number, num_beams, blocks, contour)
                return None
            self.stats.scans_incomplete += 1

        data = b"".join(pending.fragments[b] for b in blocks)
        values = struct.unpack("<%dH" % (len(data) // 2), data)
        if pending.telegram_id == TELEGRAM_ID_DISTANCE_SIGNAL:
            distances = values[0::2]
            signals: Optional[Tuple[int, ...]] = values[1::2]
        else:
            distances = values
            signals = None
        self.stats.scans_completed += 1
        return UdtScan(
            scan_number=scan_number,
            telegram_id=pending.telegram_id,
            distances_mm=distances,
            signal_strengths=signals,
            blocks=tuple(blocks),
            block_beams=tuple(block_beams),
            complete=complete,
            contour=contour,
            status=status,
            family=pending.family if pending.family is not None else self.family,
            received_at=time.time(),
        )


class _Wakeup:
    """Queue sentinel: wakes get_scan()/scans() waiters with an exception."""

    __slots__ = ("exc",)

    def __init__(self, exc: Exception) -> None:
        self.exc = exc


#: Poll interval of the receiver socket (bounds the stop() latency).
_RX_POLL_S = 0.1


class RSL235Udt:
    """Passive receiver for RSL 200 / RSL 400 UDP data telegrams.

    Configure the scanner in Sensor Studio (SETTINGS > Data telegrams):
    activate the UDP telegram, set this machine's IP as the destination,
    enable measurement value transmission -- then just listen.

    Parameters
    ----------
    port:
        UDP destination port configured in the scanner (default 3050).
    bind_address:
        Local interface to bind ("" = all).
    source_ip:
        If set, datagrams from any other IP are ignored.
    strict:
        Drop scans with missing fragments (default) instead of emitting them
        with ``complete=False``.
    scan_queue_size:
        Scans buffered for :meth:`get_scan`; when full, the oldest is dropped
        (counted in :attr:`stats`).  ``<= 0`` means unbounded (as for
        ``queue.Queue``): only use that with a consumer that keeps up.
    on_scan / on_status:
        Optional callbacks, called from the receiver thread (keep them fast).
    data_timeout:
        Seconds without datagrams after which :attr:`is_receiving` is False.

    The receiver is restartable; scans buffered before :meth:`stop` are
    discarded by the next :meth:`start`.
    """

    def __init__(self,
                 port: int = DEFAULT_UDT_PORT,
                 *,
                 bind_address: str = "",
                 source_ip: Optional[str] = None,
                 strict: bool = True,
                 scan_queue_size: int = 32,
                 on_scan: Optional[Callable[[UdtScan], None]] = None,
                 on_status: Optional[Callable[[StatusProfile], None]] = None,
                 data_timeout: float = 3.0) -> None:
        if not 0 < port <= 65535:
            raise ValueError("port must be in 1..65535")
        if data_timeout <= 0:
            raise ValueError("data_timeout must be > 0")
        self.port = port
        self.bind_address = bind_address
        self.source_ip = _canonical_ip(source_ip) if source_ip is not None else None
        self.strict = strict
        self.on_scan = on_scan
        self.on_status = on_status
        self.data_timeout = data_timeout

        self._assembler = UdtAssembler(strict=strict)
        self._scan_queue: "queue.Queue[Union[UdtScan, _Wakeup]]" = queue.Queue(maxsize=scan_queue_size)
        self._lifecycle = threading.Lock()
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._last_rx: Optional[float] = None
        self.scans_dropped_queue = 0
        self.foreign_datagrams_dropped = 0
        self.receiver_errors = 0

    # ------------------------------------------------------------------

    def start(self) -> "RSL235Udt":
        """Bind the UDP port and start the receiver thread (idempotent)."""
        with self._lifecycle:
            if self._running:
                return self
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                # No SO_REUSEADDR: a second receiver on the same port must
                # fail loudly instead of silently stealing the datagrams.
                # Windows only honours that with SO_EXCLUSIVEADDRUSE: by
                # default it lets a wildcard bind succeed next to a socket
                # holding the same port on a specific address, and lets a
                # later SO_REUSEADDR socket hijack the port.
                if sys.platform == "win32":
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
                except OSError:
                    pass
                sock.bind((self.bind_address, self.port))
                sock.settimeout(_RX_POLL_S)
            except OSError as exc:
                sock.close()
                raise ScannerConnectionError(
                    "unable to bind UDP port %s:%d: %s"
                    % (self.bind_address or "0.0.0.0", self.port, exc)) from exc
            try:
                rcvbuf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
                log.debug("UDP receive buffer: %d bytes", rcvbuf)
            except OSError:
                pass
            self._drain_queue()
            self._assembler = UdtAssembler(strict=self.strict)
            self._last_rx = None
            self._sock = sock
            self._running = True
            self._thread = threading.Thread(target=self._rx_loop, args=(sock,),
                                            name="leuze_rsl-udt-rx:%d" % self.port, daemon=True)
            self._thread.start()
            log.info("listening for UDP data telegrams on %s:%d",
                     self.bind_address or "0.0.0.0", self.port)
            return self

    def stop(self) -> None:
        """Stop the receiver thread and close the socket (idempotent).

        Waiters in :meth:`get_scan` / :meth:`scans` are woken with
        :class:`ReceiverStoppedError` / iteration end.
        """
        with self._lifecycle:
            self._running = False
            sock, self._sock = self._sock, None
            thread, self._thread = self._thread, None
        if sock is not None:
            sock.close()
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)
            if thread.is_alive():
                log.warning("receiver thread did not stop within 2 s (callback blocked?)")
        self._wake_waiters(ReceiverStoppedError("receiver stopped"))

    def __enter__(self) -> "RSL235Udt":
        return self.start()

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.stop()

    @property
    def is_running(self) -> bool:
        """True between :meth:`start` and :meth:`stop` while the receiver thread lives."""
        return self._running

    # ------------------------------------------------------------------

    def get_scan(self, timeout: Optional[float] = None) -> UdtScan:
        """Next complete scan.

        Raises :class:`ScanTimeoutError` (a ``TimeoutError``) if none arrives
        within ``timeout`` seconds, :class:`ReceiverStoppedError` if the
        receiver is not running.
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            if not self._running and self._scan_queue.empty():
                raise ReceiverStoppedError("receiver is not running")
            if deadline is None:
                wait: Optional[float] = 0.5          # keeps Ctrl+C responsive
            else:
                wait = max(0.0, deadline - time.monotonic())
            try:
                item = self._scan_queue.get(timeout=wait)
            except queue.Empty:
                if deadline is not None and time.monotonic() >= deadline:
                    raise ScanTimeoutError(
                        "no scan received within %s s (is_receiving=%s) -- check that "
                        "the scanner's UDP destination is this machine and the port "
                        "matches, and that the firewall allows inbound UDP %d"
                        % (timeout, self.is_receiving, self.port)) from None
                if not self._running and self._scan_queue.empty():
                    raise ReceiverStoppedError("receiver is not running") from None
                continue
            if isinstance(item, _Wakeup):
                self._requeue_wakeup(item)
                raise item.exc
            return item

    def scans(self, timeout: Optional[float] = None) -> Iterator[UdtScan]:
        """Iterate over scans until :meth:`stop` is called.

        With ``timeout`` set, :class:`ScanTimeoutError` is raised if no scan
        arrives in time.
        """
        while True:
            try:
                yield self.get_scan(timeout)
            except ReceiverStoppedError:
                return

    @property
    def latest_status(self) -> Optional[StatusProfile]:
        return self._assembler.latest_status

    @property
    def contour(self) -> Optional[MeasurementContour]:
        return self._assembler.contour

    @property
    def family(self) -> Optional[ScannerFamily]:
        """Device family seen in the status telegrams, once known."""
        return self._assembler.family

    @property
    def is_receiving(self) -> bool:
        if not self._running or self._last_rx is None:
            return False
        return (time.monotonic() - self._last_rx) < self.data_timeout

    @property
    def stats(self) -> Dict[str, int]:
        stats = vars(self._assembler.stats).copy()
        stats.update(scans_dropped_queue=self.scans_dropped_queue,
                     foreign_datagrams_dropped=self.foreign_datagrams_dropped,
                     receiver_errors=self.receiver_errors)
        return stats

    # ------------------------------------------------------------------

    def _rx_loop(self, sock: socket.socket) -> None:
        failure: Optional[Exception] = None
        still_current = lambda: self._sock is sock  # noqa: E731
        try:
            while self._running and self._sock is sock:
                try:
                    data, addr = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError as exc:
                    if self._running and self._sock is sock:
                        failure = exc
                    break
                if self.source_ip is not None and addr[0] != self.source_ip:
                    self.foreign_datagrams_dropped += 1
                    continue
                try:
                    self._process(data, still_current)
                except Exception:
                    # Never let a bug in a callback or a parser kill the receiver.
                    self.receiver_errors += 1
                    log.exception("error while processing a datagram")
        finally:
            if failure is not None:
                log.error("UDP receiver on port %d failed: %s", self.port, failure)
                with self._lifecycle:
                    if self._sock is sock:
                        self._running = False
                        self._sock = None
                        sock.close()
                self._wake_waiters(ScannerConnectionError(
                    "UDP receiver on port %d failed: %s" % (self.port, failure)))

    def _process(self, data: bytes, still_current: Callable[[], bool]) -> None:
        assembler = self._assembler
        had_status = assembler.stats.status_received
        rejected = assembler.stats.bad_frames + assembler.stats.unknown_ids
        scans = assembler.feed_datagram(data)
        if assembler.stats.bad_frames + assembler.stats.unknown_ids == rejected:
            self._last_rx = time.monotonic()     # only genuine telegrams count
        for scan in scans:
            self._deliver(scan, still_current)
        if (self.on_status is not None
                and assembler.stats.status_received > had_status
                and assembler.latest_status is not None):
            try:
                self.on_status(assembler.latest_status)
            except Exception:
                log.exception("on_status callback raised")

    def _deliver(self, scan: UdtScan, still_current: Callable[[], bool]) -> None:
        if self.on_scan is not None:
            try:
                self.on_scan(scan)
            except Exception:
                log.exception("on_scan callback raised")
        if not still_current():
            return          # stopped/restarted while the callback ran: old session's scan
        try:
            self._scan_queue.put_nowait(scan)
        except queue.Full:
            try:
                self._scan_queue.get_nowait()
                self.scans_dropped_queue += 1
            except queue.Empty:
                pass
            try:
                self._scan_queue.put_nowait(scan)
            except queue.Full:
                self.scans_dropped_queue += 1

    def _drain_queue(self) -> None:
        while True:
            try:
                self._scan_queue.get_nowait()
            except queue.Empty:
                return

    def _wake_waiters(self, exc: Exception) -> None:
        wake = _Wakeup(exc)
        try:
            self._scan_queue.put_nowait(wake)
        except queue.Full:
            try:
                if not isinstance(self._scan_queue.get_nowait(), _Wakeup):
                    self.scans_dropped_queue += 1
            except queue.Empty:
                pass
            try:
                self._scan_queue.put_nowait(wake)
            except queue.Full:
                pass

    def _requeue_wakeup(self, wake: _Wakeup) -> None:
        if not self._running:
            try:
                self._scan_queue.put_nowait(wake)
            except queue.Full:
                pass


def _canonical_ip(address: str) -> str:
    """Normalize ``source_ip`` so it compares equal to ``recvfrom`` addresses."""
    try:
        return socket.inet_ntoa(socket.inet_aton(address))
    except OSError:
        try:
            return socket.gethostbyname(address)
        except OSError as exc:
            raise ValueError("source_ip %r is not an IPv4 address or resolvable host: %s"
                             % (address, exc)) from exc
