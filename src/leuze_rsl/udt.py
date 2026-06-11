"""Passive receiver for RSL UDP data telegrams ("UDT").

This is the protocol the RSL 235 actually speaks on the wire (verified
against hardware): the safety sensor *pushes* UDP datagrams to a destination
IP/port configured in Sensor Studio (SETTINGS > Data telegrams) -- there is
no TCP command channel and nothing to request.  The format follows the
Leuze "RSL 400 UDP specification" (document 50130122), which the RSL 200
series reuses:

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

* ID 1 (extended status profile): 20-byte status profile (operating mode,
  OSSD/field states, ...) followed by the 8-byte *measurement contour
  description* (start index, stop index, index interval) which defines the
  beam count and angles of the measurement data.  Note: on the RSL 200
  series this datagram is 8 bytes longer than the RSL 400 document
  describes; the contour is therefore located adaptively and verified
  against the observed beam count.
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
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterator, List, Optional, Tuple

__all__ = [
    "UdtFrame",
    "StatusProfile",
    "MeasurementContour",
    "UdtScan",
    "UdtAssembler",
    "UdtStats",
    "RSL235Udt",
    "TELEGRAM_ID_STATUS",
    "TELEGRAM_ID_DISTANCE",
    "TELEGRAM_ID_DISTANCE_SIGNAL",
    "DEFAULT_UDT_PORT",
    "NO_ECHO_DISTANCE_MM",
]

log = logging.getLogger("leuze_rsl.udt")

#: Default destination port for the UDP data telegrams (set in Sensor Studio).
DEFAULT_UDT_PORT = 3050

TELEGRAM_ID_STATUS = 1            #: extended status profile
TELEGRAM_ID_DISTANCE_SIGNAL = 3   #: distance + signal strength per beam
TELEGRAM_ID_DISTANCE = 6          #: distance per beam

FRAME_SIZE = 20
_FRAME_STRUCT = struct.Struct("<IBBH4sHHI")
assert _FRAME_STRUCT.size == FRAME_SIZE

#: Angular spacing of one beam *index* (0.1 deg for the RSL series).
INDEX_RESOLUTION_DEG = 0.1

#: Default angle of beam index 0.  The RSL 200 series scans 275 deg, mapped
#: symmetrically around the front of the device (the RSL 400 spans 270 deg,
#: i.e. -135.0).  Override if your mounting/model differs.
DEFAULT_ANGLE_AT_INDEX0_DEG = -137.5

#: Distance sentinel observed on real RSL 235 hardware for beams without a
#: valid echo: 32767 mm (0x7FFF).  The spec documents 0..65535 mm, but
#: anything at or above this value is "nothing detected", not a measurement.
NO_ECHO_DISTANCE_MM = 32767


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
    def from_bytes(cls, data: bytes) -> "UdtFrame":
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
    """Decoded 20-byte status profile (RSL 400 layout, table 3.3).

    The RSL 200 series may extend this; ``raw`` always holds the full
    status+contour data block of the datagram for your own decoding.
    """

    profile_type: int          #: byte 0, type/model of the status profile
    operating_mode: int        #: 1 = safety mode, 2 = simulation mode
    error: bool                #: collective message: error with switch-off
    alarm: bool                #: collective message: warning without switch-off
    screen_contaminated: bool  #: optics cover contamination warning/switch-off
    ossd_a: bool               #: OSSD state, protective function A
    ossd_b: bool               #: OSSD state, protective function B
    parked: bool               #: park request fulfilled
    scan_number: int           #: scan counter as embedded in the profile
    a_active: bool             #: protective function A active/configured
    a_warning_violated: bool   #: active warning field A violated
    a_protective_violated: bool  #: active protective field A violated
    b_active: bool
    b_warning_violated: bool
    b_protective_violated: bool
    raw: bytes                 #: complete data block (status + contour + extras)

    @classmethod
    def from_bytes(cls, data: bytes) -> "StatusProfile":
        if len(data) < 20:
            raise ValueError("status profile needs at least 20 bytes")
        b2, b3, b12, b16 = data[2], data[3], data[12], data[16]
        return cls(
            profile_type=data[0],
            operating_mode=data[1],
            error=bool(b2 & 0x80),
            alarm=bool(b2 & 0x40),
            screen_contaminated=bool(b2 & 0x20),
            ossd_a=bool(b2 & 0x02),
            ossd_b=bool(b2 & 0x01),
            parked=bool(b3 & 0x40),
            scan_number=struct.unpack_from("<I", data, 8)[0],
            a_active=bool(b12 & 0x80),
            a_warning_violated=bool(b12 & 0x40),
            a_protective_violated=bool(b12 & 0x20),
            b_active=bool(b16 & 0x80),
            b_warning_violated=bool(b16 & 0x40),
            b_protective_violated=bool(b16 & 0x20),
            raw=bytes(data),
        )


@dataclass(frozen=True)
class MeasurementContour:
    """Measurement contour description: which beams the scanner transmits."""

    start_index: int     #: first transmitted beam index
    stop_index: int      #: last beam index
    index_interval: int  #: every n-th beam (RSL 400 spec: 1..8; RSL 200 allows more)
    reserved: int

    @property
    def num_beams(self) -> int:
        """Total beams per scan: 1 + ceil((stop - start) / interval)."""
        span = self.stop_index - self.start_index
        return 1 + -(-span // self.index_interval)

    def beam_indices(self) -> List[int]:
        return [self.start_index + i * self.index_interval
                for i in range(self.num_beams)]

    def plausible(self) -> bool:
        return (1 <= self.index_interval <= 100
                and 0 <= self.start_index < self.stop_index <= 5500)


def locate_contour(data: bytes, expected_beams: Optional[int]) -> Optional[Tuple[int, MeasurementContour]]:
    """Find the measurement contour description inside a status data block.

    The RSL 400 places it at offset 20 (right after the 20-byte status
    profile), but the RSL 200 datagram is 8 bytes longer than documented,
    so the position is verified -- preferring offset 20 -- against
    plausibility and, when known, the beam count observed in the
    measurement datagrams.
    """
    candidates: List[Tuple[int, MeasurementContour]] = []
    for offset in range(0, len(data) - 7, 2):
        start, stop, interval, reserved = struct.unpack_from("<HHHH", data, offset)
        contour = MeasurementContour(start, stop, interval, reserved)
        if not contour.plausible():
            continue
        if expected_beams is not None and contour.num_beams != expected_beams:
            continue
        candidates.append((offset, contour))
    if not candidates:
        return None
    # Prefer the documented RSL 400 position, then frames whose reserved
    # field is zero as the spec prescribes, then the earliest offset.
    candidates.sort(key=lambda c: (c[0] != 20, c[1].reserved != 0, c[0]))
    return candidates[0]


@dataclass(frozen=True)
class UdtScan:
    """One assembled scan cycle of measurement data."""

    scan_number: int
    telegram_id: int                          #: 3 or 6
    distances_mm: Tuple[int, ...]             #: distance per beam [mm]
    signal_strengths: Optional[Tuple[int, ...]]  #: [digits], None for ID 6
    num_blocks: int                           #: datagrams this scan arrived in
    contour: Optional[MeasurementContour]     #: beam geometry, if known
    status: Optional[StatusProfile]           #: latest status profile, if any
    received_at: float                        #: host time.time() of completion

    @property
    def num_beams(self) -> int:
        return len(self.distances_mm)

    @property
    def distances_m(self) -> List[float]:
        return [d / 1000.0 for d in self.distances_mm]

    def valid_mask(self, max_valid_mm: int = NO_ECHO_DISTANCE_MM - 1) -> List[bool]:
        """Per beam: True if the distance is a real measurement.

        0 mm and the 32767 mm no-echo sentinel (and anything above
        ``max_valid_mm``) count as invalid.
        """
        return [0 < d <= max_valid_mm for d in self.distances_mm]

    def beam_indices(self) -> List[int]:
        if self.contour is not None:
            return self.contour.beam_indices()[:self.num_beams]
        return list(range(self.num_beams))

    def angles_deg(self,
                   angle_at_index0: float = DEFAULT_ANGLE_AT_INDEX0_DEG,
                   index_resolution: float = INDEX_RESOLUTION_DEG) -> List[float]:
        """Beam angles in degrees: ``index0_angle + index * resolution``.

        Defaults assume the RSL 200 geometry (275 deg field of view centered
        on the device front, 0.1 deg per index).  Verify the mapping against
        a known target and adjust ``angle_at_index0`` if needed.
        """
        return [angle_at_index0 + i * index_resolution
                for i in self.beam_indices()]

    def to_cartesian(self,
                     angle_at_index0: float = DEFAULT_ANGLE_AT_INDEX0_DEG,
                     index_resolution: float = INDEX_RESOLUTION_DEG,
                     skip_invalid: bool = True) -> List[Tuple[float, float]]:
        """(x, y) points in meters; beams without echo (0 mm or the 32767 mm
        sentinel) are skipped."""
        points: List[Tuple[float, float]] = []
        for dist, angle in zip(self.distances_mm,
                               self.angles_deg(angle_at_index0, index_resolution)):
            if skip_invalid and (dist == 0 or dist >= NO_ECHO_DISTANCE_MM):
                continue
            a = math.radians(angle)
            d = dist / 1000.0
            points.append((d * math.cos(a), d * math.sin(a)))
        return points


@dataclass
class UdtStats:
    datagrams: int = 0
    bad_frames: int = 0
    unknown_ids: int = 0
    status_received: int = 0
    scans_completed: int = 0
    scans_dropped_incomplete: int = 0


def _scan_newer(a: int, b: int) -> bool:
    """True if scan number ``a`` is newer than ``b`` (wrap-aware, 32 bit)."""
    return ((a - b) & 0xFFFFFFFF) < 0x80000000 and a != b


class _PendingScan:
    __slots__ = ("telegram_id", "fragments")

    def __init__(self, telegram_id: int) -> None:
        self.telegram_id = telegram_id
        self.fragments: Dict[int, bytes] = {}     # block -> payload


class UdtAssembler:
    """Reassemble UDP data telegrams into :class:`UdtScan` objects.

    Not thread safe; feed it from one thread.  ``strict`` controls whether
    scans failing the beam-count check (lost datagram) are dropped (True,
    default) or emitted as-is.
    """

    def __init__(self, strict: bool = True) -> None:
        self.strict = strict
        self.stats = UdtStats()
        self.latest_status: Optional[StatusProfile] = None
        self.contour: Optional[MeasurementContour] = None
        self._contour_offset: Optional[int] = None
        self._observed_beams: Optional[int] = None
        self._pending: Dict[int, _PendingScan] = {}

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
            self._handle_status(payload)
            return self._finalize_older_than(frame.scan_number)
        if frame.telegram_id in (TELEGRAM_ID_DISTANCE, TELEGRAM_ID_DISTANCE_SIGNAL):
            return self._handle_measurement(frame, payload)
        self.stats.unknown_ids += 1
        return []

    # -- internals -----------------------------------------------------------

    def _handle_status(self, payload: bytes) -> None:
        try:
            self.latest_status = StatusProfile.from_bytes(payload)
        except ValueError:
            self.stats.bad_frames += 1
            return
        self.stats.status_received += 1
        self._update_contour(payload)

    def _update_contour(self, payload: bytes) -> None:
        if self._contour_offset is not None:
            # Position is stable per device; just re-read it.
            if self._contour_offset + 8 <= len(payload):
                start, stop, interval, reserved = struct.unpack_from(
                    "<HHHH", payload, self._contour_offset)
                contour = MeasurementContour(start, stop, interval, reserved)
                if contour.plausible():
                    self.contour = contour
                    return
            self._contour_offset = None        # device changed? re-locate
        located = locate_contour(payload, self._observed_beams)
        if located is not None:
            self._contour_offset, self.contour = located
            log.debug("measurement contour found at offset %d: %s",
                      self._contour_offset, self.contour)

    def _handle_measurement(self, frame: UdtFrame, payload: bytes) -> List[UdtScan]:
        per_beam = 4 if frame.telegram_id == TELEGRAM_ID_DISTANCE_SIGNAL else 2
        usable = len(payload) - (len(payload) % per_beam)
        scans = self._finalize_older_than(frame.scan_number)

        pending = self._pending.get(frame.scan_number)
        if pending is None:
            pending = self._pending[frame.scan_number] = _PendingScan(frame.telegram_id)
        pending.fragments[frame.block] = payload[:usable]

        # Track the observed beam count to (re)validate the contour position.
        beams_so_far = sum(len(f) for f in pending.fragments.values()) // per_beam
        if self.contour is not None and beams_so_far == self.contour.num_beams:
            scan = self._build(frame.scan_number, pending)
            if scan is not None:
                scans.append(scan)
            del self._pending[frame.scan_number]
        return scans

    def _finalize_older_than(self, scan_number: int) -> List[UdtScan]:
        """The scanner sends strictly in order: anything older is finished."""
        done: List[UdtScan] = []
        for number in sorted(self._pending):
            if _scan_newer(scan_number, number):
                scan = self._build(number, self._pending.pop(number))
                if scan is not None:
                    done.append(scan)
        return done

    def _build(self, scan_number: int, pending: _PendingScan) -> Optional[UdtScan]:
        blocks = sorted(pending.fragments)
        contiguous = blocks == list(range(blocks[0], blocks[0] + len(blocks)))
        data = b"".join(pending.fragments[b] for b in blocks)
        per_beam = 4 if pending.telegram_id == TELEGRAM_ID_DISTANCE_SIGNAL else 2
        num_beams = len(data) // per_beam
        self._observed_beams = num_beams

        complete = contiguous
        if self.contour is not None:
            complete = complete and (num_beams == self.contour.num_beams)
        if not complete and self.strict:
            self.stats.scans_dropped_incomplete += 1
            log.debug("dropping incomplete scan %d (%d beams, blocks %s)",
                      scan_number, num_beams, blocks)
            return None

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
            num_blocks=len(blocks),
            contour=self.contour,
            status=self.latest_status,
            received_at=time.time(),
        )


class RSL235Udt:
    """Passive receiver for the RSL 235 UDP data telegrams.

    Configure the scanner in Sensor Studio (SETTINGS > Data telegrams):
    activate the UDP telegram, set this machine's IP as the destination,
    enable measurement value transmission -- then just listen:

    Parameters
    ----------
    port:
        UDP destination port configured in the scanner (default 3050).
    bind_address:
        Local interface to bind ("" = all).
    source_ip:
        If set, datagrams from any other IP are ignored.
    strict:
        Drop scans with missing fragments instead of emitting them short.
    scan_queue_size / on_scan / on_status:
        Scan buffering and optional callbacks (called from the receiver
        thread; keep them fast).
    data_timeout:
        Seconds without datagrams after which :attr:`is_receiving` is False.
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
        self.port = port
        self.bind_address = bind_address
        self.source_ip = source_ip
        self.on_scan = on_scan
        self.on_status = on_status
        self.data_timeout = data_timeout

        self._assembler = UdtAssembler(strict=strict)
        self._scan_queue: "queue.Queue[UdtScan]" = queue.Queue(maxsize=scan_queue_size)
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False
        self._last_rx: Optional[float] = None
        self.scans_dropped_queue = 0
        self.foreign_datagrams_dropped = 0

    # ------------------------------------------------------------------

    def start(self) -> "RSL235Udt":
        if self._running:
            return self
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        except OSError:
            pass
        sock.bind((self.bind_address, self.port))
        sock.settimeout(0.5)
        self._sock = sock
        self._running = True
        self._thread = threading.Thread(target=self._rx_loop,
                                        name="leuze_rsl-udt-rx", daemon=True)
        self._thread.start()
        log.info("listening for UDP data telegrams on %s:%d",
                 self.bind_address or "0.0.0.0", self.port)
        return self

    def stop(self) -> None:
        self._running = False
        sock, self._sock = self._sock, None
        if sock is not None:
            sock.close()
        thread, self._thread = self._thread, None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)

    def __enter__(self) -> "RSL235Udt":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    # ------------------------------------------------------------------

    def get_scan(self, timeout: Optional[float] = None) -> UdtScan:
        """Next complete scan; raises ``TimeoutError`` if none arrives."""
        try:
            return self._scan_queue.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError(
                "no scan received within %s s (is_receiving=%s) -- check that "
                "the scanner's UDP destination is this machine and the port "
                "matches, and that the firewall allows inbound UDP %d"
                % (timeout, self.is_receiving, self.port)) from None

    def scans(self, timeout: Optional[float] = None) -> Iterator[UdtScan]:
        """Iterate over scans until :meth:`stop` is called."""
        while True:
            if not self._running and self._scan_queue.empty():
                return
            try:
                yield self._scan_queue.get(timeout=0.2 if timeout is None else timeout)
            except queue.Empty:
                if timeout is not None:
                    raise TimeoutError("no scan received within %s s" % timeout) from None

    @property
    def latest_status(self) -> Optional[StatusProfile]:
        return self._assembler.latest_status

    @property
    def contour(self) -> Optional[MeasurementContour]:
        return self._assembler.contour

    @property
    def is_receiving(self) -> bool:
        if not self._running or self._last_rx is None:
            return False
        return (time.monotonic() - self._last_rx) < self.data_timeout

    @property
    def stats(self) -> Dict[str, int]:
        stats = vars(self._assembler.stats).copy()
        stats.update(scans_dropped_queue=self.scans_dropped_queue,
                     foreign_datagrams_dropped=self.foreign_datagrams_dropped)
        return stats

    # ------------------------------------------------------------------

    def _rx_loop(self) -> None:
        sock = self._sock
        while self._running and sock is not None:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            if self.source_ip is not None and addr[0] != self.source_ip:
                self.foreign_datagrams_dropped += 1
                continue
            self._last_rx = time.monotonic()
            had_status = self._assembler.stats.status_received
            for scan in self._assembler.feed_datagram(data):
                self._deliver(scan)
            if (self.on_status is not None
                    and self._assembler.stats.status_received > had_status
                    and self._assembler.latest_status is not None):
                try:
                    self.on_status(self._assembler.latest_status)
                except Exception:
                    log.exception("on_status callback raised")

    def _deliver(self, scan: UdtScan) -> None:
        if self.on_scan is not None:
            try:
                self.on_scan(scan)
            except Exception:
                log.exception("on_scan callback raised")
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
