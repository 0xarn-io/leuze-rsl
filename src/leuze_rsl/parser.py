"""Assembling ROD-300-500 MDI measurement packets into complete scans.

The scanner splits one full scan (one head rotation) into ``total_number``
MDI packets, numbered ``sub_number`` 1..total_number.  :class:`ScanAssembler`
consumes a raw byte stream (UDP datagram payloads or TCP stream chunks),
locates packets via the ``LEUZ`` sync pattern, validates them and joins them
into :class:`Scan` objects.

Unlike the reference C++ driver, the assembler is strict about packet
sequencing: a scan only starts at ``sub_number == 1`` and every following
packet must continue the sequence (``sub_number`` + 1, consecutive
``packet_number``) with consistent metadata, otherwise the partial scan is
dropped (and counted).  This avoids emitting silently truncated or stitched
scans when UDP datagrams are lost.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from functools import cached_property
from typing import List, Optional, Tuple

from .errors import ProtocolError
from .protocol import (
    HEADER_SIZE,
    INTENSITY_MIN_VALID,
    SYNC,
    MdiHeader,
    MdiPacket,
    MdiPacketType,
    parse_packet,
)

__all__ = ["Scan", "ScanAssembler", "AssemblerStats", "header_plausible"]


def header_plausible(header: MdiHeader) -> bool:
    """Sanity-check an MDI header before trusting its ``packet_size``.

    Guards against corrupt headers; notably ``packet_size < 31`` would make
    a naive parser loop forever (a real bug in the reference C++ driver).
    """
    if header.packet_size < HEADER_SIZE:
        return False
    if header.total_number < 1 or not (1 <= header.sub_number <= header.total_number):
        return False
    # Like the reference driver, treat any packet type other than 1 as
    # distances-only -- but only if the size is consistent with that.
    return header.packet_size == header.expected_size()


#: How many trailing bytes to keep when discarding an unparseable buffer:
#: 3 bytes cover a partially received 4-byte sync pattern.
_TAIL_KEEP = len(SYNC) - 1


@dataclass
class AssemblerStats:
    """Counters describing the health of the incoming data stream."""

    packets_parsed: int = 0            #: well-formed MDI packets consumed
    scans_completed: int = 0           #: complete scans emitted
    scans_dropped_incomplete: int = 0  #: partial scans dropped (lost packets)
    packets_orphaned: int = 0          #: packets that did not fit any scan
    packets_out_of_sequence: int = 0   #: packet_number gaps detected (lost packets)
    resyncs: int = 0                   #: header validation failures (corrupt data)
    bytes_discarded: int = 0           #: garbage bytes skipped


@dataclass(frozen=True)
class Scan:
    """One complete scan (a full rotation of the scanner head).

    Spots are in scanner-native order: ``angles_mdeg[i]`` is the absolute
    beam angle of spot ``i`` in 1/1000 degree, exactly as reported in the
    packet headers (``first_angle`` + i * ``delta_angle``).  The sign of the
    angle increment reflects the configured data output direction.
    """

    headers: Tuple[MdiHeader, ...]           #: headers of all packets, in order
    distances_mm: Tuple[int, ...]            #: distance per spot [mm]; 0 = no echo
    intensities: Optional[Tuple[int, ...]]   #: signal strength per spot, or None
    angles_mdeg: Tuple[int, ...]             #: absolute angle per spot [1/1000 deg]

    @classmethod
    def from_packets(cls, packets: Tuple[MdiPacket, ...]) -> "Scan":
        if not packets:
            raise ValueError("a scan needs at least one packet")
        has_intensities = packets[0].header.packet_type == MdiPacketType.DISTANCE_AND_INTENSITY
        distances: List[int] = []
        intensities: List[int] = []
        angles: List[int] = []
        for packet in packets:
            if (packet.header.packet_type == MdiPacketType.DISTANCE_AND_INTENSITY) != has_intensities:
                raise ValueError("packets of one scan must share the packet type")
            distances.extend(packet.distances_mm)
            if has_intensities and packet.intensities is not None:
                intensities.extend(packet.intensities)
            angles.extend(packet.angles_mdeg())
        return cls(
            headers=tuple(p.header for p in packets),
            distances_mm=tuple(distances),
            intensities=tuple(intensities) if has_intensities else None,
            angles_mdeg=tuple(angles),
        )

    # -- metadata ----------------------------------------------------------

    @property
    def num_spots(self) -> int:
        return len(self.distances_mm)

    @property
    def packet_type(self) -> int:
        return self.headers[0].packet_type

    @property
    def scan_frequency_hz(self) -> int:
        return self.headers[0].scan_freq

    @property
    def packet_number(self) -> int:
        """Packet number of the first packet of this scan (wraps at 2**16)."""
        return self.headers[0].packet_number

    @property
    def timestamp_ms(self) -> int:
        """Scanner timestamp of the last packet [ms] (wraps at 2**16)."""
        return self.headers[-1].timestamp

    # -- converted views (computed once, cached) -----------------------------

    @cached_property
    def distances_m(self) -> Tuple[float, ...]:
        """Distances in meters (0.0 = no valid echo)."""
        return tuple(d / 1000.0 for d in self.distances_mm)

    @cached_property
    def angles_deg(self) -> Tuple[float, ...]:
        return tuple(a / 1000.0 for a in self.angles_mdeg)

    @cached_property
    def angles_rad(self) -> Tuple[float, ...]:
        return tuple(math.radians(a / 1000.0) for a in self.angles_mdeg)

    def valid_mask(self, min_intensity: int = INTENSITY_MIN_VALID) -> List[bool]:
        """Per spot: True if it is a real measurement.

        A distance of 0 means no echo; when intensities are present, values
        below ``min_intensity`` (reference driver: 32) mark an undefined
        measurement.
        """
        if self.intensities is None:
            return [d > 0 for d in self.distances_mm]
        return [d > 0 and i >= min_intensity
                for d, i in zip(self.distances_mm, self.intensities)]

    def to_cartesian(self, skip_invalid: bool = True,
                     min_intensity: int = INTENSITY_MIN_VALID) -> List[Tuple[float, float]]:
        """Spots as (x, y) in meters in the scanner coordinate frame.

        ``x`` points along 0 deg, ``y`` along +90 deg.  Spots that are not
        valid (see :meth:`valid_mask`) are omitted unless ``skip_invalid``
        is False.
        """
        points: List[Tuple[float, float]] = []
        for dist, angle, ok in zip(self.distances_mm, self.angles_rad,
                                   self.valid_mask(min_intensity)):
            if skip_invalid and not ok:
                continue
            d = dist / 1000.0
            points.append((d * math.cos(angle), d * math.sin(angle)))
        return points


class ScanAssembler:
    """Incrementally parse a raw MDI byte stream into complete scans.

    The assembler is transport agnostic: feed it TCP stream chunks via
    :meth:`feed` (bytes may be split arbitrarily) or whole UDP datagrams via
    :meth:`feed_datagram` (a datagram must hold whole packets; nothing is
    carried over between datagrams).  Both return any scans completed by the
    new data.  It is not thread safe; callers must feed it from a single
    thread (or guard it with a lock).
    """

    def __init__(self) -> None:
        self._buf = bytearray()
        self._pending: List[MdiPacket] = []
        self.stats = AssemblerStats()

    def reset(self) -> None:
        """Discard buffered bytes and any partially assembled scan."""
        self.stats.bytes_discarded += len(self._buf)
        self._buf.clear()
        if self._pending:
            self.stats.scans_dropped_incomplete += 1
        self._pending = []

    def feed(self, data: bytes) -> List[Scan]:
        """Consume raw stream bytes; return scans completed by this data."""
        self._buf += data
        scans: List[Scan] = []
        while True:
            packet = self._extract_packet()
            if packet is None:
                break
            scan = self._integrate(packet)
            if scan is not None:
                scans.append(scan)
        return scans

    def feed_datagram(self, data: bytes) -> List[Scan]:
        """Consume one UDP datagram holding whole MDI packets.

        Trailing bytes that do not form a complete packet are discarded
        (counted in ``stats.bytes_discarded``) instead of being joined with
        the next datagram, so one corrupt datagram cannot swallow the
        following ones.
        """
        scans = self.feed(data)
        if self._buf:
            self.stats.bytes_discarded += len(self._buf)
            self._buf.clear()
        return scans

    # -- internals -----------------------------------------------------------

    def _extract_packet(self) -> Optional[MdiPacket]:
        """Pop the next valid MDI packet off the buffer, or None to wait."""
        buf = self._buf
        while True:
            idx = buf.find(SYNC)
            if idx < 0:
                # No sync: drop everything except a possible partial sync tail.
                if len(buf) > _TAIL_KEEP:
                    self.stats.bytes_discarded += len(buf) - _TAIL_KEEP
                    del buf[:-_TAIL_KEEP]
                return None
            if idx > 0:
                self.stats.bytes_discarded += idx
                del buf[:idx]
            if len(buf) < HEADER_SIZE:
                return None
            header = MdiHeader.from_bytes(buf)
            if not header_plausible(header):
                # Corrupt header: skip past this sync pattern and search again.
                # (The reference driver loops forever on packet_size == 0.)
                self.stats.resyncs += 1
                self.stats.bytes_discarded += len(SYNC)
                del buf[:len(SYNC)]
                continue
            if len(buf) < header.packet_size:
                # Wait for the rest; packet_size is a u16, so the buffer
                # never grows beyond 64 KiB plus one chunk.
                return None
            try:
                packet = parse_packet(bytes(buf[:header.packet_size]))
            except ProtocolError:          # cannot happen after header_plausible
                self.stats.resyncs += 1
                self.stats.bytes_discarded += len(SYNC)
                del buf[:len(SYNC)]
                continue
            del buf[:header.packet_size]
            self.stats.packets_parsed += 1
            return packet

    def _integrate(self, packet: MdiPacket) -> Optional[Scan]:
        """Add a packet to the pending scan; return the scan when complete."""
        header = packet.header
        if header.sub_number == 1:
            if self._pending:
                self.stats.scans_dropped_incomplete += 1
            self._pending = [packet]
        else:
            if not self._pending:
                self.stats.packets_orphaned += 1
                return None
            first = self._pending[0].header
            last = self._pending[-1].header
            # The packet counter advances by one per packet; a larger gap
            # means datagrams were lost (possibly a whole rotation, which
            # would otherwise be stitched into this scan unnoticed).
            step = (header.packet_number - last.packet_number) & 0xFFFF
            if step > 1:
                self.stats.packets_out_of_sequence += 1
            expected = (
                header.sub_number == last.sub_number + 1
                and header.total_number == first.total_number
                and header.packet_type == first.packet_type
                and step <= 1
            )
            if not expected:
                self.stats.scans_dropped_incomplete += 1
                self._pending = []
                self.stats.packets_orphaned += 1
                return None
            self._pending.append(packet)

        if header.sub_number == header.total_number:
            scan = Scan.from_packets(tuple(self._pending))
            self._pending = []
            self.stats.scans_completed += 1
            return scan
        return None
