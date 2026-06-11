"""Assembling MDI measurement packets into complete scans.

The scanner splits one full scan (one head rotation) into ``total_number``
MDI packets, numbered ``sub_number`` 1..total_number.  :class:`ScanAssembler`
consumes a raw byte stream (UDP datagram payloads or TCP stream chunks),
locates packets via the ``LEUZ`` sync pattern, validates them and joins them
into :class:`Scan` objects.

Unlike the reference C++ driver, the assembler is strict about packet
sequencing: a scan only starts at ``sub_number == 1`` and every following
packet must continue the sequence with consistent metadata, otherwise the
partial scan is dropped (and counted).  This avoids emitting silently
truncated scans when UDP datagrams are lost.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .protocol import (
    HEADER_SIZE,
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
    if header.packet_type == MdiPacketType.DISTANCE_AND_INTENSITY:
        return header.packet_size == HEADER_SIZE + 4 * header.scan_spots
    # Like the reference driver, treat any other packet type as
    # distances-only -- but only if the size is consistent with that.
    return header.packet_size == HEADER_SIZE + 2 * header.scan_spots

#: Hard cap for the internal reassembly buffer.  Reaching it means the input
#: is garbage (no valid sync/packet structure); old bytes are discarded.
_MAX_BUFFER = 1 << 20

#: How many trailing bytes to keep when discarding an unparseable buffer.
#: 4 bytes cover a partially received sync pattern.
_TAIL_KEEP = len(SYNC) - 1


@dataclass
class AssemblerStats:
    """Counters describing the health of the incoming data stream."""

    packets_parsed: int = 0           #: well-formed MDI packets consumed
    scans_completed: int = 0          #: complete scans emitted
    scans_dropped_incomplete: int = 0  #: partial scans dropped (lost packets)
    packets_orphaned: int = 0         #: packets that did not fit any scan
    resyncs: int = 0                  #: header validation failures (corrupt data)
    bytes_discarded: int = 0          #: garbage bytes skipped


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
        distances: List[int] = []
        intensities: List[int] = []
        angles: List[int] = []
        has_intensities = packets[0].header.packet_type == MdiPacketType.DISTANCE_AND_INTENSITY
        for packet in packets:
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

    # -- converted views ----------------------------------------------------

    @property
    def distances_m(self) -> List[float]:
        """Distances in meters (0.0 = no valid echo)."""
        return [d / 1000.0 for d in self.distances_mm]

    @property
    def angles_deg(self) -> List[float]:
        return [a / 1000.0 for a in self.angles_mdeg]

    @property
    def angles_rad(self) -> List[float]:
        return [math.radians(a / 1000.0) for a in self.angles_mdeg]

    def to_cartesian(self, skip_invalid: bool = True) -> List[Tuple[float, float]]:
        """Spots as (x, y) in meters in the scanner coordinate frame.

        ``x`` points along 0 deg, ``y`` along +90 deg.  Spots without a valid
        echo (distance 0) are omitted unless ``skip_invalid`` is False.
        """
        points: List[Tuple[float, float]] = []
        for dist, angle in zip(self.distances_mm, self.angles_mdeg):
            if dist == 0 and skip_invalid:
                continue
            a = math.radians(angle / 1000.0)
            d = dist / 1000.0
            points.append((d * math.cos(a), d * math.sin(a)))
        return points


class ScanAssembler:
    """Incrementally parse a raw MDI byte stream into complete scans.

    The assembler is transport agnostic: feed it UDP datagram payloads or
    arbitrary TCP stream chunks via :meth:`feed`, which returns any scans
    completed by the new data.  It is not thread safe; callers must feed it
    from a single thread (or guard it with a lock).
    """

    def __init__(self) -> None:
        self._buf = bytearray()
        self._pending: List[MdiPacket] = []
        self.stats = AssemblerStats()

    def reset(self) -> None:
        """Discard buffered bytes and any partially assembled scan."""
        self._buf.clear()
        if self._pending:
            self.stats.scans_dropped_incomplete += 1
        self._pending = []

    def feed(self, data: bytes) -> List[Scan]:
        """Consume raw bytes; return scans completed by this data."""
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
                if len(buf) > _MAX_BUFFER:  # cannot happen with idx==0, kept for safety
                    del buf[:]
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
                if len(buf) > _MAX_BUFFER:
                    self.stats.bytes_discarded += len(buf)
                    del buf[:]
                return None
            packet = parse_packet(bytes(buf[:header.packet_size]))
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
            expected = self._pending and (
                header.sub_number == self._pending[-1].header.sub_number + 1
                and header.total_number == self._pending[0].header.total_number
                and header.packet_type == self._pending[0].header.packet_type
            )
            if not expected:
                if self._pending:
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
