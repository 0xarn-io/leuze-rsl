"""Software stand-ins for Leuze scanners, for tests and offline demos.

Two simulators are provided:

* :class:`UdtSimulator` -- pushes RSL-style **UDP data telegrams** (extended
  status profile + measurement data) to a target address, replicating the
  behavior observed on real RSL 235 hardware.  This is what
  :class:`~leuze_rsl.udt.RSL235Udt` receives.
* :class:`RSL235Simulator` -- implements the ROD-300-500 protocol (TCP
  command server answering ``cWN``/``cRN`` plus a ``LEUZ`` MDI packet
  streamer over UDP or TCP), as used by ROD x08 scanners and
  :class:`~leuze_rsl.driver.RSL235`.

Run standalone::

    python3 -m leuze_rsl.simulator --port 3050            # UDT push mode
    python3 -m leuze_rsl.simulator --rod --port 3050      # ROD protocol mode

Fault-injection knobs exist on both to exercise the receivers' robustness
in the test suite.
"""

from __future__ import annotations

import argparse
import logging
import math
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from .protocol import (
    ETX,
    HEADER_SIZE,
    STX,
    MdiHeader,
    MdiPacketType,
    MdiProtocol,
    Resolution,
    ScanDirection,
)

__all__ = ["RSL235Simulator", "SimulatorSettings"]

log = logging.getLogger("leuze_rsl.simulator")


@dataclass
class SimulatorSettings:
    """The simulated scanner's configuration and status values."""

    protocol: int = MdiProtocol.UDP
    packet_type: int = MdiPacketType.DISTANCE_AND_INTENSITY
    resolution: int = Resolution.RES_0200_AT_80HZ
    direction: int = ScanDirection.COUNTERCLOCKWISE
    angle_min_cdeg: int = -13760            #: [0.01 deg]
    angle_max_cdeg: int = 13760             #: [0.01 deg]
    skip_spots: int = 0
    contamination_warn_pct: int = 90
    contamination_error_pct: int = 100
    contamination_state: Tuple[int, ...] = (0,) * 9
    part_number: int = 53802110             #: RSL235-S/12-M12
    hw_version: int = 1
    sw_version: int = 2
    version_extra: Tuple[int, ...] = (0, 0, 0, 0)
    temperature_cdeg: int = 2350            #: [0.01 degC]
    operating_hours: int = 17
    window_calibration: int = 1
    filter_type: int = 0
    filter_historical_spots: int = 0
    filter_neighboring_spots: int = 0
    error_code: int = 0
    error_log_extra: int = 0
    error_log: Tuple[Tuple[int, int], ...] = ((0, 0),) * 10
    spots_per_packet: int = 600
    room_half_width_mm: int = 3000
    room_half_height_mm: int = 2000
    max_range_mm: int = 25000


class RSL235Simulator:
    """Simulated RSL 235 / ROD x08 scanner (one TCP client at a time)."""

    def __init__(self,
                 host: str = "127.0.0.1",
                 port: int = 0,
                 *,
                 udp_dest_port: Optional[int] = None,
                 settings: Optional[SimulatorSettings] = None,
                 stream_on_connect: bool = False,
                 drop_subs: Optional[Dict[int, Set[int]]] = None,
                 start_mid_scan: int = 0,
                 split_writes: int = 0,
                 prepend_garbage: bytes = b"",
                 mute: bool = False) -> None:
        self.host = host
        self.port = port                  # resolved on start() when 0
        self._udp_dest_port = udp_dest_port
        self.settings = settings or SimulatorSettings()

        # Fault injection
        self.stream_on_connect = stream_on_connect
        self.drop_subs = drop_subs or {}      #: scan index -> sub numbers to drop
        self.start_mid_scan = start_mid_scan  #: first scan starts at this sub
        self.split_writes = split_writes      #: TCP: flush in chunks this size
        self.prepend_garbage = prepend_garbage
        self.corrupt_next_packet = False      #: zero packet_size of next packet
        self.mute = mute                      #: do not answer commands

        # Counters for assertions in tests
        self.packets_sent = 0
        self.scans_generated = 0
        self.commands_received: List[str] = []

        self._listen_sock: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._stream_thread: Optional[threading.Thread] = None
        self._client_conn: Optional[socket.socket] = None
        self._send_lock = threading.Lock()
        self._streaming = False
        self._closing = False
        self._t0 = time.monotonic()
        self._packet_number = 0

    # ------------------------------------------------------------------

    @property
    def udp_dest_port(self) -> int:
        return self._udp_dest_port if self._udp_dest_port is not None else self.port

    @property
    def streaming(self) -> bool:
        return self._streaming

    def start(self) -> "RSL235Simulator":
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(1)
        sock.settimeout(0.2)
        self.port = sock.getsockname()[1]
        self._listen_sock = sock
        self._closing = False
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="rsl235sim-accept", daemon=True)
        self._accept_thread.start()
        log.info("simulator listening on %s:%d", self.host, self.port)
        return self

    def stop(self) -> None:
        self._closing = True
        self._stop_stream()
        conn = self._client_conn
        if conn is not None:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()
        sock, self._listen_sock = self._listen_sock, None
        if sock is not None:
            sock.close()
        thread, self._accept_thread = self._accept_thread, None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)

    def __enter__(self) -> "RSL235Simulator":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    # ------------------------------------------------------------------
    # TCP command server
    # ------------------------------------------------------------------

    def _accept_loop(self) -> None:
        listen = self._listen_sock
        while not self._closing and listen is not None:
            try:
                conn, addr = listen.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            log.info("client connected from %s:%d", *addr[:2])
            try:
                self._serve_client(conn, addr[0])
            except Exception:
                log.exception("client handler failed")
            finally:
                self._stop_stream()
                self._client_conn = None
                conn.close()
                log.info("client disconnected")

    def _serve_client(self, conn: socket.socket, client_ip: str) -> None:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        conn.settimeout(0.2)
        self._client_conn = conn
        if self.stream_on_connect:
            self._start_stream(conn, client_ip)
        buf = bytearray()
        while not self._closing:
            try:
                data = conn.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if not data:
                return
            buf += data
            while True:
                stx = buf.find(STX)
                if stx < 0:
                    buf.clear()
                    break
                etx = buf.find(ETX, stx)
                if etx < 0:
                    del buf[:stx]
                    break
                frame = bytes(buf[stx + 1:etx]).decode("ascii", errors="replace")
                del buf[:etx + 1]
                self._dispatch(conn, client_ip, frame)

    def _dispatch(self, conn: socket.socket, client_ip: str, frame: str) -> None:
        tokens = frame.split()
        if len(tokens) != 2:
            log.warning("ignoring malformed command frame: %r", frame)
            return
        verb, name = tokens
        self.commands_received.append(name)
        log.debug("command: %s %s", verb, name)
        if self.mute:
            return
        if verb == "cWN":
            if name == "SendMDI":
                self._start_stream(conn, client_ip)
                self._reply(conn, "cWA SendMDI")
            elif name == "StopMDI":
                self._stop_stream()
                self._reply(conn, "cWA StopMDI")
            else:
                log.warning("unknown write command: %s", name)
        elif verb == "cRN":
            values = self._read_values(name)
            if values is None:
                log.warning("unknown read command: %s", name)
                return
            self._reply(conn, "cRA %s %s" % (name, " ".join(str(v) for v in values)))
        else:
            log.warning("unknown verb: %s", verb)

    def _read_values(self, name: str) -> Optional[List[int]]:
        s = self.settings
        table = {
            "GetProto": [int(s.protocol)],
            "GetPType": [int(s.packet_type)],
            "GetResol": [int(s.resolution)],
            "GetDir": [int(s.direction)],
            "GetRange": [s.angle_min_cdeg, s.angle_max_cdeg],
            "GetSkip": [s.skip_spots],
            "GetCont": [s.contamination_warn_pct, s.contamination_error_pct],
            "GetWinStat": list(s.contamination_state),
            "GetVer": [s.part_number, s.hw_version, s.sw_version, *s.version_extra],
            "GetTem": [s.temperature_cdeg],
            "GetELog": [s.error_log_extra,
                        *(v for pair in s.error_log for v in pair)],
            "GetHours": [s.operating_hours],
            "GetWCalib": [s.window_calibration],
            "GetFilter": [s.filter_type, s.filter_historical_spots,
                          s.filter_neighboring_spots],
            "GetECode": [s.error_code],
            "GetTxMDI": [1 if self._streaming else 0],
        }
        return table.get(name)

    def _reply(self, conn: socket.socket, text: str) -> None:
        self._tcp_send(conn, STX + text.encode("ascii") + ETX)

    def _tcp_send(self, conn: socket.socket, data: bytes) -> None:
        with self._send_lock:
            try:
                if self.split_writes > 0:
                    for i in range(0, len(data), self.split_writes):
                        conn.sendall(data[i:i + self.split_writes])
                        time.sleep(0.0005)  # encourage separate TCP segments
                else:
                    conn.sendall(data)
            except OSError:
                pass

    # ------------------------------------------------------------------
    # MDI streaming
    # ------------------------------------------------------------------

    def _start_stream(self, conn: socket.socket, client_ip: str) -> None:
        if self._streaming:
            return
        self._streaming = True
        self._stream_thread = threading.Thread(
            target=self._stream_loop, args=(conn, client_ip),
            name="rsl235sim-stream", daemon=True)
        self._stream_thread.start()

    def _stop_stream(self) -> None:
        self._streaming = False
        thread, self._stream_thread = self._stream_thread, None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)

    def _stream_loop(self, conn: socket.socket, client_ip: str) -> None:
        s = self.settings
        proto = int(s.protocol)
        period = Resolution(int(s.resolution)).scan_time_s
        chunks = self._prepare_chunks()
        udp_sock: Optional[socket.socket] = None
        if proto == MdiProtocol.UDP:
            udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        garbage_pending = bool(self.prepend_garbage)
        scan_index = 0
        next_time = time.monotonic()
        try:
            while self._streaming and not self._closing:
                for raw in self._build_scan(chunks, scan_index):
                    if garbage_pending:
                        raw = self.prepend_garbage + raw
                        garbage_pending = False
                    if udp_sock is not None:
                        udp_sock.sendto(raw, (client_ip, self.udp_dest_port))
                    else:
                        self._tcp_send(conn, raw)
                    self.packets_sent += 1
                self.scans_generated += 1
                scan_index += 1
                next_time += period
                delay = next_time - time.monotonic()
                if delay > 0:
                    time.sleep(min(delay, period))
                else:
                    next_time = time.monotonic()    # fell behind; don't burst
        finally:
            if udp_sock is not None:
                udp_sock.close()

    def _prepare_chunks(self) -> List[Tuple[int, bytes, bytes]]:
        """Precompute (first_angle_mdeg, distance payload, intensity payload)
        for every packet of a scan; only headers change between scans."""
        s = self.settings
        res_deg = Resolution(int(s.resolution)).degrees * (s.skip_spots + 1)
        span_deg = (s.angle_max_cdeg - s.angle_min_cdeg) / 100.0
        num_spots = int(round(span_deg / res_deg)) + 1
        delta_mdeg = int(round(res_deg * 1000))
        if int(s.direction) == ScanDirection.COUNTERCLOCKWISE:
            first_mdeg = s.angle_min_cdeg * 10
        else:
            first_mdeg = s.angle_max_cdeg * 10
            delta_mdeg = -delta_mdeg
        self._delta_mdeg = delta_mdeg
        self._num_spots = num_spots

        angles_mdeg = [first_mdeg + i * delta_mdeg for i in range(num_spots)]
        distances = [self._room_distance_mm(a / 1000.0) for a in angles_mdeg]
        intensities = [max(32, min(4095, 1000 + int(800 * math.sin(i * 0.01))))
                       for i in range(num_spots)]

        chunks: List[Tuple[int, bytes, bytes]] = []
        for off in range(0, num_spots, s.spots_per_packet):
            n = min(s.spots_per_packet, num_spots - off)
            dist_payload = struct.pack(">%dH" % n, *distances[off:off + n])
            int_payload = struct.pack(">%dH" % n, *intensities[off:off + n])
            chunks.append((angles_mdeg[off], dist_payload, int_payload))
        return chunks

    def _room_distance_mm(self, angle_deg: float) -> int:
        """Analytic ray cast from the room center to a rectangular wall."""
        s = self.settings
        a = math.radians(angle_deg)
        dx, dy = math.cos(a), math.sin(a)
        d = float(s.max_range_mm)
        if abs(dx) > 1e-9:
            d = min(d, s.room_half_width_mm / abs(dx))
        if abs(dy) > 1e-9:
            d = min(d, s.room_half_height_mm / abs(dy))
        return int(d)

    def _build_scan(self, chunks: List[Tuple[int, bytes, bytes]],
                    scan_index: int) -> List[bytes]:
        s = self.settings
        ptype = int(s.packet_type)
        freq = int(Resolution(int(s.resolution)).frequency_hz)
        total = len(chunks)
        timestamp = int((time.monotonic() - self._t0) * 1000) & 0xFFFF
        dropped = self.drop_subs.get(scan_index, set())
        packets: List[bytes] = []
        for sub, (first_angle, dist_payload, int_payload) in enumerate(chunks, start=1):
            self._packet_number = (self._packet_number + 1) & 0xFFFF
            if sub in dropped:
                continue                      # simulate a lost datagram
            if scan_index == 0 and sub < self.start_mid_scan:
                continue                      # simulate joining mid-scan
            n = len(dist_payload) // 2
            payload = dist_payload + int_payload if ptype == MdiPacketType.DISTANCE_AND_INTENSITY \
                else dist_payload
            header = MdiHeader(
                packet_type=ptype,
                packet_size=HEADER_SIZE + len(payload),
                reserve_a=0, reserve_b=0, reserve_c=0,
                packet_number=self._packet_number,
                total_number=total,
                sub_number=sub,
                scan_freq=freq,
                scan_spots=n,
                first_angle=first_angle,
                delta_angle=self._delta_mdeg,
                timestamp=timestamp,
            )
            raw = header.to_bytes() + payload
            if self.corrupt_next_packet:
                # Zero the packet_size field -- the corruption that loops the
                # reference C++ parser forever.
                raw = raw[:5] + b"\x00\x00" + raw[7:]
                self.corrupt_next_packet = False
            packets.append(raw)
        return packets


class UdtSimulator:
    """Push RSL-style UDP data telegrams to a target, like a real RSL 235.

    Per scan cycle it sends one extended status profile (ID 1, 56 bytes --
    matching the datagram size observed on real RSL 235 hardware) followed
    by the measurement data (ID 3 or 6) split into ``beams_per_datagram``
    fragments with consecutive block numbers.

    Fault-injection knobs for tests: ``drop_blocks`` (scan index -> block
    numbers to withhold), ``contour_offset`` (move the contour description
    inside the status datagram to exercise the receiver's auto-location).
    """

    #: H1 tail and H2 exactly as captured from real RSL 235 hardware.
    H1_TAIL = (8, 0, 6)                      # h1_size, follow_flag, request_id
    HEADER2 = b"\x04\x0b\x01\x32"

    def __init__(self,
                 target_host: str = "127.0.0.1",
                 target_port: int = 3050,
                 *,
                 telegram_id: int = 3,
                 contour: Tuple[int, int, int] = (0, 2700, 10),
                 scan_period_s: float = 0.025,
                 beams_per_datagram: int = 350,
                 status_extra_bytes: int = 8,
                 contour_offset: int = 20,
                 drop_blocks: Optional[Dict[int, Set[int]]] = None,
                 room_half_width_mm: int = 3000,
                 room_half_height_mm: int = 2000,
                 max_range_mm: int = 25000) -> None:
        if telegram_id not in (3, 6):
            raise ValueError("telegram_id must be 3 or 6")
        self.target = (target_host, target_port)
        self.telegram_id = telegram_id
        self.contour = contour                #: (start_index, stop_index, interval)
        self.scan_period_s = scan_period_s
        self.beams_per_datagram = beams_per_datagram
        self.status_extra_bytes = status_extra_bytes
        self.contour_offset = contour_offset
        self.drop_blocks = drop_blocks or {}
        self.room_half_width_mm = room_half_width_mm
        self.room_half_height_mm = room_half_height_mm
        self.max_range_mm = max_range_mm

        self.scans_sent = 0
        self.datagrams_sent = 0
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._running = False

    def start(self) -> "UdtSimulator":
        if self._running:
            return self
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._running = True
        self._thread = threading.Thread(target=self._loop,
                                        name="rsl235sim-udt", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._running = False
        thread, self._thread = self._thread, None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        sock, self._sock = self._sock, None
        if sock is not None:
            sock.close()

    def __enter__(self) -> "UdtSimulator":
        return self.start()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    # ------------------------------------------------------------------

    def _frame(self, total_length: int, telegram_id: int, block: int,
               scan_number: int) -> bytes:
        h1_size, follow_flag, request_id = self.H1_TAIL
        return struct.pack("<IBBH4sHHI", total_length, h1_size, follow_flag,
                           request_id, self.HEADER2, telegram_id, block,
                           scan_number & 0xFFFFFFFF)

    def _status_datagram(self, scan_number: int) -> bytes:
        start, stop, interval = self.contour
        status = bytearray(20)
        status[0] = 1                                       # profile type
        status[1] = 1                                       # safety mode
        status[12] = 0x80                                   # A-ACTIVE
        struct.pack_into("<I", status, 8, scan_number & 0xFFFFFFFF)
        contour = struct.pack("<HHHH", start, stop, interval, 0)
        data = bytearray(self.contour_offset + 8 + self.status_extra_bytes)
        data[:20] = status
        data[self.contour_offset:self.contour_offset + 8] = contour
        return self._frame(20 + len(data), 1, 0, scan_number) + bytes(data)

    def _beam_values(self) -> List[int]:
        start, stop, interval = self.contour
        num = 1 + -(-(stop - start) // interval)
        values: List[int] = []
        for i in range(num):
            index = start + i * interval
            angle = math.radians(index * 0.1 - 137.5)
            dx, dy = math.cos(angle), math.sin(angle)
            d = float(self.max_range_mm)
            if abs(dx) > 1e-9:
                d = min(d, self.room_half_width_mm / abs(dx))
            if abs(dy) > 1e-9:
                d = min(d, self.room_half_height_mm / abs(dy))
            values.append(int(d))
        return values

    def _measurement_datagrams(self, scan_number: int,
                               distances: List[int]) -> List[bytes]:
        datagrams: List[bytes] = []
        per = self.beams_per_datagram
        for block, off in enumerate(range(0, len(distances), per)):
            chunk = distances[off:off + per]
            if self.telegram_id == 3:
                payload = b"".join(
                    struct.pack("<HH", d, max(100, min(50000, d // 2)))
                    for d in chunk)
            else:
                payload = struct.pack("<%dH" % len(chunk), *chunk)
            datagrams.append(
                self._frame(20 + len(payload), self.telegram_id, block,
                            scan_number) + payload)
        return datagrams

    def _loop(self) -> None:
        sock = self._sock
        distances = self._beam_values()
        scan_number = 0
        next_time = time.monotonic()
        while self._running and sock is not None:
            try:
                sock.sendto(self._status_datagram(scan_number), self.target)
                self.datagrams_sent += 1
                dropped = self.drop_blocks.get(self.scans_sent, set())
                for block, datagram in enumerate(
                        self._measurement_datagrams(scan_number, distances)):
                    if block in dropped:
                        continue
                    sock.sendto(datagram, self.target)
                    self.datagrams_sent += 1
            except OSError:
                break
            self.scans_sent += 1
            scan_number += 1
            next_time += self.scan_period_s
            delay = next_time - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            else:
                next_time = time.monotonic()


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="RSL235 scanner simulator")
    parser.add_argument("--host", default="127.0.0.1",
                        help="UDT mode: target host / ROD mode: listen host")
    parser.add_argument("--port", type=int, default=3050)
    parser.add_argument("--rod", action="store_true",
                        help="serve the ROD-300-500 protocol (TCP command "
                             "interface + LEUZ MDI packets) instead of "
                             "pushing UDP data telegrams")
    parser.add_argument("--protocol", choices=["udp", "tcp"], default="udp",
                        help="ROD mode: transport for the measurement data")
    parser.add_argument("--distances-only", action="store_true",
                        help="send distance-only telegrams (ID 6 / type 0)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s: %(message)s")
    if args.rod:
        settings = SimulatorSettings(
            protocol=MdiProtocol.TCP if args.protocol == "tcp" else MdiProtocol.UDP,
            packet_type=MdiPacketType.DISTANCE if args.distances_only
            else MdiPacketType.DISTANCE_AND_INTENSITY,
        )
        sim = RSL235Simulator(host=args.host, port=args.port, settings=settings)
        sim.start()
        print("ROD-protocol simulator listening on %s:%d (MDI via %s) -- "
              "Ctrl+C to stop" % (sim.host, sim.port, args.protocol.upper()))
    else:
        sim = UdtSimulator(target_host=args.host, target_port=args.port,
                           telegram_id=6 if args.distances_only else 3)
        sim.start()
        print("UDT simulator pushing data telegrams to %s:%d -- Ctrl+C to stop"
              % sim.target)
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        sim.stop()


if __name__ == "__main__":
    main()
