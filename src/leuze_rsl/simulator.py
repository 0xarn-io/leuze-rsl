"""Software stand-ins for Leuze scanners, for tests and offline demos.

Two simulators are provided:

* :class:`UdtSimulator` -- pushes RSL 200 / RSL 400 style **UDP data
  telegrams** (extended status profile + measurement data) to a target
  address.  The frame bytes come from an RSL 235 hardware capture, the
  status profile and measurement contour follow the Leuze "RSL 200 / RSL 400
  UDP specification" (50130122) byte for byte.  This is what
  :class:`~leuze_rsl.udt.RSL235Udt` receives.
* :class:`RodSimulator` -- implements the ROD-300-500 protocol of the Leuze
  **ROD 308 / ROD 508** navigation scanners (a TCP command server answering
  ``cWN``/``cRN`` plus a ``LEUZ`` MDI packet streamer over UDP or TCP), as
  spoken by the ROD client in :mod:`leuze_rsl.driver`.  It does *not* model
  an RSL 235: the RSL safety scanners only push UDP data telegrams.

Run standalone::

    python3 -m leuze_rsl.simulator --port 3050                 # RSL 200 UDT push mode
    python3 -m leuze_rsl.simulator --family rsl400 --port 3050 # RSL 400 UDT push mode
    python3 -m leuze_rsl.simulator --rod --port 3050           # ROD protocol mode

Fault-injection knobs exist on both to exercise the receivers' robustness
in the test suite.  Every simulator thread catches its own exceptions, logs
them and resets its running/streaming flag, so a dead simulator is never
mistaken for a live one.
"""

from __future__ import annotations

import argparse
import logging
import math
import os
import socket
import struct
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from types import TracebackType
from typing import Deque, Dict, List, Optional, Set, Tuple, Type, Union

from .protocol import (
    ANGLE_MAX_CDEG,
    ANGLE_MIN_CDEG,
    ETX,
    HEADER_SIZE,
    INTENSITY_MAX,
    INTENSITY_MIN_VALID,
    STX,
    MdiHeader,
    MdiPacketType,
    MdiProtocol,
    Resolution,
    ScanDirection,
    expected_spots,
)
from .udt import (
    FRAME_SIZE,
    GEOMETRY,
    STATUS_PROFILE_TYPE_RSL200,
    STATUS_PROFILE_TYPE_RSL400,
    MeasurementContour,
    ScannerFamily,
)

__all__ = [
    "RodSimulator",
    "RSL235Simulator",
    "SimulatorSettings",
    "UdtSimulator",
]

log = logging.getLogger("leuze_rsl.simulator")

#: Packets per scan the MDI header can express (``total_number`` is a u8).
MAX_PACKETS_PER_SCAN = 255

#: Poll interval of blocking socket calls (bounds the stop() latency).
_POLL_S = 0.2
#: How long stop()/StopMDI wait for a simulator thread to finish.
_JOIN_S = 2.0

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INTERRUPTED = 130


def _udp_bindable(port: int) -> bool:
    """True if a UDP socket can be bound to ``port`` on all interfaces right now."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if sys.platform == "win32":
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        probe.bind(("", port))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def _room_distance_mm(angle_deg: float, half_width_mm: int, half_height_mm: int) -> float:
    """Analytic ray cast from the centre of a rectangular room to its wall."""
    a = math.radians(angle_deg)
    dx, dy = math.cos(a), math.sin(a)
    d = math.inf
    if abs(dx) > 1e-9:
        d = min(d, half_width_mm / abs(dx))
    if abs(dy) > 1e-9:
        d = min(d, half_height_mm / abs(dy))
    return d


# ---------------------------------------------------------------------------
# ROD-300-500 protocol simulator
# ---------------------------------------------------------------------------


@dataclass
class SimulatorSettings:
    """The simulated ROD scanner's configuration and status values.

    These are what the command interface reports (``GetProto`` ... ``GetECode``)
    and what the MDI stream is generated from.  ``room_*`` / ``max_range_mm``
    describe the simulated environment; ``scan_period_s`` optionally
    overrides the scan period implied by ``resolution`` (a test knob -- the
    frequency reported in the MDI headers stays the nominal one).
    """

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
    part_number: int = 53802110             #: reported by GetVer (test value)
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
    scan_period_s: Optional[float] = None   #: override of the resolution's scan period


class RodSimulator:
    """Simulated Leuze ROD 308 / ROD 508 scanner (ROD-300-500 protocol).

    Serves one TCP client at a time on ``host:port`` (``port=0`` picks a free
    port, see :attr:`port` after :meth:`start`).  ``SendMDI`` starts the
    measurement stream -- UDP datagrams to the client's IP on
    ``udp_dest_port`` (default: the TCP port, like the real device) or
    packets interleaved on the command socket, per ``settings.protocol``.

    **Scan geometry.**  Each scan has
    :func:`~leuze_rsl.protocol.expected_spots` spots -- the same formula the
    driver uses -- at ``resolution * (skip_spots + 1)`` degree steps across
    the configured range, measured in a rectangular room
    (``settings.room_half_*_mm``).  Spots whose ray would exceed
    ``settings.max_range_mm`` are reported as *no echo*: distance 0 and
    intensity 0, below ``INTENSITY_MIN_VALID``.  ``expected_spots`` counts
    the spots at ``angle_min + k * step`` that lie within the range, so the
    last simulated angle never exceeds ``angle_max``.

    **Angle convention.**  The scanner's native angles are positive
    *clockwise*: Leuze's ROD ROS2 driver (``rod_node.cpp``,
    ``loadConfiguration``) negates the configured range to obtain REP-103
    (counter-clockwise positive) angles and, for ``CLOCKWISE``, publishes
    the first spot at ``-scan_angle_min`` with a negative increment.  In
    native terms a ``CLOCKWISE`` scan therefore starts at ``angle_min`` and
    counts up, a ``COUNTERCLOCKWISE`` scan starts at ``angle_max`` and
    counts down; the MDI headers carry exactly these native angles.

    **Fault injection** (all indices 0-based):

    * ``drop_subs`` -- ``{scan index: {sub numbers to withhold}}``;
    * ``start_mid_scan`` -- the first scan of a stream starts at this sub;
    * ``prepend_garbage`` -- bytes sent before the first packet of a stream;
    * ``corrupt_next_packet`` -- zero the ``packet_size`` of the next packet;
    * ``split_writes`` -- TCP: write each packet in chunks of this many bytes;
    * ``mute`` -- never answer commands;
    * ``invalid_spot_every`` -- every n-th spot (positions n-1, 2n-1, ...) is
      reported with distance 0 and intensity 0;
    * ``no_echo_indices`` -- spot positions reported as no echo.

    The scan index counts from 0 at every stream start (``SendMDI``), so
    ``drop_subs``, ``start_mid_scan`` and ``prepend_garbage`` are re-applied
    on each stop/start cycle.

    Counters for assertions: ``packets_sent``, ``scans_generated``,
    ``send_errors``, ``commands_received`` (the last 1000 command names).
    """

    #: Seconds a command reply may take to reach the client.
    reply_timeout_s = 1.0
    #: Seconds the client may stall before the MDI stream is given up (TCP).
    mdi_send_timeout_s = 2.0

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
                 mute: bool = False,
                 invalid_spot_every: int = 0,
                 no_echo_indices: Optional[Set[int]] = None) -> None:
        if not 0 <= port <= 65535:
            raise ValueError("port must be in 0..65535")
        if udp_dest_port is not None and not 0 < udp_dest_port <= 65535:
            raise ValueError("udp_dest_port must be in 1..65535")
        if start_mid_scan < 0:
            raise ValueError("start_mid_scan must be >= 0")
        if split_writes < 0:
            raise ValueError("split_writes must be >= 0")
        if invalid_spot_every < 0:
            raise ValueError("invalid_spot_every must be >= 0")
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
        self.invalid_spot_every = invalid_spot_every
        self.no_echo_indices: Set[int] = set(no_echo_indices or ())

        # Counters for assertions in tests
        self.packets_sent = 0
        self.scans_generated = 0
        self.send_errors = 0
        self.commands_received: Deque[str] = deque(maxlen=1000)

        self._lifecycle = threading.Lock()
        self._stream_lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._stream_stop = threading.Event()
        self._listen_sock: Optional[socket.socket] = None
        self._accept_thread: Optional[threading.Thread] = None
        self._stream_thread: Optional[threading.Thread] = None
        self._client_conn: Optional[socket.socket] = None
        self._running = False
        self._streaming = False
        self._closing = False
        self._t0 = time.monotonic()
        self._packet_number = 0
        self._delta_mdeg = 0
        self._num_spots = 0
        self._prepare_chunks()                # validates the settings up front

    # ------------------------------------------------------------------

    @property
    def udp_dest_port(self) -> int:
        return self._udp_dest_port if self._udp_dest_port is not None else self.port

    @property
    def running(self) -> bool:
        """True while the command server is listening."""
        return self._running

    @property
    def streaming(self) -> bool:
        """True while an MDI stream thread is active (what ``GetTxMDI`` reports)."""
        return self._streaming

    def start(self) -> "RodSimulator":
        """Bind the command port and start serving (idempotent)."""
        with self._lifecycle:
            if self._running:
                return self
            stale, self._listen_sock = self._listen_sock, None
            if stale is not None:
                stale.close()
            sock = self._bind_listener()
            self.port = sock.getsockname()[1]
            self._listen_sock = sock
            self._closing = False
            self._running = True
            self._accept_thread = threading.Thread(
                target=self._accept_loop, args=(sock,),
                name="rodsim-accept", daemon=True)
            self._accept_thread.start()
            log.info("ROD simulator listening on %s:%d", self.host, self.port)
            return self

    def _bind_listener(self) -> socket.socket:
        """Bind and listen on the command port.

        With ``port`` 0 the OS picks an ephemeral port, and a client binds
        the *same* number for UDP (the real device pushes to the command
        port).  Windows excludes port ranges per protocol, so a number the
        OS hands out for TCP may be refused for UDP (WSAEACCES); such a
        port is given back and another one is tried.
        """
        for _ in range(32):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                if os.name != "nt":
                    # Allow a quick restart on the same port (TIME_WAIT); on
                    # Windows the option would let us bind an occupied port.
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind((self.host, self.port))
                sock.listen(1)
                sock.settimeout(_POLL_S)
            except OSError:
                sock.close()
                raise
            if (self.port != 0 or self._udp_dest_port is not None
                    or _udp_bindable(sock.getsockname()[1])):
                return sock
            sock.close()
        raise OSError("no ephemeral port usable for both TCP and UDP found")

    def stop(self) -> None:
        """Stop streaming, drop the client and close the listen socket (idempotent)."""
        with self._lifecycle:
            self._closing = True
            self._stream_stop.set()
            conn = self._client_conn
            if conn is not None:
                try:
                    conn.shutdown(socket.SHUT_RDWR)   # unblocks send()/recv()
                except OSError:
                    pass
            self._stop_stream()
            sock, self._listen_sock = self._listen_sock, None
            if sock is not None:
                sock.close()
            thread, self._accept_thread = self._accept_thread, None
            if thread is not None and thread is not threading.current_thread():
                thread.join(timeout=_JOIN_S)
                if thread.is_alive():
                    log.warning("accept thread did not stop within %.0f s", _JOIN_S)
            self._running = False

    def __enter__(self) -> "RodSimulator":
        return self.start()

    def __exit__(self, exc_type: Optional[Type[BaseException]],
                 exc: Optional[BaseException],
                 tb: Optional[TracebackType]) -> None:
        self.stop()

    # ------------------------------------------------------------------
    # TCP command server
    # ------------------------------------------------------------------

    def _accept_loop(self, listen: socket.socket) -> None:
        try:
            while not self._closing:
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
        except Exception:
            log.exception("accept loop failed")
        finally:
            if self._listen_sock is listen:     # died on its own, not stop()
                self._running = False

    def _serve_client(self, conn: socket.socket, client_ip: str) -> None:
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        conn.settimeout(_POLL_S)
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
        try:
            self._tcp_send(conn, STX + text.encode("ascii") + ETX, self.reply_timeout_s)
        except OSError as exc:
            log.debug("could not send reply %r: %s", text, exc)

    def _tcp_send(self, conn: socket.socket, data: bytes, timeout: float) -> None:
        """Write one message atomically (no interleaving with other senders).

        Raises ``OSError`` (incl. ``socket.timeout``) when the client is gone
        or has not accepted the data within ``timeout`` seconds.  Nothing is
        ever left half-written unless the simulator is shutting down.
        """
        deadline = time.monotonic() + timeout
        with self._send_lock:
            if self.split_writes > 0:
                for i in range(0, len(data), self.split_writes):
                    self._send_all(conn, data[i:i + self.split_writes], deadline)
                    time.sleep(0)       # yield: encourage separate recv() chunks
            else:
                self._send_all(conn, data, deadline)

    def _send_all(self, conn: socket.socket, data: bytes, deadline: float) -> None:
        view = memoryview(data)
        sent = 0
        while sent < len(view):
            if self._closing:
                raise OSError("simulator is shutting down")
            try:
                sent += conn.send(view[sent:])
            except socket.timeout:
                if time.monotonic() >= deadline:
                    raise socket.timeout("client did not accept %d of %d bytes in time"
                                         % (len(view) - sent, len(view))) from None

    # ------------------------------------------------------------------
    # MDI streaming
    # ------------------------------------------------------------------

    def _start_stream(self, conn: socket.socket, client_ip: str) -> None:
        with self._stream_lock:
            old = self._stream_thread
            if old is not None and old.is_alive():
                if self._streaming:
                    return                    # already streaming
                old.join(timeout=_JOIN_S)     # previous stream winding down
                if old.is_alive():
                    log.error("previous MDI stream thread is stuck; not starting another")
                    return
            try:
                chunks = self._prepare_chunks()
            except ValueError as exc:
                log.error("cannot stream with the current settings: %s", exc)
                return
            self._stream_stop.clear()
            self._streaming = True
            self._stream_thread = threading.Thread(
                target=self._stream_loop, args=(conn, client_ip, chunks),
                name="rodsim-stream", daemon=True)
            self._stream_thread.start()

    def _stop_stream(self) -> None:
        with self._stream_lock:
            self._streaming = False
            self._stream_stop.set()
            thread = self._stream_thread
            if thread is None or thread is threading.current_thread():
                return
            thread.join(timeout=_JOIN_S)
            if thread.is_alive():
                log.warning("MDI stream thread did not stop within %.0f s", _JOIN_S)
                return
            self._stream_thread = None

    def _stream_loop(self, conn: socket.socket, client_ip: str,
                     chunks: List[Tuple[int, bytes, bytes]]) -> None:
        s = self.settings
        period = (s.scan_period_s if s.scan_period_s is not None
                  else Resolution(int(s.resolution)).scan_time_s)
        udp_sock: Optional[socket.socket] = None
        try:
            if int(s.protocol) == MdiProtocol.UDP:
                udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            target = (client_ip, self.udp_dest_port)
            garbage = self.prepend_garbage
            scan_index = 0
            next_time = time.monotonic()
            while self._streaming and not self._closing:
                for raw in self._build_scan(chunks, scan_index):
                    if not self._streaming or self._closing:
                        return
                    if garbage:
                        raw = garbage + raw
                        garbage = b""
                    if udp_sock is not None:
                        try:
                            udp_sock.sendto(raw, target)
                        except OSError as exc:
                            # A lost datagram is not fatal (ICMP unreachable,
                            # EMSGSIZE ...): count it and carry on.
                            self._note_send_error(exc)
                            continue
                    else:
                        try:
                            self._tcp_send(conn, raw, self.mdi_send_timeout_s)
                        except OSError as exc:
                            if not self._closing:
                                log.warning("MDI stream stopped: client is not "
                                            "accepting data (%s)", exc)
                            return
                    self.packets_sent += 1
                self.scans_generated += 1
                scan_index += 1
                next_time += period
                delay = next_time - time.monotonic()
                if delay > 0:
                    self._stream_stop.wait(min(delay, period))
                else:
                    next_time = time.monotonic()    # fell behind; don't burst
        except Exception:
            log.exception("MDI stream thread failed")
        finally:
            self._streaming = False
            if udp_sock is not None:
                udp_sock.close()

    def _note_send_error(self, exc: OSError) -> None:
        self.send_errors += 1
        if self.send_errors == 1:
            log.warning("sending measurement data failed: %s (further failures "
                        "are only counted in send_errors)", exc)

    def _prepare_chunks(self) -> List[Tuple[int, bytes, bytes]]:
        """Precompute (first_angle_mdeg, distance payload, intensity payload)
        for every packet of a scan; only headers change between scans.

        Raises ``ValueError`` for settings that cannot be streamed.
        """
        s = self.settings
        if s.spots_per_packet < 1:
            raise ValueError("spots_per_packet must be >= 1")
        if HEADER_SIZE + 4 * s.spots_per_packet > 0xFFFF:
            raise ValueError("spots_per_packet=%d does not fit a 16-bit packet_size"
                             % s.spots_per_packet)
        if not ANGLE_MIN_CDEG <= s.angle_min_cdeg < s.angle_max_cdeg <= ANGLE_MAX_CDEG:
            raise ValueError("angle range must satisfy %d <= angle_min < angle_max <= %d [0.01 deg]"
                             % (ANGLE_MIN_CDEG, ANGLE_MAX_CDEG))
        if s.skip_spots < 0:
            raise ValueError("skip_spots must be >= 0")
        if s.scan_period_s is not None and not s.scan_period_s > 0:
            raise ValueError("scan_period_s must be > 0")
        if s.room_half_width_mm < 1 or s.room_half_height_mm < 1 or s.max_range_mm < 1:
            raise ValueError("room dimensions and max_range_mm must be >= 1 mm")
        try:
            resolution = Resolution(int(s.resolution))
            direction = ScanDirection(int(s.direction))
            MdiPacketType(int(s.packet_type))
            MdiProtocol(int(s.protocol))
        except ValueError as exc:
            raise ValueError("unsupported setting: %s" % exc) from None

        num_spots = expected_spots(s.angle_min_cdeg, s.angle_max_cdeg,
                                   resolution.degrees, s.skip_spots)
        step_mdeg = round(resolution.degrees * 1000) * (s.skip_spots + 1)
        if direction == ScanDirection.CLOCKWISE:
            first_mdeg, delta_mdeg = s.angle_min_cdeg * 10, step_mdeg
        else:
            first_mdeg, delta_mdeg = s.angle_max_cdeg * 10, -step_mdeg
        packets = -(-num_spots // s.spots_per_packet)
        if packets > MAX_PACKETS_PER_SCAN:
            raise ValueError("%d spots in packets of %d need %d packets per scan; "
                             "the MDI header allows at most %d"
                             % (num_spots, s.spots_per_packet, packets, MAX_PACKETS_PER_SCAN))
        if self.no_echo_indices and not all(0 <= i < num_spots for i in self.no_echo_indices):
            raise ValueError("no_echo_indices must be spot positions in 0..%d" % (num_spots - 1))
        self._delta_mdeg = delta_mdeg
        self._num_spots = num_spots

        angles_mdeg = [first_mdeg + i * delta_mdeg for i in range(num_spots)]
        distances: List[int] = []
        intensities: List[int] = []
        every = self.invalid_spot_every
        for i, angle_mdeg in enumerate(angles_mdeg):
            d = _room_distance_mm(angle_mdeg / 1000.0, s.room_half_width_mm, s.room_half_height_mm)
            forced = i in self.no_echo_indices or (every > 0 and (i + 1) % every == 0)
            if forced or d > s.max_range_mm:
                distances.append(0)                       # ROD: 0 = no valid echo
                intensities.append(0)
            else:
                distances.append(int(d))
                intensities.append(max(INTENSITY_MIN_VALID,
                                       min(INTENSITY_MAX, 1000 + int(800 * math.sin(i * 0.01)))))

        chunks: List[Tuple[int, bytes, bytes]] = []
        for off in range(0, num_spots, s.spots_per_packet):
            n = min(s.spots_per_packet, num_spots - off)
            dist_payload = struct.pack(">%dH" % n, *distances[off:off + n])
            int_payload = struct.pack(">%dH" % n, *intensities[off:off + n])
            chunks.append((angles_mdeg[off], dist_payload, int_payload))
        return chunks

    def scan_packets(self, scan_index: int = 0) -> List[bytes]:
        """The raw MDI packets of one scan, exactly as the stream would send them.

        Handy for parser tests without sockets.  Advances the packet counter
        like the stream does; the fault knobs apply as documented.
        """
        return self._build_scan(self._prepare_chunks(), scan_index)

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
            payload = (dist_payload + int_payload
                       if ptype == MdiPacketType.DISTANCE_AND_INTENSITY else dist_payload)
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


#: Deprecated alias: the ROD-300-500 simulator was misnamed after the RSL 235,
#: which does not speak that protocol.  Use :class:`RodSimulator`.
RSL235Simulator = RodSimulator


# ---------------------------------------------------------------------------
# UDP data telegram simulator
# ---------------------------------------------------------------------------


class UdtSimulator:
    """Push RSL 200 / RSL 400 UDP data telegrams to a target, like the real device.

    Per scan cycle it sends one extended status profile (ID 1) followed by
    the measurement data (ID 3: distance + signal strength, or ID 6:
    distance only) split into ``beams_per_datagram`` fragments with
    consecutive block numbers.  The frame fields (``h1_size``,
    ``follow_flag``, ``request_id``, ``header2``) are those of a hardware
    capture of the selected family.

    ``family`` selects the status profile layout (spec 50130122):

    * ``ScannerFamily.RSL200`` (default; the RSL 235): type 21, 28-byte
      profile, contour at offset 28 -> 56-byte status datagram; default
      contour ``(0, 1350, 5)`` = 271 beams; beams step -0.2 deg from +135 deg
      (index 0).
    * ``ScannerFamily.RSL400``: type 1, 20-byte profile, contour at offset
      20 -> 48-byte status datagram (60 with ``signature``); default contour
      ``(0, 2699, 1)`` = 2700 beams; -0.1 deg per index from +134.95 deg.

    Forced no-echo beams carry distance 65535 and signal strength 65535;
    beams beyond ``max_range_mm`` carry 32767 (RSL 200) with a weak signal
    strength, both as captured from RSL 235 units.

    Beam geometry and the no-echo values come from
    :data:`leuze_rsl.udt.GEOMETRY`, so the simulated room is consistent with
    what :meth:`~leuze_rsl.udt.UdtScan.to_cartesian` reconstructs.

    **Status knobs** (plain attributes, read for every status datagram, so
    they can be changed while running): ``ossd``, ``protective_field_free``,
    ``warning_field_free`` (RSL 200: warning fields 1 and 2), ``error`` (the
    collective ERROR bit), ``signature`` (RSL 400 only: the 8-byte
    configuration signature, sent as the 12-byte trailer).

    **Environment knobs** (read at :meth:`start`): a rectangular room
    ``room_half_width_mm`` x ``room_half_height_mm`` around the device,
    ``max_range_mm`` beyond which a beam has no echo, ``no_echo_indices``
    (0-based beam *positions* within the scan, not measurement-contour
    indices) forced to no echo.

    **Fault injection**: ``drop_blocks`` -- ``{scan index: {block numbers to
    withhold}}``, where the scan index (= scan number) restarts at 0 on
    every :meth:`start`; ``profile_type`` -- emit an unknown status profile
    type (anything but 1 and 21) with the contour at ``contour_offset``
    (default: the family's profile length) to exercise a receiver's
    heuristic contour location.

    Counters: ``scans_sent``, ``datagrams_sent``, ``send_errors``.
    """

    #: H1 tail (h1_size, follow_flag, request_id) and H2, per family, as
    #: captured from RSL 235 hardware resp. Leuze's RSL 400 ROS driver test.
    H1_TAIL = (8, 0, 6)
    HEADER2 = b"\x04\x0b\x01\x32"
    H1_TAIL_RSL400 = (8, 0, 0xFEAF)
    HEADER2_RSL400 = b"\x04\x15\x02\xc8"
    #: Spec-valid default measurement contours (table 3.4 / 3.6).
    DEFAULT_CONTOUR: Dict[ScannerFamily, Tuple[int, int, int]] = {
        ScannerFamily.RSL200: (0, 1350, 5),
        ScannerFamily.RSL400: (0, 2699, 1),
    }
    #: Raw VOLT field of the RSL 200 profile [0.1 V]: 23.4 V, as captured
    #: from an RSL 235 on a 24 V supply.
    SUPPLY_VOLTAGE_RAW = 234
    #: TEMP field of the RSL 200 profile: 23.5 degC in [0.1 degC].
    TEMPERATURE_RAW = 235

    def __init__(self,
                 target_host: str = "127.0.0.1",
                 target_port: int = 3050,
                 *,
                 family: ScannerFamily = ScannerFamily.RSL200,
                 telegram_id: int = 3,
                 contour: Optional[Tuple[int, int, int]] = None,
                 scan_period_s: float = 0.025,
                 beams_per_datagram: int = 350,
                 ossd: bool = True,
                 protective_field_free: bool = True,
                 warning_field_free: bool = True,
                 error: bool = False,
                 signature: Optional[bytes] = None,
                 profile_type: Optional[int] = None,
                 contour_offset: Optional[int] = None,
                 drop_blocks: Optional[Dict[int, Set[int]]] = None,
                 room_half_width_mm: int = 3000,
                 room_half_height_mm: int = 2000,
                 max_range_mm: int = 25000,
                 no_echo_indices: Optional[Set[int]] = None) -> None:
        try:
            self.family = ScannerFamily(family)
        except ValueError:
            raise ValueError("family must be a ScannerFamily, not %r" % (family,)) from None
        if not 0 < target_port <= 65535:
            raise ValueError("target_port must be in 1..65535")
        if telegram_id not in (3, 6):
            raise ValueError("telegram_id must be 3 or 6")
        if contour is None:
            contour = self.DEFAULT_CONTOUR[self.family]
        start, stop, interval = (int(v) for v in contour)
        if interval < 1:
            raise ValueError("contour index interval must be >= 1")
        if not 0 <= start <= stop <= 0xFFFF:
            raise ValueError("contour must satisfy 0 <= start <= stop <= 65535")
        geometry = GEOMETRY[self.family]
        if stop > geometry.max_index or interval > 8:
            log.warning("contour %s is outside the %s specification (stop <= %d, interval 1..8)",
                        (start, stop, interval), self.family.name, geometry.max_index)
        if not scan_period_s > 0:
            raise ValueError("scan_period_s must be > 0")
        if beams_per_datagram < 1:
            raise ValueError("beams_per_datagram must be >= 1")
        if signature is not None:
            if self.family is not ScannerFamily.RSL400:
                raise ValueError("signature: only the RSL 400 profile carries a signature trailer")
            if len(signature) != 8:
                raise ValueError("signature must be exactly 8 bytes")
        if profile_type is None:
            profile_type = int(self.family)
            if contour_offset is not None:
                raise ValueError("contour_offset requires an unknown profile_type; known "
                                 "profile types carry the contour at a fixed offset")
        elif profile_type in (STATUS_PROFILE_TYPE_RSL200, STATUS_PROFILE_TYPE_RSL400):
            raise ValueError("profile_type %d is a known layout; select it with family="
                             % profile_type)
        elif not 0 <= profile_type <= 255:
            raise ValueError("profile_type must be in 0..255")
        if contour_offset is None:
            contour_offset = 28 if self.family is ScannerFamily.RSL200 else 20
        if not 2 <= contour_offset <= 1024:
            raise ValueError("contour_offset must be in 2..1024")
        if room_half_width_mm < 1 or room_half_height_mm < 1 or max_range_mm < 1:
            raise ValueError("room dimensions and max_range_mm must be >= 1 mm")
        num_beams = MeasurementContour(start, stop, interval).num_beams
        self.no_echo_indices: Set[int] = set(no_echo_indices or ())
        if not all(0 <= i < num_beams for i in self.no_echo_indices):
            raise ValueError("no_echo_indices must be beam positions in 0..%d" % (num_beams - 1))

        self.target = (target_host, target_port)
        self.telegram_id = telegram_id
        self.contour: Tuple[int, int, int] = (start, stop, interval)
        self.scan_period_s = scan_period_s
        self.beams_per_datagram = beams_per_datagram
        self.ossd = ossd
        self.protective_field_free = protective_field_free
        self.warning_field_free = warning_field_free
        self.error = error
        self.signature = signature
        self.profile_type = profile_type
        self.contour_offset = contour_offset
        self.drop_blocks = drop_blocks or {}
        self.room_half_width_mm = room_half_width_mm
        self.room_half_height_mm = room_half_height_mm
        self.max_range_mm = max_range_mm
        if self.family is ScannerFamily.RSL400:
            self._h1_tail, self._header2 = self.H1_TAIL_RSL400, self.HEADER2_RSL400
        else:
            self._h1_tail, self._header2 = self.H1_TAIL, self.HEADER2

        self.scans_sent = 0
        self.datagrams_sent = 0
        self.send_errors = 0
        self._lifecycle = threading.Lock()
        self._stop_event = threading.Event()
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._target_addr = self.target
        self._running = False

    # ------------------------------------------------------------------

    @property
    def running(self) -> bool:
        """True while the sender thread is alive."""
        return self._running

    @property
    def num_beams(self) -> int:
        """Beams per scan implied by the contour (spec formula)."""
        return MeasurementContour(*self.contour).num_beams

    def start(self) -> "UdtSimulator":
        """Start pushing telegrams (idempotent).  Resolves ``target_host`` first."""
        with self._lifecycle:
            if self._running:
                return self
            host, port = self.target
            self._target_addr = (socket.gethostbyname(host), port)   # OSError if unresolvable
            stale, self._sock = self._sock, None
            if stale is not None:
                stale.close()
            payloads = self.measurement_payloads()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock = sock
            self._stop_event.clear()
            self._running = True
            self._thread = threading.Thread(target=self._loop, args=(sock, payloads),
                                            name="udtsim-tx", daemon=True)
            self._thread.start()
            return self

    def stop(self) -> None:
        """Stop the sender thread (interrupts any wait) and close the socket."""
        with self._lifecycle:
            self._stop_event.set()
            thread, self._thread = self._thread, None
            if thread is not None and thread is not threading.current_thread():
                thread.join(timeout=_JOIN_S)
                if thread.is_alive():
                    log.warning("UDT sender thread did not stop within %.0f s", _JOIN_S)
            sock, self._sock = self._sock, None
            if sock is not None:
                sock.close()
            self._running = False

    def __enter__(self) -> "UdtSimulator":
        return self.start()

    def __exit__(self, exc_type: Optional[Type[BaseException]],
                 exc: Optional[BaseException],
                 tb: Optional[TracebackType]) -> None:
        self.stop()

    # ------------------------------------------------------------------
    # Datagram construction (public: usable in tests without sockets)
    # ------------------------------------------------------------------

    def _frame(self, total_length: int, telegram_id: int, block: int,
               scan_number: int) -> bytes:
        h1_size, follow_flag, request_id = self._h1_tail
        return struct.pack("<IBBH4sHHI", total_length, h1_size, follow_flag,
                           request_id, self._header2, telegram_id, block,
                           scan_number & 0xFFFFFFFF)

    def status_block(self, scan_number: int) -> bytes:
        """The data block of the ID 1 telegram: status profile + contour (+ trailer)."""
        contour = struct.pack("<HHHH", *self.contour, 0)
        if self.profile_type == STATUS_PROFILE_TYPE_RSL200:
            return self._profile_rsl200(scan_number) + contour
        if self.profile_type == STATUS_PROFILE_TYPE_RSL400:
            trailer = b""
            if self.signature is not None:
                trailer = b"\x01\x00\x08\x00" + self.signature       # spec table 3.7
            return self._profile_rsl400(scan_number) + contour + trailer
        # Unknown profile type: only the type/mode bytes and the contour.
        block = bytearray(self.contour_offset + 8)
        block[0] = self.profile_type
        block[1] = 1
        block[self.contour_offset:self.contour_offset + 8] = contour
        return bytes(block)

    def _profile_rsl200(self, scan_number: int) -> bytes:
        """Spec table 3.3 (28 bytes)."""
        p = bytearray(28)
        p[0] = STATUS_PROFILE_TYPE_RSL200
        p[1] = 1                                                   # OP-MODE: safety mode
        p[2] = 0x80 if self.error else 0                           # ERROR
        p[3] = ((0x80 if self.ossd else 0)                         # OSSD on
                | (0x40 if self.protective_field_free else 0)      # PF_VIO: 1 = free
                | (0x30 if self.warning_field_free else 0))        # WF_VIO_1/2: 1 = free
        p[4] = 1                                                   # TRIPLE_SEL
        struct.pack_into("<HH", p, 8, self.SUPPLY_VOLTAGE_RAW, self.TEMPERATURE_RAW)
        struct.pack_into("<I", p, 16, scan_number & 0xFFFFFFFF)   # SCAN_NUM
        # bytes 20..27: SAFE_SIG, ERR_CLASS, ERR_NUM, reserved = 0
        return bytes(p)

    def _profile_rsl400(self, scan_number: int) -> bytes:
        """Spec table 3.5 (20 bytes), modelled on the Leuze ROS driver capture."""
        p = bytearray(20)
        p[0] = STATUS_PROFILE_TYPE_RSL400
        p[1] = 1                                                   # OP-MODE: safety mode
        p[2] = (0x80 if self.error else 0) | (0x02 if self.ossd else 0)   # ERROR, A-OSSD
        struct.pack_into("<I", p, 8, scan_number & 0xFFFFFFFF)    # Scan
        p[12] = (0x80                                              # A-ACTIVE
                 | (0x40 if self.warning_field_free else 0)        # A-WF-VIO: 1 = free
                 | (0x20 if self.protective_field_free else 0))    # A-PF-VIO: 1 = free
        p[13] = 0x11                                               # bank 1, field pair 1
        p[15] = ((0xC0 if self.warning_field_free else 0)          # A-WF-VIO-SEG-1/2
                 | (0x30 if self.protective_field_free else 0))    # A-PF-VIO-SEG-1/2
        return bytes(p)

    def status_datagram(self, scan_number: int) -> bytes:
        """The complete ID 1 datagram (frame + status block) of a scan cycle."""
        block = self.status_block(scan_number)
        return self._frame(FRAME_SIZE + len(block), 1, 0, scan_number) + block

    def beam_values(self) -> List[int]:
        """Distance [mm] per beam position for the simulated room."""
        geometry = GEOMETRY[self.family]
        values: List[int] = []
        for position, index in enumerate(MeasurementContour(*self.contour).beam_indices()):
            d = _room_distance_mm(geometry.angle_deg(index),
                                  self.room_half_width_mm, self.room_half_height_mm)
            if position in self.no_echo_indices:
                values.append(geometry.no_echo_mm)          # no echo at all
            elif d > self.max_range_mm:
                values.append(geometry.max_valid_mm + 1)    # echo too weak to measure
            else:
                values.append(int(d))
        return values

    def measurement_payloads(self) -> List[bytes]:
        """Measurement data per block (without frames); constant between scans."""
        distances = self.beam_values()
        geometry = GEOMETRY[self.family]
        payloads: List[bytes] = []
        for off in range(0, len(distances), self.beams_per_datagram):
            chunk = distances[off:off + self.beams_per_datagram]
            if self.telegram_id == 3:
                values: List[int] = []
                for d in chunk:
                    values.append(d)
                    if d == geometry.no_echo_mm:
                        values.append(65535)      # hardware: no echo -> signal 0xFFFF
                    elif d > geometry.max_valid_mm:
                        values.append(150)        # hardware: too weak -> the weak signal (~140-190)
                    else:
                        values.append(max(100, min(50000, d // 2)))
                payloads.append(struct.pack("<%dH" % len(values), *values))
            else:
                payloads.append(struct.pack("<%dH" % len(chunk), *chunk))
        return payloads

    def measurement_datagrams(self, scan_number: int,
                              payloads: Optional[List[bytes]] = None) -> List[bytes]:
        """The measurement datagrams (ID 3 / 6) of one scan cycle, in block order."""
        if payloads is None:
            payloads = self.measurement_payloads()
        return [self._frame(FRAME_SIZE + len(payload), self.telegram_id, block, scan_number)
                + payload
                for block, payload in enumerate(payloads)]

    def scan_datagrams(self, scan_number: int) -> List[bytes]:
        """Status datagram followed by the measurement datagrams of one cycle."""
        return [self.status_datagram(scan_number)] + self.measurement_datagrams(scan_number)

    # ------------------------------------------------------------------

    def _send_datagram(self, sock: socket.socket, data: bytes) -> None:
        sock.sendto(data, self._target_addr)

    def _loop(self, sock: socket.socket, payloads: List[bytes]) -> None:
        try:
            scan_index = 0                     # == scan number of this run
            next_time = time.monotonic()
            while not self._stop_event.is_set():
                dropped = self.drop_blocks.get(scan_index, set())
                datagrams = [self.status_datagram(scan_index)]
                datagrams += [dg for block, dg in enumerate(
                    self.measurement_datagrams(scan_index, payloads)) if block not in dropped]
                for datagram in datagrams:
                    if self._stop_event.is_set():
                        return
                    try:
                        self._send_datagram(sock, datagram)
                    except OSError as exc:
                        # An unreachable target (ICMP port unreachable on
                        # Windows, EINVAL ...) must not kill the sender.
                        self.send_errors += 1
                        if self.send_errors == 1:
                            log.warning("sending to %s:%d failed: %s (further failures "
                                        "are only counted in send_errors)",
                                        self._target_addr[0], self._target_addr[1], exc)
                        continue
                    self.datagrams_sent += 1
                self.scans_sent += 1
                scan_index += 1
                next_time += self.scan_period_s
                delay = next_time - time.monotonic()
                if delay > 0:
                    self._stop_event.wait(delay)
                else:
                    next_time = time.monotonic()    # fell behind; don't burst
        except Exception:
            log.exception("UDT sender thread failed")
        finally:
            self._running = False


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def _port(text: str) -> int:
    value = int(text)
    if not 0 <= value <= 65535:
        raise argparse.ArgumentTypeError("port must be in 0..65535")
    return value


def _positive_int(text: str) -> int:
    value = int(text)
    if value < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return value


def _positive_float(text: str) -> float:
    value = float(text)
    if not value > 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m leuze_rsl.simulator",
        description="Leuze scanner simulator.  By default it pushes RSL 200 / RSL 400 "
                    "UDP data telegrams (what an RSL 235 sends) to --host:--port; with "
                    "--rod it serves the ROD 308/508 command interface and MDI stream "
                    "on --host:--port instead.",
        epilog="Exit codes: 0 success, 1 error, 2 usage error, 130 interrupted (Ctrl+C).")
    parser.add_argument("--host", default="127.0.0.1",
                        help="UDT mode: target host; ROD mode: listen address "
                             "(default: %(default)s)")
    parser.add_argument("--port", type=_port, default=3050,
                        help="UDT mode: target UDP port; ROD mode: TCP command port, "
                             "0 = any free port (default: %(default)s)")
    parser.add_argument("--rod", action="store_true",
                        help="serve the ROD-300-500 protocol (TCP command interface + "
                             "LEUZ MDI packets) instead of pushing UDP data telegrams")
    parser.add_argument("--protocol", choices=["udp", "tcp"], default=None,
                        help="ROD mode only: transport of the measurement data "
                             "(default: udp)")
    parser.add_argument("--distances-only", action="store_true",
                        help="send distances without signal strengths "
                             "(UDT: telegram ID 6; ROD: packet type 0)")
    parser.add_argument("--family", choices=["rsl200", "rsl400"], default=None,
                        help="UDT mode only: status profile layout and beam geometry "
                             "(default: rsl200, i.e. an RSL 235)")
    parser.add_argument("--contour", type=int, nargs=3, default=None,
                        metavar=("START", "STOP", "INTERVAL"),
                        help="UDT mode only: measurement contour (beam index range and "
                             "interval; default: 0 1350 5 for rsl200, 0 2699 1 for rsl400)")
    parser.add_argument("--period", type=_positive_float, default=None, metavar="SECONDS",
                        help="UDT mode only: scan period in seconds (default: 0.025)")
    parser.add_argument("--beams-per-datagram", type=_positive_int, default=None, metavar="N",
                        help="UDT mode only: beams per measurement datagram (default: 350)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="log every command and event (default: info level)")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    udt_only = (("--family", args.family), ("--contour", args.contour),
                ("--period", args.period), ("--beams-per-datagram", args.beams_per_datagram))
    if args.rod:
        for flag, value in udt_only:
            if value is not None:
                parser.error("%s only applies to UDT mode (without --rod)" % flag)
    else:
        if args.protocol is not None:
            parser.error("--protocol only applies to --rod mode")
        if args.port == 0:
            parser.error("--port 0 is only allowed with --rod")

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s: %(message)s")
    sim: Optional[Union[RodSimulator, UdtSimulator]] = None
    try:
        try:
            sim = _start_from_args(args)
        except (OSError, ValueError) as exc:
            print("error: %s" % exc, file=sys.stderr)
            return EXIT_ERROR
        while sim.running:
            time.sleep(0.5)
        print("error: simulator stopped unexpectedly (see log)", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
    finally:
        if sim is not None:
            sim.stop()


def _start_from_args(args: argparse.Namespace) -> Union[RodSimulator, UdtSimulator]:
    """Create and start the simulator described by the parsed CLI arguments."""
    if args.rod:
        protocol = MdiProtocol.TCP if args.protocol == "tcp" else MdiProtocol.UDP
        settings = SimulatorSettings(
            protocol=protocol,
            packet_type=(MdiPacketType.DISTANCE if args.distances_only
                         else MdiPacketType.DISTANCE_AND_INTENSITY),
        )
        rod = RodSimulator(host=args.host, port=args.port, settings=settings).start()
        print("ROD-protocol simulator listening on %s:%d (MDI via %s) -- Ctrl+C to stop"
              % (rod.host, rod.port, protocol.name))
        return rod
    else:
        family = ScannerFamily.RSL400 if args.family == "rsl400" else ScannerFamily.RSL200
        contour: Optional[Tuple[int, int, int]] = None
        if args.contour is not None:
            contour = (args.contour[0], args.contour[1], args.contour[2])
        udt = UdtSimulator(
            target_host=args.host, target_port=args.port, family=family,
            telegram_id=6 if args.distances_only else 3, contour=contour,
            scan_period_s=0.025 if args.period is None else args.period,
            beams_per_datagram=(350 if args.beams_per_datagram is None
                                else args.beams_per_datagram),
        ).start()
        print("UDT simulator (%s, %d beams, contour %s) pushing to %s:%d every %.1f ms "
              "-- Ctrl+C to stop"
              % (family.name, udt.num_beams, udt.contour, udt.target[0], udt.target[1],
                 udt.scan_period_s * 1000))
        return udt


if __name__ == "__main__":
    sys.exit(main())
