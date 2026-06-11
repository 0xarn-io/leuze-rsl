"""High level driver for the Leuze RSL 235 measurement data output.

Typical usage::

    from leuze_rsl import RSL235

    with RSL235("192.168.60.101") as scanner:        # connects + reads config
        scanner.start_measurement()
        scan = scanner.get_scan(timeout=5.0)
        print(scan.num_spots, scan.distances_m[:5])

The driver opens the TCP command interface, reads the scanner configuration,
asks the scanner to start streaming measurement data ("MDI" packets, the UDP
data telegrams) and assembles them into :class:`~leuze_rsl.parser.Scan`
objects, delivered through :meth:`RSL235.get_scan`, :meth:`RSL235.scans` or
an ``on_scan`` callback.
"""

from __future__ import annotations

import logging
import queue
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterator, List, Optional, Tuple, Union

from . import protocol
from .errors import (
    CommandError,
    CommandTimeoutError,
    NotConnectedError,
    ScannerConnectionError,
)
from .parser import Scan, ScanAssembler, header_plausible
from .protocol import (
    ETX,
    HEADER_SIZE,
    MAX_RESPONSE_LENGTH,
    SYNC,
    CommandResponse,
    FilterType,
    MdiHeader,
    MdiPacketType,
    MdiProtocol,
    Resolution,
    ScanDirection,
    WindowCalibration,
    find_response_start,
    frame_command,
    parse_response,
)

__all__ = ["RSL235", "ScannerConfig", "ScannerStatus", "ErrorLogEntry"]

log = logging.getLogger("leuze_rsl")

#: No MDI data for this long means the stream is considered stalled
#: (mirrors SCANPAR_TIMEOUT_MDI_PACKET in the reference driver).
DEFAULT_MDI_TIMEOUT = 3.0

#: Reply timeout for command interface requests (mirrors
#: CMDITF_MSG_TIMEOUT_MS in the reference driver).
DEFAULT_COMMAND_TIMEOUT = 1.0


def _to_enum(enum_cls, value: int):
    """Map a wire value onto an enum, keeping the raw int if unknown."""
    try:
        return enum_cls(value)
    except ValueError:
        return value


@dataclass(frozen=True)
class ScannerConfig:
    """Scan-relevant settings read from the scanner at connect time."""

    protocol: MdiProtocol                       #: transport of the MDI data
    packet_type: MdiPacketType                  #: distances only / + intensities
    resolution: Resolution                      #: native resolution & frequency
    direction: ScanDirection                    #: data output direction
    angle_min_deg: float                        #: first configured angle [deg]
    angle_max_deg: float                        #: last configured angle [deg]
    skip_spots: int                             #: spots skipped between outputs

    @property
    def angular_resolution_deg(self) -> float:
        """Effective angle between two *output* spots [deg]."""
        return self.resolution.degrees * (self.skip_spots + 1)

    @property
    def scan_frequency_hz(self) -> float:
        return self.resolution.frequency_hz

    @property
    def scan_time_s(self) -> float:
        return self.resolution.scan_time_s

    @property
    def expected_spots(self) -> int:
        """Approximate number of spots per scan implied by the settings."""
        span = self.angle_max_deg - self.angle_min_deg
        return int(round(span / self.angular_resolution_deg)) + 1


@dataclass(frozen=True)
class ErrorLogEntry:
    code: int
    date: int


@dataclass
class ScannerStatus:
    """Full status snapshot (everything the command interface exposes)."""

    protocol: Optional[Union[MdiProtocol, int]] = None
    packet_type: Optional[Union[MdiPacketType, int]] = None
    resolution: Optional[Union[Resolution, int]] = None
    direction: Optional[Union[ScanDirection, int]] = None
    angle_min_deg: Optional[float] = None
    angle_max_deg: Optional[float] = None
    skip_spots: Optional[int] = None
    contamination_warn_pct: Optional[int] = None
    contamination_error_pct: Optional[int] = None
    contamination_state: Optional[Tuple[int, ...]] = None     #: 9 window segments [%]
    part_number: Optional[int] = None
    hw_version: Optional[int] = None
    sw_version: Optional[int] = None
    version_extra: Tuple[int, ...] = ()
    temperature_c: Optional[float] = None
    operating_hours: Optional[int] = None
    window_calibration: Optional[Union[WindowCalibration, int]] = None
    filter_type: Optional[Union[FilterType, int]] = None
    filter_historical_spots: Optional[int] = None
    filter_neighboring_spots: Optional[int] = None
    error_code: Optional[int] = None                          #: 0 = no error
    error_log: Tuple[ErrorLogEntry, ...] = ()
    error_log_extra: Optional[int] = None                     #: undocumented first ELog value
    mdi_tx_active: Optional[bool] = None
    errors: Dict[str, str] = field(default_factory=dict)      #: per-field read failures


class RSL235:
    """Driver for a Leuze RSL 235 (RSL 200 series / ROD 300-500 protocol).

    Parameters
    ----------
    host:
        IP address or hostname of the scanner.
    port:
        Command interface port configured in the scanner (default 3050).
        The scanner pushes UDP measurement data to this same port number on
        the host running this driver.
    udp_port:
        Local UDP port to listen on for measurement data.  Defaults to
        ``port`` (which is what the scanner expects).
    udp_bind_address:
        Local address to bind the UDP socket to (default: all interfaces).
    connect_timeout / command_timeout:
        Timeouts in seconds for the TCP connect and for command replies.
    scan_queue_size:
        Number of completed scans buffered for :meth:`get_scan`.  When the
        consumer is too slow the oldest scan is dropped (counted in
        :attr:`stats`).
    on_scan:
        Optional callback invoked with every completed :class:`Scan` from
        the receiver thread (must be fast and must not block).
    verify_udp_source:
        Ignore UDP datagrams not originating from ``host`` (default True).
    mdi_timeout:
        Seconds without measurement data after which :attr:`is_receiving`
        turns False.
    """

    def __init__(self,
                 host: str,
                 port: int = protocol.DEFAULT_PORT,
                 *,
                 udp_port: Optional[int] = None,
                 udp_bind_address: str = "",
                 connect_timeout: float = 5.0,
                 command_timeout: float = DEFAULT_COMMAND_TIMEOUT,
                 scan_queue_size: int = 32,
                 on_scan: Optional[Callable[[Scan], None]] = None,
                 verify_udp_source: bool = True,
                 mdi_timeout: float = DEFAULT_MDI_TIMEOUT) -> None:
        self.host = host
        self.port = port
        self.udp_port = port if udp_port is None else udp_port
        self.udp_bind_address = udp_bind_address
        self.connect_timeout = connect_timeout
        self.command_timeout = command_timeout
        self.mdi_timeout = mdi_timeout
        self.on_scan = on_scan
        self.verify_udp_source = verify_udp_source

        self.config: Optional[ScannerConfig] = None

        self._tcp_sock: Optional[socket.socket] = None
        self._tcp_thread: Optional[threading.Thread] = None
        self._tcp_buf = bytearray()
        self._scanner_ip: Optional[str] = None

        self._udp_sock: Optional[socket.socket] = None
        self._udp_thread: Optional[threading.Thread] = None

        self._assembler = ScanAssembler()
        self._feed_lock = threading.Lock()
        self._scan_queue: "queue.Queue[Scan]" = queue.Queue(maxsize=scan_queue_size)

        # Command interface bookkeeping: one request in flight at a time.
        self._cmd_lock = threading.Lock()
        self._resp_lock = threading.Lock()
        self._resp_event = threading.Event()
        self._pending: Optional[Tuple[str, str]] = None   # (kind, name)
        self._response: Optional[CommandResponse] = None

        self._connected = False
        self._closing = False
        self._measuring = False
        self._capturing_tcp = False
        self._last_mdi: Optional[float] = None

        # Diagnostics counters (see also self._assembler.stats).
        self.scans_dropped_queue = 0
        self.unsolicited_responses = 0
        self.foreign_datagrams_dropped = 0

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self, read_config: bool = True) -> "RSL235":
        """Open the command interface and (optionally) read the configuration.

        Mirrors the reference driver's startup: connect, send ``StopMDI`` as
        a handshake, then query the scan settings.
        """
        if self._connected:
            raise ScannerConnectionError("already connected")
        try:
            sock = socket.create_connection((self.host, self.port),
                                            timeout=self.connect_timeout)
        except OSError as exc:
            raise ScannerConnectionError(
                "unable to connect to %s:%d: %s" % (self.host, self.port, exc)) from exc
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.settimeout(0.2)
        self._scanner_ip = sock.getpeername()[0]
        self._tcp_sock = sock
        self._tcp_buf = bytearray()
        self._closing = False
        self._connected = True
        self._tcp_thread = threading.Thread(
            target=self._tcp_rx_loop, name="leuze_rsl-tcp-rx", daemon=True)
        self._tcp_thread.start()
        try:
            self._write_request(protocol.CMD_STOP_MDI)
            if read_config:
                self.config = self.read_config()
        except Exception:
            self.close()
            raise
        log.info("connected to scanner at %s:%d", self.host, self.port)
        return self

    def close(self) -> None:
        """Stop measuring, close all sockets and join the worker threads."""
        if self._measuring:
            try:
                self.stop_measurement()
            except Exception:
                log.warning("stop_measurement failed during close", exc_info=True)
        self._closing = True
        self._connected = False
        self._teardown_udp()
        sock, self._tcp_sock = self._tcp_sock, None
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        thread, self._tcp_thread = self._tcp_thread, None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        self._tcp_buf.clear()
        self._fail_pending_command()

    def __enter__(self) -> "RSL235":
        return self.connect()

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def is_measuring(self) -> bool:
        """True between :meth:`start_measurement` and :meth:`stop_measurement`."""
        return self._measuring

    @property
    def is_receiving(self) -> bool:
        """True while measurement data arrived within ``mdi_timeout`` seconds."""
        if not self._measuring or self._last_mdi is None:
            return False
        return (time.monotonic() - self._last_mdi) < self.mdi_timeout

    @property
    def stats(self) -> Dict[str, int]:
        """Diagnostic counters of the data path."""
        stats = vars(self._assembler.stats).copy()
        stats.update(
            scans_dropped_queue=self.scans_dropped_queue,
            unsolicited_responses=self.unsolicited_responses,
            foreign_datagrams_dropped=self.foreign_datagrams_dropped,
        )
        return stats

    # ------------------------------------------------------------------
    # Measurement data
    # ------------------------------------------------------------------

    def start_measurement(self, protocol_override: Optional[MdiProtocol] = None) -> None:
        """Ask the scanner to stream measurement data and start receiving it.

        The transport (UDP push or TCP interleave) follows the scanner's
        ``GetProto`` setting unless ``protocol_override`` is given.
        """
        if not self._connected:
            raise NotConnectedError("connect() first")
        if self._measuring:
            return
        proto = protocol_override
        if proto is None:
            if self.config is None:
                raise CommandError(
                    "MDI protocol unknown; connect(read_config=True) or pass protocol_override")
            proto = self.config.protocol
        with self._feed_lock:
            self._assembler.reset()
        self._last_mdi = None

        if proto == MdiProtocol.UDP:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
            except OSError:
                pass
            try:
                # The scanner pushes datagrams to <our ip>:<command port>.
                sock.bind((self.udp_bind_address, self.udp_port))
            except OSError as exc:
                sock.close()
                raise ScannerConnectionError(
                    "unable to bind UDP port %d: %s" % (self.udp_port, exc)) from exc
            sock.settimeout(0.5)
            self._udp_sock = sock
            self._measuring = True
            self._udp_thread = threading.Thread(
                target=self._udp_rx_loop, name="leuze_rsl-udp-rx", daemon=True)
            self._udp_thread.start()
            try:
                # Bind first, then SendMDI: the reference driver does it the
                # other way around and can lose the first packets.
                self._write_request(protocol.CMD_SEND_MDI)
            except Exception:
                self._measuring = False
                self._teardown_udp()
                raise
        elif proto == MdiProtocol.TCP:
            self._capturing_tcp = True
            self._measuring = True
            try:
                self._write_request(protocol.CMD_SEND_MDI)
            except Exception:
                self._capturing_tcp = False
                self._measuring = False
                raise
        else:
            raise CommandError("unsupported MDI protocol: %r" % (proto,))
        log.info("measurement started (%s)", MdiProtocol(proto).name)

    def stop_measurement(self) -> None:
        """Stop the measurement data stream (best effort) and the receiver."""
        if not self._measuring:
            return
        try:
            self._write_request(protocol.CMD_STOP_MDI)
        except Exception:
            log.warning("StopMDI not acknowledged", exc_info=True)
        self._measuring = False
        self._capturing_tcp = False
        self._teardown_udp()
        with self._feed_lock:
            self._assembler.reset()
        log.info("measurement stopped")

    def get_scan(self, timeout: Optional[float] = None) -> Scan:
        """Return the next complete scan; raise ``TimeoutError`` on timeout."""
        try:
            return self._scan_queue.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError(
                "no scan received within %s s (is_receiving=%s)"
                % (timeout, self.is_receiving)) from None

    def scans(self, timeout: Optional[float] = None) -> Iterator[Scan]:
        """Iterate over scans until measurement stops.

        With ``timeout`` set, a per-scan ``TimeoutError`` is raised if no
        scan arrives in time.
        """
        while True:
            if not self._measuring and self._scan_queue.empty():
                return
            try:
                yield self._scan_queue.get(timeout=0.2 if timeout is None else timeout)
            except queue.Empty:
                if timeout is not None:
                    raise TimeoutError("no scan received within %s s" % timeout) from None

    @property
    def scans_available(self) -> int:
        return self._scan_queue.qsize()

    # ------------------------------------------------------------------
    # Configuration / status queries (TCP command interface)
    # ------------------------------------------------------------------

    def read_config(self) -> ScannerConfig:
        """Read the scan-relevant settings (strict; raises on any failure)."""
        proto = self.get_protocol()
        ptype = self.get_packet_type()
        resolution = self.get_resolution()
        direction = self.get_direction()
        angle_min, angle_max = self.get_angle_range()
        skip = self.get_skip_spots()
        try:
            config = ScannerConfig(
                protocol=MdiProtocol(int(proto)),
                packet_type=MdiPacketType(int(ptype)),
                resolution=Resolution(int(resolution)),
                direction=ScanDirection(int(direction)),
                angle_min_deg=angle_min,
                angle_max_deg=angle_max,
                skip_spots=skip,
            )
        except ValueError as exc:
            raise CommandError("scanner reported an out-of-range setting: %s" % exc) from exc
        log.info("scanner config: %s", config)
        return config

    def get_protocol(self) -> MdiProtocol:
        """Transport of the measurement data: UDP or TCP (``GetProto``)."""
        return _to_enum(MdiProtocol, self._read_request(protocol.CMD_GET_PROTO, 1)[0])

    def get_packet_type(self) -> MdiPacketType:
        """Payload type: distances only or + intensities (``GetPType``)."""
        return _to_enum(MdiPacketType, self._read_request(protocol.CMD_GET_PTYPE, 1)[0])

    def get_resolution(self) -> Resolution:
        """Angular resolution / scan frequency setting (``GetResol``)."""
        return _to_enum(Resolution, self._read_request(protocol.CMD_GET_RESOL, 1)[0])

    def get_direction(self) -> ScanDirection:
        """Data output direction (``GetDir``)."""
        return _to_enum(ScanDirection, self._read_request(protocol.CMD_GET_DIR, 1)[0])

    def get_angle_range(self) -> Tuple[float, float]:
        """Configured scan angle range in degrees (``GetRange``)."""
        values = self._read_request(protocol.CMD_GET_RANGE, 2)
        return values[0] / 100.0, values[1] / 100.0

    def get_skip_spots(self) -> int:
        """Skipped spots between successive output measurements (``GetSkip``)."""
        return self._read_request(protocol.CMD_GET_SKIP, 1)[0]

    def get_contamination_thresholds(self) -> Tuple[int, int]:
        """Warning and error contamination thresholds in % (``GetCont``)."""
        values = self._read_request(protocol.CMD_GET_CONT, 2)
        return values[0], values[1]

    def get_contamination_state(self) -> Tuple[int, ...]:
        """Contamination of the 9 window segments in % (``GetWinStat``)."""
        return self._read_request(protocol.CMD_GET_WINSTAT, 9)[:9]

    def get_version(self) -> Tuple[int, int, int, Tuple[int, ...]]:
        """Part number, hardware and software version (``GetVer``)."""
        values = self._read_request(protocol.CMD_GET_VER, 3)
        return values[0], values[1], values[2], values[3:]

    def get_temperature(self) -> float:
        """Internal temperature in deg C (``GetTem``)."""
        return self._read_request(protocol.CMD_GET_TEM, 1)[0] / 100.0

    def get_error_log(self) -> Tuple[int, Tuple[ErrorLogEntry, ...]]:
        """Stored error log: 10 (code, date) entries (``GetELog``).

        The first value of the reply is undocumented (the reference driver
        skips it); it is returned as-is alongside the entries.
        """
        values = self._read_request(protocol.CMD_GET_ELOG, 21)
        entries = tuple(ErrorLogEntry(code=values[i], date=values[i + 1])
                        for i in range(1, 21, 2))
        return values[0], entries

    def get_operating_hours(self) -> int:
        """Runtime hours (``GetHours``)."""
        return self._read_request(protocol.CMD_GET_HOURS, 1)[0]

    def get_window_calibration(self) -> WindowCalibration:
        """Window calibration state (``GetWCalib``)."""
        return _to_enum(WindowCalibration, self._read_request(protocol.CMD_GET_WCALIB, 1)[0])

    def get_filter(self) -> Tuple[Union[FilterType, int], int, int]:
        """Filter type, historical spots, neighboring spots (``GetFilter``)."""
        values = self._read_request(protocol.CMD_GET_FILTER, 3)
        return _to_enum(FilterType, values[0]), values[1], values[2]

    def get_error_code(self) -> int:
        """Currently active error code, 0 = none (``GetECode``)."""
        return self._read_request(protocol.CMD_GET_ECODE, 1)[0]

    def get_mdi_tx_active(self) -> bool:
        """Whether the scanner is currently streaming MDI data (``GetTxMDI``)."""
        return bool(self._read_request(protocol.CMD_GET_TXMDI, 1)[0])

    def get_status(self, strict: bool = False) -> ScannerStatus:
        """Read everything the command interface exposes into one snapshot.

        With ``strict=False`` (default) individual failures are recorded in
        ``ScannerStatus.errors`` instead of raising.
        """
        status = ScannerStatus()

        def read(name: str, fn: Callable[[], None]) -> None:
            try:
                fn()
            except Exception as exc:
                if strict:
                    raise
                status.errors[name] = str(exc)

        def _range() -> None:
            status.angle_min_deg, status.angle_max_deg = self.get_angle_range()

        def _cont() -> None:
            status.contamination_warn_pct, status.contamination_error_pct = \
                self.get_contamination_thresholds()

        def _ver() -> None:
            (status.part_number, status.hw_version,
             status.sw_version, status.version_extra) = self.get_version()

        def _elog() -> None:
            status.error_log_extra, status.error_log = self.get_error_log()

        def _filter() -> None:
            (status.filter_type, status.filter_historical_spots,
             status.filter_neighboring_spots) = self.get_filter()

        read("protocol", lambda: setattr(status, "protocol", self.get_protocol()))
        read("packet_type", lambda: setattr(status, "packet_type", self.get_packet_type()))
        read("resolution", lambda: setattr(status, "resolution", self.get_resolution()))
        read("direction", lambda: setattr(status, "direction", self.get_direction()))
        read("angle_range", _range)
        read("skip_spots", lambda: setattr(status, "skip_spots", self.get_skip_spots()))
        read("contamination_thresholds", _cont)
        read("contamination_state",
             lambda: setattr(status, "contamination_state", self.get_contamination_state()))
        read("version", _ver)
        read("temperature", lambda: setattr(status, "temperature_c", self.get_temperature()))
        read("error_log", _elog)
        read("operating_hours",
             lambda: setattr(status, "operating_hours", self.get_operating_hours()))
        read("window_calibration",
             lambda: setattr(status, "window_calibration", self.get_window_calibration()))
        read("filter", _filter)
        read("error_code", lambda: setattr(status, "error_code", self.get_error_code()))
        read("mdi_tx_active",
             lambda: setattr(status, "mdi_tx_active", self.get_mdi_tx_active()))
        return status

    # ------------------------------------------------------------------
    # Command interface internals
    # ------------------------------------------------------------------

    def _write_request(self, name: str) -> None:
        self._request(protocol.VERB_WRITE, name, protocol.ACK_WRITE)

    def _read_request(self, name: str, min_values: int) -> Tuple[int, ...]:
        response = self._request(protocol.VERB_READ, name, protocol.ACK_READ)
        if len(response.values) < min_values:
            raise CommandError(
                "%s: expected at least %d values, got %r"
                % (name, min_values, response.raw))
        return response.values

    def _request(self, verb: str, name: str, expect_kind: str) -> CommandResponse:
        if not self._connected:
            raise NotConnectedError("not connected to scanner")
        with self._cmd_lock:
            with self._resp_lock:
                self._pending = (expect_kind, name)
                self._response = None
                self._resp_event.clear()
            try:
                assert self._tcp_sock is not None
                self._tcp_sock.sendall(frame_command(verb, name))
            except (OSError, AssertionError) as exc:
                with self._resp_lock:
                    self._pending = None
                raise NotConnectedError("send failed: %s" % exc) from exc
            answered = self._resp_event.wait(self.command_timeout)
            with self._resp_lock:
                response = self._response
                self._pending = None
                self._response = None
            if response is None:
                if not self._connected:
                    raise NotConnectedError("connection lost while waiting for %s" % name)
                if answered:
                    raise CommandError("malformed response to %s" % name)
                raise CommandTimeoutError(
                    "no response to %s within %.1f s" % (name, self.command_timeout))
            return response

    def _fail_pending_command(self) -> None:
        """Wake up a command waiter after a disconnect."""
        with self._resp_lock:
            if self._pending is not None:
                self._response = None
                self._resp_event.set()

    # ------------------------------------------------------------------
    # Receive paths
    # ------------------------------------------------------------------

    def _tcp_rx_loop(self) -> None:
        sock = self._tcp_sock
        try:
            while not self._closing and sock is not None:
                try:
                    data = sock.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not data:
                    break
                self._tcp_buf += data
                self._process_tcp_buffer()
        finally:
            if not self._closing:
                log.warning("TCP connection to scanner lost")
            self._connected = False
            self._fail_pending_command()

    def _process_tcp_buffer(self) -> None:
        """Split the TCP byte stream into command responses and MDI packets.

        Both can interleave arbitrarily when the scanner streams measurement
        data over TCP.  The buffer is processed strictly in order; MDI
        packets are consumed atomically (length-delimited), so their binary
        payload is never misread as a response frame.
        """
        buf = self._tcp_buf
        while True:
            resp_idx = find_response_start(buf)
            sync_idx = buf.find(SYNC)
            if resp_idx < 0 and sync_idx < 0:
                # Nothing recognizable: keep a tail that may hold the start
                # of a split sync pattern or response signature.
                if len(buf) > 4:
                    del buf[:-4]
                return
            if resp_idx >= 0 and (sync_idx < 0 or resp_idx < sync_idx):
                start = resp_idx
                etx = buf.find(ETX, start)
                if etx < 0:
                    if start > 0:
                        del buf[:start]
                    if len(buf) > MAX_RESPONSE_LENGTH:
                        # Runaway frame: drop the STX and rescan.
                        del buf[:1]
                        continue
                    return
                body = bytes(buf[start + 1:etx])
                del buf[:etx + 1]
                self._handle_response(body)
                continue
            # MDI packet (or garbage before one)
            if sync_idx > 0:
                del buf[:sync_idx]
            if len(buf) < HEADER_SIZE:
                return
            try:
                header = MdiHeader.from_bytes(buf)
            except ValueError:
                del buf[:len(SYNC)]
                continue
            if not header_plausible(header):
                # A bogus header (e.g. 'LEUZ' inside garbage) must not make
                # us wait for a giant phantom packet, stalling responses.
                del buf[:len(SYNC)]
                continue
            if len(buf) < header.packet_size:
                return
            packet_bytes = bytes(buf[:header.packet_size])
            del buf[:header.packet_size]
            if self._capturing_tcp:
                self._last_mdi = time.monotonic()
                self._feed(packet_bytes)
            # else: stale stream from a previous session; discard.

    def _udp_rx_loop(self) -> None:
        sock = self._udp_sock
        while not self._closing and self._measuring and sock is not None:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            if self.verify_udp_source and addr[0] != self._scanner_ip:
                self.foreign_datagrams_dropped += 1
                continue
            self._last_mdi = time.monotonic()
            self._feed(data)

    def _feed(self, data: bytes) -> None:
        with self._feed_lock:
            scans = self._assembler.feed(data)
        for scan in scans:
            self._deliver(scan)

    def _deliver(self, scan: Scan) -> None:
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

    def _handle_response(self, body: bytes) -> None:
        try:
            response = parse_response(body)
        except ValueError:
            log.debug("unparseable response frame: %r", body)
            self.unsolicited_responses += 1
            return
        with self._resp_lock:
            if (self._pending is not None
                    and response.kind == self._pending[0]
                    and response.name == self._pending[1]):
                self._response = response
                self._resp_event.set()
                return
        self.unsolicited_responses += 1
        log.debug("unsolicited response: %r", response.raw)

    def _teardown_udp(self) -> None:
        sock, self._udp_sock = self._udp_sock, None
        if sock is not None:
            sock.close()
        thread, self._udp_thread = self._udp_thread, None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)
