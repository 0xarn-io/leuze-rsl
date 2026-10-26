"""ROD-300-500 protocol client for Leuze ROD 308 / ROD 508 navigation scanners.

This module speaks the Leuze **ROD-300-500 communication protocol** -- a
TCP command interface (default port 3050) plus ``LEUZ`` measurement data
("MDI") packets pushed over UDP or interleaved on the TCP socket -- as used
by the ROD 308 / ROD 508 (ROD x08) navigation scanners.  It was reverse
engineered from Leuze's official ROS2 driver (``leuze_rod_ros2_drivers``,
Apache-2.0); no Leuze code is included in this package.

It is **not** the interface of the RSL 235 (or any RSL 200 / RSL 400 safety
scanner): those devices push UDP data telegrams and have no command channel,
see :mod:`leuze_rsl.udt` / :class:`~leuze_rsl.udt.RSL235Udt`.  The old class
name ``RSL235`` is kept only as a deprecated alias of :class:`RodScanner`.

Typical usage::

    from leuze_rsl import RodScanner

    with RodScanner("192.168.60.101") as scanner:    # connects + reads config
        scanner.start_measurement()
        scan = scanner.get_scan(timeout=5.0)
        print(scan.num_spots, scan.distances_m[:5])

The driver opens the TCP command interface, reads the scanner configuration,
asks the scanner to start streaming measurement data and assembles the MDI
packets into :class:`~leuze_rsl.parser.Scan` objects, delivered through
:meth:`RodScanner.get_scan`, :meth:`RodScanner.scans` or an ``on_scan``
callback.

Threads
-------
One thread reads the TCP socket (command replies and, in TCP transport mode,
MDI packets).  Scans are assembled and delivered -- ``on_scan`` callback and
queue -- on a separate *receiver* thread: the UDP receiver, or a dedicated
worker fed by the TCP reader.  The receiver thread is never the thread that
handles command replies, so commands (and :meth:`RodScanner.stop_measurement`
/ :meth:`RodScanner.close`) may be issued from ``on_scan``.  Callbacks must
still be quick: while a callback runs, newly completed scans queue up and
the oldest are dropped once the queue is full.
"""

from __future__ import annotations

import logging
import queue
import socket
import threading
import time
from dataclasses import dataclass, field
from enum import IntEnum
from types import TracebackType
from typing import Callable, Dict, Iterator, List, Optional, Tuple, Type, TypeVar, Union

from . import protocol
from .errors import (
    CommandError,
    CommandTimeoutError,
    NotConnectedError,
    ReceiverStoppedError,
    RSL235Error,
    ScannerConnectionError,
    ScanTimeoutError,
)
from .parser import Scan, ScanAssembler, header_plausible
from .protocol import (
    ETX,
    HEADER_SIZE,
    MAX_RESPONSE_LENGTH,
    STX,
    SYNC,
    CommandResponse,
    FilterType,
    MdiHeader,
    MdiPacketType,
    MdiProtocol,
    Resolution,
    ScanDirection,
    WindowCalibration,
    frame_command,
    parse_response,
)

__all__ = ["RodScanner", "RSL235", "ScannerConfig", "ScannerStatus", "ErrorLogEntry"]

log = logging.getLogger("leuze_rsl")

#: No MDI data for this long means the stream is considered stalled
#: (mirrors SCANPAR_TIMEOUT_MDI_PACKET in the reference driver).
DEFAULT_MDI_TIMEOUT = 3.0

#: Reply timeout for command interface requests (mirrors
#: CMDITF_MSG_TIMEOUT_MS in the reference driver).
DEFAULT_COMMAND_TIMEOUT = 1.0

#: recv() timeout of the command socket; bounds how long close() waits for
#: the reader thread.  Also the limit for sendall() of a command frame.
_TCP_POLL_S = 0.2

#: recvfrom() timeout of the UDP data socket; bounds the teardown latency.
_UDP_POLL_S = 0.1

#: get_scan(timeout=None) waits in slices of this length so that Ctrl+C is
#: honoured promptly on every platform (Windows cannot interrupt a blocking
#: Queue.get()).
_WAIT_SLICE_S = 0.5

#: How long worker threads are given to exit before a warning is logged.
_JOIN_TIMEOUT_S = 2.0

#: TCP transport: MDI packets handed from the socket reader to the receiver
#: worker.  At 80 Hz and three packets per scan this is ~1 s of backlog.
_MDI_QUEUE_SIZE = 256

#: TCP keepalive idle / interval [s] and probe count (best effort).
_KEEPALIVE = (5, 2, 3)

#: Byte values allowed in position 2 of a response signature ("R" or "W").
_RESPONSE_KINDS = frozenset(b"RW")

E = TypeVar("E", bound=IntEnum)


def _to_enum(enum_cls: Type[E], value: int) -> Union[E, int]:
    """Map a wire value onto an enum, keeping the raw int if unknown."""
    try:
        return enum_cls(value)
    except ValueError:
        return value


def _find_response_start(buf: bytearray, start: int, end: Optional[int]) -> int:
    """Index of the next ``STX 'c' ('R'|'W') 'A' ' '`` signature in ``buf``.

    Only STX bytes in ``[start, end)`` are considered (``end=None`` means the
    whole buffer).  Returns -1 if there is none, or if the only candidate is
    cut off by the end of the buffer (callers keep a tail for that case).
    """
    i = buf.find(STX, start, end)
    while i != -1:
        if i + 5 > len(buf):
            return -1
        if (buf[i + 1] == 0x63            # 'c'
                and buf[i + 2] in _RESPONSE_KINDS
                and buf[i + 3] == 0x41    # 'A'
                and buf[i + 4] == 0x20):  # ' '
            return i
        i = buf.find(STX, i + 1, end)
    return -1


def _enable_keepalive(sock: socket.socket) -> None:
    """Best effort TCP keepalive so a silently dead scanner is noticed.

    Without it a cable pull or power loss (no FIN/RST) leaves the connection
    looking healthy forever, since nothing flows on the command socket while
    measuring over UDP.  With the settings below the kernel declares the
    peer dead after roughly 5 + 3 * 2 seconds where the knobs exist.
    """
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError as exc:
        log.debug("SO_KEEPALIVE not available: %s", exc)
        return
    idle, interval, count = _KEEPALIVE
    ioctl = getattr(sock, "ioctl", None)
    sio_keepalive = getattr(socket, "SIO_KEEPALIVE_VALS", None)
    if ioctl is not None and sio_keepalive is not None:          # Windows
        try:
            ioctl(sio_keepalive, (1, idle * 1000, interval * 1000))
        except OSError as exc:
            log.debug("SIO_KEEPALIVE_VALS failed: %s", exc)
        return
    options = (
        # Linux: TCP_KEEPIDLE; macOS/BSD: TCP_KEEPALIVE
        (getattr(socket, "TCP_KEEPIDLE", None) or getattr(socket, "TCP_KEEPALIVE", None), idle),
        (getattr(socket, "TCP_KEEPINTVL", None), interval),
        (getattr(socket, "TCP_KEEPCNT", None), count),
    )
    for option, value in options:
        if option is None:
            continue
        try:
            sock.setsockopt(socket.IPPROTO_TCP, option, value)
        except OSError as exc:
            log.debug("TCP keepalive option %r not supported: %s", option, exc)


class _Wakeup:
    """Queue sentinel: wakes get_scan()/scans() waiters with an exception."""

    __slots__ = ("exc",)

    def __init__(self, exc: Exception) -> None:
        self.exc = exc


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
    angle_min_cdeg: int = field(init=False)     #: first configured angle [0.01 deg]
    angle_max_cdeg: int = field(init=False)     #: last configured angle [0.01 deg]

    def __post_init__(self) -> None:
        # The scanner reports the range in integer centi-degrees (GetRange);
        # keep those exact values next to the float views.
        object.__setattr__(self, "angle_min_cdeg", int(round(self.angle_min_deg * 100)))
        object.__setattr__(self, "angle_max_cdeg", int(round(self.angle_max_deg * 100)))

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
        """Number of spots per scan implied by the settings.

        Computed from the integer centi-degree range exactly like the
        simulator does (:func:`leuze_rsl.protocol.expected_spots`).  Raises
        ``ValueError`` if the settings are inconsistent (empty range).
        """
        return protocol.expected_spots(self.angle_min_cdeg, self.angle_max_cdeg,
                                       self.resolution.degrees, self.skip_spots)


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


# Resources of one measurement session, handed out under the state lock and
# disposed of outside it: (udp socket, udp thread, mdi queue, mdi thread).
_ReceiverResources = Tuple[
    Optional[socket.socket],
    Optional[threading.Thread],
    Optional["queue.Queue[Optional[bytes]]"],
    Optional[threading.Thread],
]


class RodScanner:
    """ROD-300-500 protocol client for Leuze ROD 308 / ROD 508 scanners.

    This is the TCP command-interface client plus MDI packet receiver of
    the ROD x08 navigation scanners (reverse engineered from Leuze's ROS2
    driver).  It does **not** talk to an RSL 235; that device pushes UDP
    data telegrams, see :class:`leuze_rsl.udt.RSL235Udt`.

    The object is reusable: after :meth:`close` or a lost link,
    :meth:`connect` starts a fresh session on the same instance.

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
        Number of completed scans buffered for :meth:`get_scan` (>= 1).
        When the consumer is too slow the oldest scan is dropped (counted
        in :attr:`stats`).
    on_scan:
        Optional callback invoked with every completed :class:`Scan` on the
        receiver thread (UDP receiver, or the MDI worker in TCP transport
        mode).  That thread never handles command replies, so the callback
        may issue commands, :meth:`stop_measurement` or :meth:`close`.
        Keep it quick: scans completed while it runs pile up in the queue
        and the oldest are dropped once it is full.  Exceptions it raises
        are logged and swallowed.
    verify_udp_source:
        Ignore UDP datagrams not originating from ``host`` (default True).
    mdi_timeout:
        Seconds without measurement data after which :attr:`is_receiving`
        turns False.
    tcp_keepalive:
        Enable TCP keepalive (with short probe intervals where the platform
        allows) on the command socket so a silently dead scanner -- cable
        pulled, power lost -- is detected within seconds instead of never.

    Raises ``ValueError`` for out-of-range arguments.
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
                 mdi_timeout: float = DEFAULT_MDI_TIMEOUT,
                 tcp_keepalive: bool = True) -> None:
        if not 0 < port <= 65535:
            raise ValueError("port must be in 1..65535")
        if udp_port is not None and not 0 < udp_port <= 65535:
            raise ValueError("udp_port must be in 1..65535")
        if connect_timeout <= 0:
            raise ValueError("connect_timeout must be > 0")
        if command_timeout <= 0:
            raise ValueError("command_timeout must be > 0")
        if mdi_timeout <= 0:
            raise ValueError("mdi_timeout must be > 0")
        if scan_queue_size < 1:
            raise ValueError("scan_queue_size must be >= 1")
        self.host = host
        self.port = port
        self.udp_port = port if udp_port is None else udp_port
        self.udp_bind_address = udp_bind_address
        self.connect_timeout = connect_timeout
        self.command_timeout = command_timeout
        self.mdi_timeout = mdi_timeout
        self.on_scan = on_scan
        self.verify_udp_source = verify_udp_source
        self.tcp_keepalive = tcp_keepalive

        self.config: Optional[ScannerConfig] = None

        # _lifecycle serializes connect/close/start/stop (re-entrant: close()
        # is called from connect()'s failure path).  _state guards the
        # session fields and the command bookkeeping below; it is only ever
        # held for a few instructions, never while blocking.  _cmd_lock
        # admits one command at a time; _feed_lock guards the assembler.
        self._lifecycle = threading.RLock()
        self._state = threading.Lock()
        self._cmd_lock = threading.Lock()
        self._feed_lock = threading.Lock()

        self._tcp_sock: Optional[socket.socket] = None
        self._tcp_thread: Optional[threading.Thread] = None
        self._tcp_buf = bytearray()                 # owned by the TCP reader thread
        self._scanner_ip: Optional[str] = None

        self._udp_sock: Optional[socket.socket] = None
        self._udp_thread: Optional[threading.Thread] = None
        self._mdi_queue: Optional["queue.Queue[Optional[bytes]]"] = None
        self._mdi_thread: Optional[threading.Thread] = None

        self._assembler = ScanAssembler()
        self._scan_queue: "queue.Queue[Union[Scan, _Wakeup]]" = queue.Queue(maxsize=scan_queue_size)

        # Command interface bookkeeping (guarded by _state).  Requests carry
        # a monotonically increasing id; the protocol itself has no sequence
        # numbers, see _request().
        self._resp_event = threading.Event()
        self._request_id = 0
        self._pending: Optional[Tuple[str, str, int]] = None   # (kind, name, id)
        self._response: Optional[CommandResponse] = None
        self._failure: Optional[Exception] = None
        self._late_reply: Optional[Tuple[str, float, int]] = None  # (name, deadline, id)

        self._connected = False
        self._measuring = False
        self._capturing_tcp = False
        self._last_mdi: Optional[float] = None
        self._receiver_error: Optional[Exception] = None   # UDP receiver died while measuring

        # Diagnostics counters (see also self._assembler.stats).
        self.scans_dropped_queue = 0        #: scans dropped because get_scan() was too slow
        self.mdi_packets_dropped = 0        #: TCP transport: packets dropped before assembly
        self.unsolicited_responses = 0      #: replies nobody was waiting for
        self.late_responses = 0             #: replies to commands that had timed out
        self.truncated_responses = 0        #: reply frames without ETX (discarded)
        self.foreign_datagrams_dropped = 0  #: UDP datagrams not from the scanner
        self.receiver_errors = 0            #: exceptions caught on the receiver threads

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self, read_config: bool = True) -> "RodScanner":
        """Open the command interface and (optionally) read the configuration.

        Mirrors the reference driver's startup: connect, send ``StopMDI`` as
        a handshake, then query the scan settings into :attr:`config`.
        Works again after :meth:`close` or a lost link; buffered scans and
        all state of the previous session are discarded (threads of that
        session that are still winding down are waited for first).

        Raises :class:`ScannerConnectionError` if already connected, if the
        TCP connection cannot be established, or if the handshake / the
        configuration read fails (the underlying :class:`CommandTimeoutError`
        or :class:`CommandError` is chained as ``__cause__``).
        """
        with self._lifecycle:
            if self._connected:
                raise ScannerConnectionError("already connected")
            # Release whatever a lost link or an earlier session left behind.
            self._teardown(NotConnectedError("reconnecting"), wake=False)
            self._drain_queue()
            self._tcp_buf = bytearray()
            with self._feed_lock:
                self._assembler.reset()
            self._last_mdi = None
            try:
                sock = socket.create_connection((self.host, self.port),
                                                timeout=self.connect_timeout)
            except OSError as exc:
                raise ScannerConnectionError(
                    "unable to connect to %s:%d: %s" % (self.host, self.port, exc)) from exc
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                if self.tcp_keepalive:
                    _enable_keepalive(sock)
                sock.settimeout(_TCP_POLL_S)
                scanner_ip = sock.getpeername()[0]
            except OSError as exc:
                sock.close()
                raise ScannerConnectionError(
                    "unable to set up the connection to %s:%d: %s"
                    % (self.host, self.port, exc)) from exc
            thread = threading.Thread(target=self._tcp_rx_loop, args=(sock,),
                                      name="leuze_rsl-tcp-rx", daemon=True)
            with self._state:
                self._tcp_sock = sock
                self._tcp_thread = thread
                self._scanner_ip = scanner_ip
                self._connected = True
                self._pending = None
                self._response = None
                self._failure = None
                self._late_reply = None
                self._resp_event.clear()
            thread.start()
            try:
                self._write_request(protocol.CMD_STOP_MDI)
                if read_config:
                    self.config = self.read_config()
            except ScannerConnectionError:
                self.close()
                raise
            except RSL235Error as exc:
                self.close()
                raise ScannerConnectionError(
                    "handshake with %s:%d failed: %s" % (self.host, self.port, exc)) from exc
            except BaseException:
                self.close()
                raise
            log.info("connected to scanner at %s:%d", self.host, self.port)
            return self

    def close(self) -> None:
        """Stop measuring, close all sockets and join the worker threads.

        Idempotent and quiet: on an already lost link nothing is sent and
        nothing is logged above DEBUG.  Waiters in :meth:`get_scan` /
        :meth:`scans` are woken with :class:`NotConnectedError`.  Never
        raises.
        """
        if not self._acquire_lifecycle(lambda: not self._connected and not self._measuring):
            return                              # another thread closed it meanwhile
        try:
            if self._measuring and self._connected:
                try:
                    self._write_request(protocol.CMD_STOP_MDI)
                except RSL235Error as exc:
                    log.debug("StopMDI not acknowledged while closing: %s", exc)
            if self._teardown(NotConnectedError("driver closed")):
                log.info("disconnected from scanner at %s:%d", self.host, self.port)
        finally:
            self._lifecycle.release()

    def __enter__(self) -> "RodScanner":
        return self.connect()

    def __exit__(self,
                 exc_type: Optional[Type[BaseException]],
                 exc: Optional[BaseException],
                 tb: Optional[TracebackType]) -> None:
        self.close()

    @property
    def is_connected(self) -> bool:
        """True while the command connection is up (False after a lost link)."""
        return self._connected

    @property
    def is_measuring(self) -> bool:
        """True between :meth:`start_measurement` and :meth:`stop_measurement`.

        Also turns False when the link is lost or the receiver fails.
        """
        return self._measuring

    @property
    def is_receiving(self) -> bool:
        """True while measurement data arrived within ``mdi_timeout`` seconds."""
        if not self._measuring or self._last_mdi is None or self._receiver_error is not None:
            return False
        return (time.monotonic() - self._last_mdi) < self.mdi_timeout

    @property
    def stats(self) -> Dict[str, int]:
        """Diagnostic counters of the data path and the command interface."""
        stats = vars(self._assembler.stats).copy()
        stats.update(
            scans_dropped_queue=self.scans_dropped_queue,
            mdi_packets_dropped=self.mdi_packets_dropped,
            unsolicited_responses=self.unsolicited_responses,
            late_responses=self.late_responses,
            truncated_responses=self.truncated_responses,
            foreign_datagrams_dropped=self.foreign_datagrams_dropped,
            receiver_errors=self.receiver_errors,
        )
        return stats

    # ------------------------------------------------------------------
    # Measurement data
    # ------------------------------------------------------------------

    def start_measurement(self, protocol_override: Optional[MdiProtocol] = None) -> None:
        """Ask the scanner to stream measurement data and start receiving it.

        The receiver listens for the transport the scanner is configured
        for (its ``GetProto`` setting, read by :meth:`connect`).
        ``protocol_override`` only tells the driver which transport to
        listen on -- needed after ``connect(read_config=False)``; the
        protocol has no command to change the scanner's transport, so an
        override that disagrees with the configuration yields no data
        (a warning is logged).

        Scans buffered from an earlier measurement are discarded.  Calling
        this while already measuring is a no-op.

        Raises ``ValueError`` for a bad ``protocol_override`` or when the
        transport is unknown, :class:`NotConnectedError` when not connected,
        :class:`ScannerConnectionError` if the UDP port cannot be bound
        (e.g. another receiver holds it), :class:`CommandTimeoutError` /
        :class:`CommandError` if the scanner does not acknowledge
        ``SendMDI``.
        """
        if protocol_override is None:
            if self.config is None:
                raise ValueError(
                    "MDI protocol unknown: connect(read_config=True) or pass protocol_override")
            proto = self.config.protocol
        else:
            try:
                proto = MdiProtocol(protocol_override)
            except ValueError:
                raise ValueError("protocol_override must be an MdiProtocol, not %r"
                                 % (protocol_override,)) from None
            if self.config is not None and proto != self.config.protocol:
                log.warning("protocol_override=%s but the scanner is configured for %s; "
                            "the override cannot change the scanner's transport, so no "
                            "data will arrive", proto.name, self.config.protocol.name)
        with self._lifecycle:
            if not self._connected:
                raise NotConnectedError("connect() first")
            if self._measuring:
                return
            self._drain_queue()
            with self._feed_lock:
                self._assembler.reset()
            self._receiver_error = None
            self._last_mdi = None
            if proto == MdiProtocol.UDP:
                # Bind first, then SendMDI: the reference driver does it the
                # other way around and can lose the first packets.
                self._start_udp_receiver()
            else:
                self._start_tcp_worker()
            try:
                self._write_request(protocol.CMD_SEND_MDI)
            except BaseException:
                self._stop_receiving()
                raise
            log.info("measurement started (%s)", proto.name)

    def stop_measurement(self) -> None:
        """Stop the measurement data stream (best effort) and the receiver.

        Scans already buffered remain available to :meth:`get_scan` /
        :meth:`scans`; afterwards they raise / stop with
        :class:`ReceiverStoppedError`.  No-op when not measuring.  Never
        raises: a scanner that does not acknowledge ``StopMDI`` is logged.
        """
        if not self._acquire_lifecycle(lambda: not self._measuring):
            return                              # another thread stopped it meanwhile
        try:
            if not self._measuring:
                return
            if self._connected:
                try:
                    self._write_request(protocol.CMD_STOP_MDI)
                except NotConnectedError as exc:
                    log.debug("StopMDI not sent, link already lost: %s", exc)
                except RSL235Error:
                    log.warning("StopMDI not acknowledged", exc_info=True)
            self._stop_receiving()
            self._wake_waiters(ReceiverStoppedError("measurement stopped"))
            log.info("measurement stopped")
        finally:
            self._lifecycle.release()

    def get_scan(self, timeout: Optional[float] = None) -> Scan:
        """Return the next complete scan.

        Raises :class:`ScanTimeoutError` (a ``TimeoutError``) if no scan
        arrives within ``timeout`` seconds; :class:`ReceiverStoppedError`
        when measurement is not running (never started, or stopped with
        :meth:`stop_measurement` and the buffered scans are consumed);
        :class:`NotConnectedError` when the driver is closed or the link is
        lost; :class:`ScannerConnectionError` when the UDP receiver failed.
        ``timeout=None`` waits until one of those happens -- it never blocks
        forever, and stays interruptible with Ctrl+C.
        """
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            if self._scan_queue.empty():
                if self._receiver_error is not None:
                    raise ScannerConnectionError("UDP receiver failed: %s" % self._receiver_error)
                if not self._measuring:
                    raise self._not_running_error()
            if deadline is None:
                wait: Optional[float] = _WAIT_SLICE_S
            else:
                wait = max(0.0, deadline - time.monotonic())
            try:
                item = self._scan_queue.get(timeout=wait)
            except queue.Empty:
                if deadline is not None and time.monotonic() >= deadline:
                    raise ScanTimeoutError(
                        "no scan received within %s s (is_receiving=%s)"
                        % (timeout, self.is_receiving)) from None
                if self._scan_queue.empty():
                    if self._receiver_error is not None:
                        raise ScannerConnectionError(
                            "UDP receiver failed: %s" % self._receiver_error) from None
                    if not self._measuring:
                        raise self._not_running_error() from None
                continue
            if isinstance(item, _Wakeup):
                self._requeue_wakeup(item)
                raise item.exc
            return item

    def scans(self, timeout: Optional[float] = None) -> Iterator[Scan]:
        """Iterate over scans until measurement stops.

        Ends (after yielding the buffered scans) when :meth:`stop_measurement`
        is called or measurement was never started.  Propagates
        :class:`NotConnectedError` when the driver is closed or the link is
        lost, :class:`ScannerConnectionError` when the receiver fails and,
        with ``timeout`` set, :class:`ScanTimeoutError` if no scan arrives
        in time.
        """
        while True:
            try:
                yield self.get_scan(timeout)
            except ReceiverStoppedError:
                return

    @property
    def scans_available(self) -> int:
        """Complete scans currently buffered for :meth:`get_scan`."""
        with self._scan_queue.mutex:
            return sum(1 for item in self._scan_queue.queue if not isinstance(item, _Wakeup))

    # ------------------------------------------------------------------
    # Configuration / status queries (TCP command interface)
    # ------------------------------------------------------------------

    def read_config(self) -> ScannerConfig:
        """Read the scan-relevant settings (strict).

        Raises :class:`CommandError` if the scanner reports an unknown or
        inconsistent setting, plus the :meth:`get_protocol` exceptions.
        """
        proto = self.get_protocol()
        ptype = self.get_packet_type()
        resolution = self.get_resolution()
        direction = self.get_direction()
        angle_min_cdeg, angle_max_cdeg = self._get_angle_range_cdeg()
        skip = self.get_skip_spots()
        if angle_min_cdeg >= angle_max_cdeg:
            raise CommandError("scanner reported an invalid angle range: %d..%d (0.01 deg)"
                               % (angle_min_cdeg, angle_max_cdeg))
        if skip < 0:
            raise CommandError("scanner reported a negative skip count: %d" % skip)
        try:
            config = ScannerConfig(
                protocol=MdiProtocol(int(proto)),
                packet_type=MdiPacketType(int(ptype)),
                resolution=Resolution(int(resolution)),
                direction=ScanDirection(int(direction)),
                angle_min_deg=angle_min_cdeg / 100.0,
                angle_max_deg=angle_max_cdeg / 100.0,
                skip_spots=skip,
            )
        except ValueError as exc:
            raise CommandError("scanner reported an out-of-range setting: %s" % exc) from exc
        log.info("scanner config: %s", config)
        return config

    # Every getter below raises NotConnectedError when not connected,
    # CommandTimeoutError when the scanner does not answer and CommandError
    # when it answers with something unexpected.  Getters that map onto an
    # enum return the raw int for values this library does not know.

    def get_protocol(self) -> Union[MdiProtocol, int]:
        """Transport of the measurement data: UDP or TCP (``GetProto``)."""
        return _to_enum(MdiProtocol, self._read_request(protocol.CMD_GET_PROTO, 1)[0])

    def get_packet_type(self) -> Union[MdiPacketType, int]:
        """Payload type: distances only or + intensities (``GetPType``)."""
        return _to_enum(MdiPacketType, self._read_request(protocol.CMD_GET_PTYPE, 1)[0])

    def get_resolution(self) -> Union[Resolution, int]:
        """Angular resolution / scan frequency setting (``GetResol``)."""
        return _to_enum(Resolution, self._read_request(protocol.CMD_GET_RESOL, 1)[0])

    def get_direction(self) -> Union[ScanDirection, int]:
        """Data output direction (``GetDir``)."""
        return _to_enum(ScanDirection, self._read_request(protocol.CMD_GET_DIR, 1)[0])

    def get_angle_range(self) -> Tuple[float, float]:
        """Configured scan angle range in degrees (``GetRange``)."""
        angle_min_cdeg, angle_max_cdeg = self._get_angle_range_cdeg()
        return angle_min_cdeg / 100.0, angle_max_cdeg / 100.0

    def _get_angle_range_cdeg(self) -> Tuple[int, int]:
        values = self._read_request(protocol.CMD_GET_RANGE, 2)
        return values[0], values[1]

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

    def get_window_calibration(self) -> Union[WindowCalibration, int]:
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
        ``ScannerStatus.errors`` instead of raising; with ``strict=True``
        the first failure raises (see the getters for the exceptions).
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
        """Send one command and wait for its reply (one request at a time).

        Replies carry no sequence number, only the echoed command name.  A
        reply that arrives after its request timed out would therefore be
        mistaken for the reply to the next request of the same name.  To
        mitigate this, the name of a timed-out request is remembered for
        ``command_timeout`` seconds and a reply for it arriving in that
        window is discarded (counted in ``late_responses``) -- unless a
        request with the same name is already pending again, in which case
        the reply is accepted.  That residual ambiguity (retrying the same
        command immediately after a timeout may return the stale value) is
        inherent to the protocol; wait ``command_timeout`` before retrying
        if it matters.

        Raises :class:`NotConnectedError` when not connected or the link is
        lost meanwhile, :class:`CommandTimeoutError` when the scanner does
        not answer within ``command_timeout`` (or stopped reading, so the
        frame could not even be sent -- a partially sent frame then garbles
        the next one; treat repeated timeouts as a dead link and reconnect),
        :class:`CommandError` for a malformed reply.
        """
        with self._cmd_lock:
            with self._state:
                sock = self._tcp_sock
                if sock is None or not self._connected:
                    raise NotConnectedError("not connected to scanner")
                self._request_id += 1
                request_id = self._request_id
                self._pending = (expect_kind, name, request_id)
                self._response = None
                self._failure = None
                self._resp_event.clear()
            try:
                sock.sendall(frame_command(verb, name))
            except socket.timeout as exc:
                self._clear_pending()
                raise CommandTimeoutError(
                    "sending %s timed out after %.1f s (scanner not reading?)"
                    % (name, _TCP_POLL_S)) from exc
            except OSError as exc:
                self._clear_pending()
                raise NotConnectedError("send failed for %s: %s" % (name, exc)) from exc
            self._resp_event.wait(self.command_timeout)
            with self._state:
                response = self._response
                failure = self._failure
                connected = self._connected
                self._pending = None
                self._response = None
                self._failure = None
                if response is None and failure is None and connected:
                    # Timed out; the scanner may still answer (see docstring).
                    self._late_reply = (name, time.monotonic() + self.command_timeout,
                                        request_id)
            if response is not None:
                return response
            if failure is not None:
                raise failure
            if not connected:
                raise NotConnectedError("connection lost while waiting for %s" % name)
            raise CommandTimeoutError(
                "no response to %s within %.1f s" % (name, self.command_timeout))

    def _clear_pending(self) -> None:
        with self._state:
            self._pending = None
            self._response = None
            self._failure = None

    def _handle_response(self, body: bytes) -> None:
        """Dispatch one response frame body (called on the TCP reader thread)."""
        try:
            response = parse_response(body)
        except ValueError:
            tokens = body.split(b" ")
            with self._state:
                pending = self._pending
                if (pending is not None and len(tokens) >= 2
                        and tokens[0] == pending[0].encode("ascii")
                        and tokens[1] == pending[1].encode("ascii")):
                    # A garbled reply to our own command: fail it right away
                    # instead of letting the caller wait for the timeout.
                    self._failure = CommandError(
                        "malformed response to %s: %r" % (pending[1], bytes(body)))
                    self._resp_event.set()
                    return
            self.unsolicited_responses += 1
            log.debug("unparseable response frame: %r", bytes(body))
            return
        now = time.monotonic()
        with self._state:
            pending = self._pending
            if (pending is not None
                    and response.kind == pending[0]
                    and response.name == pending[1]):
                self._response = response
                self._resp_event.set()
                return
            late = self._late_reply
            if late is not None and late[0] == response.name and now < late[1]:
                self._late_reply = None
                self.late_responses += 1
                log.debug("discarding late reply to timed-out request #%d: %r",
                          late[2], response.raw)
                return
        self.unsolicited_responses += 1
        log.debug("unsolicited response: %r", response.raw)

    # ------------------------------------------------------------------
    # Session / receiver management
    # ------------------------------------------------------------------

    def _start_udp_receiver(self) -> None:
        tcp = self._tcp_sock
        if tcp is None:
            raise NotConnectedError("connect() first")
        # Same address family as the command connection so that source
        # addresses compare equal in verify_udp_source.  No SO_REUSEADDR: a
        # second receiver on this port must fail loudly instead of silently
        # stealing the datagrams.
        sock: Optional[socket.socket] = None
        try:
            sock = socket.socket(tcp.family, socket.SOCK_DGRAM)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
            except OSError:
                pass
            # The scanner pushes datagrams to <our ip>:<command port>.
            sock.bind((self.udp_bind_address, self.udp_port))
            sock.settimeout(_UDP_POLL_S)
        except OSError as exc:
            if sock is not None:
                sock.close()
            raise ScannerConnectionError(
                "unable to bind UDP port %s:%d: %s"
                % (self.udp_bind_address or "0.0.0.0", self.udp_port, exc)) from exc
        thread = threading.Thread(target=self._udp_rx_loop, args=(sock,),
                                  name="leuze_rsl-udp-rx", daemon=True)
        with self._state:
            owned = self._tcp_sock is tcp and self._connected
            if owned:
                self._udp_sock = sock
                self._udp_thread = thread
                self._measuring = True
                thread.start()          # published and started atomically w.r.t. teardown
        if not owned:
            sock.close()
            raise NotConnectedError("connection to scanner lost")

    def _start_tcp_worker(self) -> None:
        mdi_queue: "queue.Queue[Optional[bytes]]" = queue.Queue(maxsize=_MDI_QUEUE_SIZE)
        thread = threading.Thread(target=self._mdi_worker, args=(mdi_queue,),
                                  name="leuze_rsl-mdi-worker", daemon=True)
        with self._state:
            if not self._connected:
                raise NotConnectedError("connection to scanner lost")
            self._mdi_queue = mdi_queue
            self._mdi_thread = thread
            self._capturing_tcp = True
            self._measuring = True
            thread.start()              # published and started atomically w.r.t. teardown

    def _detach_receiver_locked(self) -> _ReceiverResources:
        """Clear the measurement state; caller holds ``_state``.

        The thread references stay set until :meth:`_dispose_receiver` has
        joined them: a UDP socket closed from another thread keeps its port
        until the receiver's recvfrom() returns, so a new session must wait
        for the old thread (see :meth:`connect`).
        """
        self._measuring = False
        self._capturing_tcp = False
        udp, self._udp_sock = self._udp_sock, None
        mdi_queue, self._mdi_queue = self._mdi_queue, None
        return udp, self._udp_thread, mdi_queue, self._mdi_thread

    def _dispose_receiver(self, resources: _ReceiverResources) -> None:
        udp, udp_thread, mdi_queue, mdi_thread = resources
        if udp is not None:
            udp.close()
        if mdi_queue is not None:
            self._put_mdi_sentinel(mdi_queue)
        udp_done = self._join(udp_thread, "UDP receiver")
        mdi_done = self._join(mdi_thread, "MDI worker")
        with self._state:
            if udp_done and self._udp_thread is udp_thread:
                self._udp_thread = None
            if mdi_done and self._mdi_thread is mdi_thread:
                self._mdi_thread = None

    def _stop_receiving(self) -> None:
        with self._state:
            resources = self._detach_receiver_locked()
        self._dispose_receiver(resources)
        with self._feed_lock:
            self._assembler.reset()
        self._last_mdi = None
        self._receiver_error = None
        self._purge_wakeups()

    def _purge_wakeups(self) -> None:
        """Drop stale wake-up sentinels, keeping buffered scans in order.

        Only called once the receiver threads are detached, so no producer
        races with the rebuild.
        """
        items: List[Union[Scan, _Wakeup]] = []
        while True:
            try:
                items.append(self._scan_queue.get_nowait())
            except queue.Empty:
                break
        for item in items:
            if not isinstance(item, _Wakeup):
                try:
                    self._scan_queue.put_nowait(item)
                except queue.Full:
                    break

    def _teardown(self, exc: Exception, *,
                  only_if_sock: Optional[socket.socket] = None,
                  wake: bool = True) -> bool:
        """Release the whole session: sockets, threads, pending command.

        With ``only_if_sock`` the teardown happens only if that socket is
        still the current connection, so a reader thread that outlives
        :meth:`close` can never clobber the state of a newer connection.
        Returns True if a connection was torn down.
        """
        with self._state:
            tcp = self._tcp_sock
            if only_if_sock is not None and tcp is not only_if_sock:
                return False
            had_connection = tcp is not None
            self._tcp_sock = None
            tcp_thread = self._tcp_thread
            self._connected = False
            resources = self._detach_receiver_locked()
            if self._pending is not None:
                self._failure = exc
                self._resp_event.set()
        if tcp is not None:
            try:
                tcp.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            tcp.close()
        self._dispose_receiver(resources)
        if self._join(tcp_thread, "TCP receiver"):
            with self._state:
                if self._tcp_thread is tcp_thread:
                    self._tcp_thread = None
        self._last_mdi = None
        self._receiver_error = None
        self._purge_wakeups()
        if had_connection and wake:
            self._wake_waiters(exc)
        return had_connection

    def _acquire_lifecycle(self, done: Callable[[], bool]) -> bool:
        """Take the lifecycle lock for a stop/close; False if it became moot.

        A receiver thread (``on_scan``) that stops or closes the driver
        while another thread is doing the same would wait here for a lock
        whose holder is busy joining *this* thread.  So a receiver thread
        polls for the lock and gives up -- returning False, nothing left to
        do -- as soon as ``done()`` reports that the other thread finished.
        Any other thread simply blocks.
        """
        if threading.current_thread() in (self._udp_thread, self._mdi_thread):
            while not self._lifecycle.acquire(timeout=0.05):
                if done():
                    return False
            return True
        self._lifecycle.acquire()
        return True

    @staticmethod
    def _join(thread: Optional[threading.Thread], what: str) -> bool:
        """Join ``thread``; True once it is gone (False: still running)."""
        if thread is None or thread.ident is None:      # never started
            return True
        if thread is threading.current_thread():
            return False
        thread.join(timeout=_JOIN_TIMEOUT_S)
        if thread.is_alive():
            log.warning("%s thread did not stop within %.0f s (callback blocked?)",
                        what, _JOIN_TIMEOUT_S)
            return False
        return True

    # ------------------------------------------------------------------
    # Receive paths
    # ------------------------------------------------------------------

    def _tcp_rx_loop(self, sock: socket.socket) -> None:
        reason = "connection closed by the scanner"
        try:
            while self._tcp_sock is sock:
                try:
                    data = sock.recv(65536)
                except socket.timeout:
                    continue
                except OSError as exc:
                    reason = str(exc) or type(exc).__name__
                    break
                if not data:
                    break
                self._tcp_buf += data
                try:
                    self._process_tcp_buffer()
                except Exception:
                    self.receiver_errors += 1
                    log.exception("error while demultiplexing the TCP stream; "
                                  "discarding %d buffered bytes", len(self._tcp_buf))
                    self._tcp_buf.clear()
        finally:
            lost = NotConnectedError("connection to scanner lost: %s" % reason)
            if self._teardown(lost, only_if_sock=sock):
                log.warning("TCP connection to scanner lost (%s)", reason)

    def _process_tcp_buffer(self) -> None:
        """Split the TCP byte stream into command responses and MDI packets.

        Both can interleave arbitrarily when the scanner streams measurement
        data over TCP.  The buffer is processed strictly in order and MDI
        packets are consumed atomically (length-delimited), so their binary
        payload is never misread as a response frame.  A response signature
        is only searched for in the bytes before the next ``LEUZ`` sync,
        which keeps one call linear in the buffer size.  Each iteration
        either consumes at least one byte or returns.

        Response frames are ``STX body ETX``.  A frame whose ETX never comes
        -- another signature or an MDI packet starts first, or it grows past
        ``MAX_RESPONSE_LENGTH`` -- is discarded (``truncated_responses``)
        without taking the following, valid frame with it.
        """
        buf = self._tcp_buf
        sync_idx = buf.find(SYNC)
        while True:
            if sync_idx == 0:
                resp_idx = -1
            else:
                resp_idx = _find_response_start(buf, 0, sync_idx if sync_idx > 0 else None)
            if resp_idx < 0 and sync_idx < 0:
                # Nothing recognizable: keep a tail that may hold the start
                # of a split sync pattern or response signature.
                if len(buf) > 4:
                    del buf[:-4]
                return
            if resp_idx >= 0:
                # -- command response (precedes any MDI packet in the buffer)
                start = resp_idx
                limit = sync_idx if sync_idx >= 0 else len(buf)
                etx = buf.find(ETX, start, min(limit, start + MAX_RESPONSE_LENGTH + 2))
                frame_end = etx if etx >= 0 else limit
                nxt = _find_response_start(buf, start + 1, frame_end)
                if nxt >= 0:
                    # The frame at `start` never got its ETX; the next one
                    # may be fine, so resume there.
                    self.truncated_responses += 1
                    log.debug("discarding truncated response frame %r", bytes(buf[start:nxt]))
                    del buf[:nxt]
                    if sync_idx >= 0:
                        sync_idx -= nxt
                    continue
                if etx < 0:
                    if sync_idx >= 0:
                        # Cut short by an MDI packet: drop the frame, keep the packet.
                        self.truncated_responses += 1
                        log.debug("discarding response frame cut short by MDI data %r",
                                  bytes(buf[start:sync_idx]))
                        del buf[:sync_idx]
                        sync_idx = 0
                        continue
                    if start > 0:
                        del buf[:start]
                    if len(buf) > MAX_RESPONSE_LENGTH + 2:
                        # Runaway frame: drop the STX and rescan.
                        self.truncated_responses += 1
                        del buf[:1]
                        continue
                    return
                body = bytes(buf[start + 1:etx])
                consumed = etx + 1
                del buf[:consumed]
                if sync_idx >= 0:
                    sync_idx -= consumed
                self._handle_response(body)
                continue
            # -- MDI packet (sync_idx >= 0 here)
            if sync_idx > 0:
                del buf[:sync_idx]
            if len(buf) < HEADER_SIZE:
                return
            try:
                header = MdiHeader.from_bytes(buf)
            except ValueError:
                del buf[:len(SYNC)]
                sync_idx = buf.find(SYNC)
                continue
            if not header_plausible(header):
                # A bogus header (e.g. 'LEUZ' inside garbage) must not make
                # us wait for a giant phantom packet, stalling responses.
                del buf[:len(SYNC)]
                sync_idx = buf.find(SYNC)
                continue
            if len(buf) < header.packet_size:
                return
            packet_bytes = bytes(buf[:header.packet_size])
            del buf[:header.packet_size]
            sync_idx = buf.find(SYNC)
            self._on_mdi_packet(packet_bytes)

    def _on_mdi_packet(self, packet: bytes) -> None:
        """Hand a complete MDI packet from the TCP stream to the worker."""
        if not self._capturing_tcp:
            return          # stale stream from a previous session; discard
        self._last_mdi = time.monotonic()
        mdi_queue = self._mdi_queue
        if mdi_queue is None:
            return
        try:
            mdi_queue.put_nowait(packet)
        except queue.Full:
            # The worker (on_scan) is too slow: drop the oldest packet.  The
            # assembler then drops that scan as incomplete, which is counted.
            try:
                mdi_queue.get_nowait()
                self.mdi_packets_dropped += 1
            except queue.Empty:
                pass
            try:
                mdi_queue.put_nowait(packet)
            except queue.Full:
                self.mdi_packets_dropped += 1

    @staticmethod
    def _put_mdi_sentinel(mdi_queue: "queue.Queue[Optional[bytes]]") -> None:
        try:
            mdi_queue.put_nowait(None)
        except queue.Full:
            try:
                mdi_queue.get_nowait()
            except queue.Empty:
                pass
            try:
                mdi_queue.put_nowait(None)
            except queue.Full:
                pass

    def _mdi_worker(self, mdi_queue: "queue.Queue[Optional[bytes]]") -> None:
        """TCP transport: assemble and deliver scans off the reader thread."""
        while True:
            item = mdi_queue.get()
            if item is None or self._mdi_queue is not mdi_queue:
                return
            try:
                self._feed(item, lambda: self._mdi_queue is mdi_queue)
            except Exception:
                self.receiver_errors += 1
                log.exception("error while processing an MDI packet")

    def _udp_rx_loop(self, sock: socket.socket) -> None:
        failure: Optional[OSError] = None
        try:
            while self._udp_sock is sock:
                try:
                    data, addr = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError as exc:
                    if self._udp_sock is sock:      # not our own teardown
                        failure = exc
                    break
                if self.verify_udp_source and addr[0] != self._scanner_ip:
                    self.foreign_datagrams_dropped += 1
                    continue
                self._last_mdi = time.monotonic()
                try:
                    self._feed_datagram(data, lambda: self._udp_sock is sock)
                except Exception:
                    self.receiver_errors += 1
                    log.exception("error while processing an MDI datagram")
        finally:
            if failure is not None:
                with self._state:
                    mine = self._udp_sock is sock
                    if mine:
                        self._udp_sock = None
                        self._udp_thread = None
                        # Keep _measuring: the scanner is still streaming, so
                        # stop_measurement()/close() must still send StopMDI.
                        self._receiver_error = failure
                if mine:
                    sock.close()
                    log.error("UDP receiver failed (call stop_measurement()): %s", failure)
                    self._wake_waiters(ScannerConnectionError(
                        "UDP receiver failed: %s" % failure))

    def _feed(self, data: bytes,
              still_current: Optional[Callable[[], bool]] = None) -> None:
        """Assemble packets from a stream chunk (TCP transport)."""
        with self._feed_lock:
            scans = self._assembler.feed(data)
        for scan in scans:
            self._deliver(scan, still_current)

    def _feed_datagram(self, data: bytes,
                       still_current: Optional[Callable[[], bool]] = None) -> None:
        """Assemble packets from one UDP datagram."""
        with self._feed_lock:
            scans = self._assembler.feed_datagram(data)
        for scan in scans:
            self._deliver(scan, still_current)

    def _deliver(self, scan: Scan,
                 still_current: Optional[Callable[[], bool]] = None) -> None:
        if self.on_scan is not None:
            try:
                self.on_scan(scan)
            except Exception:
                log.exception("on_scan callback raised")
        if still_current is not None and not still_current():
            # Measurement was stopped/restarted while the callback ran: this
            # scan belongs to the old session and must not surface now.
            return
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

    # ------------------------------------------------------------------
    # Scan queue helpers (mirror leuze_rsl.udt.RSL235Udt)
    # ------------------------------------------------------------------

    def _not_running_error(self) -> RSL235Error:
        if not self._connected:
            return NotConnectedError("not connected to scanner")
        return ReceiverStoppedError("measurement is not running (call start_measurement())")

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
                self._scan_queue.get_nowait()
            except queue.Empty:
                pass
            try:
                self._scan_queue.put_nowait(wake)
            except queue.Full:
                pass

    def _requeue_wakeup(self, wake: _Wakeup) -> None:
        if not self._measuring or self._receiver_error is not None:
            try:
                self._scan_queue.put_nowait(wake)
            except queue.Full:
                pass


#: Deprecated alias (the pre-0.3 name).  An RSL 235 does not speak this
#: protocol; use :class:`leuze_rsl.udt.RSL235Udt` for that device.
RSL235 = RodScanner
