"""End-to-end tests: RodScanner driver against the ROD protocol simulator (no hardware)."""

import gc
import logging
import socket
import threading
import time
import unittest
import warnings

from leuze_rsl import (
    CommandError,
    CommandTimeoutError,
    MdiPacketType,
    MdiProtocol,
    NotConnectedError,
    Resolution,
    ScanDirection,
    ScannerConnectionError,
)
from leuze_rsl import protocol
from leuze_rsl.driver import RSL235, RodScanner, ScannerConfig
from leuze_rsl.errors import ReceiverStoppedError, ScanTimeoutError
from leuze_rsl.parser import ScanAssembler
from leuze_rsl.protocol import ETX, STX, build_packet
from leuze_rsl.simulator import RSL235Simulator, SimulatorSettings


def free_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def small_settings(**overrides) -> SimulatorSettings:
    """A small, fast scan: 60 deg span, 0.2 deg -> 301 spots in 3 packets."""
    defaults = dict(
        angle_min_cdeg=-3000,
        angle_max_cdeg=3000,
        spots_per_packet=120,
    )
    defaults.update(overrides)
    return SimulatorSettings(**defaults)


def wait_until(predicate, timeout: float = 2.0, step: float = 0.01) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(step)
    return predicate()


class UdpEndToEndTests(unittest.TestCase):
    def setUp(self):
        self.udp_port = free_udp_port()
        self.sim = RSL235Simulator(udp_dest_port=self.udp_port).start()
        self.addCleanup(self.sim.stop)
        self.driver = RSL235("127.0.0.1", self.sim.port, udp_port=self.udp_port)
        self.addCleanup(self.driver.close)

    def test_full_flow(self):
        seen = []
        self.driver.on_scan = seen.append
        self.driver.connect()
        self.assertTrue(self.driver.is_connected)

        # configuration read at connect matches the simulator settings
        cfg = self.driver.config
        self.assertEqual(cfg.protocol, MdiProtocol.UDP)
        self.assertEqual(cfg.packet_type, MdiPacketType.DISTANCE_AND_INTENSITY)
        self.assertEqual(cfg.resolution, Resolution.RES_0200_AT_80HZ)
        self.assertEqual(cfg.direction, ScanDirection.COUNTERCLOCKWISE)
        self.assertEqual(cfg.angle_min_deg, -137.6)
        self.assertEqual(cfg.angle_max_deg, 137.6)
        self.assertEqual(cfg.angle_min_cdeg, -13760)
        self.assertEqual(cfg.angle_max_cdeg, 13760)
        self.assertEqual(cfg.skip_spots, 0)
        self.assertEqual(cfg.expected_spots, 1377)
        self.assertEqual(cfg.scan_frequency_hz, 80.0)

        self.driver.start_measurement()
        scans = [self.driver.get_scan(timeout=5.0) for _ in range(3)]
        for scan in scans:
            self.assertEqual(scan.num_spots, 1377)
            self.assertEqual(len(scan.headers), 3)         # 600+600+177 spots
            self.assertEqual(scan.scan_frequency_hz, 80)
            self.assertIsNotNone(scan.intensities)
            # rectangular 6 x 4 m room: distances between 2 m and the corner
            self.assertGreaterEqual(min(scan.distances_mm), 1900)
            self.assertLessEqual(max(scan.distances_mm), 3700)
            # counterclockwise output: starts at the max angle, descending
            self.assertEqual(scan.angles_mdeg[0], 137600)
            self.assertEqual(scan.angles_mdeg[1] - scan.angles_mdeg[0], -200)
            self.assertEqual(scan.angles_mdeg[-1], 137600 - 1376 * 200)
        self.assertTrue(self.driver.is_receiving)
        self.assertGreaterEqual(len(seen), 3)              # on_scan callback fired

        # the command interface keeps working while measuring
        self.assertEqual(self.driver.get_temperature(), 23.5)
        self.assertTrue(self.driver.get_mdi_tx_active())

        self.driver.stop_measurement()
        self.assertFalse(self.driver.is_measuring)
        self.assertFalse(self.sim.streaming)
        self.assertFalse(self.driver.get_mdi_tx_active())

    def test_get_status_snapshot(self):
        self.driver.connect()
        status = self.driver.get_status()
        self.assertEqual(status.errors, {})
        self.assertEqual(status.part_number, 53802110)
        self.assertEqual(status.hw_version, 1)
        self.assertEqual(status.sw_version, 2)
        self.assertEqual(status.temperature_c, 23.5)
        self.assertEqual(status.operating_hours, 17)
        self.assertEqual(status.window_calibration, 1)
        self.assertEqual(status.contamination_warn_pct, 90)
        self.assertEqual(status.contamination_error_pct, 100)
        self.assertEqual(len(status.contamination_state), 9)
        self.assertEqual(len(status.error_log), 10)
        self.assertEqual(status.error_code, 0)
        self.assertEqual(status.mdi_tx_active, False)
        self.assertEqual(status.angle_min_deg, -137.6)

    def test_scans_iterator(self):
        self.driver.connect()
        self.driver.start_measurement()
        got = []
        for scan in self.driver.scans(timeout=5.0):
            got.append(scan)
            if len(got) == 2:
                break
        self.assertEqual(len(got), 2)

    def test_queue_overflow_drops_oldest(self):
        driver = RSL235("127.0.0.1", self.sim.port, udp_port=self.udp_port,
                        scan_queue_size=2)
        self.addCleanup(driver.close)
        driver.connect()
        driver.start_measurement()
        time.sleep(0.5)                                    # ~40 scans at 80 Hz
        self.assertGreater(driver.stats["scans_dropped_queue"], 0)
        driver.get_scan(timeout=1.0)                       # still serves scans


class FaultInjectionTests(unittest.TestCase):
    def _run(self, sim: RSL235Simulator, udp_port: int, n_scans: int = 3):
        sim.start()
        self.addCleanup(sim.stop)
        driver = RSL235("127.0.0.1", sim.port, udp_port=udp_port)
        self.addCleanup(driver.close)
        driver.connect()
        driver.start_measurement()
        scans = [driver.get_scan(timeout=5.0) for _ in range(n_scans)]
        return driver, scans

    def test_lost_packet_never_yields_partial_scan(self):
        udp_port = free_udp_port()
        sim = RSL235Simulator(udp_dest_port=udp_port,
                              drop_subs={1: {2}, 3: {1}})
        driver, scans = self._run(sim, udp_port)
        for scan in scans:
            self.assertEqual(scan.num_spots, 1377)
        self.assertGreaterEqual(driver.stats["scans_dropped_incomplete"], 1)

    def test_join_mid_scan(self):
        udp_port = free_udp_port()
        sim = RSL235Simulator(udp_dest_port=udp_port, start_mid_scan=2)
        driver, scans = self._run(sim, udp_port, n_scans=2)
        for scan in scans:
            self.assertEqual(scan.num_spots, 1377)
        self.assertGreaterEqual(driver.stats["packets_orphaned"], 1)

    def test_garbage_prefix_and_corruption(self):
        udp_port = free_udp_port()
        sim = RSL235Simulator(udp_dest_port=udp_port,
                              prepend_garbage=b"\xba\xad" * 16)
        sim.corrupt_next_packet = True
        driver, scans = self._run(sim, udp_port)
        for scan in scans:
            self.assertEqual(scan.num_spots, 1377)
        self.assertGreaterEqual(driver.stats["resyncs"], 1)


class TcpEndToEndTests(unittest.TestCase):
    def test_tcp_stream_with_interleaved_commands(self):
        # TCP transport, MDI flushed in tiny chunks, stream already running
        # at connect time: the hardest case for the stream splitter.
        sim = RSL235Simulator(
            settings=small_settings(protocol=MdiProtocol.TCP),
            stream_on_connect=True,
            split_writes=7,
        )
        sim.start()
        self.addCleanup(sim.stop)
        driver = RSL235("127.0.0.1", sim.port)
        self.addCleanup(driver.close)

        driver.connect()                       # StopMDI must stop the stream
        self.assertFalse(sim.streaming)
        self.assertEqual(driver.config.protocol, MdiProtocol.TCP)
        self.assertEqual(driver.config.expected_spots, 301)

        driver.start_measurement()
        scan = driver.get_scan(timeout=10.0)
        self.assertEqual(scan.num_spots, 301)
        self.assertEqual(len(scan.headers), 3)             # 120+120+61 spots

        # command interface interleaves with the TCP measurement stream
        status = driver.get_status()
        self.assertEqual(status.errors, {})
        self.assertEqual(status.temperature_c, 23.5)
        self.assertTrue(status.mdi_tx_active)

        scan = driver.get_scan(timeout=10.0)
        self.assertEqual(scan.num_spots, 301)

        driver.stop_measurement()
        self.assertFalse(sim.streaming)

    def test_distance_only_mode(self):
        sim = RSL235Simulator(settings=small_settings(
            protocol=MdiProtocol.TCP,
            packet_type=MdiPacketType.DISTANCE,
            direction=ScanDirection.CLOCKWISE,
        ))
        sim.start()
        self.addCleanup(sim.stop)
        driver = RSL235("127.0.0.1", sim.port)
        self.addCleanup(driver.close)
        driver.connect()
        driver.start_measurement()
        scan = driver.get_scan(timeout=10.0)
        self.assertIsNone(scan.intensities)
        self.assertEqual(scan.num_spots, 301)
        # clockwise output: starts at the min angle, ascending
        self.assertEqual(scan.angles_mdeg[0], -30000)
        self.assertEqual(scan.angles_mdeg[1] - scan.angles_mdeg[0], 200)


class FailureModeTests(unittest.TestCase):
    def test_connect_refused(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()                                       # nothing listens here now
        driver = RSL235("127.0.0.1", port, connect_timeout=1.0)
        with self.assertRaises(ScannerConnectionError):
            driver.connect()

    def test_command_timeout_on_mute_scanner(self):
        sim = RSL235Simulator(mute=True)
        sim.start()
        self.addCleanup(sim.stop)
        driver = RSL235("127.0.0.1", sim.port, command_timeout=0.3)
        self.addCleanup(driver.close)
        # The StopMDI handshake times out; connect() reports that as a
        # connection failure and chains the timeout as the cause.
        with self.assertRaises(ScannerConnectionError) as cm:
            driver.connect()
        self.assertIsInstance(cm.exception.__cause__, CommandTimeoutError)
        self.assertFalse(driver.is_connected)

    def test_context_manager(self):
        udp_port = free_udp_port()
        sim = RSL235Simulator(udp_dest_port=udp_port)
        sim.start()
        self.addCleanup(sim.stop)
        with RSL235("127.0.0.1", sim.port, udp_port=udp_port) as scanner:
            scanner.start_measurement()
            scan = scanner.get_scan(timeout=5.0)
            self.assertGreater(scan.num_spots, 0)
        self.assertFalse(scanner.is_connected)
        self.assertFalse(scanner.is_measuring)


# ---------------------------------------------------------------------------
# Regression tests for the audit findings (lifecycle, wake-ups, demux, ...)
# ---------------------------------------------------------------------------


class _FakeRodServer:
    """Minimal scriptable ROD command server (one client at a time).

    ``script(name)`` may return raw bytes to send instead of the default
    reply, ``b""`` to stay silent, or ``None`` for the default reply.  It
    runs on the server thread, so it may sleep to delay a reply.
    """

    VALUES = {
        "GetProto": [0], "GetPType": [0], "GetResol": [0], "GetDir": [0],
        "GetRange": [-3000, 3000], "GetSkip": [0], "GetTem": [2350], "GetHours": [1],
    }

    def __init__(self, script=None):
        self.script = script
        self.received = []
        self._listen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listen.bind(("127.0.0.1", 0))
        self._listen.listen(1)
        self._listen.settimeout(0.1)
        self.port = self._listen.getsockname()[1]
        self._closing = False
        self._conns = []
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    def _accept(self):
        while not self._closing:
            try:
                conn, _ = self._listen.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self._conns.append(conn)
            self._serve(conn)

    def _serve(self, conn):
        conn.settimeout(0.1)
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
                etx = buf.find(ETX, stx) if stx >= 0 else -1
                if stx < 0 or etx < 0:
                    break
                tokens = bytes(buf[stx + 1:etx]).decode("ascii").split()
                del buf[:etx + 1]
                if len(tokens) != 2:
                    continue
                verb, name = tokens
                self.received.append(name)
                reply = self.script(name) if self.script is not None else None
                if reply is None:
                    if verb == "cWN":
                        reply = STX + b"cWA " + name.encode() + ETX
                    else:
                        values = " ".join(str(v) for v in self.VALUES.get(name, [0]))
                        reply = STX + ("cRA %s %s" % (name, values)).encode() + ETX
                if reply:
                    try:
                        conn.sendall(reply)
                    except OSError:
                        return

    def stop(self):
        self._closing = True
        self._listen.close()
        self._thread.join(timeout=2.0)
        for conn in self._conns:
            conn.close()


class ReconnectTests(unittest.TestCase):
    """C07 / C22 / L20: link loss resets the session; the object is reusable."""

    def _lose_link_and_reconnect(self, proto: MdiProtocol):
        udp_port = free_udp_port()
        settings = small_settings(protocol=proto)
        sim = RSL235Simulator(udp_dest_port=udp_port, settings=settings).start()
        self.addCleanup(sim.stop)
        driver = RodScanner("127.0.0.1", sim.port, udp_port=udp_port)
        self.addCleanup(driver.close)
        driver.connect()
        driver.start_measurement()
        self.assertEqual(driver.get_scan(timeout=5.0).num_spots, 301)
        port = sim.port

        sim.stop()                                  # scanner reboots / cable pulled
        self.assertTrue(wait_until(lambda: not driver.is_connected))
        self.assertFalse(driver.is_measuring)
        self.assertFalse(driver.is_receiving)
        with self.assertRaises(NotConnectedError):
            driver.get_scan(timeout=1.0)            # woken, not timed out
        with self.assertRaises(NotConnectedError):
            driver.get_temperature()

        # close() on a lost link is quiet: no warnings, no tracebacks
        records = []
        handler = logging.Handler()
        handler.emit = records.append
        logger = logging.getLogger("leuze_rsl")
        logger.addHandler(handler)
        self.addCleanup(logger.removeHandler, handler)
        driver.close()
        driver.close()                              # idempotent
        noisy = [r for r in records
                 if (r.levelno >= logging.WARNING or r.exc_info)
                 and not r.getMessage().startswith("TCP connection to scanner lost")]
        self.assertEqual(noisy, [])

        sim2 = RSL235Simulator(port=port, udp_dest_port=udp_port, settings=settings).start()
        self.addCleanup(sim2.stop)
        driver.connect()
        self.assertTrue(driver.is_connected)
        driver.start_measurement()
        self.assertIn("SendMDI", sim2.commands_received)
        scan = driver.get_scan(timeout=5.0)
        self.assertEqual(scan.num_spots, 301)
        self.assertTrue(driver.is_measuring)
        self.assertEqual(driver.get_temperature(), 23.5)

        # the dead session's sockets were closed, not leaked
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            gc.collect()
        self.assertEqual([w for w in caught if issubclass(w.category, ResourceWarning)], [])

    def test_reconnect_after_link_loss_udp(self):
        self._lose_link_and_reconnect(MdiProtocol.UDP)

    def test_reconnect_after_link_loss_tcp(self):
        self._lose_link_and_reconnect(MdiProtocol.TCP)


class ScanQueueTests(unittest.TestCase):
    """C08 / C13: stale scans and waiters."""

    def setUp(self):
        self.udp_port = free_udp_port()
        self.sim = RSL235Simulator(udp_dest_port=self.udp_port,
                                   settings=small_settings()).start()
        self.addCleanup(self.sim.stop)
        self.driver = RodScanner("127.0.0.1", self.sim.port, udp_port=self.udp_port,
                                 scan_queue_size=8)
        self.addCleanup(self.driver.close)

    def test_stale_scans_not_delivered_after_restart(self):
        delivered = []
        self.driver.on_scan = delivered.append
        self.driver.connect()
        self.driver.start_measurement()
        self.driver.get_scan(timeout=5.0)
        time.sleep(0.3)                             # the queue fills up
        self.driver.stop_measurement()
        self.assertGreater(self.driver.scans_available, 0)
        before_restart = list(delivered)
        time.sleep(0.2)
        self.driver.start_measurement()
        first = self.driver.get_scan(timeout=5.0)
        self.assertFalse(any(first is old for old in before_restart),
                         "a scan buffered before stop_measurement() was served as fresh")

        # ... and nothing survives close() + connect() either
        self.driver.stop_measurement()
        self.driver.close()
        self.driver.connect()
        with self.assertRaises(ReceiverStoppedError):
            self.driver.get_scan(timeout=0.2)

    def test_get_scan_wakes_on_link_loss(self):
        self.driver.connect()
        self.driver.start_measurement()
        self.driver.get_scan(timeout=5.0)
        result = {}

        def consumer():
            try:
                while True:
                    self.driver.get_scan()          # timeout=None
            except Exception as exc:                # noqa: BLE001
                result["exc"] = exc

        thread = threading.Thread(target=consumer, daemon=True)
        thread.start()
        time.sleep(0.1)
        self.sim.stop()
        t0 = time.monotonic()
        thread.join(1.0)
        self.assertFalse(thread.is_alive(), "get_scan(timeout=None) not woken by link loss")
        self.assertLess(time.monotonic() - t0, 1.0)
        self.assertIsInstance(result["exc"], NotConnectedError)
        # every later call fails the same way, promptly
        with self.assertRaises(NotConnectedError):
            self.driver.get_scan()

    def test_get_scan_after_stop_measurement(self):
        self.driver.connect()
        self.driver.start_measurement()
        self.driver.get_scan(timeout=5.0)
        self.driver.stop_measurement()
        # buffered scans are still served, then ReceiverStoppedError
        served = 0
        while True:
            try:
                self.driver.get_scan(timeout=1.0)
                served += 1
            except ReceiverStoppedError:
                break
        self.assertLessEqual(served, 8)
        t0 = time.monotonic()
        with self.assertRaises(ReceiverStoppedError):
            self.driver.get_scan()                  # timeout=None, must not block
        self.assertLess(time.monotonic() - t0, 0.5)

    def test_get_scan_never_started(self):
        with self.assertRaises(NotConnectedError):
            self.driver.get_scan()
        self.driver.connect()
        with self.assertRaises(ReceiverStoppedError):
            self.driver.get_scan()
        self.assertEqual(list(self.driver.scans()), [])

    def test_scan_timeout_error_is_a_timeout_error(self):
        # every scan loses its first packet -> none ever completes
        udp_port = free_udp_port()
        sim = RSL235Simulator(udp_dest_port=udp_port, settings=small_settings(),
                              drop_subs={i: {1} for i in range(10000)}).start()
        self.addCleanup(sim.stop)
        driver = RodScanner("127.0.0.1", sim.port, udp_port=udp_port)
        self.addCleanup(driver.close)
        driver.connect()
        driver.start_measurement()
        with self.assertRaises(TimeoutError) as cm:          # backwards compatible
            driver.get_scan(timeout=0.3)
        self.assertIsInstance(cm.exception, ScanTimeoutError)
        self.assertIn("no scan received within 0.3 s", str(cm.exception))
        self.assertTrue(driver.is_receiving)                  # packets did arrive

    def test_scans_iterator_terminates_after_stop(self):
        self.driver.connect()
        self.driver.start_measurement()
        done = threading.Event()
        count = []

        def consumer():
            for _ in self.driver.scans():
                count.append(1)
            done.set()

        thread = threading.Thread(target=consumer, daemon=True)
        thread.start()
        self.assertTrue(wait_until(lambda: len(count) >= 2))
        self.driver.stop_measurement()
        self.assertTrue(done.wait(2.0), "scans() did not end after stop_measurement()")

    def test_scans_iterator_propagates_link_loss(self):
        self.driver.connect()
        self.driver.start_measurement()
        self.driver.get_scan(timeout=5.0)
        self.sim.stop()
        with self.assertRaises(NotConnectedError):
            for _ in self.driver.scans(timeout=2.0):
                pass


class TcpCallbackTests(unittest.TestCase):
    """C09: commands from on_scan work in TCP transport mode."""

    def test_command_from_on_scan(self):
        sim = RSL235Simulator(settings=small_settings(protocol=MdiProtocol.TCP)).start()
        self.addCleanup(sim.stop)
        results = []

        def on_scan(scan):
            if len(results) < 3:
                try:
                    results.append(driver.get_temperature())
                except Exception as exc:            # noqa: BLE001
                    results.append(exc)

        driver = RodScanner("127.0.0.1", sim.port, on_scan=on_scan)
        self.addCleanup(driver.close)
        driver.connect()
        driver.start_measurement()                  # must not time out on SendMDI
        self.assertTrue(driver.is_measuring)
        self.assertTrue(wait_until(lambda: len(results) >= 3, timeout=3.0))
        self.assertEqual(results[:3], [23.5, 23.5, 23.5])
        self.assertGreaterEqual(driver.stats["scans_completed"], 3)
        # scans keep flowing at full rate while the callback issues commands
        n0 = driver.stats["scans_completed"]
        time.sleep(0.5)
        self.assertGreater(driver.stats["scans_completed"] - n0, 10)   # ~40 expected
        driver.stop_measurement()
        self.assertFalse(sim.streaming)

    def test_close_from_on_scan(self):
        sim = RSL235Simulator(settings=small_settings(protocol=MdiProtocol.TCP)).start()
        self.addCleanup(sim.stop)
        closed = threading.Event()

        def on_scan(scan):
            if not closed.is_set():
                driver.close()
                closed.set()

        driver = RodScanner("127.0.0.1", sim.port, on_scan=on_scan)
        self.addCleanup(driver.close)
        driver.connect()
        driver.start_measurement()
        self.assertTrue(closed.wait(3.0))
        self.assertTrue(wait_until(lambda: not driver.is_connected))
        self.assertFalse(driver.is_measuring)
        self.assertTrue(wait_until(lambda: not sim.streaming))


class DemuxTests(unittest.TestCase):
    """C23 / C24 / L29: the TCP stream splitter on a never-connected driver."""

    def _driver(self, pending=None):
        driver = RodScanner("127.0.0.1")
        driver._capturing_tcp = True
        driver._packets = []
        driver._on_mdi_packet = driver._packets.append
        if pending is not None:
            driver._pending = (pending[0], pending[1], 1)
        return driver

    def _feed(self, driver, data, chunk=None):
        if chunk is None:
            driver._tcp_buf += data
            driver._process_tcp_buffer()
        else:
            for i in range(0, len(data), chunk):
                driver._tcp_buf += data[i:i + chunk]
                driver._process_tcp_buffer()

    def _packet(self, sub=1, total=1, spots=4, first_distance=1000):
        return build_packet(packet_type=int(MdiPacketType.DISTANCE), packet_number=sub,
                            total_number=total, sub_number=sub, scan_freq=80,
                            first_angle_mdeg=0, delta_angle_mdeg=200, timestamp_ms=0,
                            distances_mm=[first_distance + i for i in range(spots)])

    def test_lost_etx_does_not_swallow_next_reply(self):
        for chunk in (None, 1, 7):
            driver = self._driver(("cRA", "GetHours"))
            self._feed(driver, b"\x02cRA GetTem 2350" + b"\x02cRA GetHours 1\x03", chunk)
            self.assertIsNotNone(driver._response, "chunk=%r" % chunk)
            self.assertEqual(driver._response.name, "GetHours")
            self.assertEqual(driver.truncated_responses, 1)
            self.assertEqual(driver.unsolicited_responses, 0)
            self.assertEqual(bytes(driver._tcp_buf), b"")

    def test_embedded_stx_keeps_the_valid_frame(self):
        driver = self._driver(("cRA", "GetTem"))
        self._feed(driver, b"\x02cRA GetTem\x02cRA GetTem 2350\x03")
        self.assertEqual(driver._response.values, (2350,))
        self.assertEqual(driver.truncated_responses, 1)

    def test_response_after_sync(self):
        driver = self._driver(("cRA", "GetTem"))
        packet = self._packet()
        self._feed(driver, packet + b"\x02cRA GetTem 2350\x03" + packet, chunk=5)
        self.assertEqual(driver._packets, [packet, packet])
        self.assertEqual(driver._response.values, (2350,))
        self.assertEqual(bytes(driver._tcp_buf), b"")

    def test_response_cut_short_by_mdi_packet(self):
        driver = self._driver(("cRA", "GetTem"))
        packet = self._packet(first_distance=3)       # payload contains an ETX byte
        self._feed(driver, b"\x02cRA GetTem 23" + packet + b"\x02cRA GetTem 2350\x03")
        self.assertEqual(driver._packets, [packet])
        self.assertEqual(driver._response.values, (2350,))
        self.assertEqual(driver.truncated_responses, 1)

    def test_malformed_reply_to_pending_command_fails_it(self):
        driver = self._driver(("cRA", "GetTem"))
        self._feed(driver, b"\x02cRA GetTem ERR\x03")
        self.assertIsNone(driver._response)
        self.assertIsInstance(driver._failure, CommandError)
        self.assertTrue(driver._resp_event.is_set())
        # a garbled frame for some *other* command is merely unsolicited
        driver = self._driver(("cRA", "GetTem"))
        self._feed(driver, b"\x02cRA GetHours ERR\x03")
        self.assertIsNone(driver._failure)
        self.assertEqual(driver.unsolicited_responses, 1)

    def test_stx_flood_without_etx_is_linear(self):
        driver = self._driver()
        t0 = time.monotonic()
        self._feed(driver, b"\x02cRA " * 100000)
        self.assertLess(time.monotonic() - t0, 2.0)
        self.assertLessEqual(len(driver._tcp_buf), 5)
        driver = self._driver()
        t0 = time.monotonic()
        self._feed(driver, b"\x02cRA " + b"\x02" * 300000)
        self.assertLess(time.monotonic() - t0, 2.0)
        self.assertLessEqual(len(driver._tcp_buf), 4)

    def test_backlog_of_packets_with_stx_heavy_payload(self):
        driver = self._driver(("cRA", "GetTem"))
        # distances 512..767 have 0x02 as their high byte
        packets = [self._packet(sub=s, total=3, spots=600, first_distance=512)
                   for s in (1, 2, 3)]
        stream = (b"".join(packets) + b"\x02cRA GetTem 2350\x03") * 10
        t0 = time.monotonic()
        self._feed(driver, stream)
        self.assertLess(time.monotonic() - t0, 1.0)
        self.assertEqual(len(driver._packets), 30)
        self.assertEqual(driver._response.values, (2350,))


class CommandInterfaceTests(unittest.TestCase):
    """L29 / C25 end to end against a scriptable fake scanner."""

    def test_malformed_reply_raises_command_error_quickly(self):
        server = _FakeRodServer(
            lambda name: STX + b"cRA GetTem 23.5" + ETX if name == "GetTem" else None)
        self.addCleanup(server.stop)
        driver = RodScanner("127.0.0.1", server.port, command_timeout=2.0)
        self.addCleanup(driver.close)
        driver.connect()
        t0 = time.monotonic()
        with self.assertRaises(CommandError):
            driver.get_temperature()
        self.assertLess(time.monotonic() - t0, 1.0)
        self.assertEqual(driver.get_operating_hours(), 1)    # interface still usable

    def test_late_reply_is_not_taken_for_the_next_command(self):
        def script(name):
            if name == "GetTem" and not seen_tem:
                seen_tem.append(True)
                time.sleep(0.45)                    # answer after the 0.3 s timeout
            return None
        seen_tem = []
        server = _FakeRodServer(script)
        self.addCleanup(server.stop)
        driver = RodScanner("127.0.0.1", server.port, command_timeout=0.3)
        self.addCleanup(driver.close)
        driver.connect()
        with self.assertRaises(CommandTimeoutError):
            driver.get_temperature()
        # the late 'cRA GetTem 2350' arrives while GetHours is pending
        self.assertEqual(driver.get_operating_hours(), 1)
        self.assertTrue(wait_until(lambda: driver.stats["late_responses"] == 1))
        self.assertEqual(driver.stats["unsolicited_responses"], 0)
        self.assertEqual(driver.get_temperature(), 23.5)

    def test_usage_errors(self):
        server = _FakeRodServer()
        self.addCleanup(server.stop)
        driver = RodScanner("127.0.0.1", server.port)
        self.addCleanup(driver.close)
        with self.assertRaises(NotConnectedError):
            driver.get_temperature()
        driver.connect(read_config=False)
        self.assertIsNone(driver.config)
        with self.assertRaises(ValueError):
            driver.start_measurement()              # transport unknown
        with self.assertRaises(ValueError):
            driver.start_measurement(protocol_override=7)
        with self.assertRaises(ScannerConnectionError):
            driver.connect()                        # already connected
        self.assertFalse(driver.is_measuring)

    def test_constructor_validation(self):
        for kwargs in (dict(port=0), dict(port=70000), dict(udp_port=0),
                       dict(scan_queue_size=0), dict(scan_queue_size=-1),
                       dict(command_timeout=0), dict(connect_timeout=-1.0),
                       dict(mdi_timeout=0)):
            with self.assertRaises(ValueError, msg=repr(kwargs)):
                RodScanner("127.0.0.1", **kwargs)
        self.assertIs(RSL235, RodScanner)           # backwards-compatible alias


class UdpSocketTests(unittest.TestCase):
    """C12: a second receiver on the data port must fail, not steal the stream."""

    def test_second_binder_fails(self):
        udp_port = free_udp_port()
        sim1 = RSL235Simulator(udp_dest_port=udp_port, settings=small_settings()).start()
        self.addCleanup(sim1.stop)
        sim2 = RSL235Simulator(udp_dest_port=udp_port, settings=small_settings()).start()
        self.addCleanup(sim2.stop)
        first = RodScanner("127.0.0.1", sim1.port, udp_port=udp_port)
        self.addCleanup(first.close)
        first.connect()
        first.start_measurement()
        first.get_scan(timeout=5.0)
        second = RodScanner("127.0.0.1", sim2.port, udp_port=udp_port)
        self.addCleanup(second.close)
        second.connect()
        with self.assertRaises(ScannerConnectionError):
            second.start_measurement()
        self.assertFalse(second.is_measuring)
        self.assertTrue(second.is_connected)
        first.get_scan(timeout=5.0)                  # the first receiver still gets data
        self.assertTrue(first.is_receiving)


class ConfigAndAssemblerTests(unittest.TestCase):
    def test_expected_spots_from_centidegrees(self):
        cfg = ScannerConfig(MdiProtocol.UDP, MdiPacketType.DISTANCE,
                            Resolution.RES_0200_AT_80HZ, ScanDirection.CLOCKWISE,
                            -137.6, 137.6, 0)
        self.assertEqual((cfg.angle_min_cdeg, cfg.angle_max_cdeg), (-13760, 13760))
        self.assertEqual(cfg.expected_spots, 1377)
        self.assertEqual(cfg.expected_spots, protocol.expected_spots(-13760, 13760, 0.2, 0))
        cfg = ScannerConfig(MdiProtocol.UDP, MdiPacketType.DISTANCE,
                            Resolution.RES_0025_AT_10HZ, ScanDirection.CLOCKWISE,
                            -30.0, 30.0, 1)
        self.assertEqual(cfg.expected_spots, protocol.expected_spots(-3000, 3000, 0.025, 1))

    def _packet(self, number, sub, total=3):
        return build_packet(packet_type=int(MdiPacketType.DISTANCE), packet_number=number,
                            total_number=total, sub_number=sub, scan_freq=80,
                            first_angle_mdeg=sub * 1000, delta_angle_mdeg=200,
                            timestamp_ms=0, distances_mm=[1, 2, 3, 4, 5])

    def test_packet_number_wraparound_is_continuous(self):
        assembler = ScanAssembler()
        scans = []
        for number, sub in ((65534, 1), (65535, 2), (0, 3)):
            scans += assembler.feed_datagram(self._packet(number, sub))
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0].num_spots, 15)
        self.assertEqual(assembler.stats.packets_out_of_sequence, 0)

    def test_packet_number_gap_drops_scan(self):
        assembler = ScanAssembler()
        scans = []
        for number, sub in ((10, 1), (11, 2), (13, 3)):    # packet 12 was lost
            scans += assembler.feed_datagram(self._packet(number, sub))
        self.assertEqual(scans, [])
        self.assertEqual(assembler.stats.packets_out_of_sequence, 1)
        self.assertEqual(assembler.stats.scans_dropped_incomplete, 1)
        # the next full scan is assembled normally
        for number, sub in ((14, 1), (15, 2), (16, 3)):
            scans += assembler.feed_datagram(self._packet(number, sub))
        self.assertEqual(len(scans), 1)


if __name__ == "__main__":
    unittest.main()


class ReceiverErrorCounterTests(unittest.TestCase):
    def test_assembler_error_is_counted_and_stream_continues(self):
        udp_port = free_udp_port()
        sim = RSL235Simulator(udp_dest_port=udp_port).start()
        self.addCleanup(sim.stop)
        driver = RodScanner("127.0.0.1", sim.port, udp_port=udp_port)
        self.addCleanup(driver.close)
        driver.connect()
        original = driver._assembler.feed_datagram
        calls = []

        def flaky(data):
            if not calls:
                calls.append(1)
                raise RuntimeError("parser bug")
            return original(data)
        driver._assembler.feed_datagram = flaky
        with self.assertLogs("leuze_rsl", level="ERROR"):
            driver.start_measurement()
            scan = driver.get_scan(timeout=5.0)
        self.assertEqual(scan.num_spots, 1377)
        self.assertEqual(driver.stats["receiver_errors"], 1)
        self.assertTrue(driver.is_measuring)

    def test_tcp_keepalive_option(self):
        sim = RSL235Simulator(settings=small_settings()).start()
        self.addCleanup(sim.stop)
        for keepalive in (True, False):
            with self.subTest(keepalive=keepalive):
                driver = RodScanner("127.0.0.1", sim.port, tcp_keepalive=keepalive)
                driver.connect()
                try:
                    value = driver._tcp_sock.getsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE)
                    self.assertEqual(bool(value), keepalive)
                finally:
                    driver.close()


class ReceiverFailureTests(unittest.TestCase):
    def test_udp_receiver_death_keeps_stop_measurement_effective(self):
        """A dead UDP receiver must not let the scanner keep streaming (regression)."""
        udp_port = free_udp_port()
        sim = RSL235Simulator(udp_dest_port=udp_port)
        sim.start()
        self.addCleanup(sim.stop)
        driver = RodScanner("127.0.0.1", sim.port, udp_port=udp_port)
        self.addCleanup(driver.close)
        driver.connect()
        driver.start_measurement()
        driver.get_scan(timeout=5.0)
        with self.assertLogs("leuze_rsl", level="ERROR"):
            driver._udp_sock.close()                     # simulate an unexpected socket error
            t0 = time.monotonic()
            with self.assertRaises(ScannerConnectionError):
                driver.get_scan()                        # no timeout: woken by the failure
        self.assertLess(time.monotonic() - t0, 2.0)
        self.assertTrue(driver.is_measuring)             # the scanner is still streaming ...
        self.assertFalse(driver.is_receiving)
        with self.assertRaises(ScannerConnectionError):
            driver.get_scan(timeout=0.2)                 # ... and the failure stays visible
        self.assertTrue(driver.is_connected)
        self.assertEqual(driver.get_temperature(), 23.5)  # command interface still works
        driver.stop_measurement()                        # must still send StopMDI
        self.assertTrue(wait_until(lambda: not sim.streaming))
        self.assertIn("StopMDI", list(sim.commands_received)[-1:])
        with self.assertRaises(ReceiverStoppedError):
            driver.get_scan(timeout=0.2)
        driver.start_measurement()                       # and measuring again works
        self.assertEqual(driver.get_scan(timeout=5.0).num_spots, 1377)
