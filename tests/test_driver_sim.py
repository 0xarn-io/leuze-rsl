"""End-to-end tests: RSL235 driver against the protocol simulator (no hardware)."""

import socket
import time
import unittest

from leuze_rsl import (
    RSL235,
    CommandTimeoutError,
    MdiPacketType,
    MdiProtocol,
    Resolution,
    ScanDirection,
    ScannerConnectionError,
)
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
            # counterclockwise: ascending angles starting at the min angle
            self.assertEqual(scan.angles_mdeg[0], -137600)
            self.assertEqual(scan.angles_mdeg[1] - scan.angles_mdeg[0], 200)
            self.assertEqual(scan.angles_mdeg[-1], -137600 + 1376 * 200)
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
        # clockwise: descending angles starting at the max angle
        self.assertEqual(scan.angles_mdeg[0], 30000)
        self.assertEqual(scan.angles_mdeg[1] - scan.angles_mdeg[0], -200)


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
        with self.assertRaises(CommandTimeoutError):
            driver.connect()                               # StopMDI handshake times out
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


if __name__ == "__main__":
    unittest.main()
