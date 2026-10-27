"""Tests for the simulators themselves: wire fidelity, knobs, thread robustness, CLI."""

import contextlib
import logging
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import unittest

import leuze_rsl
from leuze_rsl import simulator as simulator_module
from leuze_rsl.protocol import (
    ETX,
    STX,
    MdiProtocol,
    Resolution,
    ScanDirection,
    expected_spots,
    parse_packet,
)
from leuze_rsl.simulator import (
    RodSimulator,
    RSL235Simulator,
    SimulatorSettings,
    UdtSimulator,
)
from leuze_rsl.udt import (
    FRAME_SIZE,
    GEOMETRY,
    MeasurementContour,
    ScannerFamily,
    StatusProfile,
    UdtAssembler,
    UdtFrame,
)

SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(leuze_rsl.__file__)))

#: RSL 400 extended status datagram captured from hardware by Leuze's ROS
#: driver (leuze_ros_drivers test/test_parse_data.cpp, test_id_1).
ROS_CAPTURE_RSL400 = bytes([
    0x30, 0x00, 0x00, 0x00, 0x08, 0x00, 0xaf, 0xfe,              # H1
    0x04, 0x15, 0x02, 0xc8,                                      # H2
    0x01, 0x00,                                                  # ID
    0x00, 0x00,                                                  # block
    0x6e, 0x29, 0x05, 0x00,                                      # scan
    0x01, 0x01, 0x02, 0x80, 0x00, 0x00, 0x10, 0x80, 0x6e, 0x29,  # status profile
    0x05, 0x00, 0xe8, 0x11, 0x00, 0xf0, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x8b, 0x0a, 0x01, 0x00, 0x00, 0x00,              # measurement contour
])


def free_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def threads_named(name: str):
    return [t for t in threading.enumerate() if t.name == name]


class _RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@contextlib.contextmanager
def capture_logs(name: str = "leuze_rsl.simulator"):
    """Record every log record of ``name`` (assertNoLogs needs Python 3.10)."""
    logger = logging.getLogger(name)
    handler = _RecordingHandler()
    old_level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        yield handler.records
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)


def wait_until(predicate, timeout: float = 3.0, step: float = 0.01) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(step)
    return bool(predicate())


class RawRodClient:
    """Minimal ROD command-interface client (independent of the driver)."""

    def __init__(self, port: int, timeout: float = 3.0) -> None:
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.buf = bytearray()

    def send(self, verb: str, name: str) -> None:
        self.sock.sendall(STX + ("%s %s" % (verb, name)).encode("ascii") + ETX)

    def command(self, verb: str, name: str) -> str:
        """Send and return the body of the next reply (ignores MDI bytes)."""
        self.send(verb, name)
        while True:
            start = self.buf.find(STX + b"c")
            if start >= 0:
                end = self.buf.find(ETX, start)
                if end >= 0:
                    body = bytes(self.buf[start + 1:end]).decode("ascii", "replace")
                    del self.buf[:end + 1]
                    return body
            data = self.sock.recv(65536)
            if not data:
                raise ConnectionError("simulator closed the connection")
            self.buf += data

    def close(self) -> None:
        self.sock.close()


# ---------------------------------------------------------------------------
# UdtSimulator wire fidelity
# ---------------------------------------------------------------------------


class UdtStatusDatagramTests(unittest.TestCase):
    def test_default_is_spec_rsl200_extended_status_profile(self):
        sim = UdtSimulator()
        datagram = sim.status_datagram(777)
        self.assertEqual(len(datagram), 56)                 # 20 frame + 28 profile + 8 contour

        frame = UdtFrame.from_bytes(datagram)
        self.assertEqual((frame.total_length, frame.telegram_id, frame.block, frame.scan_number),
                         (56, 1, 0, 777))
        # H1 tail / H2 exactly as captured from RSL 235 hardware
        self.assertEqual(datagram[:16].hex(),
                         "38000000080006" "00" "040b0132" "0100" "0000")

        status = StatusProfile.from_bytes(datagram[FRAME_SIZE:])
        self.assertIs(status.family, ScannerFamily.RSL200)
        self.assertEqual(status.profile_type, 21)
        self.assertEqual(status.operating_mode, 1)
        self.assertEqual(status.scan_number, 777)
        self.assertTrue(status.ossd_a)
        self.assertIsNone(status.ossd_b)
        self.assertFalse(status.error)
        self.assertFalse(status.a_protective_violated)
        self.assertFalse(status.a_warning_violated)
        self.assertFalse(status.warning_field_2_violated)
        self.assertFalse(status.parked)
        self.assertEqual(status.field_triple, 1)
        self.assertEqual(status.temperature_c, 23.5)
        self.assertEqual(status.signature, 0)
        self.assertEqual((status.error_class, status.error_number), (0, 0))
        self.assertEqual(status.contour_offset, 28)

        contour = MeasurementContour.from_bytes(datagram[FRAME_SIZE:], 28)
        self.assertEqual((contour.start_index, contour.stop_index, contour.index_interval),
                         (0, 1350, 5))
        self.assertEqual(contour.num_beams, 271)
        self.assertEqual(sim.num_beams, 271)
        self.assertEqual(len(sim.beam_values()), 271)
        # the spec's reserved bytes 12..15 and 20..27 are zero
        profile = datagram[FRAME_SIZE:FRAME_SIZE + 28]
        self.assertEqual(profile[12:16], b"\0\0\0\0")
        self.assertEqual(profile[20:28], b"\0" * 8)

    def test_status_knobs_drive_the_flags(self):
        sim = UdtSimulator(ossd=False, protective_field_free=False,
                           warning_field_free=False, error=True)
        status = StatusProfile.from_bytes(sim.status_block(1))
        self.assertFalse(status.ossd_a)
        self.assertTrue(status.error)
        self.assertTrue(status.a_protective_violated)
        self.assertTrue(status.a_warning_violated)
        self.assertTrue(status.warning_field_2_violated)
        # knobs are plain attributes, re-read for every datagram
        sim.ossd = True
        sim.protective_field_free = True
        status = StatusProfile.from_bytes(sim.status_block(2))
        self.assertTrue(status.ossd_a)
        self.assertFalse(status.a_protective_violated)
        self.assertTrue(status.a_warning_violated)

    def test_rsl400_variant_matches_ros_driver_capture(self):
        capture_frame = UdtFrame.from_bytes(ROS_CAPTURE_RSL400)
        sim = UdtSimulator(family=ScannerFamily.RSL400)
        datagram = sim.status_datagram(capture_frame.scan_number)
        self.assertEqual(len(datagram), 48)                 # 20 frame + 20 profile + 8 contour
        self.assertEqual(len(ROS_CAPTURE_RSL400), 48)

        frame = UdtFrame.from_bytes(datagram)
        self.assertEqual(frame, capture_frame)              # H1, H2, ID, block, scan identical
        # profile type / mode, scan number and the measurement contour are byte-identical
        self.assertEqual(datagram[20:22], ROS_CAPTURE_RSL400[20:22])
        self.assertEqual(datagram[28:32], ROS_CAPTURE_RSL400[28:32])
        self.assertEqual(datagram[40:48], ROS_CAPTURE_RSL400[40:48])
        self.assertEqual(datagram[40:48], struct.pack("<HHHH", 0, 2699, 1, 0))

        ours = StatusProfile.from_bytes(datagram[FRAME_SIZE:])
        theirs = StatusProfile.from_bytes(ROS_CAPTURE_RSL400[FRAME_SIZE:])
        self.assertIs(ours.family, ScannerFamily.RSL400)
        for field in ("family", "operating_mode", "scan_number", "error", "alarm",
                      "ossd_a", "ossd_b", "parked", "a_active", "a_protective_violated",
                      "a_warning_violated", "a_bank", "a_field_pair", "b_active",
                      "contour_offset", "configuration_signature"):
            self.assertEqual(getattr(ours, field), getattr(theirs, field), field)
        self.assertTrue(ours.ossd_a)
        self.assertTrue(ours.a_active)
        self.assertFalse(ours.a_protective_violated)
        self.assertEqual(ours.contour_offset, 20)
        contour = MeasurementContour.from_bytes(datagram[FRAME_SIZE:], 20)
        self.assertEqual((contour.start_index, contour.stop_index, contour.index_interval),
                         (0, 2699, 1))
        self.assertEqual(contour.num_beams, 2700)

    def test_rsl400_signature_trailer(self):
        sim = UdtSimulator(family=ScannerFamily.RSL400, signature=bytes(range(8)))
        datagram = sim.status_datagram(5)
        self.assertEqual(len(datagram), 60)                 # + 12-byte signature
        self.assertEqual(datagram[48:52], b"\x01\x00\x08\x00")
        status = StatusProfile.from_bytes(datagram[FRAME_SIZE:])
        self.assertEqual(status.configuration_signature, bytes(range(8)))
        self.assertEqual(UdtFrame.from_bytes(datagram).total_length, 60)

    def test_rsl400_status_knobs(self):
        sim = UdtSimulator(family=ScannerFamily.RSL400, ossd=False,
                           protective_field_free=False, warning_field_free=False, error=True)
        status = StatusProfile.from_bytes(sim.status_block(0))
        self.assertFalse(status.ossd_a)
        self.assertTrue(status.error)
        self.assertTrue(status.a_protective_violated)
        self.assertTrue(status.a_warning_violated)
        self.assertTrue(status.a_active)

    def test_unknown_profile_type_for_heuristic_contour_location(self):
        sim = UdtSimulator(profile_type=99, contour_offset=36, beams_per_datagram=100)
        datagram = sim.status_datagram(0)
        self.assertEqual(len(datagram), FRAME_SIZE + 36 + 8)
        status = StatusProfile.from_bytes(datagram[FRAME_SIZE:])
        self.assertIsNone(status.family)
        self.assertIsNone(status.contour_offset)
        asm = UdtAssembler()
        scans = []
        for number in range(2):
            for dg in sim.scan_datagrams(number):
                scans += asm.feed_datagram(dg)
        self.assertIsNotNone(asm.contour)
        self.assertEqual(asm.contour.num_beams, 271)
        self.assertTrue(scans)
        self.assertTrue(all(s.complete and s.num_beams == 271 for s in scans))


class UdtMeasurementTests(unittest.TestCase):
    def _assemble(self, sim: UdtSimulator, cycles: int = 2):
        asm = UdtAssembler()
        scans = []
        for number in range(cycles):
            for dg in sim.scan_datagrams(number):
                scans += asm.feed_datagram(dg)
        return asm, scans

    def test_default_scan_through_the_assembler(self):
        sim = UdtSimulator(beams_per_datagram=100)
        asm, scans = self._assemble(sim)
        self.assertEqual(len(scans), 2)
        scan = scans[0]
        self.assertTrue(scan.complete)
        self.assertEqual(scan.num_beams, 271)
        self.assertEqual(scan.num_blocks, 3)                    # 100 + 100 + 71
        self.assertIs(scan.family, ScannerFamily.RSL200)
        self.assertEqual(scan.status.scan_number, scan.scan_number)
        self.assertEqual(scan.contour.num_beams, 271)
        # RSL 200 geometry: index 0 at +135 deg, -0.2 deg per index -> 271 beams span 270 deg
        angles = scan.angles_deg()
        self.assertAlmostEqual(angles[0], 135.0)
        self.assertAlmostEqual(angles[-1], -135.0)
        # 6 x 4 m room: every beam between the near wall and the corner
        self.assertGreaterEqual(min(scan.distances_mm), 1999)
        self.assertLessEqual(max(scan.distances_mm), 3606)
        self.assertTrue(all(scan.valid_mask()))
        self.assertEqual(len(scan.signal_strengths), 271)
        self.assertTrue(all(s >= 100 for s in scan.signal_strengths))
        # the room is reconstructed where it was simulated
        xs = [x for x, _ in scan.to_cartesian()]
        ys = [y for _, y in scan.to_cartesian()]
        self.assertAlmostEqual(max(abs(v) for v in xs), 3.0, delta=0.02)
        self.assertAlmostEqual(max(abs(v) for v in ys), 2.0, delta=0.02)

    def test_no_echo_beams_are_65535_with_signal_65535(self):
        """As captured from an RSL 235: distance 0xFFFF and signal strength 0xFFFF."""
        sim = UdtSimulator(no_echo_indices={0, 135, 270}, beams_per_datagram=100)
        asm, scans = self._assemble(sim)
        scan = scans[0]
        self.assertEqual([scan.distances_mm[i] for i in (0, 135, 270)], [65535] * 3)
        self.assertEqual([scan.signal_strengths[i] for i in (0, 135, 270)], [65535] * 3)
        mask = scan.valid_mask()
        self.assertEqual([mask[i] for i in (0, 135, 270)], [False] * 3)
        self.assertEqual(sum(mask), 268)
        self.assertEqual(len(scan.to_cartesian()), 268)
        self.assertEqual(scan.no_echo_mm, 65535)
        self.assertEqual(scan.status.supply_voltage_v, 23.4)

    def test_beams_beyond_max_range_have_no_echo(self):
        # open room (walls far away) but a 25 m range: nothing comes back
        sim = UdtSimulator(room_half_width_mm=10 ** 6, room_half_height_mm=10 ** 6)
        self.assertEqual(set(sim.beam_values()), {65535})
        # RSL 400: the no-echo value is the top of its 16-bit distance range
        sim400 = UdtSimulator(family=ScannerFamily.RSL400, room_half_width_mm=10 ** 6,
                              room_half_height_mm=10 ** 6, no_echo_indices={5})
        values = sim400.beam_values()
        self.assertEqual(len(values), 2700)
        self.assertEqual(set(values), {65535})
        self.assertEqual(GEOMETRY[ScannerFamily.RSL400].no_echo_mm, 65535)
        # a wall within range is seen again
        sim_near = UdtSimulator(family=ScannerFamily.RSL400, no_echo_indices={5})
        values = sim_near.beam_values()
        self.assertEqual(values[5], 65535)
        self.assertLess(max(v for i, v in enumerate(values) if i != 5), 4000)

    def test_distance_only_telegrams(self):
        sim = UdtSimulator(telegram_id=6, beams_per_datagram=1000)
        datagrams = sim.measurement_datagrams(3)
        self.assertEqual(len(datagrams), 1)
        frame = UdtFrame.from_bytes(datagrams[0])
        self.assertEqual((frame.telegram_id, frame.block, frame.scan_number), (6, 0, 3))
        self.assertEqual(frame.total_length, FRAME_SIZE + 2 * 271)
        _, scans = self._assemble(sim)
        self.assertIsNone(scans[0].signal_strengths)
        self.assertEqual(scans[0].num_beams, 271)

    def test_contour_knob(self):
        sim = UdtSimulator(contour=(100, 200, 4))
        self.assertEqual(sim.num_beams, 26)
        self.assertEqual(len(sim.beam_values()), 26)
        contour = MeasurementContour.from_bytes(sim.status_block(0), 28)
        self.assertEqual((contour.start_index, contour.stop_index, contour.index_interval),
                         (100, 200, 4))


class UdtSimulatorKnobValidationTests(unittest.TestCase):
    def test_invalid_knobs_raise_value_error(self):
        bad = [
            dict(beams_per_datagram=0),
            dict(contour=(0, 1350, 0)),
            dict(contour=(10, 5, 1)),
            dict(contour=(0, 70000, 1)),
            dict(scan_period_s=0),
            dict(scan_period_s=-1.0),
            dict(telegram_id=4),
            dict(target_port=0),
            dict(target_port=70000),
            dict(family=7),
            dict(signature=b"x" * 8),                              # RSL 200 has no trailer
            dict(family=ScannerFamily.RSL400, signature=b"x" * 7),
            dict(profile_type=21),                                 # known layout: use family=
            dict(profile_type=1),
            dict(profile_type=256),
            dict(contour_offset=28),                               # needs an unknown profile_type
            dict(profile_type=99, contour_offset=1),
            dict(no_echo_indices={271}),
            dict(no_echo_indices={-1}),
            dict(max_range_mm=0),
            dict(room_half_width_mm=0),
        ]
        for kwargs in bad:
            with self.subTest(**kwargs):
                with self.assertRaises(ValueError):
                    UdtSimulator(**kwargs)

    def test_out_of_spec_contour_is_only_warned_about(self):
        with self.assertLogs("leuze_rsl.simulator", level="WARNING") as captured:
            sim = UdtSimulator(contour=(0, 2700, 10))             # old default, > RSL 200 limits
        self.assertEqual(sim.num_beams, 271)
        self.assertIn("outside the RSL200 specification", captured.output[0])


# ---------------------------------------------------------------------------
# UdtSimulator thread robustness
# ---------------------------------------------------------------------------


class _FailingSendUdtSimulator(UdtSimulator):
    def _send_datagram(self, sock, data):
        raise OSError(101, "Network is unreachable")


class UdtSimulatorThreadTests(unittest.TestCase):
    def test_survives_unreachable_target(self):
        sim = UdtSimulator(target_port=1, scan_period_s=0.005)
        self.addCleanup(sim.stop)
        with capture_logs() as records:
            sim.start()
            self.assertTrue(wait_until(lambda: sim.scans_sent >= 3, timeout=2.0))
            time.sleep(0.05)
        self.assertEqual([r.getMessage() for r in records if r.levelno >= logging.ERROR], [])
        self.assertTrue(sim.running)
        self.assertTrue(sim._running)
        self.assertTrue(threads_named("udtsim-tx")[0].is_alive())

    def test_send_errors_do_not_kill_the_thread(self):
        sim = _FailingSendUdtSimulator(target_port=free_udp_port(), scan_period_s=0.005)
        self.addCleanup(sim.stop)
        with self.assertLogs("leuze_rsl.simulator", level="WARNING") as captured:
            sim.start()
            self.assertTrue(wait_until(lambda: sim.scans_sent >= 3, timeout=2.0))
        self.assertEqual(len(captured.output), 1)              # logged once, not per datagram
        self.assertIn("further failures are only counted", captured.output[0])
        self.assertTrue(sim.running)
        self.assertGreater(sim.send_errors, 0)
        self.assertEqual(sim.datagrams_sent, 0)
        self.assertTrue(threads_named("udtsim-tx")[0].is_alive())

    def test_stop_interrupts_a_long_scan_period(self):
        sim = UdtSimulator(target_port=free_udp_port(), scan_period_s=30.0).start()
        self.addCleanup(sim.stop)
        self.assertTrue(wait_until(lambda: sim.scans_sent >= 1))
        t0 = time.monotonic()
        sim.stop()
        self.assertLess(time.monotonic() - t0, 1.0)
        self.assertFalse(sim.running)
        self.assertEqual(threads_named("udtsim-tx"), [])

    def test_start_is_idempotent_and_restartable(self):
        sim = UdtSimulator(target_port=free_udp_port(), scan_period_s=0.005).start()
        self.addCleanup(sim.stop)
        self.assertIs(sim.start(), sim)
        self.assertEqual(len(threads_named("udtsim-tx")), 1)
        sim.stop()
        sim.stop()                                             # idempotent
        self.assertEqual(threads_named("udtsim-tx"), [])
        sim.start()
        self.assertTrue(wait_until(lambda: sim.scans_sent >= 1))
        self.assertTrue(sim.running)

    def test_drop_blocks_keyed_by_scan_index_of_each_run(self):
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(rx.close)
        rx.bind(("127.0.0.1", 0))
        rx.settimeout(1.0)
        sim = UdtSimulator(target_port=rx.getsockname()[1], scan_period_s=0.01,
                           beams_per_datagram=100, drop_blocks={0: {1}})
        self.addCleanup(sim.stop)

        def first_scan_blocks():
            blocks = []
            while True:
                frame = UdtFrame.from_bytes(rx.recvfrom(65535)[0])
                if frame.scan_number != 0:
                    return blocks
                if frame.telegram_id != 1:
                    blocks.append(frame.block)

        for run in range(2):
            sim.start()
            self.assertEqual(first_scan_blocks(), [0, 2], "run %d" % run)
            sim.stop()
            rx.settimeout(0.05)
            with contextlib.suppress(socket.timeout):
                while True:
                    rx.recvfrom(65535)                         # drain the rest
            rx.settimeout(1.0)


# ---------------------------------------------------------------------------
# RodSimulator
# ---------------------------------------------------------------------------


class RodSimulatorScanTests(unittest.TestCase):
    def test_spot_count_matches_expected_spots_and_angle_convention(self):
        ranges = [(-13760, 13760), (-3000, 3000), (2876, 5986), (0, 13755), (-13760, 13755)]
        for resolution in Resolution:
            for direction in ScanDirection:
                for skip in (0, 1, 2):
                    for amin, amax in ranges:
                        with self.subTest(resolution=resolution.name, direction=direction.name,
                                          skip=skip, range=(amin, amax)):
                            settings = SimulatorSettings(
                                resolution=resolution, direction=direction, skip_spots=skip,
                                angle_min_cdeg=amin, angle_max_cdeg=amax, spots_per_packet=16000)
                            sim = RodSimulator(settings=settings)
                            packets = [parse_packet(p) for p in sim.scan_packets()]
                            spots = sum(p.header.scan_spots for p in packets)
                            self.assertEqual(spots, expected_spots(amin, amax,
                                                                   resolution.degrees, skip))
                            angles = [a for p in packets for a in p.angles_mdeg()]
                            step = round(resolution.degrees * 1000) * (skip + 1)
                            if direction == ScanDirection.CLOCKWISE:
                                # native angles are clockwise-positive: CW counts up from min
                                self.assertEqual(angles[0], amin * 10)
                                self.assertEqual(angles[1] - angles[0], step)
                                last_boundary = amax * 10
                            else:
                                self.assertEqual(angles[0], amax * 10)
                                self.assertEqual(angles[1] - angles[0], -step)
                                last_boundary = amin * 10
                            if ((amax - amin) * 10) % step == 0:
                                self.assertEqual(angles[-1], last_boundary)

    def test_default_scan_geometry(self):
        sim = RodSimulator()
        packets = [parse_packet(p) for p in sim.scan_packets()]
        self.assertEqual(len(packets), 3)                      # 600 + 600 + 177
        self.assertEqual([p.header.scan_spots for p in packets], [600, 600, 177])
        self.assertEqual([p.header.sub_number for p in packets], [1, 2, 3])
        self.assertTrue(all(p.header.total_number == 3 for p in packets))
        self.assertTrue(all(p.header.scan_freq == 80 for p in packets))
        distances = [d for p in packets for d in p.distances_mm]
        intensities = [i for p in packets for i in p.intensities]
        self.assertEqual(len(distances), 1377)
        self.assertGreaterEqual(min(distances), 1999)
        self.assertLessEqual(max(distances), 3606)
        self.assertGreaterEqual(min(intensities), 32)
        # counterclockwise (default): starts at angle_max, counts down to angle_min
        angles = [a for p in packets for a in p.angles_mdeg()]
        self.assertEqual((angles[0], angles[-1]), (137600, -137600))

    def test_invalid_spots_and_no_echo(self):
        sim = RodSimulator(invalid_spot_every=10, no_echo_indices={3})
        packets = [parse_packet(p) for p in sim.scan_packets()]
        distances = [d for p in packets for d in p.distances_mm]
        intensities = [i for p in packets for i in p.intensities]
        zero = [i for i, d in enumerate(distances) if d == 0]
        self.assertEqual(zero[:5], [3, 9, 19, 29, 39])
        self.assertEqual(len(zero), 1377 // 10 + 1)
        self.assertEqual([intensities[i] for i in zero], [0] * len(zero))
        self.assertTrue(all(d > 0 and i >= 32
                            for j, (d, i) in enumerate(zip(distances, intensities))
                            if j not in zero))
        # an open room beyond max_range_mm: no echo anywhere
        sim = RodSimulator(settings=SimulatorSettings(room_half_width_mm=10 ** 6,
                                                      room_half_height_mm=10 ** 6))
        packets = [parse_packet(p) for p in sim.scan_packets()]
        self.assertEqual({d for p in packets for d in p.distances_mm}, {0})
        self.assertEqual({i for p in packets for i in p.intensities}, {0})

    def test_invalid_knobs_raise_value_error(self):
        bad_settings = [
            dict(spots_per_packet=0),
            dict(spots_per_packet=5),                              # 276 packets > 255
            dict(spots_per_packet=20000),                          # > 16-bit packet_size
            dict(angle_min_cdeg=3000, angle_max_cdeg=3000),
            dict(angle_min_cdeg=5000, angle_max_cdeg=-5000),
            dict(angle_max_cdeg=20000),
            dict(skip_spots=-1),
            dict(scan_period_s=0),
            dict(resolution=9),
            dict(direction=5),
            dict(packet_type=2),
            dict(max_range_mm=0),
        ]
        for kwargs in bad_settings:
            with self.subTest(**kwargs):
                with self.assertRaises(ValueError):
                    RodSimulator(settings=SimulatorSettings(**kwargs))
        for kwargs in (dict(udp_dest_port=0), dict(port=70000), dict(invalid_spot_every=-1),
                       dict(start_mid_scan=-1), dict(split_writes=-1),
                       dict(no_echo_indices={1377})):
            with self.subTest(**kwargs):
                with self.assertRaises(ValueError):
                    RodSimulator(**kwargs)

    def test_alias_and_exports(self):
        self.assertIs(RSL235Simulator, RodSimulator)
        for name in ("RodSimulator", "RSL235Simulator", "UdtSimulator", "SimulatorSettings"):
            self.assertIn(name, simulator_module.__all__)
        namespace = {}
        exec("from leuze_rsl.simulator import *", namespace)
        self.assertIn("UdtSimulator", namespace)


class RodSimulatorLifecycleTests(unittest.TestCase):
    def test_start_twice_is_a_noop_and_stop_is_idempotent(self):
        sim = RodSimulator().start()
        self.addCleanup(sim.stop)
        port = sim.port
        self.assertGreater(port, 0)
        self.assertIs(sim.start(), sim)
        self.assertEqual(sim.port, port)
        self.assertEqual(len(threads_named("rodsim-accept")), 1)
        self.assertTrue(sim.running)
        sim.stop()
        sim.stop()
        self.assertFalse(sim.running)
        self.assertEqual(threads_named("rodsim-accept"), [])
        # restartable
        sim.start()
        self.assertTrue(sim.running)
        with contextlib.closing(socket.create_connection(("127.0.0.1", sim.port), timeout=2.0)):
            pass

    def test_bind_failure_propagates_and_leaves_nothing_running(self):
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(blocker.close)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        sim = RodSimulator(port=blocker.getsockname()[1])
        with self.assertRaises(OSError):
            sim.start()
        self.assertFalse(sim.running)
        self.assertEqual(threads_named("rodsim-accept"), [])

    def test_commands_received_is_bounded(self):
        sim = RodSimulator().start()
        self.addCleanup(sim.stop)
        self.assertEqual(sim.commands_received.maxlen, 1000)
        client = RawRodClient(sim.port)
        self.addCleanup(client.close)
        self.assertEqual(client.command("cRN", "GetTxMDI"), "cRA GetTxMDI 0")
        self.assertEqual(client.command("cRN", "GetRange"), "cRA GetRange -13760 13760")
        self.assertEqual(list(sim.commands_received), ["GetTxMDI", "GetRange"])

    def test_stream_stops_within_a_second_despite_long_scan_period(self):
        udp_port = free_udp_port()
        sim = RodSimulator(udp_dest_port=udp_port,
                           settings=SimulatorSettings(scan_period_s=30.0)).start()
        self.addCleanup(sim.stop)
        client = RawRodClient(sim.port)
        self.addCleanup(client.close)
        self.assertEqual(client.command("cWN", "SendMDI"), "cWA SendMDI")
        self.assertTrue(sim.streaming)
        self.assertEqual(client.command("cRN", "GetTxMDI"), "cRA GetTxMDI 1")
        self.assertTrue(wait_until(lambda: sim.scans_generated >= 1))
        t0 = time.monotonic()
        sim.stop()
        self.assertLess(time.monotonic() - t0, 1.0)
        self.assertFalse(sim.streaming)
        self.assertEqual(threads_named("rodsim-stream"), [])

    def test_stop_mdi_and_restart_without_a_second_stream_thread(self):
        udp_port = free_udp_port()
        sim = RodSimulator(udp_dest_port=udp_port,
                           settings=SimulatorSettings(scan_period_s=5.0)).start()
        self.addCleanup(sim.stop)
        client = RawRodClient(sim.port)
        self.addCleanup(client.close)
        for _ in range(3):
            self.assertEqual(client.command("cWN", "SendMDI"), "cWA SendMDI")
            self.assertEqual(client.command("cWN", "SendMDI"), "cWA SendMDI")   # no-op
            self.assertEqual(len(threads_named("rodsim-stream")), 1)
            t0 = time.monotonic()
            self.assertEqual(client.command("cWN", "StopMDI"), "cWA StopMDI")
            self.assertLess(time.monotonic() - t0, 1.0)               # not one scan period
            self.assertFalse(sim.streaming)
            self.assertEqual(client.command("cRN", "GetTxMDI"), "cRA GetTxMDI 0")
            self.assertEqual(threads_named("rodsim-stream"), [])

    def test_tcp_stream_stops_when_the_client_stops_reading(self):
        sim = RodSimulator(settings=SimulatorSettings(protocol=MdiProtocol.TCP,
                                                      scan_period_s=0.001))
        sim.mdi_send_timeout_s = 0.3
        sim.start()
        self.addCleanup(sim.stop)
        client = RawRodClient(sim.port)
        self.addCleanup(client.close)
        client.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        with self.assertLogs("leuze_rsl.simulator", level="WARNING") as captured:
            client.send("cWN", "SendMDI")                  # never read anything again
            self.assertTrue(wait_until(lambda: sim.streaming))
            self.assertTrue(wait_until(lambda: not sim.streaming, timeout=6.0))
            self.assertTrue(wait_until(lambda: not threads_named("rodsim-stream"), timeout=3.0))
        self.assertIn("client is not accepting data", "\n".join(captured.output))
        self.assertGreater(sim.packets_sent, 0)
        self.assertTrue(sim.running)                       # the command server survives

    def test_tcp_split_writes_deliver_whole_packets(self):
        sim = RodSimulator(settings=SimulatorSettings(protocol=MdiProtocol.TCP,
                                                      angle_min_cdeg=-3000,
                                                      angle_max_cdeg=3000,
                                                      spots_per_packet=120),
                           split_writes=7, stream_on_connect=True).start()
        self.addCleanup(sim.stop)
        client = RawRodClient(sim.port)
        self.addCleanup(client.close)
        data = bytearray()
        deadline = time.monotonic() + 3.0
        while data.count(b"LEUZ") < 4 and time.monotonic() < deadline:   # 3 complete packets
            data += client.sock.recv(65536)
        t0 = time.monotonic()
        client.buf = bytearray(data)                       # a copy: keep `data` for parsing
        self.assertEqual(client.command("cWN", "StopMDI"), "cWA StopMDI")
        self.assertLess(time.monotonic() - t0, 1.0)
        self.assertFalse(sim.streaming)
        # every complete packet on the wire parses (no packet was left half-written)
        start = data.find(b"LEUZ")
        parsed = 0
        while start >= 0:
            try:
                packet = parse_packet(data, start)
            except ValueError:
                break
            parsed += 1
            self.assertEqual(packet.header.scan_spots, [120, 120, 61][(packet.header.sub_number - 1)])
            start = data.find(b"LEUZ", start + packet.header.packet_size)
        self.assertGreaterEqual(parsed, 3)


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def run_cli(*args: str, timeout: float = 10.0) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONPATH=SRC_DIR)
    return subprocess.run([sys.executable, "-m", "leuze_rsl.simulator", *args],
                          capture_output=True, text=True, env=env, timeout=timeout)


class CliTests(unittest.TestCase):
    def test_help(self):
        result = run_cli("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage: python -m leuze_rsl.simulator", result.stdout)
        for flag in ("--host", "--port", "--rod", "--protocol", "--distances-only",
                     "--family", "--contour", "--period", "--beams-per-datagram", "--verbose"):
            self.assertIn(flag, result.stdout)
        self.assertNotIn("simulator.py", result.stdout)

    def test_usage_errors(self):
        for args in (["--protocol", "tcp"], ["--rod", "--family", "rsl400"],
                     ["--rod", "--contour", "0", "1350", "5"], ["--port", "0"],
                     ["--contour", "0", "1350"], ["--period", "0"]):
            with self.subTest(args=args):
                result = run_cli(*args)
                self.assertEqual(result.returncode, 2)
                self.assertIn("usage:", result.stderr)

    def test_port_collision_is_reported_with_exit_code_1(self):
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.addCleanup(blocker.close)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        result = run_cli("--rod", "--port", str(blocker.getsockname()[1]))
        self.assertEqual(result.returncode, 1)
        self.assertTrue(result.stderr.startswith("error:"), result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    @unittest.skipIf(sys.platform == "win32", "SIGINT cannot be sent to a child process on Windows")
    def test_ctrl_c_exits_130(self):
        env = dict(os.environ, PYTHONPATH=SRC_DIR)
        proc = subprocess.Popen(
            [sys.executable, "-u", "-m", "leuze_rsl.simulator", "--rod", "--port", "0"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        try:
            banner = proc.stdout.readline()
            self.assertIn("ROD-protocol simulator listening", banner)
            proc.send_signal(signal.SIGINT)
            stdout, stderr = proc.communicate(timeout=10.0)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        self.assertEqual(proc.returncode, 130)
        self.assertIn("interrupted", stderr)
        self.assertNotIn("Traceback", stderr)

    @unittest.skipIf(sys.platform == "win32", "SIGINT cannot be sent to a child process on Windows")
    def test_main_in_process_with_udt_target(self):
        """main() with family/contour/period knobs builds the right simulator."""
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(rx.close)
        rx.bind(("127.0.0.1", 0))
        rx.settimeout(2.0)
        port = rx.getsockname()[1]
        env = dict(os.environ, PYTHONPATH=SRC_DIR)
        proc = subprocess.Popen(
            [sys.executable, "-u", "-m", "leuze_rsl.simulator", "--port", str(port),
             "--family", "rsl400", "--contour", "0", "999", "1", "--period", "0.01",
             "--beams-per-datagram", "500", "--distances-only"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
        try:
            banner = proc.stdout.readline()
            self.assertIn("RSL400", banner)
            self.assertIn("1000 beams", banner)
            status = rx.recvfrom(65535)[0]
            while UdtFrame.from_bytes(status).telegram_id != 1:
                status = rx.recvfrom(65535)[0]
            self.assertEqual(len(status), 48)
            self.assertIs(StatusProfile.from_bytes(status[FRAME_SIZE:]).family,
                          ScannerFamily.RSL400)
            data = rx.recvfrom(65535)[0]
            frame = UdtFrame.from_bytes(data)
            self.assertEqual(frame.telegram_id, 6)
            self.assertEqual(frame.total_length, FRAME_SIZE + 2 * 500)
            proc.send_signal(signal.SIGINT)
            _, stderr = proc.communicate(timeout=10.0)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        self.assertEqual(proc.returncode, 130, stderr)


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    unittest.main()
