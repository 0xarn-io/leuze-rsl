"""Tests for the UDP data telegram ("UDT") receiver -- the RSL 235 wire format."""

import socket
import struct
import time
import unittest

from leuze_rsl.simulator import UdtSimulator
from leuze_rsl.udt import (
    FRAME_SIZE,
    TELEGRAM_ID_DISTANCE,
    TELEGRAM_ID_DISTANCE_SIGNAL,
    TELEGRAM_ID_STATUS,
    MeasurementContour,
    RSL235Udt,
    StatusProfile,
    UdtAssembler,
    UdtFrame,
    locate_contour,
)


def make_frame(total_length, telegram_id, block, scan_number) -> bytes:
    return struct.pack("<IBBH4sHHI", total_length, 8, 0, 6,
                       b"\x04\x0b\x01\x32", telegram_id, block, scan_number)


def make_status_datagram(scan_number, contour=(0, 2700, 10), contour_offset=20,
                         extra=8) -> bytes:
    status = bytearray(20)
    status[0] = 1
    status[1] = 1
    struct.pack_into("<I", status, 8, scan_number)
    data = bytearray(contour_offset + 8 + extra)
    data[:20] = status
    data[contour_offset:contour_offset + 8] = struct.pack(
        "<HHHH", contour[0], contour[1], contour[2], 0)
    return make_frame(FRAME_SIZE + len(data), TELEGRAM_ID_STATUS, 0,
                      scan_number) + bytes(data)


def make_measurement_datagram(scan_number, block, distances, signals=None) -> bytes:
    if signals is not None:
        payload = b"".join(struct.pack("<HH", d, s)
                           for d, s in zip(distances, signals))
        telegram_id = TELEGRAM_ID_DISTANCE_SIGNAL
    else:
        payload = struct.pack("<%dH" % len(distances), *distances)
        telegram_id = TELEGRAM_ID_DISTANCE
    return make_frame(FRAME_SIZE + len(payload), telegram_id, block,
                      scan_number) + payload


class FrameTests(unittest.TestCase):
    def test_parse_real_capture_status_head(self):
        """The exact first 16 bytes captured from real RSL 235 hardware."""
        head = bytes.fromhex("38 00 00 00 08 00 06 00 04 0b 01 32 01 00 00 00"
                             .replace(" ", ""))
        frame = UdtFrame.from_bytes(head + struct.pack("<I", 12345))
        self.assertEqual(frame.total_length, 56)
        self.assertEqual(frame.h1_size, 8)
        self.assertEqual(frame.follow_flag, 0)
        self.assertEqual(frame.request_id, 6)
        self.assertEqual(frame.header2, b"\x04\x0b\x01\x32")
        self.assertEqual(frame.telegram_id, 1)          # status profile
        self.assertEqual(frame.block, 0)
        self.assertEqual(frame.scan_number, 12345)

    def test_parse_real_capture_measurement_head(self):
        head = bytes.fromhex("50 04 00 00 08 00 06 00 04 0b 01 32 03 00 00 00"
                             .replace(" ", ""))
        frame = UdtFrame.from_bytes(head + struct.pack("<I", 7))
        self.assertEqual(frame.total_length, 1104)      # 20 + 271 beams * 4
        self.assertEqual(frame.telegram_id, 3)          # distance + signal
        self.assertEqual((frame.total_length - FRAME_SIZE) // 4, 271)

    def test_round_trip(self):
        raw = make_frame(56, 1, 3, 0xDEADBEEF)
        frame = UdtFrame.from_bytes(raw)
        self.assertEqual(frame.to_bytes(), raw)


class ContourTests(unittest.TestCase):
    def test_num_beams_formula(self):
        self.assertEqual(MeasurementContour(0, 2700, 10, 0).num_beams, 271)
        self.assertEqual(MeasurementContour(0, 2699, 1, 0).num_beams, 2700)
        # ceil: 2700/8 = 337.5 -> 338 (+1)
        self.assertEqual(MeasurementContour(0, 2700, 8, 0).num_beams, 339)
        self.assertEqual(MeasurementContour(100, 200, 4, 0).num_beams, 26)

    def test_locate_at_documented_offset(self):
        datagram = make_status_datagram(5, contour=(0, 2700, 10))
        located = locate_contour(datagram[FRAME_SIZE:], expected_beams=271)
        self.assertIsNotNone(located)
        offset, contour = located
        self.assertEqual(offset, 20)
        self.assertEqual((contour.start_index, contour.stop_index,
                          contour.index_interval), (0, 2700, 10))

    def test_locate_at_shifted_offset(self):
        """RSL 200 datagrams are longer than documented; auto-locate must cope."""
        datagram = make_status_datagram(5, contour=(0, 2700, 10),
                                        contour_offset=28, extra=0)
        located = locate_contour(datagram[FRAME_SIZE:], expected_beams=271)
        self.assertIsNotNone(located)
        offset, contour = located
        self.assertEqual(offset, 28)
        self.assertEqual(contour.num_beams, 271)


class StatusProfileTests(unittest.TestCase):
    def test_flag_decoding(self):
        data = bytearray(36)
        data[0] = 1
        data[1] = 2                       # simulation mode
        data[2] = 0x80 | 0x40 | 0x02      # error, alarm, ossd_a
        data[12] = 0x80 | 0x20            # a_active, a_pf violated
        struct.pack_into("<I", data, 8, 99)
        status = StatusProfile.from_bytes(bytes(data))
        self.assertEqual(status.operating_mode, 2)
        self.assertTrue(status.error)
        self.assertTrue(status.alarm)
        self.assertTrue(status.ossd_a)
        self.assertFalse(status.ossd_b)
        self.assertTrue(status.a_active)
        self.assertTrue(status.a_protective_violated)
        self.assertEqual(status.scan_number, 99)
        self.assertEqual(len(status.raw), 36)


class AssemblerTests(unittest.TestCase):
    def test_single_fragment_scan_with_status(self):
        asm = UdtAssembler()
        distances = list(range(1000, 1000 + 271))
        signals = [500] * 271
        scans = asm.feed_datagram(make_status_datagram(7))
        self.assertEqual(scans, [])
        self.assertIsNotNone(asm.latest_status)
        self.assertEqual(asm.contour.num_beams, 271)
        # contour known + beam count matches -> emitted immediately
        scans = asm.feed_datagram(make_measurement_datagram(7, 0, distances, signals))
        self.assertEqual(len(scans), 1)
        scan = scans[0]
        self.assertEqual(scan.scan_number, 7)
        self.assertEqual(scan.num_beams, 271)
        self.assertEqual(scan.distances_mm[0], 1000)
        self.assertEqual(scan.signal_strengths[0], 500)
        self.assertEqual(scan.num_blocks, 1)
        self.assertIsNotNone(scan.status)

    def test_multi_fragment_assembly(self):
        asm = UdtAssembler()
        asm.feed_datagram(make_status_datagram(1, contour=(0, 2700, 10)))
        distances = list(range(271))
        scans = []
        scans += asm.feed_datagram(make_measurement_datagram(1, 0, distances[:100],
                                                             [1] * 100))
        scans += asm.feed_datagram(make_measurement_datagram(1, 1, distances[100:200],
                                                             [1] * 100))
        self.assertEqual(scans, [])
        scans += asm.feed_datagram(make_measurement_datagram(1, 2, distances[200:],
                                                             [1] * 71))
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0].distances_mm, tuple(distances))
        self.assertEqual(scans[0].num_blocks, 3)

    def test_lost_fragment_dropped_in_strict_mode(self):
        asm = UdtAssembler(strict=True)
        asm.feed_datagram(make_status_datagram(1))
        distances = list(range(271))
        asm.feed_datagram(make_measurement_datagram(1, 0, distances[:100], [1] * 100))
        # block 1 lost; scan 2 begins -> scan 1 finalized incomplete -> dropped
        scans = asm.feed_datagram(make_status_datagram(2))
        self.assertEqual(scans, [])
        self.assertEqual(asm.stats.scans_dropped_incomplete, 1)
        scans = asm.feed_datagram(make_measurement_datagram(2, 0, distances, [1] * 271))
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0].scan_number, 2)

    def test_lost_fragment_emitted_in_lenient_mode(self):
        asm = UdtAssembler(strict=False)
        asm.feed_datagram(make_status_datagram(1))
        asm.feed_datagram(make_measurement_datagram(1, 0, [10] * 100, [1] * 100))
        scans = asm.feed_datagram(make_status_datagram(2))
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0].num_beams, 100)

    def test_distance_only_telegrams(self):
        asm = UdtAssembler()
        scans = asm.feed_datagram(make_measurement_datagram(3, 0, [1, 2, 3]))
        self.assertEqual(scans, [])                      # no contour yet
        scans = asm.feed_datagram(make_measurement_datagram(4, 0, [4, 5, 6]))
        self.assertEqual(len(scans), 1)                  # scan 3 finalized
        self.assertEqual(scans[0].distances_mm, (1, 2, 3))
        self.assertIsNone(scans[0].signal_strengths)

    def test_truncated_datagram_rejected(self):
        asm = UdtAssembler()
        self.assertEqual(asm.feed_datagram(b"\x01\x02\x03"), [])
        datagram = make_status_datagram(1)
        self.assertEqual(asm.feed_datagram(datagram[:30]), [])
        self.assertEqual(asm.stats.bad_frames, 2)

    def test_scan_number_wraparound(self):
        asm = UdtAssembler()                             # no contour known
        scans = asm.feed_datagram(
            make_measurement_datagram(0xFFFFFFFF, 0, [7] * 10, [1] * 10))
        self.assertEqual(scans, [])                      # still pending
        scans = asm.feed_datagram(make_measurement_datagram(0, 0, [8] * 10, [1] * 10))
        self.assertEqual(len(scans), 1)                  # wrap: 0 is newer
        self.assertEqual(scans[0].scan_number, 0xFFFFFFFF)

    def test_no_echo_sentinel_handling(self):
        """Real RSL 235 hardware reports 32767 mm for beams without echo."""
        asm = UdtAssembler()
        scans = asm.feed_datagram(make_measurement_datagram(
            1, 0, [1000, 32767, 0, 2000], [10, 0, 0, 20]))
        scans += asm.feed_datagram(make_measurement_datagram(
            2, 0, [1] * 4, [1] * 4))
        scan = scans[0]
        self.assertEqual(scan.valid_mask(), [True, False, False, True])
        points = scan.to_cartesian(angle_at_index0=0.0)
        self.assertEqual(len(points), 2)                 # sentinel + 0 skipped
        self.assertEqual(len(scan.to_cartesian(skip_invalid=False)), 4)

    def test_angles_from_contour(self):
        asm = UdtAssembler()
        asm.feed_datagram(make_status_datagram(1, contour=(1000, 1750, 5)))
        n = MeasurementContour(1000, 1750, 5, 0).num_beams
        scans = asm.feed_datagram(make_measurement_datagram(1, 0, [100] * n, [1] * n))
        self.assertEqual(len(scans), 1)
        angles = scans[0].angles_deg()                   # index*0.1 - 137.5
        self.assertAlmostEqual(angles[0], 1000 * 0.1 - 137.5)
        self.assertAlmostEqual(angles[1] - angles[0], 0.5)


class EndToEndTests(unittest.TestCase):
    @staticmethod
    def free_udp_port() -> int:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        return port

    def test_receive_from_simulator(self):
        port = self.free_udp_port()
        receiver = RSL235Udt(port=port, source_ip="127.0.0.1")
        receiver.start()
        self.addCleanup(receiver.stop)
        sim = UdtSimulator(target_port=port, scan_period_s=0.01).start()
        self.addCleanup(sim.stop)

        scans = [receiver.get_scan(timeout=5.0) for _ in range(3)]
        numbers = [s.scan_number for s in scans]
        self.assertEqual(numbers, sorted(numbers))
        for scan in scans:
            self.assertEqual(scan.num_beams, 271)
            self.assertIsNotNone(scan.signal_strengths)
            self.assertGreaterEqual(min(scan.distances_mm), 1900)
            self.assertLessEqual(max(scan.distances_mm), 25000)
        self.assertTrue(receiver.is_receiving)
        self.assertIsNotNone(receiver.latest_status)
        self.assertEqual(receiver.contour.num_beams, 271)

    def test_multi_datagram_scans_and_drops(self):
        port = self.free_udp_port()
        receiver = RSL235Udt(port=port)
        receiver.start()
        self.addCleanup(receiver.stop)
        # 271 beams in chunks of 100 -> blocks 0..2; drop block 1 of scan 2
        sim = UdtSimulator(target_port=port, scan_period_s=0.01,
                           beams_per_datagram=100,
                           drop_blocks={2: {1}}).start()
        self.addCleanup(sim.stop)

        scans = [receiver.get_scan(timeout=5.0) for _ in range(4)]
        for scan in scans:
            self.assertEqual(scan.num_beams, 271)
            self.assertEqual(scan.num_blocks, 3)
        deadline = time.monotonic() + 2.0
        while (receiver.stats["scans_dropped_incomplete"] < 1
               and time.monotonic() < deadline):
            time.sleep(0.02)
        self.assertGreaterEqual(receiver.stats["scans_dropped_incomplete"], 1)

    def test_shifted_contour_offset(self):
        """Receiver must find the contour even at a non-RSL400 position."""
        port = self.free_udp_port()
        receiver = RSL235Udt(port=port)
        receiver.start()
        self.addCleanup(receiver.stop)
        sim = UdtSimulator(target_port=port, scan_period_s=0.01,
                           contour_offset=28, status_extra_bytes=0).start()
        self.addCleanup(sim.stop)

        scan = receiver.get_scan(timeout=5.0)
        self.assertEqual(scan.num_beams, 271)
        deadline = time.monotonic() + 2.0
        while receiver.contour is None and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertIsNotNone(receiver.contour)
        self.assertEqual(receiver.contour.num_beams, 271)

    def test_source_filtering_and_callbacks(self):
        port = self.free_udp_port()
        seen_scans, seen_status = [], []
        receiver = RSL235Udt(port=port, source_ip="203.0.113.1",   # nothing matches
                             on_scan=seen_scans.append,
                             on_status=seen_status.append)
        receiver.start()
        sim = UdtSimulator(target_port=port, scan_period_s=0.01).start()
        self.addCleanup(sim.stop)
        with self.assertRaises(TimeoutError):
            receiver.get_scan(timeout=0.3)
        self.assertGreater(receiver.stats["foreign_datagrams_dropped"], 0)
        receiver.stop()

        # correct source: callbacks fire
        receiver2 = RSL235Udt(port=port, source_ip="127.0.0.1",
                              on_scan=seen_scans.append,
                              on_status=seen_status.append)
        receiver2.start()
        self.addCleanup(receiver2.stop)
        receiver2.get_scan(timeout=5.0)
        self.assertGreaterEqual(len(seen_scans), 1)
        self.assertGreaterEqual(len(seen_status), 1)


if __name__ == "__main__":
    unittest.main()
