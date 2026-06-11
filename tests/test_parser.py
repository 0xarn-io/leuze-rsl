"""Unit tests for the MDI scan assembler."""

import math
import unittest

from pyrsl235.parser import ScanAssembler
from pyrsl235.protocol import MdiPacketType, build_packet


def make_packet(sub, total, *, ptype=MdiPacketType.DISTANCE_AND_INTENSITY,
                spots=4, packet_number=None, first_angle=0, delta=100,
                base_distance=1000):
    distances = [base_distance + sub * 10 + i for i in range(spots)]
    intensities = [2000 + sub * 10 + i for i in range(spots)]
    return build_packet(
        packet_type=ptype,
        packet_number=packet_number if packet_number is not None else sub,
        total_number=total,
        sub_number=sub,
        scan_freq=80,
        first_angle_mdeg=first_angle + (sub - 1) * spots * delta,
        delta_angle_mdeg=delta,
        timestamp_ms=sub,
        distances_mm=distances,
        intensities=intensities if ptype == MdiPacketType.DISTANCE_AND_INTENSITY else None,
    )


def make_scan_bytes(total=3, **kwargs):
    return b"".join(make_packet(sub, total, **kwargs) for sub in range(1, total + 1))


class AssemblerTests(unittest.TestCase):
    def test_single_packet_scan(self):
        asm = ScanAssembler()
        scans = asm.feed(make_packet(1, 1, spots=5))
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0].num_spots, 5)
        self.assertEqual(asm.stats.scans_completed, 1)

    def test_multi_packet_scan_concatenation(self):
        asm = ScanAssembler()
        scans = asm.feed(make_scan_bytes(total=3, spots=4))
        self.assertEqual(len(scans), 1)
        scan = scans[0]
        self.assertEqual(scan.num_spots, 12)
        # distances of sub 1, then sub 2, then sub 3
        self.assertEqual(scan.distances_mm[:4], (1010, 1011, 1012, 1013))
        self.assertEqual(scan.distances_mm[4:8], (1020, 1021, 1022, 1023))
        self.assertEqual(scan.intensities[:4], (2010, 2011, 2012, 2013))
        # angles continue seamlessly across packets
        self.assertEqual(scan.angles_mdeg, tuple(i * 100 for i in range(12)))
        self.assertEqual(len(scan.headers), 3)

    def test_distance_only_packets(self):
        asm = ScanAssembler()
        scans = asm.feed(make_scan_bytes(total=2, ptype=MdiPacketType.DISTANCE))
        self.assertEqual(len(scans), 1)
        self.assertIsNone(scans[0].intensities)

    def test_byte_at_a_time_feed(self):
        asm = ScanAssembler()
        data = make_scan_bytes(total=3)
        scans = []
        for i in range(len(data)):
            scans += asm.feed(data[i:i + 1])
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0].num_spots, 12)

    def test_garbage_before_packet_is_skipped(self):
        asm = ScanAssembler()
        scans = asm.feed(b"\xde\xad\xbe\xef" + make_packet(1, 1))
        self.assertEqual(len(scans), 1)
        self.assertGreaterEqual(asm.stats.bytes_discarded, 4)

    def test_corrupt_packet_size_zero_does_not_loop(self):
        """Regression test for the C++ infinite loop on packet_size == 0."""
        asm = ScanAssembler()
        bad = bytearray(make_packet(1, 1))
        bad[5:7] = b"\x00\x00"          # packet_size := 0
        scans = asm.feed(bytes(bad) + make_packet(1, 1))
        self.assertEqual(len(scans), 1)  # the good packet still parses
        self.assertGreaterEqual(asm.stats.resyncs, 1)

    def test_inconsistent_size_resyncs(self):
        asm = ScanAssembler()
        bad = bytearray(make_packet(1, 1, spots=4))
        bad[19:21] = (9999).to_bytes(2, "big")   # scan_spots no longer matches size
        scans = asm.feed(bytes(bad) + make_packet(1, 1))
        self.assertEqual(len(scans), 1)
        self.assertGreaterEqual(asm.stats.resyncs, 1)

    def test_mid_scan_join_produces_no_partial_scan(self):
        asm = ScanAssembler()
        # join the stream at sub 2 of 3: that scan must be dropped entirely
        scans = asm.feed(make_packet(2, 3) + make_packet(3, 3))
        self.assertEqual(scans, [])
        self.assertEqual(asm.stats.scans_completed, 0)
        self.assertGreaterEqual(asm.stats.packets_orphaned, 1)
        # the next full scan comes through
        scans = asm.feed(make_scan_bytes(total=3))
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0].num_spots, 12)

    def test_missing_sub_packet_drops_scan(self):
        asm = ScanAssembler()
        data = make_packet(1, 3) + make_packet(3, 3)      # sub 2 lost
        scans = asm.feed(data)
        self.assertEqual(scans, [])
        self.assertGreaterEqual(asm.stats.scans_dropped_incomplete, 1)
        scans = asm.feed(make_scan_bytes(total=3))
        self.assertEqual(len(scans), 1)

    def test_total_number_change_mid_scan_drops(self):
        asm = ScanAssembler()
        scans = asm.feed(make_packet(1, 3) + make_packet(2, 4))
        self.assertEqual(scans, [])
        self.assertGreaterEqual(asm.stats.scans_dropped_incomplete, 1)

    def test_new_sub1_replaces_stale_partial(self):
        asm = ScanAssembler()
        scans = asm.feed(make_packet(1, 3))               # partial scan pending
        self.assertEqual(scans, [])
        scans = asm.feed(make_scan_bytes(total=2))         # fresh complete scan
        self.assertEqual(len(scans), 1)
        self.assertEqual(asm.stats.scans_dropped_incomplete, 1)

    def test_multiple_scans_in_one_feed(self):
        asm = ScanAssembler()
        scans = asm.feed(make_scan_bytes(total=2) + make_scan_bytes(total=2))
        self.assertEqual(len(scans), 2)

    def test_reset_drops_pending(self):
        asm = ScanAssembler()
        asm.feed(make_packet(1, 3))
        asm.reset()
        self.assertEqual(asm.stats.scans_dropped_incomplete, 1)
        scans = asm.feed(make_scan_bytes(total=3))
        self.assertEqual(len(scans), 1)


class ScanViewTests(unittest.TestCase):
    def make_scan(self):
        asm = ScanAssembler()
        raw = build_packet(
            packet_type=MdiPacketType.DISTANCE_AND_INTENSITY,
            packet_number=1, total_number=1, sub_number=1, scan_freq=40,
            first_angle_mdeg=-90000, delta_angle_mdeg=45000, timestamp_ms=77,
            distances_mm=[1000, 0, 2000, 500, 3000],
            intensities=[100, 0, 300, 400, 500])
        return asm.feed(raw)[0]

    def test_metadata(self):
        scan = self.make_scan()
        self.assertEqual(scan.scan_frequency_hz, 40)
        self.assertEqual(scan.timestamp_ms, 77)
        self.assertEqual(scan.packet_number, 1)
        self.assertEqual(scan.packet_type, MdiPacketType.DISTANCE_AND_INTENSITY)

    def test_angle_and_distance_views(self):
        scan = self.make_scan()
        self.assertEqual(scan.angles_deg, [-90.0, -45.0, 0.0, 45.0, 90.0])
        self.assertAlmostEqual(scan.angles_rad[0], -math.pi / 2)
        self.assertEqual(scan.distances_m, [1.0, 0.0, 2.0, 0.5, 3.0])

    def test_to_cartesian(self):
        scan = self.make_scan()
        points = scan.to_cartesian()                      # skips the 0 distance
        self.assertEqual(len(points), 4)
        x, y = points[0]                                  # 1 m at -90 deg
        self.assertAlmostEqual(x, 0.0, places=6)
        self.assertAlmostEqual(y, -1.0, places=6)
        x, y = points[1]                                  # 2 m at 0 deg
        self.assertAlmostEqual(x, 2.0, places=6)
        self.assertAlmostEqual(y, 0.0, places=6)
        self.assertEqual(len(scan.to_cartesian(skip_invalid=False)), 5)


if __name__ == "__main__":
    unittest.main()
