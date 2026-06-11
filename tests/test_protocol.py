"""Unit tests for the wire protocol primitives."""

import struct
import unittest

from pyrsl235.protocol import (
    HEADER_SIZE,
    SYNC,
    MdiHeader,
    MdiPacketType,
    Resolution,
    build_packet,
    find_response_start,
    frame_command,
    parse_packet,
    parse_response,
)


def make_header_bytes() -> bytes:
    """A hand-built header to pin the exact byte layout (all big-endian)."""
    return (
        b"LEUZ"                                  # sync
        + bytes([1])                             # packet_type = 1
        + (31 + 3 * 4).to_bytes(2, "big")        # packet_size = 43 (3 spots, dist+int)
        + (0).to_bytes(2, "big")                 # reserve_a
        + (0).to_bytes(2, "big")                 # reserve_b
        + (0).to_bytes(2, "big")                 # reserve_c
        + (1234).to_bytes(2, "big")              # packet_number
        + bytes([3])                             # total_number
        + bytes([2])                             # sub_number
        + (40).to_bytes(2, "big")                # scan_freq
        + (3).to_bytes(2, "big")                 # scan_spots
        + (-137600).to_bytes(4, "big", signed=True)  # first_angle (-137.600 deg)
        + (100).to_bytes(4, "big", signed=True)  # delta_angle (0.100 deg)
        + (5000).to_bytes(2, "big")              # timestamp
    )


class HeaderTests(unittest.TestCase):
    def test_header_size_is_31(self):
        self.assertEqual(HEADER_SIZE, 31)
        self.assertEqual(len(make_header_bytes()), 31)

    def test_from_bytes_field_by_field(self):
        h = MdiHeader.from_bytes(make_header_bytes())
        self.assertEqual(h.packet_type, 1)
        self.assertEqual(h.packet_size, 43)
        self.assertEqual(h.packet_number, 1234)
        self.assertEqual(h.total_number, 3)
        self.assertEqual(h.sub_number, 2)
        self.assertEqual(h.scan_freq, 40)
        self.assertEqual(h.scan_spots, 3)
        self.assertEqual(h.first_angle, -137600)   # signed!
        self.assertEqual(h.delta_angle, 100)
        self.assertEqual(h.timestamp, 5000)

    def test_round_trip(self):
        raw = make_header_bytes()
        self.assertEqual(MdiHeader.from_bytes(raw).to_bytes(), raw)

    def test_bad_sync_rejected(self):
        raw = b"XEUZ" + make_header_bytes()[4:]
        with self.assertRaises(ValueError):
            MdiHeader.from_bytes(raw)

    def test_expected_size(self):
        h = MdiHeader.from_bytes(make_header_bytes())
        self.assertEqual(h.expected_size(), 31 + 3 * 4)


class PacketTests(unittest.TestCase):
    def test_build_and_parse_distance_and_intensity(self):
        raw = build_packet(
            packet_type=MdiPacketType.DISTANCE_AND_INTENSITY,
            packet_number=7, total_number=2, sub_number=1, scan_freq=80,
            first_angle_mdeg=-10000, delta_angle_mdeg=200, timestamp_ms=42,
            distances_mm=[1000, 2000, 3000], intensities=[100, 200, 300])
        self.assertEqual(len(raw), 31 + 3 * 4)
        self.assertTrue(raw.startswith(SYNC))
        pkt = parse_packet(raw)
        self.assertEqual(pkt.distances_mm, (1000, 2000, 3000))
        self.assertEqual(pkt.intensities, (100, 200, 300))
        self.assertEqual(pkt.angles_mdeg(), [-10000, -9800, -9600])
        # distances come first in the payload, then intensities
        self.assertEqual(struct.unpack(">3H", raw[31:37]), (1000, 2000, 3000))
        self.assertEqual(struct.unpack(">3H", raw[37:43]), (100, 200, 300))

    def test_build_and_parse_distance_only(self):
        raw = build_packet(
            packet_type=MdiPacketType.DISTANCE,
            packet_number=8, total_number=1, sub_number=1, scan_freq=80,
            first_angle_mdeg=0, delta_angle_mdeg=-200, timestamp_ms=0,
            distances_mm=[5, 6])
        self.assertEqual(len(raw), 31 + 2 * 2)
        pkt = parse_packet(raw)
        self.assertEqual(pkt.distances_mm, (5, 6))
        self.assertIsNone(pkt.intensities)

    def test_intensities_required_for_type_1(self):
        with self.assertRaises(ValueError):
            build_packet(
                packet_type=MdiPacketType.DISTANCE_AND_INTENSITY,
                packet_number=0, total_number=1, sub_number=1, scan_freq=80,
                first_angle_mdeg=0, delta_angle_mdeg=1, timestamp_ms=0,
                distances_mm=[1, 2])


class CommandTests(unittest.TestCase):
    def test_frame_command(self):
        self.assertEqual(frame_command("cWN", "SendMDI"), b"\x02cWN SendMDI\x03")
        self.assertEqual(frame_command("cRN", "GetRange"), b"\x02cRN GetRange\x03")

    def test_parse_read_response(self):
        resp = parse_response(b"cRA GetRange -13760 13760")
        self.assertEqual(resp.kind, "cRA")
        self.assertEqual(resp.name, "GetRange")
        self.assertEqual(resp.values, (-13760, 13760))

    def test_parse_write_ack(self):
        resp = parse_response(b"cWA SendMDI")
        self.assertEqual(resp.kind, "cWA")
        self.assertEqual(resp.name, "SendMDI")
        self.assertEqual(resp.values, ())

    def test_parse_rejects_junk(self):
        with self.assertRaises(ValueError):
            parse_response(b"hello world")
        with self.assertRaises(ValueError):
            parse_response(b"cRA GetTem not-a-number")

    def test_find_response_start(self):
        buf = b"garbage\x02cRA GetTem 2350\x03"
        self.assertEqual(find_response_start(buf), 7)
        self.assertEqual(find_response_start(b"no frame here"), -1)
        # a complete signature is 5 bytes; a partial one must not match
        self.assertEqual(find_response_start(b"\x02cRA"), -1)
        # STX that does not start a response is skipped
        buf = b"\x02xyz\x02cWA StopMDI\x03"
        self.assertEqual(find_response_start(buf), 4)


class ResolutionTests(unittest.TestCase):
    def test_resolution_table(self):
        self.assertEqual(Resolution.RES_0200_AT_80HZ.degrees, 0.2)
        self.assertEqual(Resolution.RES_0200_AT_80HZ.frequency_hz, 80.0)
        self.assertEqual(Resolution.RES_0100_AT_40HZ.degrees, 0.1)
        self.assertEqual(Resolution.RES_0050_AT_20HZ.frequency_hz, 20.0)
        self.assertEqual(Resolution.RES_0025_AT_10HZ.degrees, 0.025)
        self.assertEqual(Resolution.RES_0200_AT_50HZ.frequency_hz, 50.0)
        self.assertAlmostEqual(Resolution.RES_0200_AT_50HZ.scan_time_s, 0.02)


if __name__ == "__main__":
    unittest.main()
