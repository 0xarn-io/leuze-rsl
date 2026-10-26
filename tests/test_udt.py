"""Tests for the UDP data telegram ("UDT") receiver -- the RSL 200 / RSL 400 wire format.

Byte layouts are built by hand from the Leuze "RSL 200 / RSL 400 UDP
specification" 50130122 (EN 2024/10/01) tables 3.3-3.6 so that they pin the
wire format independently of the production structs.
"""

import socket
import struct
import threading
import time
import unittest
import warnings

from leuze_rsl.errors import (
    ProtocolError,
    ReceiverStoppedError,
    RSL235Error,
    ScannerConnectionError,
    ScanTimeoutError,
)
from leuze_rsl.simulator import UdtSimulator
from leuze_rsl.udt import (
    FRAME_SIZE,
    GEOMETRY,
    STATUS_PROFILE_TYPE_RSL200,
    TELEGRAM_ID_DISTANCE,
    TELEGRAM_ID_DISTANCE_SIGNAL,
    TELEGRAM_ID_STATUS,
    MeasurementContour,
    RSL235Udt,
    ScannerFamily,
    StatusProfile,
    UdtAssembler,
    UdtFrame,
    locate_contour,
)

# H1 tail and H2 exactly as captured from real RSL 235 hardware.
_H1_H2 = (8, 0, 6, b"\x04\x0b\x01\x32")


def make_frame(total_length, telegram_id, block, scan_number) -> bytes:
    h1_size, follow_flag, request_id, header2 = _H1_H2
    return struct.pack("<IBBH4sHHI", total_length, h1_size, follow_flag,
                       request_id, header2, telegram_id, block, scan_number)


def rsl200_status_block(scan_number, *, contour=(0, 1350, 5), ossd=True,
                        pf_free=True, wf1_free=True, wf2_free=True, parked=False,
                        error=False, warning=False, field_triple=1,
                        voltage_raw=24000, temperature_raw=235, signature=0,
                        error_class=0, error_number=0) -> bytes:
    """28-byte RSL 200 status profile (spec table 3.3) + 8-byte contour (table 3.4)."""
    p = bytearray(28)
    p[0] = STATUS_PROFILE_TYPE_RSL200
    p[1] = 1                                        # safety mode
    p[2] = (0x80 if error else 0) | (0x40 if warning else 0)
    p[3] = ((0x80 if ossd else 0) | (0x40 if pf_free else 0) | (0x20 if wf1_free else 0)
            | (0x10 if wf2_free else 0) | (0x02 if parked else 0))
    p[4] = field_triple
    struct.pack_into("<HH", p, 8, voltage_raw, temperature_raw)
    struct.pack_into("<II", p, 16, scan_number & 0xFFFFFFFF, signature)
    p[24] = error_class
    struct.pack_into("<H", p, 25, error_number)
    if contour is None:
        contour_bytes = bytes(8)                    # measurement transmission inactive
    else:
        contour_bytes = struct.pack("<HHHH", contour[0], contour[1], contour[2], 0)
    return bytes(p) + contour_bytes


def make_status_datagram(scan_number, **kwargs) -> bytes:
    """Spec-conformant RSL 200 extended status profile datagram (56 bytes)."""
    data = rsl200_status_block(scan_number, **kwargs)
    return make_frame(FRAME_SIZE + len(data), TELEGRAM_ID_STATUS, 0, scan_number) + data


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


#: Extended status profile of a real RSL 400, captured with Wireshark by
#: Leuze's RSL 400 ROS driver (leuze_rsl_driver test_parse_data.cpp): scan
#: 338286, A-OSSD on, protective function A active with both fields free,
#: contour 0..2699 step 1 (2700 beams).
RSL400_CAPTURE = bytes([
    0x30, 0x00, 0x00, 0x00, 0x08, 0x00, 0xaf, 0xfe,              # H1
    0x04, 0x15, 0x02, 0xc8,                                      # H2
    0x01, 0x00, 0x00, 0x00, 0x6e, 0x29, 0x05, 0x00,              # ID, block, scan
    0x01, 0x01, 0x02, 0x80, 0x00, 0x00, 0x10, 0x80,              # status profile
    0x6e, 0x29, 0x05, 0x00, 0xe8, 0x11, 0x00, 0xf0,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x8b, 0x0a, 0x01, 0x00, 0x00, 0x00,              # contour
])


class FrameTests(unittest.TestCase):
    def test_parse_real_capture_status_head(self):
        """The exact first 16 bytes captured from real RSL 235 hardware."""
        head = bytes.fromhex("38 00 00 00 08 00 06 00 04 0b 01 32 01 00 00 00"
                             .replace(" ", ""))
        frame = UdtFrame.from_bytes(head + struct.pack("<I", 12345))
        self.assertEqual(frame.total_length, 56)          # 20 + 28 + 8: RSL 200 layout
        self.assertEqual(frame.h1_size, 8)
        self.assertEqual(frame.follow_flag, 0)
        self.assertEqual(frame.request_id, 6)
        self.assertEqual(frame.header2, b"\x04\x0b\x01\x32")
        self.assertEqual(frame.telegram_id, 1)
        self.assertEqual(frame.block, 0)
        self.assertEqual(frame.scan_number, 12345)

    def test_parse_real_capture_measurement_head(self):
        head = bytes.fromhex("50 04 00 00 08 00 06 00 04 0b 01 32 03 00 00 00"
                             .replace(" ", ""))
        frame = UdtFrame.from_bytes(head + struct.pack("<I", 7))
        self.assertEqual(frame.total_length, 1104)      # 20 + 271 beams * 4
        self.assertEqual(frame.telegram_id, 3)
        self.assertEqual((frame.total_length - FRAME_SIZE) // 4, 271)
        # 271 beams is exactly the spec-valid RSL 200 full-range contour (0, 1350, 5)
        self.assertEqual(MeasurementContour(0, 1350, 5).num_beams, 271)

    def test_round_trip(self):
        raw = make_frame(56, 1, 3, 0xDEADBEEF)
        frame = UdtFrame.from_bytes(raw)
        self.assertEqual(frame.to_bytes(), raw)

    def test_short_frame_is_protocol_error(self):
        with self.assertRaises(ProtocolError):
            UdtFrame.from_bytes(b"\x01\x02\x03")
        with self.assertRaises(ValueError):             # ProtocolError is a ValueError
            UdtFrame.from_bytes(b"")


class StatusProfileRsl200Tests(unittest.TestCase):
    """Spec table 3.3 (RSL 200 series, profile type 21)."""

    def test_layout_and_polarity(self):
        data = rsl200_status_block(777, ossd=True, pf_free=False, wf1_free=True,
                                   wf2_free=False, parked=True, warning=True,
                                   field_triple=7, voltage_raw=24000,
                                   temperature_raw=235, signature=0xDEADBEEF,
                                   error_class=2, error_number=1234)
        status = StatusProfile.from_bytes(data)
        self.assertEqual(status.family, ScannerFamily.RSL200)
        self.assertEqual(status.profile_type, 21)
        self.assertEqual(status.profile_length, 28)
        self.assertEqual(status.contour_offset, 28)
        self.assertEqual(status.operating_mode, 1)
        self.assertTrue(status.alarm)
        self.assertFalse(status.error)
        self.assertTrue(status.ossd_a)
        self.assertIsNone(status.ossd_b)
        self.assertTrue(status.a_active)
        self.assertTrue(status.a_protective_violated)      # PF_VIO bit 0 = violated
        self.assertFalse(status.a_warning_violated)        # WF_VIO_1 bit 1 = free
        self.assertTrue(status.warning_field_2_violated)
        self.assertTrue(status.parked)
        self.assertIsNone(status.b_active)
        self.assertEqual(status.scan_number, 777)          # bytes 16..19
        self.assertEqual(status.field_triple, 7)
        self.assertEqual(status.supply_voltage_raw, 24000)
        self.assertAlmostEqual(status.temperature_c, 23.5)
        self.assertEqual(status.signature, 0xDEADBEEF)
        self.assertEqual(status.error_class, 2)
        self.assertEqual(status.error_number, 1234)
        self.assertEqual(len(status.raw), 36)

    def test_every_byte2_and_byte3_flag(self):
        base = bytearray(rsl200_status_block(1, ossd=False, pf_free=False,
                                             wf1_free=False, wf2_free=False))
        checks = [
            (2, 0x80, "error"), (2, 0x40, "alarm"), (2, 0x20, "screen_contaminated"),
            (2, 0x10, "edm_error"), (2, 0x08, "field_selection_error"),
            (2, 0x04, "screen_error"), (2, 0x02, "screen_warning"),
            (3, 0x80, "ossd_a"), (3, 0x08, "restart_interlock"), (3, 0x02, "parked"),
        ]
        for byte, mask, attr in checks:
            with self.subTest(attr=attr):
                data = bytearray(base)
                self.assertFalse(getattr(StatusProfile.from_bytes(bytes(data)), attr))
                data[byte] |= mask
                self.assertTrue(getattr(StatusProfile.from_bytes(bytes(data)), attr))
        # inverted-polarity field bits
        for mask, attr in [(0x40, "a_protective_violated"), (0x20, "a_warning_violated"),
                           (0x10, "warning_field_2_violated")]:
            with self.subTest(attr=attr):
                data = bytearray(base)
                self.assertTrue(getattr(StatusProfile.from_bytes(bytes(data)), attr))
                data[3] |= mask
                self.assertFalse(getattr(StatusProfile.from_bytes(bytes(data)), attr))

    def test_inputs_outputs_bitmasks(self):
        data = bytearray(rsl200_status_block(1))
        data[6] = 0b0000_0101
        data[7] = 0b1000_0000
        status = StatusProfile.from_bytes(bytes(data))
        self.assertEqual(status.inputs, 0b0000_0101)      # IN1 and IN3
        self.assertEqual(status.outputs, 0b1000_0000)     # OUT8

    def test_too_short_for_type(self):
        with self.assertRaises(ProtocolError):
            StatusProfile.from_bytes(rsl200_status_block(1)[:27])


class StatusProfileRsl400Tests(unittest.TestCase):
    """Spec table 3.5 (RSL 400 series, profile type 1), checked on a real capture."""

    def test_real_capture(self):
        frame = UdtFrame.from_bytes(RSL400_CAPTURE)
        self.assertEqual(frame.total_length, 48)
        self.assertEqual(frame.scan_number, 338286)
        status = StatusProfile.from_bytes(RSL400_CAPTURE[FRAME_SIZE:])
        self.assertEqual(status.family, ScannerFamily.RSL400)
        self.assertEqual(status.profile_length, 20)
        self.assertEqual(status.contour_offset, 20)
        self.assertEqual(status.scan_number, frame.scan_number)   # bytes 8..11
        self.assertEqual(status.operating_mode, 1)
        self.assertTrue(status.ossd_a)
        self.assertFalse(status.ossd_b)
        self.assertTrue(status.estop_active)
        self.assertTrue(status.a_active)
        self.assertFalse(status.a_protective_violated)     # bit set = free
        self.assertFalse(status.a_warning_violated)
        self.assertEqual((status.a_bank, status.a_field_pair), (1, 1))
        self.assertFalse(status.b_active)
        self.assertFalse(status.b_protective_violated)      # inactive function: never "violated"
        self.assertFalse(status.b_warning_violated)
        self.assertIsNone(status.configuration_signature)
        contour = MeasurementContour.from_bytes(RSL400_CAPTURE[FRAME_SIZE:], status.contour_offset)
        self.assertEqual((contour.start_index, contour.stop_index, contour.index_interval),
                         (0, 2699, 1))
        self.assertEqual(contour.num_beams, 2700)
        self.assertTrue(contour.plausible(ScannerFamily.RSL400))

    def test_field_violation_polarity(self):
        data = bytearray(RSL400_CAPTURE[FRAME_SIZE:])
        data[12] = 0x80            # A active, warning + protective field VIOLATED (bits 6/5 = 0)
        data[16] = 0x80 | 0x40     # B active, warning field free, protective field violated
        status = StatusProfile.from_bytes(bytes(data))
        self.assertTrue(status.a_protective_violated)
        self.assertTrue(status.a_warning_violated)
        self.assertTrue(status.b_protective_violated)
        self.assertFalse(status.b_warning_violated)
        self.assertTrue(status.b_active)

    def test_signature_trailer(self):
        data = RSL400_CAPTURE[FRAME_SIZE:] + b"\x01\x00\x08\x00" + bytes(range(8))
        status = StatusProfile.from_bytes(data)
        self.assertEqual(status.configuration_signature, bytes(range(8)))

    def test_unknown_profile_type_decodes_common_bits_only(self):
        data = bytes([99, 2, 0x80 | 0x40]) + bytes(40)
        status = StatusProfile.from_bytes(data)
        self.assertIsNone(status.family)
        self.assertIsNone(status.contour_offset)
        self.assertEqual(status.operating_mode, 2)
        self.assertTrue(status.error)
        self.assertTrue(status.alarm)
        self.assertFalse(status.ossd_a)


class ContourTests(unittest.TestCase):
    def test_num_beams_formula(self):
        self.assertEqual(MeasurementContour(0, 1350, 5).num_beams, 271)
        self.assertEqual(MeasurementContour(0, 1350, 1).num_beams, 1351)
        self.assertEqual(MeasurementContour(0, 2699, 1).num_beams, 2700)
        # ceil: 2700/8 = 337.5 -> 338 (+1)
        self.assertEqual(MeasurementContour(0, 2700, 8).num_beams, 339)
        self.assertEqual(MeasurementContour(100, 200, 4).num_beams, 26)

    def test_validation(self):
        with self.assertRaises(ProtocolError):
            MeasurementContour(0, 100, 0)
        with self.assertRaises(ProtocolError):
            MeasurementContour(200, 100, 1)
        self.assertIsNone(MeasurementContour.from_bytes(bytes(8)))        # inactive
        with self.assertRaises(ProtocolError):
            MeasurementContour.from_bytes(bytes(7))

    def test_plausible_per_family(self):
        self.assertTrue(MeasurementContour(0, 1350, 8).plausible(ScannerFamily.RSL200))
        self.assertFalse(MeasurementContour(0, 1351, 1).plausible(ScannerFamily.RSL200))
        self.assertFalse(MeasurementContour(0, 2700, 10).plausible(ScannerFamily.RSL400))
        self.assertTrue(MeasurementContour(0, 2699, 1).plausible(ScannerFamily.RSL400))

    def test_locate_heuristic_prefers_matching_beam_count(self):
        # decoy at offset 20 (101 beams), real contour at 28 (271 beams)
        data = bytearray(36)
        data[20:28] = struct.pack("<HHHH", 0, 100, 1, 0)
        data[28:36] = struct.pack("<HHHH", 0, 1350, 5, 0)
        offset, contour = locate_contour(bytes(data), expected_beams=271)
        self.assertEqual(offset, 28)
        self.assertEqual(contour.num_beams, 271)
        self.assertIsNone(locate_contour(bytes(36), None))


class AssemblerTests(unittest.TestCase):
    def test_single_fragment_scan_with_status(self):
        asm = UdtAssembler()
        distances = list(range(1000, 1000 + 271))
        signals = [500] * 271
        scans = asm.feed_datagram(make_status_datagram(7))
        self.assertEqual(scans, [])
        self.assertEqual(asm.family, ScannerFamily.RSL200)
        self.assertEqual(asm.contour.num_beams, 271)
        # contour known + beam count matches -> emitted immediately
        scans = asm.feed_datagram(make_measurement_datagram(7, 0, distances, signals))
        self.assertEqual(len(scans), 1)
        scan = scans[0]
        self.assertEqual(scan.scan_number, 7)
        self.assertEqual(scan.num_beams, 271)
        self.assertTrue(scan.complete)
        self.assertEqual(scan.distances_mm[0], 1000)
        self.assertEqual(scan.signal_strengths[0], 500)
        self.assertEqual(scan.num_blocks, 1)
        self.assertEqual(scan.blocks, (0,))
        self.assertEqual(scan.status.scan_number, 7)
        self.assertEqual(scan.family, ScannerFamily.RSL200)

    def test_multi_fragment_assembly(self):
        asm = UdtAssembler()
        asm.feed_datagram(make_status_datagram(1))
        distances = list(range(271))
        scans = []
        scans += asm.feed_datagram(make_measurement_datagram(1, 0, distances[:100], [1] * 100))
        scans += asm.feed_datagram(make_measurement_datagram(1, 1, distances[100:200], [1] * 100))
        self.assertEqual(scans, [])
        scans += asm.feed_datagram(make_measurement_datagram(1, 2, distances[200:], [1] * 71))
        self.assertEqual(len(scans), 1)
        self.assertEqual(scans[0].distances_mm, tuple(distances))
        self.assertEqual(scans[0].num_blocks, 3)
        self.assertEqual(scans[0].block_beams, (100, 100, 71))

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

    def test_lost_leading_block_dropped_in_strict_mode(self):
        """A run of blocks not starting at 0 is not complete (regression)."""
        asm = UdtAssembler()
        asm.feed_datagram(make_status_datagram(1))
        asm.feed_datagram(make_measurement_datagram(1, 1, [1] * 100, [1] * 100))
        asm.feed_datagram(make_measurement_datagram(1, 2, [1] * 71, [1] * 71))
        self.assertEqual(asm.feed_datagram(make_status_datagram(2)), [])
        self.assertEqual(asm.stats.scans_dropped_incomplete, 1)

    def test_no_contour_means_no_complete_scan(self):
        """Without a status telegram completeness cannot be verified (regression)."""
        asm = UdtAssembler()
        self.assertEqual(asm.feed_datagram(make_measurement_datagram(3, 0, [1, 2, 3])), [])
        self.assertEqual(asm.feed_datagram(make_measurement_datagram(4, 0, [4, 5, 6])), [])
        self.assertEqual(asm.stats.scans_dropped_incomplete, 1)
        lenient = UdtAssembler(strict=False)
        lenient.feed_datagram(make_measurement_datagram(3, 0, [1, 2, 3]))
        scans = lenient.feed_datagram(make_measurement_datagram(4, 0, [4, 5, 6]))
        self.assertEqual(len(scans), 1)
        self.assertFalse(scans[0].complete)
        self.assertEqual(scans[0].distances_mm, (1, 2, 3))
        self.assertIsNone(scans[0].signal_strengths)
        self.assertEqual(scans[0].beam_indices(), [0, 1, 2])
        self.assertEqual(lenient.stats.scans_incomplete, 1)

    def test_lenient_mode_reconstructs_beam_indices_of_received_blocks(self):
        asm = UdtAssembler(strict=False)
        asm.feed_datagram(make_status_datagram(1))
        asm.feed_datagram(make_measurement_datagram(1, 0, [10] * 100, [1] * 100))
        asm.feed_datagram(make_measurement_datagram(1, 2, [30] * 71, [1] * 71))   # block 1 lost
        scans = asm.feed_datagram(make_status_datagram(2))
        self.assertEqual(len(scans), 1)
        scan = scans[0]
        self.assertFalse(scan.complete)
        self.assertEqual(scan.blocks, (0, 2))
        indices = scan.beam_indices()
        self.assertEqual(len(indices), 171)
        self.assertEqual(indices[:2], [0, 5])
        self.assertEqual(indices[100], 200 * 5)          # first beam of block 2
        self.assertEqual(indices[-1], 1350)

    def test_status_after_data_order_is_tolerated(self):
        """The spec sends status first; a device sending it after the data still works."""
        asm = UdtAssembler()
        asm.feed_datagram(make_measurement_datagram(1, 0, [1] * 271, [1] * 271))
        self.assertEqual(asm.feed_datagram(make_status_datagram(1)), [])      # same cycle
        scans = asm.feed_datagram(make_measurement_datagram(2, 0, [2] * 271, [1] * 271))
        # scan 1 is finalized by the newer cycle; scan 2 completes at once (contour known)
        self.assertEqual([(s.scan_number, s.complete) for s in scans], [(1, True), (2, True)])
        self.assertEqual(scans[0].status.scan_number, 1)
        self.assertEqual(scans[0].family, ScannerFamily.RSL200)
        self.assertIsNone(scans[1].status)                 # scan 2's status not seen (yet)

    def test_inactive_contour(self):
        asm = UdtAssembler()
        asm.feed_datagram(make_status_datagram(1, contour=None))
        self.assertIsNotNone(asm.latest_status)
        self.assertIsNone(asm.contour)

    def test_status_attached_is_the_scans_own_cycle(self):
        """Status is per cycle; a lost status telegram gives status=None (regression)."""
        asm = UdtAssembler()
        asm.feed_datagram(make_status_datagram(5, ossd=True))
        asm.feed_datagram(make_measurement_datagram(5, 0, [1] * 100, [1] * 100))   # incomplete...
        scans = asm.feed_datagram(make_status_datagram(6, ossd=False))         # ...finalized here
        self.assertEqual(scans, [])
        # scan 6's status telegram was received before its data
        scans = asm.feed_datagram(make_measurement_datagram(6, 0, [1] * 271, [1] * 271))
        self.assertFalse(scans[0].status.ossd_a)
        self.assertEqual(scans[0].status.scan_number, 6)
        # scan 7's status telegram is lost: its data still completes, status None
        scans = asm.feed_datagram(make_measurement_datagram(7, 0, [1] * 271, [1] * 271))
        self.assertEqual(len(scans), 1)
        self.assertIsNone(scans[0].status)
        self.assertEqual(scans[0].family, ScannerFamily.RSL200)
        self.assertTrue(scans[0].complete)

    def test_truncated_datagram_rejected(self):
        asm = UdtAssembler()
        self.assertEqual(asm.feed_datagram(b"\x01\x02\x03"), [])
        datagram = make_status_datagram(1)
        self.assertEqual(asm.feed_datagram(datagram[:30]), [])
        self.assertEqual(asm.stats.bad_frames, 2)

    def test_trailing_padding_tolerated_and_partial_beams_counted(self):
        asm = UdtAssembler()
        asm.feed_datagram(make_status_datagram(1, contour=(0, 20, 10)))      # 3 beams
        datagram = make_measurement_datagram(1, 0, [1, 2, 3], [4, 5, 6])
        scans = asm.feed_datagram(datagram + b"\x00\x00")                     # padding
        self.assertEqual(len(scans), 1)
        asm.feed_datagram(make_status_datagram(2, contour=(0, 20, 10)))
        odd = make_measurement_datagram(2, 0, [1, 2, 3], [4, 5, 6])
        odd = struct.pack("<I", len(odd) + 3) + odd[4:] + b"\x01\x02\x03"
        scans = asm.feed_datagram(odd)
        self.assertEqual(len(scans), 1)
        self.assertEqual(asm.stats.bytes_discarded, 3)

    def test_unknown_telegram_id_counted(self):
        asm = UdtAssembler()
        asm.feed_datagram(make_frame(FRAME_SIZE + 4, 42, 0, 1) + bytes(4))
        self.assertEqual(asm.stats.unknown_ids, 1)

    def test_scan_number_wraparound(self):
        asm = UdtAssembler()
        asm.feed_datagram(make_status_datagram(0xFFFFFFFF, contour=(0, 90, 10)))  # 10 beams
        asm.feed_datagram(make_measurement_datagram(0xFFFFFFFF, 0, [7] * 5, [1] * 5))
        scans = asm.feed_datagram(make_measurement_datagram(0xFFFFFFFF, 1, [7] * 5, [1] * 5))
        self.assertEqual([s.scan_number for s in scans], [0xFFFFFFFF])
        scans = asm.feed_datagram(make_status_datagram(0, contour=(0, 90, 10)))
        scans += asm.feed_datagram(make_measurement_datagram(0, 0, [8] * 10, [1] * 10))
        self.assertEqual([s.scan_number for s in scans], [0])        # wrap: 0 is newer
        self.assertEqual(asm.stats.stale_datagrams, 0)

    def test_duplicate_or_late_datagram_is_ignored(self):
        """A finished scan is never delivered twice (regression)."""
        asm = UdtAssembler()
        asm.feed_datagram(make_status_datagram(10))
        datagram = make_measurement_datagram(10, 0, [1] * 271, [1] * 271)
        self.assertEqual(len(asm.feed_datagram(datagram)), 1)
        self.assertEqual(asm.feed_datagram(datagram), [])                   # duplicate
        self.assertEqual(asm.feed_datagram(make_measurement_datagram(9, 0, [1] * 271, [1] * 271)), [])
        self.assertEqual(asm.feed_datagram(make_status_datagram(9)), [])    # late status: accepted, harmless
        self.assertEqual(asm.stats.stale_datagrams, 2)
        self.assertEqual(asm.stats.scans_completed, 1)

    def test_status_after_data_every_cycle(self):
        """Status telegrams are never 'stale', so a status-after-data device keeps working."""
        asm = UdtAssembler()
        got = []
        for n in range(1, 6):
            got += asm.feed_datagram(make_measurement_datagram(n, 0, [n] * 271, [1] * 271))
            got += asm.feed_datagram(make_status_datagram(n, ossd=bool(n % 2)))
        self.assertEqual([s.scan_number for s in got], [1, 2, 3, 4, 5])
        self.assertEqual(asm.stats.stale_datagrams, 0)
        self.assertEqual(asm.latest_status.scan_number, 5)

    def test_restart_flush_returns_lenient_scans(self):
        asm = UdtAssembler(strict=False)
        asm.feed_datagram(make_status_datagram(50))
        asm.feed_datagram(make_measurement_datagram(50, 0, [1] * 100, [1] * 100))   # partial
        asm._last_activity -= 5.0
        scans = asm.feed_datagram(make_status_datagram(0))                           # restart
        self.assertEqual([(s.scan_number, s.complete) for s in scans], [(50, False)])

    def test_index_resolution_alias_reproduces_the_default(self):
        from leuze_rsl.udt import DEFAULT_ANGLE_AT_INDEX0_DEG, INDEX_RESOLUTION_DEG
        asm = UdtAssembler()
        asm.feed_datagram(make_status_datagram(1))
        scan = asm.feed_datagram(make_measurement_datagram(1, 0, [1] * 271, [1] * 271))[0]
        self.assertEqual(scan.angles_deg(DEFAULT_ANGLE_AT_INDEX0_DEG, INDEX_RESOLUTION_DEG),
                         scan.angles_deg())

    def test_scanner_restart_resets_the_sequence(self):
        asm = UdtAssembler()
        asm.feed_datagram(make_status_datagram(5000))
        asm.feed_datagram(make_measurement_datagram(5000, 0, [1] * 271, [1] * 271))
        asm._last_activity -= 5.0                        # scanner was silent for 5 s
        scans = asm.feed_datagram(make_status_datagram(0))
        scans += asm.feed_datagram(make_measurement_datagram(0, 0, [2] * 271, [1] * 271))
        self.assertEqual([s.scan_number for s in scans], [0])
        self.assertEqual(asm.stats.sequence_resets, 1)

    def test_pending_scans_never_accumulate(self):
        """Older scan numbers behind the stream are stale, so at most one cycle is in flight."""
        asm = UdtAssembler(strict=False, max_pending=3)
        for number in (100, 99, 98, 97, 96, 95):
            asm.feed_datagram(make_measurement_datagram(number, 0, [1] * 5))
        self.assertEqual(list(asm._pending), [100])
        self.assertEqual(asm.stats.stale_datagrams, 5)
        for number in (101, 102, 103):                    # newer: each finalizes the previous
            asm.feed_datagram(make_measurement_datagram(number, 0, [1] * 5))
        self.assertEqual(list(asm._pending), [103])
        self.assertEqual(asm.stats.scans_completed, 3)

    def test_single_forged_far_ahead_datagram_does_not_blind_the_receiver(self):
        """One foreign datagram 200 cycles ahead must not make genuine cycles stale."""
        asm = UdtAssembler()
        got = []
        for n in range(1, 4):
            got += asm.feed_datagram(make_status_datagram(n))
            got += asm.feed_datagram(make_measurement_datagram(n, 0, [n] * 271, [1] * 271))
        got += asm.feed_datagram(make_measurement_datagram(203, 0, [9] * 10, [1] * 10))  # stray data
        for n in range(4, 6):
            got += asm.feed_datagram(make_status_datagram(n))
            got += asm.feed_datagram(make_measurement_datagram(n, 0, [n] * 271, [1] * 271))
        got += asm.feed_datagram(make_status_datagram(305, contour=(0, 100, 1)))         # stray status
        for n in range(6, 8):
            got += asm.feed_datagram(make_status_datagram(n))
            got += asm.feed_datagram(make_measurement_datagram(n, 0, [n] * 271, [1] * 271))
        self.assertEqual([s.scan_number for s in got], [1, 2, 3, 4, 5, 6, 7])
        self.assertEqual(asm.stats.stale_datagrams, 0)
        self.assertEqual(asm.stats.outlier_datagrams, 2)
        self.assertEqual(asm.contour.num_beams, 271)              # forged status not adopted
        self.assertEqual(asm.latest_status.scan_number, 7)

    def test_confirmed_forward_jump_is_accepted(self):
        """After an outage the stream resumes far ahead: the second datagram confirms it."""
        asm = UdtAssembler()
        asm.feed_datagram(make_status_datagram(1))
        asm.feed_datagram(make_measurement_datagram(1, 0, [1] * 271, [1] * 271))
        got = asm.feed_datagram(make_status_datagram(500))                                # outlier
        got += asm.feed_datagram(make_measurement_datagram(500, 0, [5] * 271, [1] * 271))  # confirms
        got += asm.feed_datagram(make_status_datagram(501))
        got += asm.feed_datagram(make_measurement_datagram(501, 0, [5] * 271, [1] * 271))
        self.assertEqual([s.scan_number for s in got], [500, 501])
        self.assertEqual(asm.stats.sequence_jumps, 1)
        self.assertIsNone(got[0].status)                          # its status arrived unconfirmed
        self.assertEqual(got[1].status.scan_number, 501)

    def test_mixed_telegram_ids_rejected(self):
        asm = UdtAssembler()
        asm.feed_datagram(make_status_datagram(1, contour=(0, 10, 10)))   # 2 beams
        asm.feed_datagram(make_measurement_datagram(1, 0, [1], [1]))      # ID 3
        scans = asm.feed_datagram(make_measurement_datagram(1, 1, [2]))   # ID 6 under same scan
        self.assertEqual(scans, [])
        self.assertEqual(asm.stats.bad_frames, 1)

    def test_empty_measurement_payload_never_yields_a_scan(self):
        for strict in (True, False):
            asm = UdtAssembler(strict=strict)
            asm.feed_datagram(make_status_datagram(1, contour=(0, 10, 10)))      # 2 beams
            asm.feed_datagram(make_measurement_datagram(1, 0, [5]))              # first beam
            # an empty datagram is bogus: counted, and it must not finish scan 1
            self.assertEqual(asm.feed_datagram(make_frame(FRAME_SIZE, TELEGRAM_ID_DISTANCE, 1, 1)), [])
            self.assertEqual(asm.stats.bad_frames, 1)
            scans = asm.feed_datagram(make_measurement_datagram(1, 1, [6]))      # completes
            self.assertEqual([(s.num_beams, s.complete) for s in scans], [(2, True)])

    def test_oversize_scan_is_discarded(self):
        asm = UdtAssembler(strict=False)
        for block in range(70):                                   # 70 distinct fragments
            asm.feed_datagram(make_measurement_datagram(1, block, [1]))
        self.assertEqual(asm.stats.scans_dropped_oversize, 1)
        self.assertEqual(asm._pending, {})
        # the discarded cycle counts as finished: its remaining datagrams are stale
        self.assertEqual(asm.feed_datagram(make_measurement_datagram(1, 70, [1])), [])
        self.assertEqual(asm.stats.stale_datagrams, 6)

    def test_large_backward_jump_is_a_restart_even_without_a_pause(self):
        asm = UdtAssembler()
        asm.feed_datagram(make_status_datagram(100000))
        asm.feed_datagram(make_measurement_datagram(100000, 0, [1] * 271, [1] * 271))
        scans = asm.feed_datagram(make_status_datagram(3))        # counter reset, no pause
        scans += asm.feed_datagram(make_measurement_datagram(3, 0, [2] * 271, [1] * 271))
        self.assertEqual([s.scan_number for s in scans], [3])
        self.assertEqual(asm.stats.sequence_resets, 1)
        # but a datagram a few cycles behind, right after the stream, is stale
        self.assertEqual(asm.feed_datagram(make_measurement_datagram(2, 0, [2] * 271, [1] * 271)), [])
        self.assertEqual(asm.stats.stale_datagrams, 1)

    def test_unknown_profile_type_uses_heuristic_and_self_heals(self):
        """A decoy contour at the documented RSL 400 offset must not stick (regression)."""
        def status(scan):
            data = bytearray(44)
            data[0] = 99                                   # unknown profile type
            data[20:28] = struct.pack("<HHHH", 0, 100, 1, 0)       # plausible decoy: 101 beams
            data[36:44] = struct.pack("<HHHH", 0, 1350, 5, 0)      # real contour: 271 beams
            return make_frame(FRAME_SIZE + len(data), TELEGRAM_ID_STATUS, 0, scan) + bytes(data)
        asm = UdtAssembler()
        asm.feed_datagram(status(1))
        self.assertEqual(asm.contour.num_beams, 101)     # heuristic picks the decoy first
        self.assertEqual(asm.feed_datagram(make_measurement_datagram(1, 0, [1] * 271, [1] * 271)), [])
        scans = asm.feed_datagram(status(2))              # scan 1 dropped, beam count learned
        self.assertEqual(scans, [])
        self.assertEqual(asm.contour.num_beams, 271)     # relocated to the real contour
        scans = asm.feed_datagram(make_measurement_datagram(2, 0, [1] * 271, [1] * 271))
        self.assertEqual(len(scans), 1)
        self.assertTrue(scans[0].complete)


class ScanViewTests(unittest.TestCase):
    def make_scan(self, family=ScannerFamily.RSL200, contour=(0, 1350, 5), values=None):
        asm = UdtAssembler()
        n = MeasurementContour(*contour).num_beams
        values = values or [1000] * n
        if family is ScannerFamily.RSL200:
            asm.feed_datagram(make_status_datagram(1, contour=contour))
        else:
            data = bytearray(RSL400_CAPTURE[FRAME_SIZE:])
            data[8:12] = struct.pack("<I", 1)
            data[20:28] = struct.pack("<HHHH", contour[0], contour[1], contour[2], 0)
            asm.feed_datagram(make_frame(FRAME_SIZE + len(data), TELEGRAM_ID_STATUS, 0, 1) + bytes(data))
        scans = asm.feed_datagram(make_measurement_datagram(1, 0, values, [100] * n))
        self.assertEqual(len(scans), 1)
        return scans[0]

    def test_rsl200_geometry(self):
        scan = self.make_scan()
        angles = scan.angles_deg()
        self.assertAlmostEqual(angles[0], 135.0)          # index 0 at the CCW edge
        self.assertAlmostEqual(angles[1], 134.0)          # 5 indices * 0.2 deg
        self.assertAlmostEqual(angles[-1], -135.0)
        self.assertEqual(scan.no_echo_mm, 32767)
        self.assertEqual(scan.geometry, GEOMETRY[ScannerFamily.RSL200])

    def test_rsl400_geometry(self):
        scan = self.make_scan(family=ScannerFamily.RSL400, contour=(0, 2699, 1))
        angles = scan.angles_deg()
        self.assertEqual(len(angles), 2700)
        self.assertAlmostEqual(angles[0], 134.95)
        self.assertAlmostEqual(angles[-1], -134.95)
        self.assertEqual(scan.no_echo_mm, 65535)

    def test_geometry_override(self):
        scan = self.make_scan(contour=(0, 10, 5))         # 3 beams: indices 0, 5, 10
        self.assertEqual(scan.angles_deg(angle_at_index0=-137.5, index_resolution=0.1),
                         [-137.5, -137.0, -136.5])

    def test_no_echo_sentinel_handling(self):
        """Real RSL 235 hardware reports 32767 mm for beams without echo."""
        scan = self.make_scan(contour=(0, 15, 5), values=[1000, 32767, 0, 2000])
        self.assertEqual(scan.valid_mask(), [True, False, False, True])
        self.assertEqual(len(scan.to_cartesian()), 2)
        self.assertEqual(len(scan.to_cartesian(skip_invalid=False)), 4)
        self.assertEqual(scan.valid_mask(max_valid_mm=1500), [True, False, False, False])
        self.assertEqual(len(scan.to_cartesian(max_valid_mm=1500)), 1)

    def test_rsl400_sentinel_is_65535(self):
        scan = self.make_scan(family=ScannerFamily.RSL400, contour=(0, 3, 1),
                              values=[40000, 65535, 0, 1])
        self.assertEqual(scan.valid_mask(), [True, False, False, True])

    def test_cartesian_frame(self):
        scan = self.make_scan(contour=(675, 675, 1), values=[2000])   # index 675 -> 0 deg
        (x, y), = scan.to_cartesian()
        self.assertAlmostEqual(x, 2.0)
        self.assertAlmostEqual(y, 0.0)
        scan = self.make_scan(contour=(225, 225, 1), values=[1000])   # 135 - 45 = +90 deg
        (x, y), = scan.to_cartesian()
        self.assertAlmostEqual(x, 0.0)
        self.assertAlmostEqual(y, 1.0)

    def test_distances_m_is_cached_tuple(self):
        scan = self.make_scan(contour=(0, 5, 5), values=[1500, 250])
        self.assertEqual(scan.distances_m, (1.5, 0.25))
        self.assertIs(scan.distances_m, scan.distances_m)


class EndToEndTests(unittest.TestCase):
    @staticmethod
    def free_udp_port() -> int:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        return port

    def start_receiver(self, **kwargs) -> RSL235Udt:
        receiver = RSL235Udt(port=kwargs.pop("port", self.free_udp_port()), **kwargs)
        receiver.start()
        self.addCleanup(receiver.stop)
        return receiver

    def start_simulator(self, port, **kwargs) -> UdtSimulator:
        sim = UdtSimulator(target_port=port, scan_period_s=kwargs.pop("scan_period_s", 0.01), **kwargs).start()
        self.addCleanup(sim.stop)
        return sim

    def test_receive_from_simulator(self):
        receiver = self.start_receiver(source_ip="127.0.0.1")
        self.start_simulator(receiver.port)
        scans = [receiver.get_scan(timeout=5.0) for _ in range(3)]
        numbers = [s.scan_number for s in scans]
        self.assertEqual(numbers, sorted(numbers))
        for scan in scans:
            self.assertEqual(scan.num_beams, 271)
            self.assertTrue(scan.complete)
            self.assertEqual(scan.family, ScannerFamily.RSL200)
            self.assertIsNotNone(scan.signal_strengths)
            self.assertEqual(scan.status.scan_number, scan.scan_number)
            self.assertTrue(scan.status.ossd_a)
            valid = [d for d, ok in zip(scan.distances_mm, scan.valid_mask()) if ok]
            self.assertGreaterEqual(min(valid), 1900)        # 6 x 4 m room
            self.assertLessEqual(max(valid), 3700)
        self.assertTrue(receiver.is_receiving)
        self.assertEqual(receiver.family, ScannerFamily.RSL200)
        self.assertEqual(receiver.contour.num_beams, 271)

    def test_multi_datagram_scans_and_drops(self):
        receiver = self.start_receiver()
        # 271 beams in chunks of 100 -> blocks 0..2; drop block 1 of scan 2
        self.start_simulator(receiver.port, beams_per_datagram=100, drop_blocks={2: {1}})
        scans = [receiver.get_scan(timeout=5.0) for _ in range(4)]
        for scan in scans:
            self.assertEqual(scan.num_beams, 271)
            self.assertEqual(scan.num_blocks, 3)
            self.assertTrue(scan.complete)
        deadline = time.monotonic() + 2.0
        while (receiver.stats["scans_dropped_incomplete"] < 1
               and time.monotonic() < deadline):
            time.sleep(0.02)
        self.assertGreaterEqual(receiver.stats["scans_dropped_incomplete"], 1)

    def test_rsl400_layout_end_to_end(self):
        receiver = self.start_receiver()
        self.start_simulator(receiver.port, family=ScannerFamily.RSL400)
        scan = receiver.get_scan(timeout=5.0)
        self.assertEqual(scan.family, ScannerFamily.RSL400)
        self.assertEqual(scan.num_beams, 2700)
        self.assertEqual(receiver.contour.num_beams, 2700)
        self.assertAlmostEqual(scan.angles_deg()[0], 134.95)

    def test_source_filtering_and_callbacks(self):
        seen_scans, seen_status = [], []
        receiver = self.start_receiver(source_ip="203.0.113.1",      # nothing matches
                                       on_scan=seen_scans.append,
                                       on_status=seen_status.append)
        self.start_simulator(receiver.port)
        with self.assertRaises(ScanTimeoutError):
            receiver.get_scan(timeout=0.3)
        self.assertGreater(receiver.stats["foreign_datagrams_dropped"], 0)
        self.assertEqual(seen_scans, [])
        self.assertEqual(seen_status, [])
        self.assertFalse(receiver.is_receiving)               # filtered datagrams do not count
        receiver.stop()

        # correct source: callbacks fire
        receiver2 = self.start_receiver(port=receiver.port, source_ip="127.0.0.1",
                                        on_scan=seen_scans.append,
                                        on_status=seen_status.append)
        receiver2.get_scan(timeout=5.0)
        self.assertGreaterEqual(len(seen_scans), 1)
        self.assertGreaterEqual(len(seen_status), 1)

    def test_scan_timeout_is_both_hierarchies(self):
        receiver = self.start_receiver()
        with self.assertRaises(TimeoutError):
            receiver.get_scan(timeout=0.2)
        with self.assertRaises(RSL235Error):
            receiver.get_scan(timeout=0.2)

    def test_stop_wakes_blocked_get_scan(self):
        receiver = self.start_receiver()
        result = []

        def waiter():
            try:
                receiver.get_scan()                      # no timeout
            except RSL235Error as exc:
                result.append(exc)
        thread = threading.Thread(target=waiter)
        thread.start()
        time.sleep(0.2)
        t0 = time.monotonic()
        receiver.stop()
        thread.join(timeout=3.0)
        self.assertFalse(thread.is_alive())
        self.assertLess(time.monotonic() - t0, 2.0)
        self.assertIsInstance(result[0], ReceiverStoppedError)
        with self.assertRaises(ReceiverStoppedError):
            receiver.get_scan(timeout=1.0)              # stays stopped
        self.assertEqual(list(receiver.scans()), [])

    def test_get_scan_before_start_raises(self):
        receiver = RSL235Udt(port=self.free_udp_port())
        with self.assertRaises(ReceiverStoppedError):
            receiver.get_scan(timeout=1.0)

    def test_restart_discards_stale_scans(self):
        receiver = self.start_receiver()
        sim = self.start_simulator(receiver.port)
        receiver.get_scan(timeout=5.0)
        time.sleep(0.1)                                   # let a few scans queue up
        sim.stop()
        receiver.stop()
        self.assertFalse(receiver.is_receiving)
        receiver.start()                                  # same object, same port
        self.assertFalse(receiver.is_receiving)
        with self.assertRaises(ScanTimeoutError):
            receiver.get_scan(timeout=0.3)                # nothing stale is served
        self.start_simulator(receiver.port)
        scan = receiver.get_scan(timeout=5.0)
        self.assertTrue(scan.complete)

    def test_second_receiver_on_same_port_fails_loudly(self):
        receiver = self.start_receiver()
        second = RSL235Udt(port=receiver.port)
        with self.assertRaises(ScannerConnectionError):
            second.start()
        self.assertFalse(second.is_running)

    def test_scans_iterator_with_timeout(self):
        receiver = self.start_receiver()
        self.start_simulator(receiver.port)
        got = []
        for scan in receiver.scans(timeout=5.0):
            got.append(scan)
            if len(got) == 2:
                break
        self.assertEqual(len(got), 2)

    def test_queue_overflow_drops_oldest(self):
        receiver = self.start_receiver(scan_queue_size=2)
        self.start_simulator(receiver.port, scan_period_s=0.002)
        deadline = time.monotonic() + 3.0
        while receiver.stats["scans_dropped_queue"] == 0 and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertGreater(receiver.stats["scans_dropped_queue"], 0)
        first = receiver.get_scan(timeout=1.0)
        second = receiver.get_scan(timeout=1.0)
        self.assertGreater(second.scan_number, first.scan_number)   # oldest dropped, order kept

    def test_callback_exception_does_not_kill_receiver(self):
        def boom(scan):
            raise RuntimeError("callback bug")
        receiver = self.start_receiver(on_scan=boom)
        with self.assertLogs("leuze_rsl.udt", level="ERROR"):
            self.start_simulator(receiver.port)
            scan = receiver.get_scan(timeout=5.0)
        self.assertTrue(scan.complete)
        self.assertTrue(receiver.is_running)

    def test_receiver_socket_failure_wakes_waiters(self):
        receiver = self.start_receiver()
        with self.assertLogs("leuze_rsl.udt", level="ERROR"):
            receiver._sock.close()                       # simulate an unexpected socket error
            with self.assertRaises(ScannerConnectionError):
                receiver.get_scan()                      # no timeout: woken by the failure
        self.assertFalse(receiver.is_running)
        self.assertFalse(receiver.is_receiving)
        with self.assertRaises(ScannerConnectionError):
            receiver.get_scan(timeout=0.2)
        receiver.start()                                  # restartable
        self.assertTrue(receiver.is_running)

    def test_parser_error_is_counted_and_does_not_kill_the_receiver(self):
        receiver = self.start_receiver()
        original = receiver._assembler.feed_datagram
        calls = []

        def flaky(data):
            if not calls:
                calls.append(1)
                raise RuntimeError("parser bug")
            return original(data)
        receiver._assembler.feed_datagram = flaky
        with self.assertLogs("leuze_rsl.udt", level="ERROR"):
            self.start_simulator(receiver.port)
            scan = receiver.get_scan(timeout=5.0)
        self.assertTrue(scan.complete)
        self.assertEqual(receiver.stats["receiver_errors"], 1)
        self.assertTrue(receiver.is_running)

    def test_constructor_validation(self):
        for kwargs in (dict(port=0), dict(port=70000),
                       dict(data_timeout=0), dict(source_ip="not a host.invalid")):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                RSL235Udt(**kwargs)

    def test_no_resource_warnings(self):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            receiver = RSL235Udt(port=self.free_udp_port())
            receiver.start()
            receiver.stop()
            receiver = None
            import gc
            gc.collect()
        self.assertEqual([w for w in caught if issubclass(w.category, ResourceWarning)], [])


if __name__ == "__main__":
    unittest.main()
