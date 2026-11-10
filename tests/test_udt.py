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
from unittest import mock

from leuze_rsl.errors import (
    ProtocolError,
    ReceiverStoppedError,
    RSL235Error,
    ScannerConnectionError,
    ScanTimeoutError,
)
from leuze_rsl.simulator import UdtSimulator
from leuze_rsl import udt as udt_module
from leuze_rsl.udt import (
    FRAME_SIZE,
    GEOMETRY,
    NO_ECHO_DISTANCE_MM,
    BeamGeometry,
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

#: One complete cycle (scan 5453125) captured from an RSL 235 (RSL235-S, 24 V
#: supply, Sensor Studio: ID 3, contour 0..1350 step 5) on 2026-10-27: the
#: 56-byte status datagram and the 1104-byte distance+signal datagram.
RSL235_CAPTURE_STATUS = bytes.fromhex(
    "3800000008000600040b0132010000004535530015000000007a0000ea003b0100000000"
    "453553000000000049eb04000000460505000000"
)

#: Measurement datagram of the same cycle (271 beams).
RSL235_CAPTURE_MEASUREMENT = bytes.fromhex(
    "5004000008000600040b01320300000045355300ffffffff2201cb02ed005002c503e202"
    "b203e602a902750272011e059101fd047e03ed02da0297039501d7047e01c8045303f502"
    "31022b0479018b043402190438020e048f0143046b02c903c5016204b1015704d6014104"
    "c5013f04dd01260405020404e501e7034402c3033202c8032502bc033702930367027e03"
    "6902e9025d02f102d6020d03d3020e03d1020c03cf021703cb021c03ca021e03cb022203"
    "c8022703c7022703c6022b03c3022e03c5023703c6024d03c8029203c902a303c3024b03"
    "c10249038102bf0382027e038302660384025d0386024d038b0240038f0240038e023603"
    "a6022d03d7021f03db021c03de022203e1022003e6021503e9021503ee021003f4020e03"
    "f7020e03000311030503190309030f0310030a03140305031d030803ea0144049201f802"
    "8201f5027a01f1027101ee026301eb025a01de025101df024901ed024701ec024d01e802"
    "5001e7025801ed025b01f0027b01a2028d018f0294017f0299018502a1018d02a8019a02"
    "b4019702bd019802c1019d02ce019002da018602e6018602f0018202fd019a0206028b02"
    "17028b022502a0022f029b02460297025e0289027002a0028202850297028202ad028302"
    "cd027e02e7027b020b034f022c037b025303420280034602b50366022504e20373040204"
    "b104c303e204ee023d0501037d052c020806310294064002300740027308340494095a03"
    "8e0b48042c0cab03690c7b035c0c97034d0c2503570bc002530bab02710bbf01630b7d01"
    "590b6501700b73016d0b6c01700b66017c0b5a01730b6f01790b67017e0b5d01990b4b01"
    "9a0b4301ae0b2601bc0b3f01be0b2301e70b2a01ea0b26010b0c0a01250c2001340c0f01"
    "2c378a0050358900b33566023f352e022435c9015533b7018331ad01e32fa101772e9f01"
    "0c2d7e01cb2b8201932a8301bc29e00161287a0170275801971a2d012e0e1a02fb0d5602"
    "042464013f236501d121dc01d721620146215f01d02094014920a201ad28a7022f286602"
    "9f272d02a41a1902e71a1f02062689021f256702e524180257246e027b2422024b0a1702"
    "630a2c027c0a2e017d20c203101da1027c1c3302cc1c5701dc1c6701eb1c3501221d0001"
    "96260d02d723260293240a02e325180228261502cc2523024125260297251002361f0802"
    "f11efb01cf24180208251c02d8241c025f242502b8241b02b32376021d24ee02a7235502"
    "1d247602432425023d24280261241b02fb23210202243c02ce2325027724290250244002"
    "702424023e249702250669027005c4029104b402f203a6028c03a2023603ad02fd02b502"
    "c002b60284026c026402c00235020702ff01760200022f02e1018502c0010a02c001c101"
    "a5018d028f013d028001db016a010d026d01dc014701750153019002410148013b010002"
    "3601f401210120011a01d5011e0111027e177e010801f900000100020001f1012e08ec00"
    "2510a201e2009d01ef004002d9009901b70453019708f601"
)

#: One cycle (scan 332669) from a second RSL 235 unit mounted overhead in a
#: hall, in safety mode with a configuration signature; its measurement
#: datagram carries the 32767 marker (echo too weak) on far-looking beams.
RSL235_CAPTURE_FAR_STATUS = bytes.fromhex(
    "3800000008000600040b0132010000007d130500150100f401870000ea00620100000000"
    "7d130500aa2faec249eb04000000460505000000"
)

#: Measurement datagram of that cycle (271 beams, 7 with 32767).
RSL235_CAPTURE_FAR_MEASUREMENT = bytes.fromhex(
    "5004000008000600040b0132030000007d130500d41c1402571d1602e51d1e02731e1802"
    "0b1f1402b11f10027520290227212302d7210e029a22fd017a23f7016724fb0165250302"
    "6526fb01bf273002af28f601fd29eb014d2bd301c72cd301572ecc010c30b801d831b801"
    "e433a0018e36620279387e01173b3201ff3d1301205c91003c612b02124f8e00f70f8c02"
    "e90f8602e30f5802a11179028e1179027e1178026b117a025e118f02ff7f8e00ff7f8f00"
    "ff7f9000ff7f8e00ff7f8f00ff7f8f00133e0502193e1e02283e0602243e20027f3e7b02"
    "3a3ef701563eb3017d3ee701bf3e2602dc3eb901053fa501403fe001e93ec701ff7f9200"
    "140c03021f0c0602280c03023f0c0402480cfd015d0c05027a0c1002810c0902920c0202"
    "b10c0b02d9069001ef060c02f7062a0207076e020f0728021d07150232079c014a070202"
    "6207f70164071d0275070b0292070202ad070e02b5071502d0071402ea071d0203080202"
    "2a081e023f08d9015e08140294080602ae08ce01cf080202ff080c022e0905024509fe01"
    "8209f001c0090c02f3090e022a0ae801750a0802a60af201050b1602700a8d02690a1b02"
    "810a29028b0c3303d10cbd02240d3a02160d8a02ef0ca002ec0ab302120b3602010b3502"
    "390b5903250b5803030b5803eb0a4503e40a3d03c80a3303b80a3503b50a2703910a0903"
    "850afc026c0ada02520ac402340a9002190a60020b0a61020a0a6b02080a7202f9096b02"
    "fc098402090ac602110af002190a3203180a6403fb09d602eb099d02090a0e03130a0d03"
    "0c0aed02fb099802fb098702f6096602000a5602050a54020d0a63021f0a7502300a8202"
    "430a8a02660aef02840a0303970a0203a50a2503ab0a4a03ca0a4203d30a4903e20a4003"
    "e90a0b03030b2b03280b39031b0b93021e0b4302200b3d02ef0cad02170d95023e0d3402"
    "620d2802810d31026e0a0c027c0a2d02a40ab603700c99021b0c8902d00b7602be0b9602"
    "ea0b8f02170c9102490c95027b0c8e02b80cab02e90c8302230d8802d510170229111d02"
    "7b111702d41119023212150296121d0201131d026a131602e61315026a141102f6140b02"
    "8615080229160d02d21607028217fe014b180c0261187a021d187602ee176c02d9174d02"
    "90175702551766023517a3020d176202f1169e02fc163f02d1162802b81628029a163502"
    "7b1630026416280249162b0232162a02241632021a1627020b162e02fc1530021c161d02"
    "081607023a341d02290587022f05b1022d054f035e05b7038b05210308341f0215342602"
    "213426029e05c3011e2d1502162de10187342502a9342502ca342302f9341f0226352402"
    "bd301702ff2fae01442f9101042d0602f72b1d02182ed502cb2c5d01e12aaf01af284901"
    "41328c001b2537018d233c013e223d01c82007021520fa01b01e6301ba1d9101d91c8001"
    "081c8301361b9101731a8601cc197601251986017b189801ed17a30161179f01e016bb01"
    "ac160e022c163a027515250211132e01df112a0179107a02"
)

#: Status datagram of a third RSL 235 unit (scan 332646) whose optics cover
#: warning is active: byte 2 = 0x62 (WARNING + SCREEN + SCREEN_WARNING).
RSL235_CAPTURE_WARNING_STATUS = bytes.fromhex(
    "3800000008000600040b01320100000066130500150162f401870000ec005b0100000000"
    "66130500be302bd649ea04000000460505000000"
)


class Rsl235CaptureTests(unittest.TestCase):
    """Byte-exact decoding of one cycle captured from real RSL 235 hardware."""

    def test_status_datagram(self):
        frame = UdtFrame.from_bytes(RSL235_CAPTURE_STATUS)
        self.assertEqual((frame.total_length, frame.h1_size, frame.follow_flag, frame.request_id),
                         (56, 8, 0, 6))
        self.assertEqual(frame.header2, b"\x04\x0b\x01\x32")
        self.assertEqual((frame.telegram_id, frame.block, frame.scan_number), (1, 0, 5453125))
        status = StatusProfile.from_bytes(RSL235_CAPTURE_STATUS[FRAME_SIZE:])
        self.assertEqual(status.family, ScannerFamily.RSL200)
        self.assertEqual((status.profile_type, status.profile_length, status.contour_offset), (21, 28, 28))
        self.assertEqual(status.scan_number, frame.scan_number)      # SCAN_NUM == frame scan number
        self.assertEqual(status.operating_mode, 0)
        self.assertFalse(status.error)
        self.assertFalse(status.ossd_a)                              # OSSDs off ...
        self.assertTrue(status.a_protective_violated)                # ... objects inside the fields
        self.assertTrue(status.a_warning_violated)
        self.assertTrue(status.warning_field_2_violated)
        self.assertFalse(status.parked)
        self.assertFalse(status.restart_interlock)
        self.assertEqual((status.field_triple, status.inputs, status.outputs), (0, 0, 0))
        self.assertEqual(status.supply_voltage_raw, 234)             # 24 V supply -> unit is 0.1 V
        self.assertEqual(status.supply_voltage_v, 23.4)
        self.assertEqual(status.temperature_c, 31.5)
        self.assertEqual(status.signature, 0)
        self.assertEqual((status.error_class, status.error_number), (73, 1259))
        contour = MeasurementContour.from_bytes(RSL235_CAPTURE_STATUS[FRAME_SIZE:], status.contour_offset)
        self.assertEqual(contour, MeasurementContour(0, 1350, 5, 0))
        self.assertEqual(contour.num_beams, 271)

    def test_measurement_datagram(self):
        frame = UdtFrame.from_bytes(RSL235_CAPTURE_MEASUREMENT)
        self.assertEqual((frame.total_length, frame.telegram_id, frame.block, frame.scan_number),
                         (1104, TELEGRAM_ID_DISTANCE_SIGNAL, 0, 5453125))
        asm = UdtAssembler(strict=True)
        self.assertEqual(asm.feed_datagram(RSL235_CAPTURE_STATUS), [])
        scans = asm.feed_datagram(RSL235_CAPTURE_MEASUREMENT)
        self.assertEqual(len(scans), 1)
        scan = scans[0]
        self.assertTrue(scan.complete)
        self.assertEqual((scan.num_beams, scan.num_blocks, scan.family), (271, 1, ScannerFamily.RSL200))
        self.assertEqual(scan.status.scan_number, 5453125)
        self.assertEqual(scan.beam_indices()[:3], [0, 5, 10])
        self.assertEqual(len(scan.angles_deg()), 271)
        # beam 0 has no echo: distance 0xFFFF with signal strength 0xFFFF
        self.assertEqual((scan.distances_mm[0], scan.signal_strengths[0]), (65535, 65535))
        self.assertEqual(scan.distances_mm[1:4], (290, 237, 965))
        self.assertEqual(scan.signal_strengths[1:4], (715, 592, 738))
        mask = scan.valid_mask()
        self.assertEqual(mask[:2], [False, True])
        self.assertEqual(sum(mask), 270)
        valid = [d for d, ok in zip(scan.distances_mm, mask) if ok]
        self.assertEqual((min(valid), max(valid)), (217, 14124))
        self.assertNotIn(32767, scan.distances_mm)
        self.assertEqual(len(scan.to_cartesian()), 270)
        self.assertEqual(asm.stats.scans_completed, 1)
        self.assertEqual(asm.stats.cycles_missed, 0)

    def test_configured_unit_and_weak_echo_marker(self):
        """A unit in safety mode: fields free, OSSD on, signature set; 32767 marks weak echoes."""
        status = StatusProfile.from_bytes(RSL235_CAPTURE_FAR_STATUS[FRAME_SIZE:])
        self.assertEqual(status.scan_number, 332669)
        self.assertEqual(status.operating_mode, 1)                   # safety mode
        self.assertTrue(status.ossd_a)
        self.assertFalse(status.a_protective_violated)
        self.assertFalse(status.a_warning_violated)
        self.assertFalse(status.warning_field_2_violated)
        self.assertEqual(status.field_triple, 1)
        self.assertEqual(status.signature, 3266195370)               # non-zero once configured
        self.assertEqual((status.supply_voltage_v, status.temperature_c), (23.4, 35.4))
        self.assertEqual((status.error, status.error_class, status.error_number), (False, 73, 1259))
        asm = UdtAssembler()
        asm.feed_datagram(RSL235_CAPTURE_FAR_STATUS)
        scan = asm.feed_datagram(RSL235_CAPTURE_FAR_MEASUREMENT)[0]
        weak = [i for i, d in enumerate(scan.distances_mm) if d == 32767]
        self.assertEqual(weak, [38, 39, 40, 41, 42, 43, 57])
        for i in weak:                                              # a real, weak signal is reported
            self.assertTrue(140 <= scan.signal_strengths[i] <= 190, scan.signal_strengths[i])
        self.assertNotIn(65535, scan.distances_mm)
        mask = scan.valid_mask()
        self.assertFalse(any(mask[i] for i in weak))
        self.assertEqual(sum(mask), 264)
        self.assertEqual(scan.distances_mm[36:38], (4459, 4446))
        self.assertEqual(len(scan.to_cartesian()), 264)

    def test_optics_cover_warning_and_remaining_table_bits(self):
        """WARNING, SCREEN and SCREEN_WARNING come together on hardware; CLEAR and SSREC are decoded."""
        warn = StatusProfile.from_bytes(RSL235_CAPTURE_WARNING_STATUS[FRAME_SIZE:])
        self.assertEqual(warn.scan_number, 332646)
        self.assertTrue(warn.alarm and warn.warning and warn.screen_contaminated and warn.screen_warning)
        self.assertFalse(warn.screen_error or warn.error)
        self.assertTrue(warn.ossd_a)                                 # a warning does not switch off
        self.assertEqual((warn.ossd_clear, warn.event_log), (True, True))
        self.assertEqual((warn.error_class, warn.error_number), (73, 1258))
        clean = StatusProfile.from_bytes(RSL235_CAPTURE_FAR_STATUS[FRAME_SIZE:])
        self.assertFalse(clean.alarm or clean.warning or clean.screen_contaminated or clean.screen_warning)
        self.assertEqual((clean.ossd_clear, clean.event_log), (True, True))
        bench = StatusProfile.from_bytes(RSL235_CAPTURE_STATUS[FRAME_SIZE:])   # unconfigured, OSSDs off
        self.assertEqual((bench.ossd_clear, bench.event_log), (False, False))
        rsl400 = StatusProfile.from_bytes(RSL400_CAPTURE[FRAME_SIZE:])
        self.assertEqual((rsl400.ossd_clear, rsl400.event_log), (None, None))
        self.assertEqual(rsl400.warning, rsl400.alarm)


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


class SpecTableBitWalkTests(unittest.TestCase):
    """Flip every single bit of both status profiles and check exactly which attribute changes.

    The tables below are written from the specification (tables 3.3 and 3.5),
    not from the decoder: (byte, mask) -> (attribute, value when the bit is 1).
    Any wrong mask, offset, polarity or width in the decoder fails here.
    """

    RSL200_BITS = {
        (2, 0x80): ("error", True), (2, 0x40): ("alarm", True), (2, 0x20): ("screen_contaminated", True),
        (2, 0x10): ("edm_error", True), (2, 0x08): ("field_selection_error", True),
        (2, 0x04): ("screen_error", True), (2, 0x02): ("screen_warning", True),
        (3, 0x80): ("ossd_a", True), (3, 0x40): ("a_protective_violated", False),
        (3, 0x20): ("a_warning_violated", False), (3, 0x10): ("warning_field_2_violated", False),
        (3, 0x08): ("restart_interlock", True), (3, 0x04): ("ossd_clear", True), (3, 0x02): ("parked", True),
        (5, 0x01): ("event_log", True),
    }
    #: little-endian numeric fields: first byte -> (attribute, width in bytes, scale)
    RSL200_NUMBERS = {1: ("operating_mode", 1, 1), 4: ("field_triple", 1, 1), 6: ("inputs", 1, 1),
                      7: ("outputs", 1, 1), 8: ("supply_voltage_raw", 2, 1), 10: ("temperature_c", 2, 0.1),
                      16: ("scan_number", 4, 1), 20: ("signature", 4, 1), 24: ("error_class", 1, 1),
                      25: ("error_number", 2, 1)}
    RSL400_BITS = {
        (2, 0x80): ("error", True), (2, 0x40): ("alarm", True), (2, 0x20): ("screen_contaminated", True),
        (2, 0x10): ("edm_error", True), (2, 0x08): ("field_selection_error", True),
        (2, 0x04): ("estop_error", True), (2, 0x02): ("ossd_a", True), (2, 0x01): ("ossd_b", True),
        (3, 0x80): ("estop_active", True), (3, 0x40): ("parked", True),
        # base profile below has both functions active with both fields free (bits set)
        (12, 0x80): ("a_active", True), (12, 0x40): ("a_warning_violated", False),
        (12, 0x20): ("a_protective_violated", False),
        (16, 0x80): ("b_active", True), (16, 0x40): ("b_warning_violated", False),
        (16, 0x20): ("b_protective_violated", False),
    }
    RSL400_NUMBERS = {1: ("operating_mode", 1, 1), 8: ("scan_number", 4, 1)}
    RSL400_NIBBLES = {13: ("a_bank", "a_field_pair"), 17: ("b_bank", "b_field_pair")}

    @staticmethod
    def fields(status):
        values = dict(vars(status))
        del values["raw"]
        return values

    def walk(self, base, length, bits, numbers, nibbles=()):
        base_fields = self.fields(StatusProfile.from_bytes(bytes(base)))
        number_bytes = {first + i: (first, spec) for first, spec in numbers.items() for i in range(spec[1])}
        checked = 0
        for byte in range(1, length):
            for bit in range(8):
                mask = 1 << bit
                data = bytearray(base)
                data[byte] ^= mask
                now_set = bool(data[byte] & mask)
                got = self.fields(StatusProfile.from_bytes(bytes(data)))
                changed = {k: v for k, v in got.items() if v != base_fields[k]}
                where = "byte %d bit %d" % (byte, bit)
                if (byte, mask) in bits:
                    attribute, when_set = bits[(byte, mask)]
                    self.assertEqual(changed, {attribute: when_set if now_set else not when_set}, where)
                elif byte in number_bytes:
                    first, (attribute, width, scale) = number_bytes[byte]
                    raw = int.from_bytes(data[first:first + width], "little")
                    self.assertEqual(list(changed), [attribute], where)
                    self.assertAlmostEqual(changed[attribute], raw * scale, places=6, msg=where)
                elif byte in nibbles:
                    high, low = nibbles[byte]
                    self.assertEqual(changed, {high: data[byte] >> 4} if mask >= 0x10
                                     else {low: data[byte] & 0x0F}, where)
                else:
                    self.assertEqual(changed, {}, where + " is reserved or not decoded")
                checked += 1
        return checked

    def test_rsl200_table_3_3(self):
        base = bytearray(28 + 8)
        base[0] = 21
        base[28:36] = struct.pack("<HHHH", 0, 1350, 5, 0)
        self.assertEqual(self.walk(base, 28, self.RSL200_BITS, self.RSL200_NUMBERS), 27 * 8)

    def test_rsl400_table_3_5(self):
        base = bytearray(20 + 8)
        base[0] = 1
        base[12] = base[16] = 0xE0                                # A and B active, warning and protective field free
        base[20:28] = struct.pack("<HHHH", 0, 2699, 1, 0)
        checked = self.walk(base, 20, self.RSL400_BITS, self.RSL400_NUMBERS, self.RSL400_NIBBLES)
        self.assertEqual(checked, 19 * 8)

    def test_rsl400_table_3_5_with_inactive_functions(self):
        """Same walk from an all-zero profile: only the ACTIVE bits may change anything in bytes 12 and 16."""
        base = bytearray(20 + 8)
        base[0] = 1
        base[20:28] = struct.pack("<HHHH", 0, 2699, 1, 0)
        bits = dict(self.RSL400_BITS)
        for byte, letter in ((12, "a"), (16, "b")):
            del bits[(byte, 0x40)], bits[(byte, 0x20)]             # gated while inactive: no visible change
            del bits[(byte, 0x80)]
        base_fields = self.fields(StatusProfile.from_bytes(bytes(base)))
        for byte, letter in ((12, "a"), (16, "b")):
            for bit in range(8):
                data = bytearray(base)
                data[byte] ^= 1 << bit
                got = self.fields(StatusProfile.from_bytes(bytes(data)))
                changed = {k: v for k, v in got.items() if v != base_fields[k]}
                expected = ({letter + "_active": True, letter + "_protective_violated": True,
                             letter + "_warning_violated": True} if bit == 7 else {})
                self.assertEqual(changed, expected, "byte %d bit %d" % (byte, bit))
        skip = {12, 16}
        for byte in range(1, 20):
            if byte in skip:
                continue
            for bit in range(8):
                data = bytearray(base)
                data[byte] ^= 1 << bit
                got = self.fields(StatusProfile.from_bytes(bytes(data)))
                changed = {k: v for k, v in got.items() if v != base_fields[k]}
                if (byte, 1 << bit) in bits:
                    self.assertEqual(changed, {bits[(byte, 1 << bit)][0]: bits[(byte, 1 << bit)][1]})
                elif byte not in (1, 8, 9, 10, 11, 13, 17):
                    self.assertEqual(changed, {}, "byte %d bit %d" % (byte, bit))

    def test_rsl400_field_flags_are_reported_only_while_the_function_is_active(self):
        base = bytearray(20 + 8)
        base[0] = 1                                               # A and B inactive, field bits 0 ("violation")
        status = StatusProfile.from_bytes(bytes(base))
        self.assertEqual((status.a_active, status.a_protective_violated, status.a_warning_violated),
                         (False, False, False))
        self.assertEqual((status.b_active, status.b_protective_violated, status.b_warning_violated),
                         (False, False, False))
        base[12] = 0x80                                           # A active, both field bits 0
        status = StatusProfile.from_bytes(bytes(base))
        self.assertEqual((status.a_protective_violated, status.a_warning_violated), (True, True))
        self.assertEqual((status.b_protective_violated, status.b_warning_violated), (False, False))
        base[12] = base[16] = 0x80 | 0x1F                         # the five other bits of the byte do not matter
        status = StatusProfile.from_bytes(bytes(base))
        self.assertEqual((status.a_protective_violated, status.a_warning_violated), (True, True))
        self.assertEqual((status.b_protective_violated, status.b_warning_violated), (True, True))


class DecodingBoundaryTests(unittest.TestCase):
    """Exact limits, pinned after mutation testing showed they were not."""

    def test_geometry_constants(self):
        self.assertEqual(GEOMETRY[ScannerFamily.RSL200], BeamGeometry(-0.2, 135.0, 1350, 65535, 32766))
        self.assertEqual(GEOMETRY[ScannerFamily.RSL400], BeamGeometry(-0.1, 134.95, 2699, 65535, 65534))
        self.assertEqual(NO_ECHO_DISTANCE_MM, 65535)
        self.assertEqual((udt_module._STALE_WINDOW, udt_module._FORWARD_WINDOW), (256, 8))
        self.assertEqual((udt_module._MAX_FRAGMENTS_PER_SCAN, udt_module._MAX_BYTES_PER_SCAN), (64, 262144))

    def test_status_profile_minimum_lengths(self):
        with self.assertRaises(ProtocolError):
            StatusProfile.from_bytes(bytes([99, 0]))                    # 2 bytes: no flags byte
        self.assertEqual(StatusProfile.from_bytes(bytes([99, 0, 0])).profile_type, 99)
        self.assertEqual(StatusProfile.from_bytes(rsl200_status_block(1)[:28]).scan_number, 1)   # exactly 28
        with self.assertRaises(ProtocolError):
            StatusProfile.from_bytes(rsl200_status_block(1)[:27])
        rsl400 = RSL400_CAPTURE[FRAME_SIZE:]
        self.assertEqual(StatusProfile.from_bytes(rsl400[:20]).scan_number, 338286)              # exactly 20
        with self.assertRaises(ProtocolError):
            StatusProfile.from_bytes(rsl400[:19])

    def test_unknown_profile_type_has_neutral_defaults(self):
        status = StatusProfile.from_bytes(bytes([99, 2, 0xFF]) + bytes([0xFF]) * 40)
        self.assertEqual((status.ossd_a, status.ossd_b, status.parked, status.scan_number), (False, None, False, 0))
        self.assertEqual((status.a_active, status.a_protective_violated, status.a_warning_violated),
                         (False, False, False))
        self.assertEqual((status.b_active, status.b_protective_violated, status.b_warning_violated),
                         (None, None, None))
        self.assertEqual((status.profile_length, status.contour_offset), (0, None))

    def test_rsl400_signature_trailer_conditions(self):
        block = RSL400_CAPTURE[FRAME_SIZE:FRAME_SIZE + 28]
        signature = bytes(range(0x10, 0x18))
        self.assertEqual(StatusProfile.from_bytes(block + b"\x01\x00\x08\x00" + signature
                                                  + b"\xAA\xBB").configuration_signature, signature)   # extra bytes ignored
        self.assertIsNone(StatusProfile.from_bytes(block + b"\x02\x00\x08\x00" + signature).configuration_signature)
        self.assertIsNone(StatusProfile.from_bytes(block + b"\x01\x00\x08\x00" + signature[:7]).configuration_signature)
        self.assertIsNone(StatusProfile.from_bytes(block).configuration_signature)

    def test_contour_value_limits(self):
        self.assertEqual(MeasurementContour(0, 10, 1).reserved, 0)
        self.assertEqual(MeasurementContour(0, 0, 1).num_beams, 1)                 # a single beam at index 0
        self.assertEqual(MeasurementContour(0xFFFF, 0xFFFF, 1).num_beams, 1)
        self.assertEqual(MeasurementContour(0, 0xFFFF, 1).num_beams, 65536)
        for bad in ((-1, 5, 1), (0, 0x10000, 1), (0x10000, 0x10000, 1), (0, 5, 0), (6, 5, 1)):
            with self.subTest(contour=bad), self.assertRaises(ProtocolError):
                MeasurementContour(*bad)

    def test_contour_plausibility_limits(self):
        rsl200, rsl400 = ScannerFamily.RSL200, ScannerFamily.RSL400
        self.assertTrue(MeasurementContour(0, 1350, 8).plausible(rsl200))
        self.assertFalse(MeasurementContour(0, 1350, 9).plausible(rsl200))          # interval 1..8
        self.assertFalse(MeasurementContour(0, 1351, 1).plausible(rsl200))          # stop <= 1350
        self.assertTrue(MeasurementContour(0, 2699, 1).plausible(rsl400))
        self.assertFalse(MeasurementContour(0, 2700, 1).plausible(rsl400))
        self.assertTrue(MeasurementContour(0, 2699, 1).plausible())                 # family unknown: widest range
        self.assertFalse(MeasurementContour(0, 2700, 1).plausible())
        self.assertFalse(MeasurementContour(7, 7, 1).plausible())                   # start < stop
        self.assertTrue(MeasurementContour(6, 7, 1).plausible())

    def test_locate_contour_search_rules(self):
        contour = struct.pack("<HHHH", 0, 100, 1, 0)
        # found at the very last possible offset, and only at even offsets
        self.assertEqual(locate_contour(bytes(30) + contour, 101)[0], 30)
        self.assertIsNone(locate_contour(bytes(31) + contour, 101))
        # preference: a known profile length first, then a zero reserved field, then the earliest
        two = bytearray(40)
        two[4:12] = contour
        two[28:36] = contour
        self.assertEqual(locate_contour(bytes(two), 101)[0], 28)
        two = bytearray(40)
        two[4:12] = contour
        two[20:28] = contour
        self.assertEqual(locate_contour(bytes(two), 101)[0], 20)
        two = bytearray(40)
        two[4:12] = struct.pack("<HHHH", 0, 100, 1, 7)             # reserved != 0
        two[12:20] = contour
        self.assertEqual(locate_contour(bytes(two), 101)[0], 12)
        two = bytearray(40)
        two[4:12] = contour
        two[12:20] = struct.pack("<HHHH", 1, 101, 1, 0)             # a different contour with the same beam count
        self.assertEqual(locate_contour(bytes(two), 101), (4, MeasurementContour(0, 100, 1)))

    def test_scan_number_ordering_is_wrap_aware(self):
        newer = udt_module._scan_newer
        self.assertTrue(newer(1, 0))
        self.assertFalse(newer(0, 1))
        self.assertFalse(newer(5, 5))
        self.assertTrue(newer(0, 0xFFFFFFFF))                       # across the wrap
        self.assertFalse(newer(0xFFFFFFFF, 0))
        self.assertTrue(newer(0x7FFFFFFF, 0))                       # just under half the range
        self.assertFalse(newer(0x80000000, 0))                      # exactly half: not newer
        self.assertTrue(newer(0, 0x80000001))


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

    def test_skipped_cycles_are_counted(self):
        """An RSL 235 at telegram interval 1 skips every 11th cycle: the gap is visible in the stats."""
        asm = UdtAssembler()
        got = []
        for n in (1, 2, 4, 5, 8):                                   # cycles 3, 6, 7 never sent
            got += asm.feed_datagram(make_status_datagram(n))
            got += asm.feed_datagram(make_measurement_datagram(n, 0, [n] * 271, [1] * 271))
        self.assertEqual([s.scan_number for s in got], [1, 2, 4, 5, 8])
        self.assertEqual(asm.stats.cycles_missed, 3)
        self.assertEqual(asm.stats.sequence_jumps, 0)
        self.assertEqual(asm.stats.stale_datagrams, 0)

    def test_duplicate_or_late_datagram_is_ignored(self):
        """A finished scan is never delivered twice (regression)."""
        asm = UdtAssembler()
        asm.feed_datagram(make_status_datagram(10))
        datagram = make_measurement_datagram(10, 0, [1] * 271, [1] * 271)
        self.assertEqual(len(asm.feed_datagram(datagram)), 1)
        self.assertEqual(asm.feed_datagram(datagram), [])                   # duplicate
        self.assertEqual(asm.feed_datagram(make_measurement_datagram(9, 0, [1] * 271, [1] * 271)), [])
        self.assertEqual(asm.feed_datagram(make_status_datagram(9)), [])    # late status of an older cycle
        self.assertEqual(asm.stats.stale_datagrams, 3)
        self.assertEqual(asm.stats.scans_completed, 1)
        self.assertEqual(asm.latest_status.scan_number, 10)                 # never turned back

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
        self.assertEqual(asm.stats.cycles_missed, 498)
        self.assertIsNone(got[0].status)                          # its status arrived unconfirmed
        self.assertEqual(got[1].status.scan_number, 501)

    def test_unconfirmed_far_ahead_scan_is_never_emitted(self):
        """A complete stray cycle far ahead is not a scan and must not disable duplicate protection (regression)."""
        asm = UdtAssembler()
        got = asm.feed_datagram(make_status_datagram(100))
        got += asm.feed_datagram(make_measurement_datagram(100, 0, [1] * 271, [1] * 271))
        got += asm.feed_datagram(make_measurement_datagram(1100, 0, [9] * 271, [1] * 271))   # complete, far ahead
        got += asm.feed_datagram(make_status_datagram(101))
        datagram = make_measurement_datagram(101, 0, [2] * 271, [1] * 271)
        got += asm.feed_datagram(datagram)
        got += asm.feed_datagram(datagram)                                                # duplicate of cycle 101
        self.assertEqual([s.scan_number for s in got], [100, 101])
        self.assertEqual(asm.stats.outlier_datagrams, 1)
        self.assertEqual(asm.stats.stale_datagrams, 1)
        self.assertEqual(len(asm._pending), 0)                    # the stray's data was discarded

    def test_duplicated_far_ahead_datagram_yields_one_scan(self):
        """Found by model checking: S(n), D(n+1000), D(n+1000) delivered scan n+1000 twice (regression)."""
        asm = UdtAssembler()
        asm.feed_datagram(make_status_datagram(100))
        datagram = make_measurement_datagram(1100, 0, [5] * 271, [1] * 271)
        self.assertEqual(asm.feed_datagram(datagram), [])         # unconfirmed: kept, not emitted
        got = asm.feed_datagram(datagram)                         # the same number again: the stream is there
        got += asm.feed_datagram(datagram)
        self.assertEqual([s.scan_number for s in got], [1100])
        self.assertEqual(asm.stats.sequence_jumps, 1)

    def test_far_ahead_scan_is_emitted_once_the_next_cycle_confirms_it(self):
        """After an outage with the first status lost, the first data cycle is delivered with the next cycle."""
        asm = UdtAssembler()
        asm.feed_datagram(make_status_datagram(1))
        asm.feed_datagram(make_measurement_datagram(1, 0, [1] * 271, [1] * 271))
        self.assertEqual(asm.feed_datagram(make_measurement_datagram(500, 0, [5] * 271, [1] * 271)), [])
        got = asm.feed_datagram(make_status_datagram(501))
        self.assertEqual([(s.scan_number, s.complete) for s in got], [(500, True)])
        self.assertEqual(got[0].distances_mm, (5,) * 271)
        got = asm.feed_datagram(make_measurement_datagram(501, 0, [6] * 271, [1] * 271))
        self.assertEqual([s.scan_number for s in got], [501])
        self.assertEqual(got[0].status.scan_number, 501)

    def test_restart_does_not_emit_an_unconfirmed_far_ahead_cycle(self):
        asm = UdtAssembler(strict=False)
        asm.feed_datagram(make_status_datagram(5000))
        asm.feed_datagram(make_measurement_datagram(5000, 0, [1] * 271, [1] * 271))
        asm.feed_datagram(make_measurement_datagram(9000, 0, [9] * 271, [1] * 271))          # stray
        got = asm.feed_datagram(make_status_datagram(3))                                     # counter restarted
        got += asm.feed_datagram(make_measurement_datagram(3, 0, [3] * 271, [1] * 271))
        self.assertEqual([s.scan_number for s in got], [3])
        self.assertEqual(asm.stats.sequence_resets, 1)

    def test_late_status_of_an_older_cycle_does_not_turn_back_the_status(self):
        """Found by model checking: S(n+1), late S(n), D(n+1) stripped scan n+1 of its status (regression)."""
        asm = UdtAssembler()
        asm.feed_datagram(make_status_datagram(10))
        asm.feed_datagram(make_measurement_datagram(10, 0, [1] * 271, [1] * 271))
        asm.feed_datagram(make_status_datagram(11, ossd=False))
        self.assertEqual(asm.feed_datagram(make_status_datagram(10)), [])                 # duplicate arriving late
        scans = asm.feed_datagram(make_measurement_datagram(11, 0, [2] * 271, [1] * 271))
        self.assertEqual(scans[0].status.scan_number, 11)
        self.assertFalse(scans[0].status.ossd_a)
        self.assertEqual(asm.latest_status.scan_number, 11)
        self.assertEqual(asm.stats.stale_datagrams, 1)
        self.assertEqual(asm.stats.status_received, 2)

    def test_late_status_newer_than_the_held_one_is_adopted(self):
        asm = UdtAssembler()
        asm.feed_datagram(make_status_datagram(10))
        for n in (10, 11, 12):                                    # the statuses of 11 and 12 are delayed
            asm.feed_datagram(make_measurement_datagram(n, 0, [n] * 271, [1] * 271))
        asm.feed_datagram(make_status_datagram(11))
        self.assertEqual(asm.latest_status.scan_number, 11)
        asm.feed_datagram(make_status_datagram(10))
        self.assertEqual(asm.latest_status.scan_number, 11)       # never backwards
        self.assertEqual(asm.stats.stale_datagrams, 1)

    def test_status_held_before_a_restart_does_not_block_the_new_run(self):
        asm = UdtAssembler()
        asm.feed_datagram(make_status_datagram(5000))
        asm.feed_datagram(make_measurement_datagram(5000, 0, [1] * 271, [1] * 271))
        asm.feed_datagram(make_measurement_datagram(10, 0, [1] * 271, [1] * 271))  # counter restarted, status lost
        asm.feed_datagram(make_measurement_datagram(11, 0, [1] * 271, [1] * 271))
        asm.feed_datagram(make_status_datagram(10))                                # late status of the new run
        self.assertEqual(asm.stats.sequence_resets, 1)
        self.assertEqual(asm.latest_status.scan_number, 10)

    def test_forward_window_boundary(self):
        """Up to 8 scan numbers ahead is the same stream; 9 ahead needs confirmation."""
        asm = UdtAssembler()
        asm.feed_datagram(make_status_datagram(100))
        asm.feed_datagram(make_measurement_datagram(100, 0, [1] * 271, [1] * 271))
        got = asm.feed_datagram(make_measurement_datagram(108, 0, [2] * 271, [1] * 271))     # 8 ahead
        self.assertEqual([s.scan_number for s in got], [108])
        self.assertEqual((asm.stats.cycles_missed, asm.stats.outlier_datagrams, asm.stats.sequence_jumps), (7, 0, 0))
        self.assertEqual(asm.feed_datagram(make_measurement_datagram(117, 0, [3] * 271, [1] * 271)), [])   # 9 ahead
        self.assertEqual(asm.stats.outlier_datagrams, 1)
        got = asm.feed_datagram(make_status_datagram(125))          # 8 after the candidate: confirms it
        self.assertEqual([s.scan_number for s in got], [117])
        self.assertEqual((asm.stats.sequence_jumps, asm.stats.cycles_missed), (1, 7 + 16))
        self.assertEqual(asm.feed_datagram(make_status_datagram(140)), [])                  # 15 ahead: outlier again
        self.assertEqual(asm.feed_datagram(make_status_datagram(149)), [])                  # 9 after it: no confirmation
        self.assertEqual(asm.stats.outlier_datagrams, 3)
        self.assertEqual(asm.latest_status.scan_number, 125)

    def test_a_second_stray_replaces_the_first(self):
        asm = UdtAssembler(strict=False)
        asm.feed_datagram(make_status_datagram(100))
        asm.feed_datagram(make_measurement_datagram(100, 0, [1] * 271, [1] * 271))
        asm.feed_datagram(make_measurement_datagram(5000, 0, [7] * 100, [1] * 100))         # stray, incomplete
        self.assertEqual(sorted(asm._pending), [5000])
        asm.feed_datagram(make_measurement_datagram(9000, 0, [8] * 100, [1] * 100))         # another stray
        self.assertEqual(sorted(asm._pending), [9000])
        asm.feed_datagram(make_measurement_datagram(9000, 1, [8] * 100, [1] * 100))         # same number: confirmed
        got = asm.feed_datagram(make_status_datagram(9001))
        self.assertEqual([(s.scan_number, s.complete, s.num_beams) for s in got], [(9000, False, 200)])
        self.assertEqual(len(asm._pending), 0)

    def test_stale_window_and_restart_gap_boundaries(self):
        clock = mock.Mock()
        clock.monotonic.return_value = 1000.0
        clock.time.return_value = 1.7e9
        with mock.patch.object(udt_module, "time", clock):
            def run(back_by, pause):
                asm = UdtAssembler()
                asm.feed_datagram(make_status_datagram(10000))
                asm.feed_datagram(make_measurement_datagram(10000, 0, [1] * 271, [1] * 271))
                clock.monotonic.return_value += pause
                got = asm.feed_datagram(make_measurement_datagram(10000 - back_by, 0, [2] * 271, [1] * 271))
                return len(got), asm.stats.stale_datagrams, asm.stats.sequence_resets
            self.assertEqual(run(256, 0.5), (0, 1, 0))              # 256 back within a second: late datagram
            self.assertEqual(run(257, 0.5), (1, 0, 1))              # further back: the counter restarted
            self.assertEqual(run(1, 0.999), (0, 1, 0))              # just under the restart pause
            self.assertEqual(run(1, 1.0), (1, 0, 1))                # a pause of 1 s: restart

    def test_restart_adopts_the_status_that_announces_it(self):
        asm = UdtAssembler()
        asm.feed_datagram(make_status_datagram(5000))
        asm.feed_datagram(make_measurement_datagram(5000, 0, [1] * 271, [1] * 271))
        asm.feed_datagram(make_status_datagram(3, ossd=False))      # 4997 back: restart
        self.assertEqual(asm.stats.sequence_resets, 1)
        self.assertEqual(asm.latest_status.scan_number, 3)
        scans = asm.feed_datagram(make_measurement_datagram(3, 0, [2] * 271, [1] * 271))
        self.assertEqual(scans[0].status.scan_number, 3)
        self.assertFalse(scans[0].status.ossd_a)

    def test_byte_limit_per_scan_boundary(self):
        asm = UdtAssembler(strict=False)
        chunk = 65536                                               # bytes per fragment: 4 fragments = the limit
        beams = chunk // 2
        for block in range(4):
            asm.feed_datagram(make_measurement_datagram(1, block, [1] * beams))
        self.assertEqual(asm.stats.scans_dropped_oversize, 0)       # exactly 256 KiB is still accepted
        asm.feed_datagram(make_measurement_datagram(1, 4, [1]))     # two bytes more
        self.assertEqual(asm.stats.scans_dropped_oversize, 1)
        self.assertEqual(len(asm._pending), 0)

    def test_resent_block_replaces_the_earlier_one(self):
        asm = UdtAssembler()
        asm.feed_datagram(make_status_datagram(1))
        self.assertEqual(asm.feed_datagram(make_measurement_datagram(1, 0, [1] * 100, [1] * 100)), [])
        scans = asm.feed_datagram(make_measurement_datagram(1, 0, [2] * 271, [1] * 271))    # same block, full size
        self.assertEqual([(s.num_beams, s.complete, set(s.distances_mm)) for s in scans], [(271, True, {2})])
        asm.feed_datagram(make_status_datagram(2))
        asm.feed_datagram(make_measurement_datagram(2, 0, [3] * 200, [1] * 200))
        asm.feed_datagram(make_measurement_datagram(2, 0, [3] * 100, [1] * 100))            # shrinks to 100 beams
        self.assertEqual(asm.feed_datagram(make_measurement_datagram(2, 1, [4] * 100, [1] * 100)), [])  # 200, not 300
        scans = asm.feed_datagram(make_measurement_datagram(2, 2, [5] * 71, [1] * 71))
        self.assertEqual([(s.num_beams, s.complete) for s in scans], [(271, True)])

    def test_missing_middle_block_is_incomplete_even_if_the_beam_count_matches(self):
        asm = UdtAssembler(strict=False)
        asm.feed_datagram(make_status_datagram(1))
        asm.feed_datagram(make_measurement_datagram(1, 0, [1] * 135, [1] * 135))
        scans = asm.feed_datagram(make_measurement_datagram(1, 2, [1] * 136, [1] * 136))    # 271 beams, block 1 missing
        self.assertEqual([(s.num_beams, s.complete, s.blocks) for s in scans], [(271, False, (0, 2))])
        strict = UdtAssembler()
        strict.feed_datagram(make_status_datagram(1))
        strict.feed_datagram(make_measurement_datagram(1, 0, [1] * 135, [1] * 135))
        self.assertEqual(strict.feed_datagram(make_measurement_datagram(1, 2, [1] * 136, [1] * 136)), [])
        self.assertEqual(strict.stats.scans_dropped_incomplete, 1)

    def test_pending_limit_finishes_the_oldest_and_discards_a_stray(self):
        with self.assertRaises(ValueError):
            UdtAssembler(max_pending=0)
        asm = UdtAssembler(strict=False, max_pending=1)
        asm.feed_datagram(make_status_datagram(100))
        asm.feed_datagram(make_measurement_datagram(100, 0, [1] * 100, [1] * 100))          # in flight
        got = asm.feed_datagram(make_measurement_datagram(7000, 0, [9] * 100, [1] * 100))
        self.assertEqual([(s.scan_number, s.complete) for s in got], [(100, False)])   # limit 1: the oldest is finished
        self.assertEqual(sorted(asm._pending), [7000])
        self.assertEqual(asm.stats.scans_incomplete, 1)
        got = asm.feed_datagram(make_measurement_datagram(101, 0, [2] * 100, [1] * 100))
        self.assertEqual(got, [])
        self.assertEqual(sorted(asm._pending), [101])               # the stray is discarded, never emitted
        self.assertEqual(asm.stats.scans_incomplete, 1)

    def test_pending_limit_discards_the_stray_before_a_real_cycle(self):
        asm = UdtAssembler(strict=False, max_pending=1)
        asm.feed_datagram(make_status_datagram(100))                # cycle 100 announced, no data yet
        self.assertEqual(asm.feed_datagram(make_measurement_datagram(7000, 0, [9] * 100, [1] * 100)), [])
        self.assertEqual(sorted(asm._pending), [7000])
        got = asm.feed_datagram(make_measurement_datagram(100, 0, [1] * 100, [1] * 100))    # needs the only slot
        self.assertEqual(got, [])                                   # the stray is dropped, not emitted
        self.assertEqual(sorted(asm._pending), [100])
        self.assertEqual((asm.stats.scans_incomplete, asm.stats.scans_completed), (0, 0))

    def test_unknown_profile_contour_that_turns_to_zero(self):
        """Heuristic path: the contour found earlier becomes all zero (measurement switched off)."""
        def status(number, contour):
            block = bytearray(40)
            block[0] = 77                                           # a profile type the specification does not know
            block[24:32] = struct.pack("<HHHH", *contour, 0)
            return make_frame(FRAME_SIZE + len(block), TELEGRAM_ID_STATUS, 0, number) + bytes(block)
        asm = UdtAssembler()
        asm.feed_datagram(status(1, (0, 100, 1)))
        self.assertEqual((asm._contour_offset, asm.contour.num_beams), (24, 101))
        asm.feed_datagram(status(2, (0, 0, 0)))
        self.assertIsNone(asm.contour)
        asm.feed_datagram(status(3, (0, 50, 1)))                    # and it is found again when it returns
        self.assertEqual(asm.contour.num_beams, 51)

    def test_bad_status_payloads_are_counted(self):
        asm = UdtAssembler()
        asm.feed_datagram(make_frame(FRAME_SIZE + 10, TELEGRAM_ID_STATUS, 0, 1) + rsl200_status_block(1)[:10])
        self.assertEqual((asm.stats.bad_frames, asm.stats.status_received), (1, 0))
        block = bytearray(rsl200_status_block(2))
        block[28:36] = struct.pack("<HHHH", 500, 100, 1, 0)        # start > stop
        asm.feed_datagram(make_frame(FRAME_SIZE + len(block), TELEGRAM_ID_STATUS, 0, 2) + bytes(block))
        self.assertEqual((asm.stats.bad_frames, asm.stats.status_received), (2, 1))
        self.assertIsNone(asm.contour)
        truncated = make_measurement_datagram(2, 0, [1] * 271, [1] * 271)[:500]            # shorter than announced
        self.assertEqual(asm.feed_datagram(truncated), [])
        self.assertEqual(asm.stats.bad_frames, 3)
        self.assertEqual(len(asm._pending), 0)

    def test_every_datagram_is_counted_exactly_once(self):
        """bad + unknown + stale + outlier + accepted == datagrams, over a messy stream."""
        asm = UdtAssembler()
        accepted = 0
        stream = [
            make_status_datagram(1), make_measurement_datagram(1, 0, [1] * 271, [1] * 271),
            make_measurement_datagram(1, 0, [1] * 271, [1] * 271),                 # stale data
            make_status_datagram(2), make_status_datagram(1),                      # stale status
            make_measurement_datagram(900, 0, [9] * 271, [1] * 271),               # outlier
            b"short",                                                              # bad frame
            make_frame(FRAME_SIZE + 4, 9, 0, 2) + b"abcd",                         # unknown id
            make_frame(FRAME_SIZE, TELEGRAM_ID_DISTANCE, 0, 2),                    # empty measurement: bad
            make_measurement_datagram(2, 0, [2] * 271, [1] * 271),
        ]
        for datagram in stream:
            before = (asm.stats.bad_frames, asm.stats.unknown_ids, asm.stats.stale_datagrams,
                      asm.stats.outlier_datagrams)
            asm.feed_datagram(datagram)
            after = (asm.stats.bad_frames, asm.stats.unknown_ids, asm.stats.stale_datagrams,
                     asm.stats.outlier_datagrams)
            self.assertLessEqual(sum(after) - sum(before), 1)
            accepted += sum(after) == sum(before)
        self.assertEqual(asm.stats.datagrams, len(stream))
        self.assertEqual((asm.stats.bad_frames, asm.stats.unknown_ids, asm.stats.stale_datagrams,
                          asm.stats.outlier_datagrams), (2, 1, 2, 1))
        self.assertEqual(accepted, 4)
        self.assertEqual(asm.stats.scans_completed, 2)

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
        self.assertEqual(scan.no_echo_mm, 65535)
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
        """RSL 235 hardware sends 65535 for no echo; the spec's range top 32767 is invalid too."""
        scan = self.make_scan(contour=(0, 20, 5), values=[1000, 65535, 0, 2000, 32767])
        self.assertEqual(scan.valid_mask(), [True, False, False, True, False])
        self.assertEqual(len(scan.to_cartesian()), 2)
        self.assertEqual(len(scan.to_cartesian(skip_invalid=False)), 5)
        self.assertEqual(scan.valid_mask(max_valid_mm=1500), [True, False, False, False, False])
        self.assertEqual(len(scan.to_cartesian(max_valid_mm=1500)), 1)
        # the RSL 400 range reaches 65534: only 0 and 65535 are invalid there
        scan400 = self.make_scan(family=ScannerFamily.RSL400, contour=(0, 3, 1),
                                 values=[32767, 65534, 65535, 0])
        self.assertEqual(scan400.valid_mask(), [True, True, False, False])

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

    def test_beam_indices_of_incomplete_scans(self):
        def lenient(blocks):
            asm = UdtAssembler(strict=False)
            asm.feed_datagram(make_status_datagram(1, contour=(0, 1350, 5)))               # 271 beams
            scans = []
            for block, count in blocks:
                scans += asm.feed_datagram(make_measurement_datagram(1, block, [1] * count, [1] * count))
            scans += asm.feed_datagram(make_status_datagram(2))
            return scans[0]
        lone_first = lenient([(0, 100)])
        self.assertEqual((lone_first.complete, lone_first.beam_indices()[:3], lone_first.beam_indices()[-1]),
                         (False, [0, 5, 10], 495))
        lone_other = lenient([(1, 100)])                           # fragment size unknown: positions only
        self.assertEqual(lone_other.beam_indices(), list(range(100)))
        first_and_last = lenient([(0, 100), (2, 71)])
        self.assertEqual(first_and_last.beam_indices()[100], 1000)  # block 2 starts at beam 200 -> index 1000
        self.assertEqual(len(first_and_last.angles_deg()), 171)

    def test_repr_is_short(self):
        scan = self.make_scan()
        self.assertEqual(repr(scan), "UdtScan(scan_number=1, beams=271, blocks=1, complete=True, "
                                     "family=RSL200, telegram_id=3, status=yes)")
        self.assertLess(len(repr(self.make_scan(family=ScannerFamily.RSL400, contour=(0, 2699, 1)))), 120)

    def test_scan_carries_wall_and_monotonic_receive_times(self):
        wall, mono = time.time(), time.monotonic()
        scan = self.make_scan()
        self.assertGreaterEqual(scan.received_at, wall - 1.0)
        self.assertTrue(mono <= scan.received_monotonic <= time.monotonic())
        self.assertTrue(0.0 <= scan.age_s() < 5.0)


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

    def test_six_scanners_in_one_process(self):
        """One receiver per scanner (six RSL 235 pushing to six ports): no cross-talk."""
        receivers = [self.start_receiver() for _ in range(6)]
        for k, receiver in enumerate(receivers):
            half = 1000 * (k + 1)                       # each simulated room has its own size
            self.start_simulator(receiver.port, room_half_width_mm=half, room_half_height_mm=half)
        for k, receiver in enumerate(receivers):
            scans = [receiver.get_scan(timeout=5.0) for _ in range(3)]
            for scan in scans:
                self.assertEqual(scan.num_beams, 271)
                nearest = min(d for d, ok in zip(scan.distances_mm, scan.valid_mask()) if ok)
                self.assertAlmostEqual(nearest, 1000 * (k + 1), delta=20)   # its own room
            self.assertEqual(receiver.stats["foreign_datagrams_dropped"], 0)
            self.assertEqual(receiver.stats["scans_dropped_incomplete"], 0)
        thread_names = {t.name for t in threading.enumerate()}
        for receiver in receivers:
            self.assertIn("leuze_rsl-udt-rx:%d" % receiver.port, thread_names)

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

    def test_latest_scan_skips_the_backlog(self):
        receiver = self.start_receiver(scan_queue_size=4)
        self.assertIsNone(receiver.latest_scan)
        simulator = self.start_simulator(receiver.port)
        first = receiver.get_scan(timeout=5.0)
        deadline = time.monotonic() + 5.0
        while receiver.stats["scans_dropped_queue"] == 0 and time.monotonic() < deadline:
            time.sleep(0.01)                                      # nobody consumes: a backlog builds up
        simulator.stop()                                          # freeze the stream before comparing
        seen = -1
        while receiver.stats["datagrams"] != seen:                # let datagrams in flight arrive
            seen = receiver.stats["datagrams"]
            time.sleep(0.2)
        self.assertEqual(receiver.scans_available, 4)
        newest = receiver.latest_scan
        queued = [receiver.get_scan(timeout=1.0) for _ in range(4)]   # get_scan() serves the backlog in order
        self.assertEqual([s.scan_number for s in queued], sorted(s.scan_number for s in queued))
        self.assertIs(queued[-1], newest)                         # the newest scan is the last one in the backlog
        self.assertGreater(newest.scan_number, queued[0].scan_number)
        self.assertGreater(newest.scan_number, first.scan_number)
        self.assertLess(newest.age_s(), 5.0)
        receiver.stop()
        self.assertIsNotNone(receiver.latest_scan)                # still readable after stop()
        receiver.start()
        self.assertIsNone(receiver.latest_scan)                   # a new session starts empty

    def feed_cycle(self, receiver, sender, number, value):
        for datagram in (make_status_datagram(number),
                         make_measurement_datagram(number, 0, [value] * 271, [1] * 271)):
            receiver._handle_datagram(datagram, sender, lambda: True)

    def drain(self, receiver):
        scans = []
        while receiver.scans_available:
            scans.append(receiver.get_scan(timeout=0.1))
        return scans

    def test_second_scanner_on_the_same_port_is_ignored_not_merged(self):
        """Two units pushing to one port (same counter range, as when powered together) stay separate."""
        receiver = RSL235Udt(port=self.free_udp_port())
        with self.assertLogs("leuze_rsl.udt", level="WARNING") as logs:
            for n in range(1, 6):
                self.feed_cycle(receiver, "192.168.20.101", 1000 + n, 1)
                self.feed_cycle(receiver, "192.168.20.103", 1000 + n - 1, 2)     # other unit, one cycle behind
                self.feed_cycle(receiver, "192.168.20.103", 1000 + n + 1, 2)     # ... and ahead
        scans = self.drain(receiver)
        self.assertEqual([s.scan_number for s in scans], [1001, 1002, 1003, 1004, 1005])
        self.assertTrue(all(set(s.distances_mm) == {1} for s in scans))          # only the first unit's data
        self.assertEqual(receiver.source_address, "192.168.20.101")
        self.assertEqual(receiver.stats["foreign_datagrams_dropped"], 20)
        self.assertEqual(receiver.stats["stale_datagrams"], 0)
        self.assertEqual(len(logs.records), 1)                                   # reported once, not per datagram
        self.assertIn("192.168.20.103", logs.output[0])
        self.assertIn("192.168.20.101", logs.output[0])

    def test_another_scanner_takes_over_once_the_first_is_silent(self):
        receiver = RSL235Udt(port=self.free_udp_port(), data_timeout=3.0)
        self.assertIsNone(receiver.source_address)
        self.feed_cycle(receiver, "192.168.20.101", 500, 1)
        with self.assertLogs("leuze_rsl.udt", level="WARNING"):
            self.feed_cycle(receiver, "192.168.20.103", 77, 2)                   # first unit still alive: ignored
        self.assertEqual(receiver.source_address, "192.168.20.101")
        receiver._last_rx -= 10.0                                                # ... silent for 10 s
        with self.assertLogs("leuze_rsl.udt", level="WARNING") as logs:
            self.feed_cycle(receiver, "192.168.20.103", 78, 2)
        self.assertEqual(receiver.source_address, "192.168.20.103")
        self.assertIn("now come from 192.168.20.103", logs.output[0])
        first, second = self.drain(receiver)
        self.assertEqual((set(first.distances_mm), set(second.distances_mm)), ({1}, {2}))
        # the new scanner starts from a clean slate: its own status at once, no "restart" of the old counter
        self.assertEqual((second.scan_number, second.status.scan_number), (78, 78))
        self.assertEqual(receiver.latest_status.scan_number, 78)
        stats = receiver.stats
        self.assertEqual((stats["datagrams"], stats["scans_completed"]), (4, 2))        # the counters carry on
        self.assertEqual((stats["sequence_resets"], stats["sequence_jumps"], stats["foreign_datagrams_dropped"]),
                         (0, 0, 2))
        receiver._last_rx -= 10.0
        receiver._handle_datagram(b"garbage", "10.9.9.9", lambda: True)          # garbage never takes over
        self.assertEqual(receiver.source_address, "192.168.20.103")
        self.assertEqual(receiver.latest_status.scan_number, 78)

    def test_garbage_from_another_host_does_not_take_the_stream(self):
        receiver = RSL235Udt(port=self.free_udp_port())
        receiver._handle_datagram(b"not a telegram", "10.9.9.9", lambda: True)   # e.g. a port scan
        self.assertIsNone(receiver.source_address)
        self.feed_cycle(receiver, "192.168.20.101", 500, 1)                      # the scanner is not locked out
        self.assertEqual(receiver.source_address, "192.168.20.101")
        self.assertEqual(len(self.drain(receiver)), 1)
        self.assertEqual(receiver.stats["bad_frames"], 1)

    def test_source_ip_pins_the_sender(self):
        receiver = RSL235Udt(port=self.free_udp_port(), source_ip="192.168.20.103")
        self.feed_cycle(receiver, "192.168.20.101", 500, 1)
        self.feed_cycle(receiver, "192.168.20.103", 600, 2)
        self.assertEqual([set(s.distances_mm) for s in self.drain(receiver)], [{2}])
        self.assertEqual(receiver.stats["foreign_datagrams_dropped"], 2)
        self.assertEqual(receiver.source_address, "192.168.20.103")

    def test_two_senders_over_real_sockets(self):
        second = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(second.close)
        try:
            second.bind(("127.0.0.2", 0))
        except OSError:
            self.skipTest("no second loopback address on this platform")
        receiver = self.start_receiver()
        self.start_simulator(receiver.port)                                     # sends from 127.0.0.1
        receiver.get_scan(timeout=5.0)
        with self.assertLogs("leuze_rsl.udt", level="WARNING") as logs:
            try:
                for n in range(5):
                    second.sendto(make_status_datagram(900000 + n), ("127.0.0.1", receiver.port))
                    second.sendto(make_measurement_datagram(900000 + n, 0, [7] * 271, [1] * 271),
                                  ("127.0.0.1", receiver.port))
            except OSError:
                self.skipTest("cannot send between loopback addresses on this platform")
            deadline = time.monotonic() + 5.0
            while receiver.stats["foreign_datagrams_dropped"] < 10 and time.monotonic() < deadline:
                time.sleep(0.01)
        self.assertEqual(len(logs.records), 1)
        self.assertEqual(receiver.stats["foreign_datagrams_dropped"], 10)
        self.assertEqual(receiver.source_address, "127.0.0.1")
        self.assertEqual(receiver.stats["sequence_jumps"], 0)
        for _ in range(5):
            self.assertNotEqual(set(receiver.get_scan(timeout=5.0).distances_mm), {7})

    def test_is_receiving_survives_a_concurrent_restart(self):
        """Regression: is_receiving read the timestamp twice and raised TypeError when start() reset it in between."""
        receiver = RSL235Udt(port=self.free_udp_port())

        values = iter([123.0, None])                  # what two consecutive reads would see during a restart
        receiver._running = True
        with mock.patch.object(RSL235Udt, "_last_rx", new_callable=mock.PropertyMock,
                               side_effect=lambda: next(values), create=True):
            self.assertIn(receiver.is_receiving, (True, False))    # must not raise

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
