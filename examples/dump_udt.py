#!/usr/bin/env python3
"""Diagnostic: dump and decode raw UDP data telegrams from an RSL scanner.

Prints the decoded frame of every datagram and the full hex of the first
few -- useful to verify the telegram layout of a particular device model.

    python3 examples/dump_udt.py --port 3050 --hex-count 4
    python3 examples/dump_udt.py --simulate
"""

import argparse
import importlib.util
import socket
import sys
from pathlib import Path

if importlib.util.find_spec("leuze_rsl") is None:   # allow running from the repo checkout
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from leuze_rsl.errors import ProtocolError
from leuze_rsl.udt import FRAME_SIZE, MeasurementContour, StatusProfile, UdtFrame, locate_contour

ID_NAMES = {1: "status", 3: "dist+signal", 6: "distance"}


def hexdump(data: bytes, prefix: str = "    ") -> str:
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        lines.append("%s%04x  %s" % (prefix, off, chunk.hex(" ")))
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=3050,
                        help="UDP port to listen on (default: %(default)s)")
    parser.add_argument("--count", type=int, default=20,
                        help="datagrams to decode (default: %(default)s)")
    parser.add_argument("--hex-count", type=int, default=4,
                        help="datagrams to fully hex-dump (default: %(default)s)")
    parser.add_argument("--simulate", action="store_true",
                        help="dump the built-in simulator's datagrams")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    simulator = None
    try:
        sock.bind(("", args.port))
        sock.settimeout(0.5)            # keeps Ctrl+C responsive on Windows
        if args.simulate:
            from leuze_rsl.simulator import UdtSimulator
            simulator = UdtSimulator(target_port=args.port).start()
        print("listening on UDP port %d ... Ctrl+C to stop" % args.port)

        beams_per_scan = {}             # scan number -> beams seen so far
        n = 0
        while n < args.count:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            line = "#%-3d %5d B from %s:%d" % (n, len(data), addr[0], addr[1])
            if len(data) >= FRAME_SIZE:
                frame = UdtFrame.from_bytes(data)
                line += ("  id=%d(%s) block=%d scan=%d len=%d h2=%s"
                         % (frame.telegram_id,
                            ID_NAMES.get(frame.telegram_id, "?"),
                            frame.block, frame.scan_number,
                            frame.total_length, frame.header2.hex()))
                payload = data[FRAME_SIZE:]
                if frame.telegram_id in (3, 6):
                    per_beam = 4 if frame.telegram_id == 3 else 2
                    beams_per_scan[frame.scan_number] = (
                        beams_per_scan.get(frame.scan_number, 0) + len(payload) // per_beam)
                elif frame.telegram_id == 1:
                    try:
                        status = StatusProfile.from_bytes(payload)
                    except ProtocolError as exc:
                        print(line + "\n     status: undecodable (%s)" % exc)
                        n += 1
                        continue
                    line += ("\n     status: type=%d (%s) mode=%d error=%s alarm=%s "
                             "ossd=%s pf_violated=%s scan=%d"
                             % (status.profile_type,
                                status.family.name if status.family else "unknown layout",
                                status.operating_mode, status.error, status.alarm,
                                status.ossd_a, status.a_protective_violated,
                                status.scan_number))
                    if status.contour_offset is not None:
                        contour = MeasurementContour.from_bytes(payload, status.contour_offset)
                        located = (status.contour_offset, contour) if contour else None
                    else:
                        expected = beams_per_scan.get(frame.scan_number - 1)
                        located = locate_contour(payload, expected)
                    if located:
                        off, c = located
                        line += ("\n     contour @data[%d]: start=%d stop=%d "
                                 "interval=%d -> %d beams"
                                 % (off, c.start_index, c.stop_index,
                                    c.index_interval, c.num_beams))
                    else:
                        line += "\n     contour: none (measurement transmission inactive?)"
            print(line)
            if n < args.hex_count:
                print(hexdump(data if len(data) <= 96 else data[:96]))
                if len(data) > 96:
                    print("    ... (%d more bytes)" % (len(data) - 96))
            n += 1
    except KeyboardInterrupt:
        return 130
    except OSError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    finally:
        if simulator is not None:
            simulator.stop()
        sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
