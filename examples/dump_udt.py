#!/usr/bin/env python3
"""Diagnostic: dump and decode raw UDP data telegrams from an RSL scanner.

Prints the decoded frame of every datagram and the full hex of the first
few -- useful to verify the telegram layout of a particular device model.

    python3 examples/dump_udt.py --port 3050 --hex-count 4
"""

import argparse
import socket
import sys
from pathlib import Path

try:
    import leuze_rsl  # noqa: F401
except ImportError:                       # allow running from the repo checkout
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from leuze_rsl.udt import FRAME_SIZE, StatusProfile, UdtFrame, locate_contour

ID_NAMES = {1: "status", 3: "dist+signal", 6: "distance"}


def hexdump(data: bytes, prefix: str = "    ") -> str:
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        lines.append("%s%04x  %s" % (prefix, off, chunk.hex(" ")))
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=3050)
    parser.add_argument("--count", type=int, default=20,
                        help="datagrams to decode (default: %(default)s)")
    parser.add_argument("--hex-count", type=int, default=4,
                        help="datagrams to fully hex-dump (default: %(default)s)")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", args.port))
    print("listening on UDP port %d ... Ctrl+C to stop" % args.port)

    expected_beams = None
    try:
        for n in range(args.count):
            data, addr = sock.recvfrom(65535)
            line = "#%-3d %5d B from %s:%d" % (n, len(data), addr[0], addr[1])
            if len(data) >= FRAME_SIZE:
                frame = UdtFrame.from_bytes(data)
                line += ("  id=%d(%s) block=%d scan=%d len=%d h2=%s"
                         % (frame.telegram_id,
                            ID_NAMES.get(frame.telegram_id, "?"),
                            frame.block, frame.scan_number,
                            frame.total_length, frame.header2.hex()))
                payload = data[FRAME_SIZE:]
                if frame.telegram_id == 3:
                    expected_beams = len(payload) // 4
                elif frame.telegram_id == 6:
                    expected_beams = len(payload) // 2
                elif frame.telegram_id == 1:
                    status = StatusProfile.from_bytes(payload)
                    line += ("\n     status: type=%d mode=%d error=%s alarm=%s "
                             "ossd_a=%s ossd_b=%s scan=%d"
                             % (status.profile_type, status.operating_mode,
                                status.error, status.alarm, status.ossd_a,
                                status.ossd_b, status.scan_number))
                    located = locate_contour(payload, expected_beams)
                    if located:
                        off, c = located
                        line += ("\n     contour @data[%d]: start=%d stop=%d "
                                 "interval=%d -> %d beams"
                                 % (off, c.start_index, c.stop_index,
                                    c.index_interval, c.num_beams))
            print(line)
            if n < args.hex_count:
                print(hexdump(data if len(data) <= 96 else data[:96]))
                if len(data) > 96:
                    print("    ... (%d more bytes)" % (len(data) - 96))
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
