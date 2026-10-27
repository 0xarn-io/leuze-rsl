#!/usr/bin/env python3
"""Record raw UDP data telegrams from an RSL scanner to a file.

Needs only the standard library, so it can run on any machine the scanner
pushes to (configure this machine's IP and port under Sensor Studio >
SETTINGS > Data telegrams).  The file holds the datagrams exactly as sent,
for offline analysis or a bug report:

    python3 examples/record_udt.py --port 9999 --seconds 10 --out rsl235.bin

File format (little-endian): the 8-byte magic ``LRSLUDT1``, then one record
per datagram: ``<d4sH`` = receive time (seconds since the epoch), source IPv4
address, payload length, followed by the payload bytes.
"""

import argparse
import socket
import struct
import time

MAGIC = b"LRSLUDT1"
RECORD = struct.Struct("<d4sH")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=3050,
                        help="UDP port the scanner pushes to (default: %(default)s)")
    parser.add_argument("--seconds", type=float, default=10.0,
                        help="recording duration (default: %(default)s)")
    parser.add_argument("--out", default="udt_capture.bin",
                        help="output file (default: %(default)s)")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", args.port))
    sock.settimeout(1.0)                # keeps Ctrl+C responsive on Windows
    count = 0
    deadline = time.monotonic() + args.seconds
    print("recording UDP port %d for %.0f s to %s ..." % (args.port, args.seconds, args.out))
    try:
        with open(args.out, "wb") as out:
            out.write(MAGIC)
            while time.monotonic() < deadline:
                try:
                    data, (ip, _) = sock.recvfrom(65535)
                except socket.timeout:
                    continue
                out.write(RECORD.pack(time.time(), socket.inet_aton(ip), len(data)))
                out.write(data)
                count += 1
    except KeyboardInterrupt:
        pass
    finally:
        sock.close()
    print("recorded %d datagrams to %s" % (count, args.out))
    return 0 if count else 1


if __name__ == "__main__":
    raise SystemExit(main())
