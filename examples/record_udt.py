#!/usr/bin/env python3
"""Record raw UDP data telegrams from one or more RSL scanners to files.

Needs only the standard library, so it can run on any machine the scanners
push to (configure this machine's IP and one port per scanner under Sensor
Studio > SETTINGS > Data telegrams).  The files hold the datagrams exactly as
sent, for offline analysis or a bug report:

    python3 examples/record_udt.py --port 9999 --seconds 10 --out rsl235.bin
    python3 examples/record_udt.py --port 9991 9992 9993 9994 9995 9996

With several ports, every port is recorded to its own file (``--out`` must
contain ``{port}``; the default is ``udt_{port}.bin``).

File format (little-endian): the 8-byte magic ``LRSLUDT1``, then one record
per datagram: ``<d4sH`` = receive time (seconds since the epoch), source IPv4
address, payload length, followed by the payload bytes.
"""

import argparse
import select
import socket
import struct
import time
from typing import Dict

MAGIC = b"LRSLUDT1"
RECORD = struct.Struct("<d4sH")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, nargs="+", default=[3050], metavar="PORT",
                        help="UDP port(s) the scanner(s) push to (default: %(default)s)")
    parser.add_argument("--seconds", type=float, default=10.0,
                        help="recording duration (default: %(default)s)")
    parser.add_argument("--out", default="udt_{port}.bin",
                        help="output file; {port} is replaced by the port number "
                             "(default: %(default)s)")
    args = parser.parse_args()
    if len(set(args.port)) != len(args.port):
        parser.error("ports must be distinct")
    if len(args.port) > 1 and "{port}" not in args.out:
        parser.error("--out must contain {port} when recording several ports")

    sockets: Dict[socket.socket, int] = {}
    files = {}
    counts = {port: 0 for port in args.port}
    try:
        for port in args.port:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("", port))
            sockets[sock] = port
            path = args.out.replace("{port}", str(port))
            files[port] = (path, open(path, "wb"))
            files[port][1].write(MAGIC)
        print("recording UDP port(s) %s for %.0f s ... Ctrl+C to stop early"
              % (", ".join(str(p) for p in args.port), args.seconds))
        deadline = time.monotonic() + args.seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            ready, _, _ = select.select(list(sockets), [], [], min(1.0, remaining))
            now = time.time()
            for sock in ready:
                data, (ip, _) = sock.recvfrom(65535)
                port = sockets[sock]
                out = files[port][1]
                out.write(RECORD.pack(now, socket.inet_aton(ip), len(data)))
                out.write(data)
                counts[port] += 1
    except KeyboardInterrupt:
        pass
    finally:
        for sock in sockets:
            sock.close()
        for _, out in files.values():
            out.close()
    for port in args.port:
        if port in files:
            print("port %d: recorded %d datagrams to %s" % (port, counts[port], files[port][0]))
    return 0 if all(counts.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())
