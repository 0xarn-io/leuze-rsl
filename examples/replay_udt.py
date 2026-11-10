#!/usr/bin/env python3
"""Decode capture files written by record_udt.py, without a scanner.

Feeds the recorded datagrams to the same assembler the live receiver uses
and prints what a receiver would have seen: scans, missed cycles, the
status profile and any warning the device reports.

    python3 examples/replay_udt.py udt_9991.bin udt_9992.bin
    python3 examples/replay_udt.py rsl235.bin --scans 5       # also list the first scans
"""

import argparse
import importlib.util
import socket
import struct
import sys
from pathlib import Path
from typing import Iterator, Tuple

if importlib.util.find_spec("leuze_rsl") is None:   # allow running from the repo checkout
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from leuze_rsl.udt import UdtAssembler

MAGIC = b"LRSLUDT1"
RECORD = struct.Struct("<d4sH")


def read_capture(path: str) -> Iterator[Tuple[float, str, bytes]]:
    """Yield ``(receive time, sender IP, datagram)`` for every record of a capture file."""
    with open(path, "rb") as capture:
        if capture.read(len(MAGIC)) != MAGIC:
            raise ValueError("%s is not a record_udt.py capture" % path)
        while True:
            header = capture.read(RECORD.size)
            if len(header) < RECORD.size:
                return
            received, ip, length = RECORD.unpack(header)
            datagram = capture.read(length)
            if len(datagram) < length:
                return                                  # recording was cut off mid-record
            yield received, socket.inet_ntoa(ip), datagram


def replay(path: str, list_scans: int) -> bool:
    assembler = UdtAssembler()
    senders = set()
    scans = []
    first = last = None
    for received, sender, datagram in read_capture(path):
        first = received if first is None else first
        last = received
        senders.add(sender)
        scans.extend(assembler.feed_datagram(datagram))
    stats = assembler.stats
    print("%s: %d datagrams from %s in %.1f s" % (
        path, stats.datagrams, ", ".join(sorted(senders)) or "nobody",
        (last - first) if first is not None and last is not None else 0.0))
    if len(senders) > 1:
        print("  NOTE: several senders in one file -- two scanners pushed to this port; "
              "a live receiver follows only one of them")
    print("  scans: %d complete, %d dropped incomplete, %d cycles never sent or lost, "
          "%d bad frames, %d stale datagrams"
          % (len(scans), stats.scans_dropped_incomplete, stats.cycles_missed,
             stats.bad_frames, stats.stale_datagrams))
    contour = assembler.contour
    if contour is not None:
        print("  contour: indices %d..%d step %d -> %d beams"
              % (contour.start_index, contour.stop_index, contour.index_interval, contour.num_beams))
    for scan in scans[:list_scans]:
        valid = [d for d, ok in zip(scan.distances_mm, scan.valid_mask()) if ok]
        print("  scan %10d: %4d beams, %4d valid, min %s mm, max %s mm" % (
            scan.scan_number, scan.num_beams, len(valid),
            min(valid) if valid else "-", max(valid) if valid else "-"))
    if scans:
        beams = sum(scan.num_beams for scan in scans)
        no_echo = sum(scan.distances_mm.count(65535) for scan in scans)
        weak = sum(scan.distances_mm.count(32767) for scan in scans)
        print("  beams: %d, of which %d without echo (65535) and %d without distance (32767)"
              % (beams, no_echo, weak))
    status = assembler.latest_status
    if status is not None:
        print("  status: family=%s mode=%d error=%s warning=%s ossd=%s protective_field_violated=%s"
              % (status.family.name if status.family is not None else "unknown",
                 status.operating_mode, status.error, status.warning, status.ossd_a,
                 status.a_protective_violated))
        if status.supply_voltage_v is not None:
            print("  supply %.1f V, temperature %s degC" % (status.supply_voltage_v, status.temperature_c))
        with_warning = sum(1 for scan in scans if scan.status is not None and scan.status.screen_warning)
        if with_warning:
            print("  DEVICE WARNING: optics cover contamination warning in %d of %d scans"
                  % (with_warning, len(scans)))
        if any(scan.status is not None and scan.status.screen_error for scan in scans):
            print("  DEVICE ERROR: optics cover contamination error (OSSDs switched off)")
    return bool(scans)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("files", nargs="+", help="capture file(s) written by record_udt.py")
    parser.add_argument("--scans", type=int, default=0, metavar="N",
                        help="also list the first N scans of every file (default: %(default)s)")
    args = parser.parse_args()
    ok = True
    for path in args.files:
        try:
            ok = replay(path, max(0, args.scans)) and ok
        except (OSError, ValueError) as exc:
            print("error: %s" % exc, file=sys.stderr)
            ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
