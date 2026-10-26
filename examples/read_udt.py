#!/usr/bin/env python3
"""Receive the UDP data telegrams ("UDT") an RSL 235 pushes and print them.

The scanner must be configured in Sensor Studio (SETTINGS > Data telegrams):
UDP telegram active, destination = this machine's IP, and measurement value
transmission enabled.  Then simply:

    python3 examples/read_udt.py --port 3050 --count 10

Without hardware (spins up the built-in UDT simulator):

    python3 examples/read_udt.py --simulate
"""

import argparse
import logging
import sys
from pathlib import Path

try:
    import leuze_rsl
except ImportError:                       # allow running from the repo checkout
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    import leuze_rsl

from leuze_rsl import RSL235Udt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--port", type=int, default=leuze_rsl.DEFAULT_UDT_PORT,
                        help="UDP destination port configured in the scanner "
                             "(default: %(default)s)")
    parser.add_argument("--source-ip", default=None,
                        help="only accept datagrams from this scanner IP")
    parser.add_argument("--count", type=int, default=10,
                        help="number of scans to read (default: %(default)s)")
    parser.add_argument("--simulate", action="store_true",
                        help="run against the built-in simulator instead of hardware")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(asctime)s %(name)s %(levelname)s: %(message)s")

    simulator = None
    receiver = RSL235Udt(port=args.port, source_ip=args.source_ip)
    try:
        receiver.start()                  # bind before the simulator starts pushing
        if args.simulate:
            from leuze_rsl.simulator import UdtSimulator
            simulator = UdtSimulator(target_port=args.port).start()
            print("UDT simulator pushing to 127.0.0.1:%d" % args.port)
        print("listening for UDP data telegrams on port %d ..." % args.port)
        scan = None
        for _ in range(args.count):
            scan = receiver.get_scan(timeout=5.0)
            valid = [d for d, ok in zip(scan.distances_mm, scan.valid_mask()) if ok]
            line = ("scan %10d: %4d beams in %d datagram(s)  "
                    % (scan.scan_number, scan.num_beams, scan.num_blocks))
            if valid:
                line += ("min %6.2f m  max %6.2f m  (%d no-echo)"
                         % (min(valid) / 1000.0, max(valid) / 1000.0,
                            scan.num_beams - len(valid)))
            else:
                line += "no valid echoes"
            if scan.signal_strengths:
                line += "  signal[mid]=%d" % scan.signal_strengths[len(scan.signal_strengths) // 2]
            print(line)

        if scan is not None and scan.contour is not None:
            c = scan.contour
            angles = scan.angles_deg()
            print("contour: indices %d..%d step %d -> %d beams, angles %.1f..%.1f deg "
                  "(%s geometry; verify against a known target)"
                  % (c.start_index, c.stop_index, c.index_interval, c.num_beams,
                     angles[0], angles[-1],
                     scan.family.name if scan.family is not None else "default"))
        status = receiver.latest_status
        if status is not None:
            print("status: family=%s mode=%d error=%s alarm=%s screen=%s ossd=%s "
                  "protective_field_violated=%s warning_field_violated=%s"
                  % (status.family.name if status.family is not None else "unknown",
                     status.operating_mode, status.error, status.alarm,
                     status.screen_contaminated, status.ossd_a,
                     status.a_protective_violated, status.a_warning_violated))
        print("stats:", receiver.stats)
    except KeyboardInterrupt:
        return 130
    except (leuze_rsl.RSL235Error, OSError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    finally:
        if simulator is not None:
            simulator.stop()
        receiver.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
