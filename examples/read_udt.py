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

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(name)s %(levelname)s: %(message)s")

    simulator = None
    if args.simulate:
        from leuze_rsl.simulator import UdtSimulator
        simulator = UdtSimulator(target_port=args.port).start()
        print("UDT simulator pushing to 127.0.0.1:%d" % args.port)

    try:
        with RSL235Udt(port=args.port, source_ip=args.source_ip) as receiver:
            print("listening for UDP data telegrams on port %d ..." % args.port)
            for i in range(args.count):
                scan = receiver.get_scan(timeout=5.0)
                valid = [d for d, ok in zip(scan.distances_mm, scan.valid_mask())
                         if ok]
                line = ("scan %10d: %4d beams in %d datagram(s)  "
                        % (scan.scan_number, scan.num_beams, scan.num_blocks))
                if valid:
                    line += ("min %6.2f m  max %6.2f m  (%d no-echo)"
                             % (min(valid) / 1000.0, max(valid) / 1000.0,
                                scan.num_beams - len(valid)))
                else:
                    line += "no valid echoes"
                if scan.signal_strengths is not None:
                    line += "  signal[mid]=%d" % scan.signal_strengths[scan.num_beams // 2]
                print(line)

            if receiver.contour is not None:
                c = receiver.contour
                print("contour: indices %d..%d step %d -> %d beams, "
                      "angles %.1f..%.1f deg (assuming 275 deg FoV centered)"
                      % (c.start_index, c.stop_index, c.index_interval,
                         c.num_beams, scan.angles_deg()[0], scan.angles_deg()[-1]))
            status = receiver.latest_status
            if status is not None:
                print("status: mode=%d error=%s alarm=%s screen=%s ossd_a=%s ossd_b=%s"
                      % (status.operating_mode, status.error, status.alarm,
                         status.screen_contaminated, status.ossd_a, status.ossd_b))
            print("stats:", receiver.stats)
    except (TimeoutError, leuze_rsl.RSL235Error) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    finally:
        if simulator is not None:
            simulator.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
