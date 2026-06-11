#!/usr/bin/env python3
"""Read measurement data (UDP data telegrams) from an RSL 235 and print it.

Against a real scanner:

    python3 examples/read_udt.py 192.168.60.101 --port 3050 --count 10

Without hardware (spins up the built-in simulator):

    python3 examples/read_udt.py --simulate
"""

import argparse
import logging
import sys
from pathlib import Path

try:
    import leuze_rsl
except ImportError:                       # allow running from the repo checkout
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import leuze_rsl

from leuze_rsl import RSL235


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("host", nargs="?", default="192.168.60.101",
                        help="scanner IP address (default: %(default)s)")
    parser.add_argument("--port", type=int, default=leuze_rsl.DEFAULT_PORT,
                        help="scanner port (default: %(default)s)")
    parser.add_argument("--udp-port", type=int, default=None,
                        help="local UDP port for the data (default: same as --port)")
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
        from leuze_rsl.simulator import RSL235Simulator
        simulator = RSL235Simulator().start()
        args.host, args.port, args.udp_port = "127.0.0.1", simulator.port, None
        print("simulator running on 127.0.0.1:%d" % simulator.port)

    try:
        with RSL235(args.host, args.port, udp_port=args.udp_port) as scanner:
            cfg = scanner.config
            print("connected: %.1f..%.1f deg @ %.3f deg / %.0f Hz, %s via %s"
                  % (cfg.angle_min_deg, cfg.angle_max_deg,
                     cfg.angular_resolution_deg, cfg.scan_frequency_hz,
                     cfg.packet_type.name, cfg.protocol.name))

            scanner.start_measurement()
            for i in range(args.count):
                scan = scanner.get_scan(timeout=5.0)
                valid = [d for d in scan.distances_mm if d > 0]
                line = ("scan %3d: %4d spots  t=%5d ms  "
                        % (i, scan.num_spots, scan.timestamp_ms))
                if valid:
                    line += ("min %5.2f m  max %5.2f m"
                             % (min(valid) / 1000.0, max(valid) / 1000.0))
                else:
                    line += "no valid echoes"
                if scan.intensities is not None:
                    line += "  intensity[mid]=%d" % scan.intensities[scan.num_spots // 2]
                print(line)
            scanner.stop_measurement()
            print("stats:", scanner.stats)
    except (TimeoutError, leuze_rsl.RSL235Error) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    finally:
        if simulator is not None:
            simulator.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
