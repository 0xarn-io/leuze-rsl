"""Command-line entry point: read scans from a Leuze scanner and print them.

Run directly from an installed package, no checkout needed::

    python -m leuze_rsl --port 3050 --count 10        # RSL 235 UDT (default)
    python -m leuze_rsl --rod 192.168.60.101          # ROD 308/508 TCP client
    python -m leuze_rsl --simulate                    # built-in simulator

For the default (UDT) mode the scanner must be configured in Sensor Studio to
push its UDP telegram to this machine's IP on the given port. For ``--rod`` the
tool connects to the scanner at the supplied IP over TCP.
"""

import argparse
import logging
import sys

from . import DEFAULT_UDT_PORT, RSL235Error, RSL235Udt


def _run_udt(args: argparse.Namespace) -> int:
    simulator = None
    if args.simulate:
        from .simulator import UdtSimulator
        simulator = UdtSimulator(target_port=args.port).start()
        print("UDT simulator pushing to 127.0.0.1:%d" % args.port)
    try:
        with RSL235Udt(port=args.port, source_ip=args.source_ip) as receiver:
            print("listening for UDP data telegrams on port %d ..." % args.port)
            for _ in range(args.count):
                scan = receiver.get_scan(timeout=args.timeout)
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
                    line += ("  signal[mid]=%d"
                             % scan.signal_strengths[scan.num_beams // 2])
                print(line)
            status = receiver.latest_status
            if status is not None:
                print("status: mode=%d error=%s ossd_a=%s ossd_b=%s"
                      % (status.operating_mode, status.error,
                         status.ossd_a, status.ossd_b))
            print("stats:", receiver.stats)
    except (TimeoutError, RSL235Error) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    finally:
        if simulator is not None:
            simulator.stop()
    return 0


def _run_rod(args: argparse.Namespace) -> int:
    from . import RSL235
    try:
        with RSL235(args.rod, port=args.port) as scanner:
            scanner.start_measurement()
            print("connected to %s, reading %d scans ..."
                  % (args.rod, args.count))
            for _ in range(args.count):
                scan = scanner.get_scan(timeout=args.timeout)
                valid = [d for d in scan.distances_mm if d > 0]  # 0 = no echo
                line = ("scan #%d: %4d spots  "
                        % (scan.packet_number, scan.num_spots))
                line += (("min %6.2f m  max %6.2f m  (%d no-echo)"
                          % (min(valid) / 1000.0, max(valid) / 1000.0,
                             scan.num_spots - len(valid)))
                         if valid else "no valid echoes")
                print(line)
    except (TimeoutError, RSL235Error) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m leuze_rsl",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rod", metavar="IP", default=None,
                        help="connect to a ROD 308/508 scanner at this IP over "
                             "TCP instead of listening for RSL 235 UDT")
    parser.add_argument("--port", type=int, default=DEFAULT_UDT_PORT,
                        help="UDT destination port, or ROD TCP port "
                             "(default: %(default)s)")
    parser.add_argument("--source-ip", default=None,
                        help="UDT mode: only accept datagrams from this scanner IP")
    parser.add_argument("--count", type=int, default=10,
                        help="number of scans to read (default: %(default)s)")
    parser.add_argument("--timeout", type=float, default=5.0,
                        help="per-scan timeout in seconds (default: %(default)s)")
    parser.add_argument("--simulate", action="store_true",
                        help="UDT mode: run against the built-in simulator")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s: %(message)s")

    return _run_rod(args) if args.rod else _run_udt(args)


if __name__ == "__main__":
    sys.exit(main())
