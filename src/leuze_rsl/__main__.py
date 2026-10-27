"""Command-line entry point: read scans from a Leuze scanner and print them.

Run directly from an installed package, no checkout needed::

    python -m leuze_rsl --port 3050 --count 10        # RSL 235 UDT (default)
    python -m leuze_rsl --rod 192.168.60.101          # ROD 308/508 TCP client
    python -m leuze_rsl --simulate                    # built-in simulator
    python -m leuze_rsl --rod --simulate              # built-in ROD simulator

For the default (UDT) mode the scanner must be configured in Sensor Studio to
push its UDP telegram to this machine's IP on the given port. For ``--rod`` the
tool connects to the scanner at the supplied IP over TCP.

Exit codes: 0 success, 1 error, 2 usage error, 130 interrupted (Ctrl+C).
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Any, List, Optional

from .errors import RSL235Error
from .udt import DEFAULT_UDT_PORT, RSL235Udt

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INTERRUPTED = 130


def _run_udt(args: argparse.Namespace) -> int:
    simulator: Any = None
    receiver = RSL235Udt(port=args.port, source_ip=args.source_ip)
    try:
        receiver.start()            # bind before the simulator starts pushing
        if args.simulate:
            from .simulator import UdtSimulator
            simulator = UdtSimulator(target_port=args.port).start()
            print("UDT simulator pushing to 127.0.0.1:%d" % args.port)
        print("listening for UDP data telegrams on port %d ..." % args.port)
        for _ in range(args.count):
            scan = receiver.get_scan(timeout=args.timeout)
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
        status = receiver.latest_status
        if status is not None:
            line = ("status: family=%s mode=%d error=%s ossd=%s protective_field_violated=%s"
                    % (status.family.name if status.family is not None else "unknown",
                       status.operating_mode, status.error, status.ossd_a,
                       status.a_protective_violated))
            if status.supply_voltage_v is not None and status.temperature_c is not None:
                line += "  supply=%.1f V  temperature=%.1f degC" % (
                    status.supply_voltage_v, status.temperature_c)
            print(line)
        contour = receiver.contour
        if contour is not None:
            print("contour: indices %d..%d step %d -> %d beams"
                  % (contour.start_index, contour.stop_index,
                     contour.index_interval, contour.num_beams))
        print("stats:", receiver.stats)
    finally:
        if simulator is not None:
            simulator.stop()
        receiver.stop()
    return EXIT_OK


def _run_rod(args: argparse.Namespace) -> int:
    from .driver import RSL235
    simulator: Any = None
    host, port, udp_port = args.rod, args.port, args.udp_port
    if args.simulate:
        from .simulator import RSL235Simulator
        simulator = RSL235Simulator().start()
        host, port, udp_port = "127.0.0.1", simulator.port, None
        print("ROD simulator listening on 127.0.0.1:%d" % simulator.port)
    try:
        with RSL235(host, port=port, udp_port=udp_port) as scanner:
            scanner.start_measurement()
            print("connected to %s:%d, reading %d scans ..." % (host, port, args.count))
            for _ in range(args.count):
                scan = scanner.get_scan(timeout=args.timeout)
                valid = [d for d, ok in zip(scan.distances_mm, scan.valid_mask()) if ok]
                line = ("packet #%5d: %4d spots  t=%5d ms  "
                        % (scan.packet_number, scan.num_spots, scan.timestamp_ms))
                line += (("min %6.2f m  max %6.2f m  (%d invalid)"
                          % (min(valid) / 1000.0, max(valid) / 1000.0,
                             scan.num_spots - len(valid)))
                         if valid else "no valid echoes")
                print(line)
            print("stats:", scanner.stats)
    finally:
        if simulator is not None:
            simulator.stop()
    return EXIT_OK


def _port(text: str) -> int:
    value = int(text)
    if not 1 <= value <= 65535:
        raise argparse.ArgumentTypeError("port must be in 1..65535")
    return value


def _non_negative_int(text: str) -> int:
    value = int(text)
    if value < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return value


def _positive_float(text: str) -> float:
    value = float(text)
    if not value > 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m leuze_rsl",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rod", metavar="IP", nargs="?", const="192.168.60.101", default=None,
                        help="connect to a ROD 308/508 scanner at this IP over TCP "
                             "(default IP: %(const)s) instead of listening for RSL UDT")
    parser.add_argument("--port", type=_port, default=DEFAULT_UDT_PORT,
                        help="UDT destination port, or ROD TCP command port "
                             "(default: %(default)s)")
    parser.add_argument("--udp-port", type=_port, default=None,
                        help="ROD mode: local UDP port for the measurement data "
                             "(default: same as --port)")
    parser.add_argument("--source-ip", default=None,
                        help="UDT mode: only accept datagrams from this scanner IP")
    parser.add_argument("--count", type=_non_negative_int, default=10,
                        help="number of scans to read (default: %(default)s)")
    parser.add_argument("--timeout", type=_positive_float, default=5.0,
                        help="per-scan timeout in seconds (default: %(default)s)")
    parser.add_argument("--simulate", action="store_true",
                        help="run against the built-in simulator instead of hardware")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="log library messages (-v: info, -vv: debug)")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.rod is None and args.udp_port is not None:
        parser.error("--udp-port only applies to --rod mode")
    if args.rod is not None and args.source_ip is not None:
        parser.error("--source-ip only applies to UDT mode")

    level = logging.WARNING if args.verbose == 0 else (
        logging.INFO if args.verbose == 1 else logging.DEBUG)
    logging.basicConfig(level=level,
                        format="%(asctime)s %(name)s %(levelname)s: %(message)s")

    try:
        return _run_rod(args) if args.rod is not None else _run_udt(args)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_INTERRUPTED
    except (RSL235Error, OSError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
