#!/usr/bin/env python3
"""Dump configuration and status of an RSL 235 via the TCP command interface.

    python3 examples/read_status.py 192.168.60.101
    python3 examples/read_status.py --simulate
"""

import argparse
import sys
from pathlib import Path

try:
    import leuze_rsl
except ImportError:                       # allow running from the repo checkout
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import leuze_rsl

from leuze_rsl import RSL235


def fmt(value):
    import enum
    if isinstance(value, enum.Enum):
        return "%s (%d)" % (value.name, value.value)
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", nargs="?", default="192.168.60.101")
    parser.add_argument("--port", type=int, default=leuze_rsl.DEFAULT_PORT)
    parser.add_argument("--simulate", action="store_true")
    args = parser.parse_args()

    simulator = None
    if args.simulate:
        from leuze_rsl.simulator import RSL235Simulator
        simulator = RSL235Simulator().start()
        args.host, args.port = "127.0.0.1", simulator.port

    try:
        with RSL235(args.host, args.port) as scanner:
            status = scanner.get_status()
            print("RSL235 status (%s:%d)" % (args.host, args.port))
            print("-" * 50)
            print("part number:          %s" % status.part_number)
            print("hw / sw version:      %s / %s" % (status.hw_version, status.sw_version))
            print("temperature:          %s degC" % status.temperature_c)
            print("operating hours:      %s h" % status.operating_hours)
            print("window calibration:   %s" % fmt(status.window_calibration))
            print("protocol:             %s" % fmt(status.protocol))
            print("packet type:          %s" % fmt(status.packet_type))
            print("resolution:           %s" % fmt(status.resolution))
            print("direction:            %s" % fmt(status.direction))
            print("angle range:          %s .. %s deg" % (status.angle_min_deg,
                                                          status.angle_max_deg))
            print("skip spots:           %s" % status.skip_spots)
            print("filter:               %s (hist=%s, nghb=%s)"
                  % (fmt(status.filter_type), status.filter_historical_spots,
                     status.filter_neighboring_spots))
            print("contamination:        warn>=%s%% error>=%s%% state=%s"
                  % (status.contamination_warn_pct, status.contamination_error_pct,
                     status.contamination_state))
            print("active error code:    %s" % status.error_code)
            print("error log:            %s" % [(e.code, e.date) for e in status.error_log])
            print("MDI stream active:    %s" % status.mdi_tx_active)
            if status.errors:
                print("fields that failed:   %s" % status.errors)
    except leuze_rsl.RSL235Error as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    finally:
        if simulator is not None:
            simulator.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
