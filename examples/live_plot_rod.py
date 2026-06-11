#!/usr/bin/env python3
"""Live polar plot of RSL 235 scans (requires matplotlib).

    python3 examples/live_plot.py 192.168.60.101
    python3 examples/live_plot.py --simulate
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", nargs="?", default="192.168.60.101")
    parser.add_argument("--port", type=int, default=leuze_rsl.DEFAULT_PORT)
    parser.add_argument("--rmax", type=float, default=10.0,
                        help="plot range in meters (default: %(default)s)")
    parser.add_argument("--simulate", action="store_true")
    args = parser.parse_args()

    try:
        import matplotlib.pyplot as plt
    except ImportError:
        print("this example needs matplotlib:  pip install matplotlib",
              file=sys.stderr)
        return 1

    simulator = None
    if args.simulate:
        from leuze_rsl.simulator import RSL235Simulator
        simulator = RSL235Simulator().start()
        args.host, args.port = "127.0.0.1", simulator.port

    try:
        with RSL235(args.host, args.port) as scanner:
            scanner.start_measurement()
            plt.ion()
            fig = plt.figure("RSL235 live scan")
            ax = fig.add_subplot(111, projection="polar")
            scatter = ax.scatter([], [], s=2)
            ax.set_rmax(args.rmax)
            ax.set_title("RSL235 @ %s" % args.host)
            while plt.fignum_exists(fig.number):
                scan = scanner.get_scan(timeout=5.0)
                pairs = [(a, d) for a, d in zip(scan.angles_rad, scan.distances_m)
                         if d > 0.0]
                scatter.set_offsets(pairs)
                fig.canvas.draw_idle()
                plt.pause(0.001)
    except (TimeoutError, leuze_rsl.RSL235Error) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        pass
    finally:
        if simulator is not None:
            simulator.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
