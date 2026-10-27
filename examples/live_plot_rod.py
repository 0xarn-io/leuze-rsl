#!/usr/bin/env python3
"""Live polar plot of Leuze ROD 308/508 scans (ROD-300-500 protocol; requires matplotlib).

    python3 examples/live_plot_rod.py 192.168.60.101
    python3 examples/live_plot_rod.py --simulate
"""

import argparse
import sys
from pathlib import Path

try:
    import leuze_rsl
except ImportError:                       # allow running from the repo checkout
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    import leuze_rsl

from leuze_rsl import RSL235


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("host", nargs="?", default="192.168.60.101",
                        help="scanner IP address (default: %(default)s)")
    parser.add_argument("--port", type=int, default=leuze_rsl.DEFAULT_PORT,
                        help="scanner TCP command port (default: %(default)s)")
    parser.add_argument("--rmax", type=float, default=10.0,
                        help="plot range in meters (default: %(default)s)")
    parser.add_argument("--simulate", action="store_true",
                        help="run against the built-in simulator instead of hardware")
    args = parser.parse_args()

    try:
        import matplotlib.pyplot as plt
        import numpy as np
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
            fig = plt.figure("ROD live scan")
            ax = fig.add_subplot(111, projection="polar")
            scatter = ax.scatter([], [], s=2)
            ax.set_rmax(args.rmax)
            ax.set_title("ROD scanner @ %s" % args.host)
            while plt.fignum_exists(fig.number):
                scan = scanner.get_scan(timeout=5.0)
                pairs = [(a, d) for a, d, ok in zip(scan.angles_rad, scan.distances_m,
                                                    scan.valid_mask()) if ok]
                scatter.set_offsets(np.array(pairs) if pairs else np.empty((0, 2)))
                fig.canvas.draw_idle()
                plt.pause(0.001)
    except KeyboardInterrupt:
        return 130
    except (leuze_rsl.RSL235Error, OSError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 1
    finally:
        if simulator is not None:
            simulator.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
