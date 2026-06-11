#!/usr/bin/env python3
"""Live polar plot of the UDP data telegrams an RSL 235 pushes (matplotlib).

    python3 examples/live_plot.py --port 3050
    python3 examples/live_plot.py --simulate
"""

import argparse
import math
import sys
from pathlib import Path

try:
    import leuze_rsl
except ImportError:                       # allow running from the repo checkout
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
    import leuze_rsl

from leuze_rsl import RSL235Udt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=leuze_rsl.DEFAULT_UDT_PORT)
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
        from leuze_rsl.simulator import UdtSimulator
        simulator = UdtSimulator(target_port=args.port).start()

    try:
        with RSL235Udt(port=args.port) as receiver:
            plt.ion()
            fig = plt.figure("RSL235 live scan")
            ax = fig.add_subplot(111, projection="polar")
            scatter = ax.scatter([], [], s=2)
            ax.set_rmax(args.rmax)
            ax.set_title("RSL235 UDP data telegrams (port %d)" % args.port)
            while plt.fignum_exists(fig.number):
                scan = receiver.get_scan(timeout=5.0)
                pairs = [(math.radians(a), d) for a, d, ok in
                         zip(scan.angles_deg(), scan.distances_m,
                             scan.valid_mask()) if ok]
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
