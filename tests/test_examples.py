"""The record / replay example scripts, run as a user would run them."""

import os
import socket
import struct
import subprocess
import sys
import tempfile
import unittest

from leuze_rsl.simulator import UdtSimulator

EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples")
SRC = os.path.join(os.path.dirname(EXAMPLES), "src")


def run_example(name, *args, timeout=30.0):
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run([sys.executable, os.path.join(EXAMPLES, name), *args],
                          capture_output=True, text=True, env=env, timeout=timeout)


def free_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class RecordReplayTests(unittest.TestCase):
    def test_record_then_replay(self):
        port = free_udp_port()
        with tempfile.TemporaryDirectory() as folder:
            capture = os.path.join(folder, "capture_{port}.bin")
            path = capture.replace("{port}", str(port))
            sim = UdtSimulator(target_port=port, scan_period_s=0.02, contamination_warning=True).start()
            try:
                recorded = run_example("record_udt.py", "--port", str(port), "--seconds", "1.5", "--out", capture)
            finally:
                sim.stop()
            self.assertEqual(recorded.returncode, 0, recorded.stderr)
            self.assertIn("recorded", recorded.stdout)
            with open(path, "rb") as handle:
                blob = handle.read()
            self.assertEqual(blob[:8], b"LRSLUDT1")
            received, ip, length = struct.unpack_from("<d4sH", blob, 8)
            self.assertEqual(socket.inet_ntoa(ip), "127.0.0.1")
            self.assertIn(length, (56, 1104))     # the recorder joins a running stream: status or data first
            self.assertGreater(received, 1.6e9)
            self.assertEqual(blob[8 + 14:8 + 14 + 4], struct.pack("<I", length))   # the datagram's own length field

            again = run_example("record_udt.py", "--port", str(port), "--seconds", "0.2", "--out", capture)
            self.assertEqual(again.returncode, 1)                                   # never overwrites silently
            self.assertIn("already exists", again.stderr)
            self.assertNotIn("Traceback", again.stderr)
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), blob)

            replayed = run_example("replay_udt.py", path, "--scans", "2")
            self.assertEqual(replayed.returncode, 0, replayed.stderr)
            self.assertIn("from 127.0.0.1", replayed.stdout)
            self.assertIn("contour: indices 0..1350 step 5 -> 271 beams", replayed.stdout)
            self.assertIn("status: family=RSL200 mode=1 error=False warning=True", replayed.stdout)
            self.assertIn("DEVICE WARNING: optics cover contamination warning", replayed.stdout)
            self.assertEqual(replayed.stdout.count(" 271 beams, "), 2)

    def test_usage_and_file_errors_are_clean(self):
        self.assertEqual(run_example("record_udt.py", "--port", "70000").returncode, 2)
        self.assertEqual(run_example("record_udt.py", "--seconds", "0").returncode, 2)
        self.assertEqual(run_example("record_udt.py", "--port", "5001", "5002", "--out", "x.bin").returncode, 2)
        with tempfile.TemporaryDirectory() as folder:
            missing = run_example("record_udt.py", "--port", str(free_udp_port()), "--seconds", "0.2",
                                  "--out", os.path.join(folder, "no", "such", "dir.bin"))
            self.assertEqual(missing.returncode, 1)
            self.assertTrue(missing.stderr.startswith("error:"), missing.stderr)
            bogus = os.path.join(folder, "bogus.bin")
            with open(bogus, "wb") as handle:
                handle.write(b"not a capture")
            replayed = run_example("replay_udt.py", bogus)
            self.assertEqual(replayed.returncode, 1)
            self.assertIn("is not a record_udt.py capture", replayed.stderr)
            self.assertNotIn("Traceback", replayed.stderr)


if __name__ == "__main__":
    unittest.main()
