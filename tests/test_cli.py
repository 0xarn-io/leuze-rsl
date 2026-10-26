"""Tests for the command-line entry point (python -m leuze_rsl)."""

import contextlib
import io
import logging
import socket
import unittest
from unittest import mock

from leuze_rsl import __main__ as cli


def free_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class CliTests(unittest.TestCase):
    def setUp(self):
        # logging.basicConfig is process-global; restore the root logger afterwards
        root = logging.getLogger()
        self._handlers, self._level = root.handlers[:], root.level
        root.handlers[:] = []
        self.addCleanup(self._restore)

    def _restore(self):
        root = logging.getLogger()
        root.handlers[:] = self._handlers
        root.setLevel(self._level)

    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_udt_simulate(self):
        code, out, err = self.run_cli(["--simulate", "--count", "2", "--port", str(free_udp_port())])
        self.assertEqual(code, 0, err)
        self.assertEqual(out.count("beams in"), 2)
        self.assertIn("family=RSL200", out)
        self.assertIn("contour: indices 0..1350 step 5 -> 271 beams", out)
        self.assertEqual(err, "")                      # quiet by default

    def test_rod_simulate(self):
        code, out, err = self.run_cli(["--rod", "--simulate", "--count", "2"])
        self.assertEqual(code, 0, err)
        self.assertEqual(out.count("spots"), 2)
        self.assertIn("packet #", out)

    def test_count_zero(self):
        code, out, _ = self.run_cli(["--simulate", "--count", "0", "--port", str(free_udp_port())])
        self.assertEqual(code, 0)
        self.assertIn("stats:", out)

    def test_timeout_without_data_is_an_error_not_a_traceback(self):
        code, out, err = self.run_cli(["--count", "1", "--timeout", "0.3", "--port", str(free_udp_port())])
        self.assertEqual(code, 1)
        self.assertTrue(err.startswith("error: no scan received within 0.3 s"), err)

    def test_argument_validation(self):
        for argv in (["--timeout", "0"], ["--count", "-1"], ["--port", "70000"],
                     ["--udp-port", "3050"], ["--rod", "--source-ip", "1.2.3.4"]):
            with self.subTest(argv=argv), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as ctx:
                    cli.main(argv)
                self.assertEqual(ctx.exception.code, 2)

    def test_ctrl_c_exits_130_without_traceback(self):
        for argv, target in ((["--count", "1"], "_run_udt"), (["--rod", "--simulate"], "_run_rod")):
            with self.subTest(argv=argv), mock.patch.object(cli, target, side_effect=KeyboardInterrupt):
                code, _, err = self.run_cli(argv)
                self.assertEqual(code, 130)
                self.assertEqual(err, "interrupted\n")

    def test_port_in_use_is_reported(self):
        blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        blocker.bind(("127.0.0.1", 0))
        self.addCleanup(blocker.close)
        port = blocker.getsockname()[1]
        code, _, err = self.run_cli(["--count", "1", "--port", str(port)])
        self.assertEqual(code, 1)
        self.assertIn("unable to bind UDP port", err)


if __name__ == "__main__":
    unittest.main()
