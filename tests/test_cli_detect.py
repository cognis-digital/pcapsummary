"""CLI-level tests for the `detect` subcommand and shared exit-code contract.

Exit codes for `detect`:
    0  clean — no detections
    1  one or more detections fired (CI can gate on this)
    2  usage / file error, or empty/unparseable input

Also re-verifies the `summarize` exit-code contract and hardening (bad --top,
stdin input). No network.
"""

import contextlib
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pcapsummary.cli import main  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS = os.path.join(ROOT, "demos")


def _demo(name, filename="capture_export.txt"):
    return os.path.join(DEMOS, name, filename)


def _run(argv, stdin_text=None):
    out, err = io.StringIO(), io.StringIO()
    old_stdin = sys.stdin
    if stdin_text is not None:
        sys.stdin = io.StringIO(stdin_text)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(argv)
    finally:
        sys.stdin = old_stdin
    return rc, out.getvalue(), err.getvalue()


class TestDetectExitCodes(unittest.TestCase):
    def test_port_scan_exit_one(self):
        rc, out, _ = _run(["detect", _demo("02-port-scan")])
        self.assertEqual(rc, 1)
        self.assertIn("port_scan", out)

    def test_beacon_exit_one(self):
        rc, out, _ = _run(["detect", _demo("03-beaconing")])
        self.assertEqual(rc, 1)
        self.assertIn("beaconing", out)

    def test_exfil_exit_one(self):
        rc, out, _ = _run(["detect", _demo("04-exfil-volume")])
        self.assertEqual(rc, 1)
        self.assertIn("exfil", out)

    def test_dns_tunnel_exit_one(self):
        rc, out, _ = _run(["detect", _demo("05-dns-tunnel")])
        self.assertEqual(rc, 1)
        self.assertIn("dns_tunnel", out)

    def test_clean_exit_zero(self):
        rc, out, _ = _run(["detect", _demo("08-office-baseline")])
        self.assertEqual(rc, 0)
        self.assertIn("No detections", out)

    def test_basic_clean_exit_zero(self):
        rc, _, _ = _run(["detect", _demo("01-basic")])
        self.assertEqual(rc, 0)

    def test_missing_file_exit_two(self):
        rc, _, err = _run(["detect", "no_such_file_98765.txt"])
        self.assertEqual(rc, 2)
        self.assertIn("cannot read", err)

    def test_empty_input_exit_two(self):
        rc, _, err = _run(["detect", "-"], stdin_text="")
        self.assertEqual(rc, 2)
        self.assertIn("no packets", err)


class TestDetectOptions(unittest.TestCase):
    def test_json_format_is_valid(self):
        rc, out, _ = _run(["detect", _demo("02-port-scan"), "--format", "json"])
        self.assertEqual(rc, 1)
        data = json.loads(out)
        self.assertTrue(any(f["type"] == "port_scan" for f in data))

    def test_only_subset_suppresses(self):
        # Restricting to dns_tunnel on a port-scan capture yields nothing.
        rc, out, _ = _run(
            ["detect", _demo("02-port-scan"), "--only", "dns_tunnel"]
        )
        self.assertEqual(rc, 0)

    def test_only_matches_relevant_detector(self):
        rc, _, _ = _run(
            ["detect", _demo("02-port-scan"), "--only", "port_scan"]
        )
        self.assertEqual(rc, 1)

    def test_unknown_detector_exit_two(self):
        rc, _, err = _run(["detect", _demo("01-basic"), "--only", "bogus"])
        self.assertEqual(rc, 2)
        self.assertIn("unknown detector", err)

    def test_stdin_dash_input(self):
        text = open(_demo("02-port-scan"), encoding="utf-8").read()
        rc, out, _ = _run(["detect", "-"], stdin_text=text)
        self.assertEqual(rc, 1)
        self.assertIn("port_scan", out)

    def test_bad_top_exit_two(self):
        rc, _, err = _run(["detect", _demo("01-basic"), "--top", "-3"])
        self.assertEqual(rc, 2)
        self.assertIn("--top", err)


class TestSummarizeHardening(unittest.TestCase):
    def test_summarize_bad_top_exit_two(self):
        rc, _, err = _run(["summarize", _demo("01-basic"), "--top", "0"])
        self.assertEqual(rc, 2)
        self.assertIn("--top", err)

    def test_summarize_stdin(self):
        text = open(_demo("01-basic"), encoding="utf-8").read()
        rc, out, _ = _run(["summarize", "-", "--format", "json"], stdin_text=text)
        self.assertEqual(rc, 0)
        self.assertGreater(json.loads(out)["total_packets"], 0)


class TestVersionAndHelp(unittest.TestCase):
    def test_version_action_prints_version(self):
        from pcapsummary import TOOL_VERSION

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            with self.assertRaises(SystemExit) as ctx:
                main(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn(TOOL_VERSION, buf.getvalue())

    def test_no_subcommand_exit_two(self):
        rc, _, _ = _run([])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
