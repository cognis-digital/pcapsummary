"""Tests for the runnable demo scenario scripts in demos/.

Each scenario must import, run its main() without error, exit cleanly, and
print narrated output. This keeps the demos honest: if the real API changes
shape, the demos fail here rather than misleading a reader. No network.
"""

import contextlib
import importlib
import io
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS = os.path.join(ROOT, "demos")
sys.path.insert(0, ROOT)
sys.path.insert(0, DEMOS)

SCENARIOS = [
    "01_soc_triage",
    "02_threat_hunter_scan",
    "03_ir_beacon_and_exfil",
    "04_sysadmin_ci_gate",
    "05_dns_tunnel_and_lateral",
]


class TestDemoScripts(unittest.TestCase):
    def setUp(self):
        # Demos that drive the CLI use relative demos/ paths; run from root.
        self._cwd = os.getcwd()
        os.chdir(ROOT)

    def tearDown(self):
        os.chdir(self._cwd)

    def _run(self, name):
        mod = importlib.import_module(name)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            mod.main()
        return buf.getvalue()

    def test_each_scenario_runs_and_narrates(self):
        for name in SCENARIOS:
            with self.subTest(scenario=name):
                out = self._run(name)
                self.assertIn("Verdict", out)
                self.assertGreater(len(out.strip().splitlines()), 5)

    def test_run_all_returns_zero(self):
        run_all = importlib.import_module("run_all")
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            rc = run_all.main()
        self.assertEqual(rc, 0)
        self.assertIn("All demo scenarios completed.", buf.getvalue())

    def test_common_helpers_use_real_api(self):
        common = importlib.import_module("_common")
        summary = common.load_summary("01-basic")
        # Real Summary object from the real summarize() path.
        self.assertEqual(summary.total_packets, 20)
        self.assertEqual(summary.parse_errors, 0)
        self.assertTrue(summary.protocols)


if __name__ == "__main__":
    unittest.main()
