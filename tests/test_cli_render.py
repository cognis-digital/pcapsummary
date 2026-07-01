"""Rendering tests for the CLI table/csv/json output paths.

Asserts the human-readable table contains the headline fields, CSV is
well-formed and truncation of long routes/pairs works, and JSON is stable and
sorted. These guard the output contract users script against. No network.
"""

import contextlib
import csv
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pcapsummary.cli import main  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _demo(name, filename="capture_export.txt"):
    return os.path.join(ROOT, "demos", name, filename)


def _run(argv, stdin_text=None):
    out, err = io.StringIO(), io.StringIO()
    old = sys.stdin
    if stdin_text is not None:
        sys.stdin = io.StringIO(stdin_text)
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main(argv)
    finally:
        sys.stdin = old
    return rc, out.getvalue(), err.getvalue()


class TestTableRender(unittest.TestCase):
    def test_table_has_headline_fields(self):
        rc, out, _ = _run(["summarize", _demo("01-basic")])
        self.assertEqual(rc, 0)
        for label in (
            "Packets parsed", "Total bytes", "Flows", "Time span",
            "Parse errors", "Protocol distribution", "Top talkers", "Top flows",
        ):
            self.assertIn(label, out)

    def test_table_shows_version(self):
        from pcapsummary import TOOL_VERSION

        _, out, _ = _run(["summarize", _demo("01-basic")])
        self.assertIn(TOOL_VERSION, out)

    def test_top_limits_flow_rows(self):
        _, out, _ = _run(["summarize", _demo("02-port-scan"), "--top", "3"])
        # "Top flows (by bytes, max 3)" header must reflect the limit.
        self.assertIn("max 3", out)

    def test_long_endpoint_truncated(self):
        # IPv6 pair produces a long "A <-> B" that must be truncated with '...'.
        text = (
            "src,dst,proto,length\n"
            "2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff,"
            "2001:db8:1111:2222:3333:4444:5555:6666,TCP,100\n"
        )
        rc, out, _ = _run(["summarize", "-"], stdin_text=text)
        self.assertEqual(rc, 0)
        self.assertIn("...", out)


class TestCsvRender(unittest.TestCase):
    def test_csv_header_row(self):
        rc, out, _ = _run(["summarize", _demo("01-basic"), "--format", "csv"])
        self.assertEqual(rc, 0)
        rows = list(csv.reader(io.StringIO(out)))
        self.assertEqual(
            rows[0],
            ["src", "sport", "dst", "dport", "proto", "packets", "bytes", "duration"],
        )

    def test_csv_empty_ports_render_blank(self):
        # ICMP/ARP flows have no ports -> empty string cells, not "None".
        rc, out, _ = _run(["summarize", _demo("06-tab-export", "capture_export.tsv"),
                           "--format", "csv"])
        self.assertEqual(rc, 0)
        self.assertNotIn("None", out)

    def test_csv_sorted_heaviest_first(self):
        rc, out, _ = _run(["summarize", _demo("04-exfil-volume"), "--format", "csv"])
        reader = list(csv.DictReader(io.StringIO(out)))
        byte_vals = [int(r["bytes"]) for r in reader]
        self.assertEqual(byte_vals, sorted(byte_vals, reverse=True))


class TestJsonRender(unittest.TestCase):
    def test_json_sorted_keys_stable(self):
        rc, out, _ = _run(["summarize", _demo("01-basic"), "--format", "json"])
        self.assertEqual(rc, 0)
        data = json.loads(out)
        # sort_keys=True -> top-level keys are alphabetical.
        keys = list(data.keys())
        self.assertEqual(keys, sorted(keys))

    def test_json_flow_dict_shape(self):
        _, out, _ = _run(["summarize", _demo("01-basic"), "--format", "json"])
        data = json.loads(out)
        flow = data["flows"][0]
        for k in ("src", "dst", "proto", "packets", "bytes", "duration"):
            self.assertIn(k, flow)

    def test_json_talker_endpoints_are_pairs(self):
        _, out, _ = _run(["summarize", _demo("01-basic"), "--format", "json"])
        data = json.loads(out)
        self.assertEqual(len(data["talkers"][0]["endpoints"]), 2)

    def test_malformed_json_still_valid_and_exit_one(self):
        rc, out, _ = _run(["summarize", _demo("07-malformed-ci"), "--format", "json"])
        self.assertEqual(rc, 1)  # parse errors present
        data = json.loads(out)   # but output is still valid JSON
        self.assertEqual(data["parse_errors"], 3)


if __name__ == "__main__":
    unittest.main()
