"""Hardening tests: error paths, edge cases, and input validation."""

from __future__ import annotations

import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pcapsummary.cli import main  # noqa: E402
from pcapsummary.core import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    parse_export,
    summarize,
)


class TestCoreConstants(unittest.TestCase):
    """TOOL_NAME and TOOL_VERSION must now live in core (not just __init__ fallback)."""

    def test_tool_name_is_string(self):
        self.assertIsInstance(TOOL_NAME, str)
        self.assertTrue(TOOL_NAME)

    def test_tool_version_is_string(self):
        self.assertIsInstance(TOOL_VERSION, str)
        self.assertTrue(TOOL_VERSION)


class TestSummarizeEdgeCases(unittest.TestCase):
    def test_empty_packet_list_no_division_by_zero(self):
        """summarize([]) must return a valid Summary with zero counts."""
        s = summarize([], parse_errors=0)
        self.assertEqual(s.total_packets, 0)
        self.assertEqual(s.total_bytes, 0)
        self.assertEqual(s.time_span, 0.0)
        self.assertEqual(s.flows, [])
        self.assertEqual(s.talkers, [])
        self.assertEqual(s.protocols, [])

    def test_packets_missing_times(self):
        """Packets with time=None must not cause errors; time_span is 0."""
        from pcapsummary.core import Packet

        pkts = [
            Packet(src="1.1.1.1", dst="2.2.2.2", proto="TCP", length=100),
            Packet(src="1.1.1.1", dst="2.2.2.2", proto="TCP", length=200),
        ]
        s = summarize(pkts)
        self.assertEqual(s.time_span, 0.0)
        self.assertEqual(s.total_bytes, 300)

    def test_as_dict_no_packets(self):
        """Summary.as_dict() on empty input must be serialisable JSON."""
        s = summarize([], parse_errors=3)
        d = s.as_dict()
        dumped = json.dumps(d)
        loaded = json.loads(dumped)
        self.assertEqual(loaded["total_packets"], 0)
        self.assertEqual(loaded["parse_errors"], 3)

    def test_single_packet_summary(self):
        """One packet — no ZeroDivision, protocols_pct = 100.0."""
        from pcapsummary.core import Packet

        pkts = [Packet(src="10.0.0.1", dst="10.0.0.2", proto="ICMP", length=64)]
        s = summarize(pkts)
        self.assertEqual(len(s.protocols), 1)
        self.assertAlmostEqual(s.protocols[0]["packets_pct"], 100.0)


class TestParseEdgeCases(unittest.TestCase):
    def test_all_comment_lines_returns_empty(self):
        text = "# comment\n# another\n"
        packets, errors = parse_export(text)
        self.assertEqual(packets, [])
        self.assertEqual(errors, 0)

    def test_header_only_no_data_returns_empty(self):
        """A header row with no data rows produces no packets and no errors."""
        text = (
            "frame.number,frame.time_relative,ip.src,ip.dst,"
            "_ws.col.Protocol,frame.len\n"
        )
        packets, errors = parse_export(text)
        self.assertEqual(packets, [])
        self.assertEqual(errors, 0)

    def test_rows_missing_src_dst_counted_as_errors(self):
        """Rows with empty src or dst must increment parse_errors."""
        text = (
            "ip.src,ip.dst,_ws.col.Protocol,frame.len\n"
            ",10.0.0.2,TCP,100\n"          # missing src
            "10.0.0.1,,TCP,100\n"          # missing dst
        )
        packets, errors = parse_export(text)
        self.assertEqual(packets, [])
        self.assertEqual(errors, 2)


class TestCLIValidation(unittest.TestCase):
    def test_top_zero_exits_two(self):
        """--top 0 is invalid; must print an error and exit 2."""
        import contextlib

        buf = io.StringIO()
        demo = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "demos",
            "01-basic",
            "capture_export.txt",
        )
        with contextlib.redirect_stderr(buf):
            rc = main(["summarize", demo, "--top", "0"])
        self.assertEqual(rc, 2)
        self.assertIn("--top", buf.getvalue())

    def test_top_negative_exits_two(self):
        """--top -5 is invalid; must print an error and exit 2."""
        import contextlib

        buf = io.StringIO()
        demo = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "demos",
            "01-basic",
            "capture_export.txt",
        )
        with contextlib.redirect_stderr(buf):
            rc = main(["summarize", demo, "--top", "-5"])
        self.assertEqual(rc, 2)
        self.assertIn("--top", buf.getvalue())

    def test_empty_file_exits_one(self):
        """An empty input file must exit 1 (no packets found) without traceback."""
        import contextlib
        import tempfile

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False
        ) as fh:
            fh.write("")
            tmp = fh.name
        try:
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                rc = main(["summarize", tmp])
            self.assertEqual(rc, 1)
        finally:
            os.unlink(tmp)


class TestMCPServerImports(unittest.TestCase):
    def test_mcp_server_references_valid_core_functions(self):
        """mcp_server.py must import parse_export and summarize, not phantom names."""
        import ast

        src_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "pcapsummary",
            "mcp_server.py",
        )
        with open(src_path) as fh:
            tree = ast.parse(fh.read())

        imported_names: set = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "pcapsummary.core":
                for alias in node.names:
                    imported_names.add(alias.name)

        # These are the only public functions that exist in core.
        allowed = {"parse_export", "summarize", "TOOL_NAME", "TOOL_VERSION"}
        unexpected = imported_names - allowed
        self.assertEqual(
            unexpected,
            set(),
            f"mcp_server.py imports non-existent names from core: {unexpected}",
        )


if __name__ == "__main__":
    unittest.main()
