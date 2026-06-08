"""Smoke tests for PCAPSUMMARY. No network access."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pcapsummary import TOOL_NAME, TOOL_VERSION, parse_export, summarize  # noqa: E402
from pcapsummary.cli import main  # noqa: E402

HEADER_CSV = (
    "frame.number,frame.time_relative,ip.src,ip.dst,_ws.col.Protocol,"
    "tcp.srcport,tcp.dstport,udp.srcport,udp.dstport,frame.len\n"
    "1,0.0,10.0.0.1,10.0.0.2,TCP,1234,80,,,100\n"
    "2,0.5,10.0.0.2,10.0.0.1,TCP,80,1234,,,1500\n"
    "3,1.0,10.0.0.1,8.8.8.8,DNS,,,5000,53,80\n"
    "4,1.5,10.0.0.1,10.0.0.2,TCP,1234,80,,,200\n"
)

DEMO_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos",
    "01-basic",
    "capture_export.txt",
)


class TestParse(unittest.TestCase):
    def test_metadata(self):
        self.assertEqual(TOOL_NAME, "pcapsummary")
        self.assertTrue(TOOL_VERSION)

    def test_parse_header_csv(self):
        packets, errors = parse_export(HEADER_CSV)
        self.assertEqual(errors, 0)
        self.assertEqual(len(packets), 4)
        self.assertEqual(packets[0].src, "10.0.0.1")
        self.assertEqual(packets[0].dst, "10.0.0.2")
        self.assertEqual(packets[0].proto, "TCP")
        self.assertEqual(packets[0].dport, 80)
        self.assertEqual(packets[0].length, 100)

    def test_parse_dns_udp_ports(self):
        packets, _ = parse_export(HEADER_CSV)
        dns = [p for p in packets if p.proto == "DNS"][0]
        self.assertEqual(dns.sport, 5000)
        self.assertEqual(dns.dport, 53)

    def test_parse_tab_separated(self):
        tab = (
            "No.\tSource\tDestination\tProtocol\tLength\n"
            "1\t1.1.1.1\t2.2.2.2\tICMP\t64\n"
        )
        packets, errors = parse_export(tab)
        self.assertEqual(errors, 0)
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].proto, "ICMP")
        self.assertEqual(packets[0].length, 64)

    def test_comments_and_blank_lines_skipped(self):
        text = "# comment\n\n" + HEADER_CSV
        packets, errors = parse_export(text)
        self.assertEqual(len(packets), 4)
        self.assertEqual(errors, 0)

    def test_empty_input(self):
        packets, errors = parse_export("")
        self.assertEqual(packets, [])
        self.assertEqual(errors, 0)


class TestSummarize(unittest.TestCase):
    def test_summary_totals(self):
        packets, errors = parse_export(HEADER_CSV)
        summary = summarize(packets, parse_errors=errors)
        self.assertEqual(summary.total_packets, 4)
        self.assertEqual(summary.total_bytes, 1880)
        self.assertEqual(summary.time_span, 1.5)

    def test_protocol_distribution(self):
        packets, _ = parse_export(HEADER_CSV)
        summary = summarize(packets)
        protos = {p["proto"]: p for p in summary.protocols}
        self.assertEqual(protos["TCP"]["packets"], 3)
        self.assertEqual(protos["DNS"]["packets"], 1)
        self.assertAlmostEqual(protos["TCP"]["packets_pct"], 75.0)

    def test_top_talker_bidirectional(self):
        packets, _ = parse_export(HEADER_CSV)
        summary = summarize(packets)
        top = summary.talkers[0]
        # 10.0.0.1 <-> 10.0.0.2 carries 100+1500+200 = 1800 bytes
        self.assertEqual(sorted(top["endpoints"]), ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(top["bytes"], 1800)
        self.assertEqual(top["packets"], 3)

    def test_flow_aggregation(self):
        packets, _ = parse_export(HEADER_CSV)
        summary = summarize(packets)
        # Same 5-tuple (1234->80 TCP) should merge frames 1 and 4.
        merged = [
            f for f in summary.flows
            if f.src == "10.0.0.1" and f.dport == 80 and f.proto == "TCP"
        ]
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].packets, 2)
        self.assertEqual(merged[0].bytes, 300)


class TestCLI(unittest.TestCase):
    def test_demo_json_exit_zero(self):
        rc = main(["summarize", DEMO_PATH, "--format", "json"])
        self.assertEqual(rc, 0)

    def test_demo_table_exit_zero(self):
        rc = main(["summarize", DEMO_PATH])
        self.assertEqual(rc, 0)

    def test_missing_file_exit_two(self):
        rc = main(["summarize", "does_not_exist_12345.txt"])
        self.assertEqual(rc, 2)

    def test_no_subcommand_exit_two(self):
        rc = main([])
        self.assertEqual(rc, 2)

    def test_json_is_valid(self):
        import contextlib
        import io as _io

        buf = _io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main(["summarize", DEMO_PATH, "--format", "json"])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertIn("flows", data)
        self.assertIn("talkers", data)
        self.assertIn("protocols", data)
        self.assertGreater(data["total_packets"], 0)


if __name__ == "__main__":
    unittest.main()
