"""Tests for the CSV export feature and for every demo scenario.

Each demo must actually produce its intended observable shape (top talker,
protocol dominance, byte asymmetry, parse-error exit code, etc.). No network.
"""

import contextlib
import csv
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pcapsummary import parse_export, summarize  # noqa: E402
from pcapsummary.cli import main  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS = os.path.join(ROOT, "demos")


def _demo(name, filename="capture_export.txt"):
    return os.path.join(DEMOS, name, filename)


def _summary_for(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    packets, errors = parse_export(text)
    return summarize(packets, parse_errors=errors)


def _run_capture(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        with contextlib.redirect_stderr(io.StringIO()):
            rc = main(argv)
    return rc, buf.getvalue()


class TestCsvFormat(unittest.TestCase):
    def test_csv_has_header_and_rows(self):
        rc, out = _run_capture(
            ["summarize", _demo("01-basic"), "--format", "csv"]
        )
        self.assertEqual(rc, 0)
        rows = list(csv.reader(io.StringIO(out)))
        self.assertEqual(
            rows[0],
            ["src", "sport", "dst", "dport", "proto", "packets", "bytes", "duration"],
        )
        # One row per flow; demo 01 has 14 flows.
        self.assertEqual(len(rows) - 1, 14)

    def test_csv_rows_are_parseable_numbers(self):
        rc, out = _run_capture(
            ["summarize", _demo("01-basic"), "--format", "csv"]
        )
        self.assertEqual(rc, 0)
        reader = csv.DictReader(io.StringIO(out))
        first = next(reader)
        # Heaviest flow is sorted first; bytes/packets must be ints.
        self.assertTrue(int(first["bytes"]) > 0)
        self.assertTrue(int(first["packets"]) > 0)


class TestDemosFire(unittest.TestCase):
    def test_01_basic_top_talker_is_tls_session(self):
        s = _summary_for(_demo("01-basic"))
        top = s.talkers[0]
        self.assertEqual(
            sorted(top["endpoints"]), ["192.168.1.50", "93.184.216.34"]
        )
        self.assertEqual(s.parse_errors, 0)

    def test_02_port_scan_fanout(self):
        s = _summary_for(_demo("02-port-scan"))
        # The scanner hits many distinct destination ports on one target.
        scan_dports = {
            f.dport
            for f in s.flows
            if f.src == "10.0.0.66" and f.dst == "10.0.0.10"
        }
        self.assertGreaterEqual(len(scan_dports), 20)
        # Top talker pair is scanner <-> target.
        self.assertEqual(
            sorted(s.talkers[0]["endpoints"]), ["10.0.0.10", "10.0.0.66"]
        )

    def test_03_beaconing_uniform_repeated_flows(self):
        s = _summary_for(_demo("03-beaconing"))
        # Five separate TLS flows to the same dst:dport, each one packet.
        beacons = [
            f
            for f in s.flows
            if f.dst == "203.0.113.45" and f.dport == 8443 and f.proto == "TLSV1.2"
        ]
        self.assertEqual(len(beacons), 5)
        self.assertTrue(all(f.packets == 1 for f in beacons))
        # Regular cadence over a multi-minute span.
        self.assertGreater(s.time_span, 200)

    def test_04_exfil_outbound_asymmetry(self):
        s = _summary_for(_demo("04-exfil-volume"))
        out_flow = next(
            f
            for f in s.flows
            if f.src == "192.168.5.40"
            and f.dst == "198.51.100.77"
            and f.proto == "TLSV1.3"
        )
        in_flow = next(
            f
            for f in s.flows
            if f.src == "198.51.100.77"
            and f.dst == "192.168.5.40"
            and f.proto == "TLSV1.3"
        )
        # Outbound carries an order of magnitude more bytes than the return.
        self.assertGreater(out_flow.bytes, in_flow.bytes * 5)

    def test_05_dns_tunnel_protocol_dominance(self):
        s = _summary_for(_demo("05-dns-tunnel"))
        protos = {p["proto"]: p for p in s.protocols}
        self.assertIn("DNS", protos)
        self.assertGreaterEqual(protos["DNS"]["packets_pct"], 80.0)

    def test_06_tab_export_autodetect(self):
        s = _summary_for(_demo("06-tab-export", "capture_export.tsv"))
        self.assertEqual(s.parse_errors, 0)
        self.assertEqual(s.total_packets, 12)
        seen = {p["proto"] for p in s.protocols}
        self.assertIn("ICMPV6", seen)
        self.assertIn("ARP", seen)

    def test_07_malformed_exit_one(self):
        rc, _ = _run_capture(["summarize", _demo("07-malformed-ci")])
        self.assertEqual(rc, 1)
        s = _summary_for(_demo("07-malformed-ci"))
        self.assertEqual(s.parse_errors, 3)
        self.assertEqual(s.total_packets, 4)

    def test_08_office_baseline_balanced_clean(self):
        rc, _ = _run_capture(["summarize", _demo("08-office-baseline")])
        self.assertEqual(rc, 0)
        s = _summary_for(_demo("08-office-baseline"))
        # No single protocol dominates the way an anomaly demo would.
        top_proto_pct = max(p["packets_pct"] for p in s.protocols)
        self.assertLess(top_proto_pct, 60.0)
        self.assertEqual(s.parse_errors, 0)

    def test_09_smb_lateral_fanout(self):
        s = _summary_for(_demo("09-smb-lateral"))
        peers = {
            f.dst
            for f in s.flows
            if f.src == "10.20.0.50" and f.dport == 445
        }
        self.assertGreaterEqual(len(peers), 6)


if __name__ == "__main__":
    unittest.main()
