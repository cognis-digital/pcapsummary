"""Tests for the heuristic detectors (pcapsummary.detectors).

Covers each detector's positive case, its negative/clean case, the tuning
knobs, error paths on bad thresholds, and the run_all aggregation/ordering.
Detectors run over Summary objects built from the bundled offline fixtures and
from small hand-built captures — no network.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pcapsummary.core import parse_export, summarize  # noqa: E402
from pcapsummary import detectors  # noqa: E402
from pcapsummary.detectors import (  # noqa: E402
    detect_beaconing,
    detect_dns_tunnel,
    detect_exfil,
    detect_port_scan,
    run_all,
    DETECTORS,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMOS = os.path.join(ROOT, "demos")


def _summary(name, filename="capture_export.txt", top=10):
    path = os.path.join(DEMOS, name, filename)
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    packets, errors = parse_export(text)
    return summarize(packets, parse_errors=errors, top=top)


def _summary_from_text(text):
    packets, errors = parse_export(text)
    return summarize(packets, parse_errors=errors)


class TestPortScan(unittest.TestCase):
    def test_fires_on_port_scan_fixture(self):
        findings = detect_port_scan(_summary("02-port-scan"))
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["type"], "port_scan")
        self.assertEqual(f["src"], "10.0.0.66")
        self.assertEqual(f["dst"], "10.0.0.10")
        self.assertGreaterEqual(f["evidence"]["distinct_dports"], 20)

    def test_severity_high_when_mostly_probes(self):
        findings = detect_port_scan(_summary("02-port-scan"))
        self.assertEqual(findings[0]["severity"], "high")

    def test_clean_capture_no_scan(self):
        self.assertEqual(detect_port_scan(_summary("01-basic")), [])
        self.assertEqual(detect_port_scan(_summary("08-office-baseline")), [])

    def test_threshold_suppresses_below_min_ports(self):
        # Raising min_ports above the fixture's fan-out silences the finding.
        self.assertEqual(
            detect_port_scan(_summary("02-port-scan"), min_ports=100), []
        )

    def test_bad_min_ports_raises(self):
        with self.assertRaises(ValueError):
            detect_port_scan(_summary("01-basic"), min_ports=0)

    def test_ports_sample_capped_at_20(self):
        f = detect_port_scan(_summary("02-port-scan"))[0]
        self.assertLessEqual(len(f["evidence"]["ports_sample"]), 20)

    def test_empty_summary_no_findings(self):
        self.assertEqual(detect_port_scan(summarize([])), [])


class TestBeaconing(unittest.TestCase):
    def test_fires_on_beacon_fixture(self):
        findings = detect_beaconing(_summary("03-beaconing"))
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["type"], "beaconing")
        self.assertEqual(f["dst"], "203.0.113.45")
        self.assertEqual(f["dport"], 8443)
        self.assertGreaterEqual(f["evidence"]["events"], 5)
        # ~60s cadence in the fixture.
        self.assertAlmostEqual(f["evidence"]["mean_interval"], 60.0, delta=1.0)

    def test_low_jitter_is_high_severity(self):
        f = detect_beaconing(_summary("03-beaconing"))[0]
        self.assertEqual(f["severity"], "high")

    def test_clean_capture_no_beacon(self):
        self.assertEqual(detect_beaconing(_summary("01-basic")), [])

    def test_min_events_suppresses(self):
        self.assertEqual(
            detect_beaconing(_summary("03-beaconing"), min_events=50), []
        )

    def test_jittery_traffic_not_flagged(self):
        # Irregular gaps: 1s, 20s, 2s, 40s to the same channel -> high jitter.
        text = (
            "frame.number,frame.time_relative,ip.src,ip.dst,_ws.col.Protocol,"
            "tcp.srcport,tcp.dstport,udp.srcport,udp.dstport,frame.len\n"
            "1,0.0,10.0.0.5,9.9.9.9,TCP,50000,4444,,,100\n"
            "2,1.0,10.0.0.5,9.9.9.9,TCP,50001,4444,,,100\n"
            "3,21.0,10.0.0.5,9.9.9.9,TCP,50002,4444,,,100\n"
            "4,23.0,10.0.0.5,9.9.9.9,TCP,50003,4444,,,100\n"
            "5,63.0,10.0.0.5,9.9.9.9,TCP,50004,4444,,,100\n"
        )
        self.assertEqual(detect_beaconing(_summary_from_text(text)), [])

    def test_bad_min_events_raises(self):
        with self.assertRaises(ValueError):
            detect_beaconing(_summary("03-beaconing"), min_events=1)

    def test_bad_jitter_raises(self):
        with self.assertRaises(ValueError):
            detect_beaconing(_summary("03-beaconing"), max_jitter_ratio=-0.1)


class TestExfil(unittest.TestCase):
    def test_fires_on_exfil_fixture(self):
        findings = detect_exfil(_summary("04-exfil-volume"))
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["type"], "exfil")
        self.assertEqual(f["src"], "192.168.5.40")
        self.assertEqual(f["dst"], "198.51.100.77")
        self.assertGreater(f["evidence"]["ratio"], 5.0)

    def test_reports_heavier_direction_only(self):
        # Never double-counts a pair; the outbound leg is the heavier one.
        findings = detect_exfil(_summary("04-exfil-volume"))
        self.assertEqual(len(findings), 1)
        self.assertGreater(
            findings[0]["evidence"]["out_bytes"],
            findings[0]["evidence"]["return_bytes"],
        )

    def test_min_bytes_floor_suppresses(self):
        self.assertEqual(
            detect_exfil(_summary("04-exfil-volume"), min_bytes=10_000_000), []
        )

    def test_min_ratio_suppresses(self):
        self.assertEqual(
            detect_exfil(_summary("04-exfil-volume"), min_ratio=1000.0), []
        )

    def test_balanced_traffic_not_flagged(self):
        self.assertEqual(detect_exfil(_summary("08-office-baseline")), [])

    def test_bad_min_bytes_raises(self):
        with self.assertRaises(ValueError):
            detect_exfil(_summary("04-exfil-volume"), min_bytes=-1)

    def test_bad_min_ratio_raises(self):
        with self.assertRaises(ValueError):
            detect_exfil(_summary("04-exfil-volume"), min_ratio=0)


class TestDnsTunnel(unittest.TestCase):
    def test_fires_on_dns_tunnel_fixture(self):
        findings = detect_dns_tunnel(_summary("05-dns-tunnel"))
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f["type"], "dns_tunnel")
        self.assertGreaterEqual(f["evidence"]["dns_pct"], 60.0)

    def test_clean_baseline_no_tunnel(self):
        self.assertEqual(detect_dns_tunnel(_summary("08-office-baseline")), [])

    def test_no_dns_no_finding(self):
        self.assertEqual(detect_dns_tunnel(_summary("09-smb-lateral")), [])

    def test_min_packets_guards_tiny_captures(self):
        # A capture that is 100% DNS but only 2 packets should not fire.
        text = (
            "frame.number,frame.time_relative,ip.src,ip.dst,_ws.col.Protocol,"
            "tcp.srcport,tcp.dstport,udp.srcport,udp.dstport,frame.len\n"
            "1,0.0,10.0.0.1,10.0.0.2,DNS,,,5000,53,80\n"
            "2,0.1,10.0.0.2,10.0.0.1,DNS,,,53,5000,120\n"
        )
        self.assertEqual(
            detect_dns_tunnel(_summary_from_text(text), min_packets=10), []
        )

    def test_bad_min_pct_raises(self):
        with self.assertRaises(ValueError):
            detect_dns_tunnel(_summary("05-dns-tunnel"), min_pct=150)


class TestRunAll(unittest.TestCase):
    def test_registry_names(self):
        self.assertEqual(
            set(DETECTORS), {"port_scan", "beaconing", "exfil", "dns_tunnel"}
        )

    def test_run_all_on_clean_is_empty(self):
        self.assertEqual(run_all(_summary("08-office-baseline")), [])

    def test_run_all_finds_scan(self):
        findings = run_all(_summary("02-port-scan"))
        self.assertTrue(any(f["type"] == "port_scan" for f in findings))

    def test_run_all_ordered_high_first(self):
        # dns-tunnel fixture yields both a beacon and a tunnel finding.
        findings = run_all(_summary("05-dns-tunnel"))
        self.assertGreaterEqual(len(findings), 1)
        rank = {"high": 0, "medium": 1, "low": 2}
        ranks = [rank[f["severity"]] for f in findings]
        self.assertEqual(ranks, sorted(ranks))

    def test_run_all_only_subset(self):
        findings = run_all(_summary("02-port-scan"), only=["dns_tunnel"])
        self.assertEqual(findings, [])

    def test_run_all_unknown_detector_raises(self):
        with self.assertRaises(KeyError):
            run_all(_summary("01-basic"), only=["nope"])

    def test_findings_are_json_serializable(self):
        import json

        for name in ("02-port-scan", "03-beaconing", "04-exfil-volume", "05-dns-tunnel"):
            with self.subTest(fixture=name):
                findings = run_all(_summary(name))
                json.dumps(findings)  # must not raise


if __name__ == "__main__":
    unittest.main()
