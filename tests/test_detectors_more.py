"""Additional detector edge cases and integration-shape assertions.

Focuses on boundary conditions (exactly-at-threshold), multi-finding captures,
finding-schema stability, and that detector output round-trips to the connect
map_record shape. No network.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pcapsummary.core import parse_export, summarize  # noqa: E402
from pcapsummary.detectors import (  # noqa: E402
    detect_beaconing,
    detect_dns_tunnel,
    detect_exfil,
    detect_port_scan,
    run_all,
)

HDR = (
    "frame.number,frame.time_relative,ip.src,ip.dst,_ws.col.Protocol,"
    "tcp.srcport,tcp.dstport,udp.srcport,udp.dstport,frame.len\n"
)


def _summary(text):
    packets, errors = parse_export(text)
    return summarize(packets, parse_errors=errors)


def _scan_capture(n_ports):
    rows = [HDR.rstrip("\n")]
    for i in range(n_ports):
        rows.append(
            f"{i+1},{i*0.001:.3f},10.0.0.9,10.0.0.1,TCP,{40000+i},{i+1},,,58"
        )
    return "\n".join(rows) + "\n"


class TestPortScanBoundary(unittest.TestCase):
    def test_exactly_min_ports_fires(self):
        s = _summary(_scan_capture(15))
        self.assertEqual(len(detect_port_scan(s, min_ports=15)), 1)

    def test_one_below_min_ports_silent(self):
        s = _summary(_scan_capture(14))
        self.assertEqual(detect_port_scan(s, min_ports=15), [])

    def test_multiple_scanners_sorted_by_fanout(self):
        # Two scanners with different fan-out; the bigger one comes first.
        big = _scan_capture(30).splitlines()[1:]
        small = [
            f"{100+i},{i*0.001:.3f},10.0.0.8,10.0.0.2,TCP,{50000+i},{i+1},,,58"
            for i in range(20)
        ]
        text = HDR + "\n".join(big + small) + "\n"
        findings = detect_port_scan(_summary(text), min_ports=15)
        self.assertEqual(len(findings), 2)
        self.assertGreaterEqual(
            findings[0]["evidence"]["distinct_dports"],
            findings[1]["evidence"]["distinct_dports"],
        )


class TestExfilBoundary(unittest.TestCase):
    def _pair(self, out_bytes, in_bytes):
        return _summary(
            HDR
            + f"1,0.0,10.0.0.5,9.9.9.9,TCP,5000,443,,,{out_bytes}\n"
            + f"2,0.1,9.9.9.9,10.0.0.5,TCP,443,5000,,,{in_bytes}\n"
        )

    def test_at_ratio_boundary_fires(self):
        s = self._pair(50000, 10000)  # exactly 5x
        self.assertEqual(len(detect_exfil(s, min_bytes=1000, min_ratio=5.0)), 1)

    def test_below_ratio_silent(self):
        s = self._pair(40000, 10000)  # 4x
        self.assertEqual(detect_exfil(s, min_bytes=1000, min_ratio=5.0), [])

    def test_zero_return_traffic_handled(self):
        # Return bytes 0 must not divide-by-zero; ratio uses max(return,1).
        s = _summary(HDR + "1,0.0,10.0.0.5,9.9.9.9,TCP,5000,443,,,60000\n")
        findings = detect_exfil(s, min_bytes=1000, min_ratio=5.0)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["evidence"]["return_bytes"], 0)


class TestDnsTunnelBoundary(unittest.TestCase):
    def test_at_pct_boundary(self):
        # 6 DNS of 10 packets = 60%.
        rows = [HDR.rstrip("\n")]
        for i in range(6):
            rows.append(f"{i+1},{i*0.1:.1f},10.0.0.1,10.0.0.2,DNS,,,{5000+i},53,80")
        for i in range(4):
            rows.append(f"{i+7},{i*0.1:.1f},10.0.0.1,10.0.0.3,TCP,{6000+i},80,,,80")
        s = _summary("\n".join(rows) + "\n")
        self.assertEqual(len(detect_dns_tunnel(s, min_pct=60.0, min_packets=1)), 1)


class TestFindingSchema(unittest.TestCase):
    def test_every_finding_has_core_keys(self):
        from pcapsummary.detectors import DETECTORS

        ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for fixture in ("02-port-scan", "03-beaconing", "04-exfil-volume", "05-dns-tunnel"):
            path = os.path.join(ROOT, "demos", fixture, "capture_export.txt")
            with open(path, encoding="utf-8") as fh:
                s = _summary(fh.read())
            for f in run_all(s):
                with self.subTest(fixture=fixture, dtype=f["type"]):
                    self.assertIn(f["type"], DETECTORS)
                    self.assertIn(f["severity"], ("low", "medium", "high"))
                    self.assertIsInstance(f["title"], str)
                    self.assertTrue(f["title"])
                    self.assertIn("evidence", f)
                    self.assertIsInstance(f["evidence"], dict)

    def test_empty_capture_all_detectors_empty(self):
        s = summarize([])
        self.assertEqual(run_all(s), [])
        self.assertEqual(detect_port_scan(s), [])
        self.assertEqual(detect_beaconing(s), [])
        self.assertEqual(detect_exfil(s), [])
        self.assertEqual(detect_dns_tunnel(s), [])


class TestConnectMapping(unittest.TestCase):
    def test_map_record_strips_transport_fields(self):
        # connect.map_record must survive a detector finding without crashing.
        import importlib

        connect = importlib.import_module("pcapsummary.connect")
        ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(ROOT, "demos", "02-port-scan", "capture_export.txt")
        with open(path, encoding="utf-8") as fh:
            s = _summary(fh.read())
        finding = run_all(s)[0]
        out = connect.map_record(finding)
        self.assertIsInstance(out, dict)
        # Transport-level keys are dropped; the human-readable core survives.
        self.assertIn("title", out)
        self.assertNotIn("src", out)


if __name__ == "__main__":
    unittest.main()
