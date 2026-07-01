"""Edge-case and error-path coverage for the parser + summarizer core.

Malformed rows, empty/whitespace/comment-only input, header vs positional
fallback, port coalescing, dialect autodetection, IPv6, version consistency,
and Flow/Summary shape. No network.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pcapsummary import TOOL_NAME, TOOL_VERSION  # noqa: E402
from pcapsummary.core import (  # noqa: E402
    Flow,
    Packet,
    Summary,
    parse_export,
    summarize,
)

HDR = (
    "frame.number,frame.time_relative,ip.src,ip.dst,_ws.col.Protocol,"
    "tcp.srcport,tcp.dstport,udp.srcport,udp.dstport,frame.len\n"
)


class TestVersionConsistency(unittest.TestCase):
    """The version regression: VERSION file, pyproject, and runtime must agree."""

    def _root(self):
        return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def test_version_file_matches_runtime(self):
        with open(os.path.join(self._root(), "VERSION"), encoding="utf-8") as fh:
            file_version = fh.read().strip()
        self.assertEqual(file_version, TOOL_VERSION)

    def test_pyproject_matches_runtime(self):
        with open(
            os.path.join(self._root(), "pyproject.toml"), encoding="utf-8"
        ) as fh:
            text = fh.read()
        self.assertIn(f'version = "{TOOL_VERSION}"', text)

    def test_tool_name(self):
        self.assertEqual(TOOL_NAME, "pcapsummary")


class TestParseMalformed(unittest.TestCase):
    def test_rows_missing_src_dst_count_as_errors(self):
        text = HDR + (
            "1,0.0,10.0.0.1,10.0.0.2,TCP,1,2,,,100\n"
            "2,0.1,,,TCP,1,2,,,50\n"        # no src/dst -> error
            "3,0.2,10.0.0.1,,TCP,1,2,,,50\n"  # no dst -> error
        )
        packets, errors = parse_export(text)
        self.assertEqual(len(packets), 1)
        self.assertEqual(errors, 2)

    def test_garbage_numbers_are_tolerated(self):
        # Non-numeric ports/length must not crash; they coerce to None/0.
        text = HDR + "1,notatime,10.0.0.1,10.0.0.2,TCP,abc,def,,,xyz\n"
        packets, errors = parse_export(text)
        self.assertEqual(errors, 0)
        self.assertEqual(len(packets), 1)
        self.assertIsNone(packets[0].sport)
        self.assertIsNone(packets[0].time)
        self.assertEqual(packets[0].length, 0)

    def test_float_length_coerced_to_int(self):
        text = HDR + "1,0.0,10.0.0.1,10.0.0.2,TCP,1,2,,,100.0\n"
        packets, _ = parse_export(text)
        self.assertEqual(packets[0].length, 100)

    def test_short_positional_row_is_error(self):
        # No recognizable header -> positional; rows with <5 cells are errors.
        text = "a,b,c\n1,2\n"
        packets, errors = parse_export(text)
        self.assertEqual(packets, [])
        self.assertEqual(errors, 2)

    def test_completely_empty(self):
        self.assertEqual(parse_export(""), ([], 0))

    def test_whitespace_only(self):
        self.assertEqual(parse_export("   \n\t\n  "), ([], 0))

    def test_comment_only(self):
        self.assertEqual(parse_export("# just a comment\n#another"), ([], 0))

    def test_blank_data_rows_skipped_not_errored(self):
        text = HDR + "1,0.0,10.0.0.1,10.0.0.2,TCP,1,2,,,100\n,,,,,,,,,\n"
        packets, errors = parse_export(text)
        self.assertEqual(len(packets), 1)
        self.assertEqual(errors, 0)

    def test_unknown_protocol_becomes_UNKNOWN(self):
        text = HDR + "1,0.0,10.0.0.1,10.0.0.2,,1,2,,,100\n"
        packets, _ = parse_export(text)
        self.assertEqual(packets[0].proto, "UNKNOWN")


class TestDialectAndHeader(unittest.TestCase):
    def test_tab_autodetect(self):
        text = "No.\tSource\tDestination\tProtocol\tLength\n1\t1.1.1.1\t2.2.2.2\tUDP\t42\n"
        packets, errors = parse_export(text)
        self.assertEqual(errors, 0)
        self.assertEqual(packets[0].proto, "UDP")

    def test_udp_ports_coalesced(self):
        text = HDR + "1,0.0,10.0.0.1,8.8.8.8,DNS,,,5000,53,80\n"
        packets, _ = parse_export(text)
        self.assertEqual(packets[0].sport, 5000)
        self.assertEqual(packets[0].dport, 53)

    def test_generic_srcport_header(self):
        text = "src,dst,proto,srcport,dstport,length\n10.0.0.1,10.0.0.2,TCP,1111,22,64\n"
        packets, errors = parse_export(text)
        self.assertEqual(errors, 0)
        self.assertEqual(packets[0].sport, 1111)
        self.assertEqual(packets[0].dport, 22)

    def test_positional_fallback_no_header(self):
        # No header keywords -> positional layout used.
        text = "1,0.0,10.0.0.1,10.0.0.2,TCP,1234,80,,,100\n"
        packets, errors = parse_export(text)
        self.assertEqual(errors, 0)
        self.assertEqual(packets[0].dport, 80)
        self.assertEqual(packets[0].length, 100)

    def test_ipv6_addresses(self):
        text = "src,dst,proto,length\n2001:db8::1,2001:db8::2,ICMPv6,80\n"
        packets, errors = parse_export(text)
        self.assertEqual(errors, 0)
        self.assertEqual(packets[0].src, "2001:db8::1")
        self.assertEqual(packets[0].proto, "ICMPV6")

    def test_quoted_fields(self):
        text = 'src,dst,proto,length\n"10.0.0.1","10.0.0.2","TCP","100"\n'
        packets, errors = parse_export(text)
        self.assertEqual(errors, 0)
        self.assertEqual(packets[0].length, 100)


class TestSummarizeShapes(unittest.TestCase):
    def test_summary_as_dict_keys(self):
        packets, errors = parse_export(HDR + "1,0.0,10.0.0.1,10.0.0.2,TCP,1,2,,,100\n")
        d = summarize(packets, parse_errors=errors).as_dict()
        for key in (
            "total_packets", "total_bytes", "parse_errors", "time_span",
            "flow_count", "flows", "talkers", "protocols",
        ):
            self.assertIn(key, d)

    def test_flow_duration_and_as_dict(self):
        text = HDR + (
            "1,10.0,10.0.0.1,10.0.0.2,TCP,1,80,,,100\n"
            "2,13.0,10.0.0.1,10.0.0.2,TCP,1,80,,,100\n"
        )
        packets, _ = parse_export(text)
        s = summarize(packets)
        flow = next(f for f in s.flows if f.dport == 80)
        self.assertAlmostEqual(flow.duration, 3.0)
        self.assertEqual(flow.as_dict()["packets"], 2)

    def test_flow_duration_none_times(self):
        f = Flow(src="a", dst="b", proto="TCP", sport=1, dport=2)
        self.assertEqual(f.duration, 0.0)

    def test_empty_summary(self):
        s = summarize([])
        self.assertEqual(s.total_packets, 0)
        self.assertEqual(s.total_bytes, 0)
        self.assertEqual(s.time_span, 0.0)
        self.assertEqual(s.flows, [])

    def test_top_zero_yields_no_talkers(self):
        packets, _ = parse_export(HDR + "1,0.0,10.0.0.1,10.0.0.2,TCP,1,2,,,100\n")
        s = summarize(packets, top=0)
        self.assertEqual(s.talkers, [])

    def test_negative_top_raises(self):
        packets, _ = parse_export(HDR + "1,0.0,10.0.0.1,10.0.0.2,TCP,1,2,,,100\n")
        with self.assertRaises(ValueError):
            summarize(packets, top=-1)

    def test_packet_dataclass_defaults(self):
        p = Packet()
        self.assertEqual(p.src, "")
        self.assertEqual(p.length, 0)
        self.assertIsNone(p.sport)

    def test_protocol_percentages_sum_to_100(self):
        text = HDR + (
            "1,0.0,10.0.0.1,10.0.0.2,TCP,1,2,,,100\n"
            "2,0.1,10.0.0.1,8.8.8.8,DNS,,,5,53,80\n"
            "3,0.2,10.0.0.1,10.0.0.3,UDP,,,6,7,90\n"
        )
        packets, _ = parse_export(text)
        s = summarize(packets)
        total_pct = sum(p["packets_pct"] for p in s.protocols)
        self.assertAlmostEqual(total_pct, 100.0, delta=0.1)


if __name__ == "__main__":
    unittest.main()
