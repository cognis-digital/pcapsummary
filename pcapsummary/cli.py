"""Command-line interface for PCAPSUMMARY.

Usage:
    pcapsummary summarize <export.txt> [--format table|json|csv] [--top N]
    pcapsummary --version

Exit codes:
    0  success, packets parsed, no problems
    1  findings: parse errors encountered, or empty/unparseable input
    2  usage / file error
"""

from __future__ import annotations

import argparse
import io
import json
import sys
from typing import Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import parse_export, summarize
from .detectors import DETECTORS, run_all as run_detectors


def _read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def _render_table(summary, top: int) -> str:
    lines = []
    lines.append(f"{TOOL_NAME} {TOOL_VERSION} - pcap at a glance")
    lines.append("=" * 52)
    lines.append(f"Packets parsed : {summary.total_packets}")
    lines.append(f"Total bytes    : {summary.total_bytes}")
    lines.append(f"Flows          : {len(summary.flows)}")
    lines.append(f"Time span (s)  : {round(summary.time_span, 3)}")
    lines.append(f"Parse errors   : {summary.parse_errors}")
    lines.append("")

    lines.append("Protocol distribution")
    lines.append("-" * 52)
    lines.append(f"{'PROTO':<12}{'PKTS':>8}{'BYTES':>12}{'PKT%':>8}")
    for p in summary.protocols:
        lines.append(
            f"{p['proto']:<12}{p['packets']:>8}{p['bytes']:>12}{p['packets_pct']:>7}%"
        )
    lines.append("")

    lines.append(f"Top talkers (by bytes, max {top})")
    lines.append("-" * 52)
    lines.append(f"{'ENDPOINT A <-> ENDPOINT B':<34}{'PKTS':>7}{'BYTES':>11}")
    for t in summary.talkers:
        a, b = t["endpoints"]
        pair = f"{a} <-> {b}"
        if len(pair) > 33:
            pair = pair[:30] + "..."
        lines.append(f"{pair:<34}{t['packets']:>7}{t['bytes']:>11}")
    lines.append("")

    lines.append(f"Top flows (by bytes, max {top})")
    lines.append("-" * 52)
    lines.append(f"{'SRC->DST':<30}{'PROTO':<8}{'PKTS':>6}{'BYTES':>10}")
    for f in summary.flows[:top]:
        sp = f"{f.src}:{f.sport}" if f.sport is not None else f.src
        dp = f"{f.dst}:{f.dport}" if f.dport is not None else f.dst
        route = f"{sp}->{dp}"
        if len(route) > 29:
            route = route[:26] + "..."
        lines.append(
            f"{route:<30}{f.proto:<8}{f.packets:>6}{f.bytes:>10}"
        )
    return "\n".join(lines)


def _render_csv(summary) -> str:
    """Emit one row per flow as CSV — convenient for spreadsheets / pandas.

    Flows are already sorted by (bytes, packets) descending in the summary, so
    the heaviest flows appear first. Header row is always present.
    """
    import csv as _csv

    buf = io.StringIO()
    writer = _csv.writer(buf, lineterminator="\n")
    writer.writerow(
        ["src", "sport", "dst", "dport", "proto", "packets", "bytes", "duration"]
    )
    for f in summary.flows:
        writer.writerow(
            [
                f.src,
                "" if f.sport is None else f.sport,
                f.dst,
                "" if f.dport is None else f.dport,
                f.proto,
                f.packets,
                f.bytes,
                f.duration,
            ]
        )
    return buf.getvalue().rstrip("\n")


def _cmd_summarize(args) -> int:
    if args.top < 1:
        print("error: --top must be a positive integer", file=sys.stderr)
        return 2
    try:
        text = _read_input(args.input)
    except OSError as exc:
        print(f"error: cannot read {args.input}: {exc}", file=sys.stderr)
        return 2

    packets, errors = parse_export(text)
    summary = summarize(packets, parse_errors=errors, top=args.top)

    if args.format == "json":
        print(json.dumps(summary.as_dict(), indent=2, sort_keys=True))
    elif args.format == "csv":
        print(_render_csv(summary))
    else:
        print(_render_table(summary, args.top))

    # Findings / failure semantics: empty input or any parse errors are
    # actionable findings worth a non-zero exit for scripting/CI.
    if summary.total_packets == 0:
        print("no packets parsed from input", file=sys.stderr)
        return 1
    if summary.parse_errors > 0:
        return 1
    return 0


_SEV_ORDER = {"high": 0, "medium": 1, "low": 2}


def _render_findings_table(findings: list) -> str:
    lines = [f"{TOOL_NAME} {TOOL_VERSION} - detections", "=" * 52]
    if not findings:
        lines.append("No detections. Traffic looks clean against current thresholds.")
        return "\n".join(lines)
    lines.append(f"{len(findings)} detection(s):")
    lines.append("")
    for f in findings:
        lines.append(f"[{f['severity'].upper():<6}] {f['type']}: {f['title']}")
    return "\n".join(lines)


def _cmd_detect(args) -> int:
    if args.top < 1:
        print("error: --top must be a positive integer", file=sys.stderr)
        return 2
    try:
        text = _read_input(args.input)
    except OSError as exc:
        print(f"error: cannot read {args.input}: {exc}", file=sys.stderr)
        return 2

    only = None
    if args.only:
        only = [n.strip() for n in args.only.split(",") if n.strip()]
        unknown = [n for n in only if n not in DETECTORS]
        if unknown:
            print(
                f"error: unknown detector(s): {', '.join(unknown)}; "
                f"choose from {', '.join(sorted(DETECTORS))}",
                file=sys.stderr,
            )
            return 2

    packets, errors = parse_export(text)
    summary = summarize(packets, parse_errors=errors, top=args.top)

    if summary.total_packets == 0:
        print("no packets parsed from input", file=sys.stderr)
        return 2

    try:
        findings = run_detectors(summary, only=only)
    except KeyError as exc:  # defensive; unknown names already screened above
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(findings, indent=2, sort_keys=True))
    else:
        print(_render_findings_table(findings))

    # Exit-code contract: 1 when any detection fires (so CI can gate), else 0.
    return 1 if findings else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Summarize flows/talkers/protocols from a pcap text export "
        "(defensive analysis only; no live capture).",
    )
    parser.add_argument(
        "--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}"
    )
    sub = parser.add_subparsers(dest="command")

    p_sum = sub.add_parser(
        "summarize", help="summarize a tshark-style text export"
    )
    p_sum.add_argument(
        "input", help="path to text export, or '-' for stdin"
    )
    p_sum.add_argument(
        "--format",
        choices=["table", "json", "csv"],
        default="table",
        help="output format (default: table). csv emits one row per flow.",
    )
    p_sum.add_argument(
        "--top",
        type=int,
        default=10,
        help="number of top talkers/flows to show (default: 10)",
    )
    p_sum.set_defaults(func=_cmd_summarize)

    p_det = sub.add_parser(
        "detect",
        help="run heuristic detectors (port-scan / beacon / exfil / dns-tunnel)",
    )
    p_det.add_argument("input", help="path to text export, or '-' for stdin")
    p_det.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="output format (default: table)",
    )
    p_det.add_argument(
        "--only",
        default=None,
        help="comma-separated subset of detectors to run "
        f"(choices: {', '.join(sorted(DETECTORS))})",
    )
    p_det.add_argument(
        "--top",
        type=int,
        default=10,
        help="top talkers/flows retained in the summary (default: 10)",
    )
    p_det.set_defaults(func=_cmd_detect)
    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help(sys.stderr)
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
