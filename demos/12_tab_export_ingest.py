"""Scenario 12 - Analyst: ingesting a tab-separated tshark export.

pcapsummary autodetects comma- vs tab-separated exports and maps columns by
header name. This scenario feeds a TSV capture (ARP/ICMP/ICMPv6) and confirms
the dialect and headers were understood with zero parse errors.

Data: demos/06-tab-export/capture_export.tsv (offline fixture).
"""
from _common import load_summary, overview, rule


def main() -> None:
    rule("TAB EXPORT INGEST  -  autodetect TSV + header mapping")
    summary = load_summary("06-tab-export", filename="capture_export.tsv")

    print("\nCapture overview:")
    overview(summary)

    print("\nProtocol mix parsed from the tab-separated export:")
    for p in summary.protocols:
        print(f"     {p['proto']:<10} {p['packets']} pkts  {p['packets_pct']}%")

    seen = {p["proto"] for p in summary.protocols}
    ok = summary.parse_errors == 0 and {"ARP", "ICMP"} <= seen
    print(
        f"\nVerdict: TSV autodetected, {summary.total_packets} packets, "
        f"{summary.parse_errors} errors -> {'clean ingest' if ok else 'check dialect'}."
    )


if __name__ == "__main__":
    main()
