"""Scenario 15 - Capacity/security review: top-talker bandwidth report.

Bidirectional endpoint pairs ranked by bytes answer "who moved the most data".
This scenario prints the top talkers for a capture and the single heaviest
5-tuple flow underneath them - the first thing a reviewer checks.

Data: demos/01-basic/capture_export.txt (offline fixture).
"""
from _common import load_summary, overview, rule


def main() -> None:
    rule("TOP TALKERS REPORT  -  who moved the most data")
    summary = load_summary("01-basic", top=5)

    print("\nCapture overview:")
    overview(summary)

    print("\nTop talkers (bidirectional pairs, by bytes):")
    for i, t in enumerate(summary.talkers, 1):
        a, b = t["endpoints"]
        print(f"     {i}. {a} <-> {b}   {t['bytes']} bytes / {t['packets']} pkts")

    f = summary.flows[0]
    print(
        f"\nHeaviest single flow: {f.src} -> {f.dst} [{f.proto}] "
        f"{f.bytes} bytes over {f.packets} pkts."
    )
    print(
        "\nVerdict: the top pair and heaviest flow are where a bandwidth or "
        "data-movement review starts."
    )


if __name__ == "__main__":
    main()
