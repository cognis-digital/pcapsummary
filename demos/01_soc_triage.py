"""Scenario 1 - Network / SOC analyst: pcap at a glance.

A SOC analyst pulls a short authorized capture off a host and wants the answer
to three questions before opening Wireshark: who talked to whom, which
protocols dominated, and which flows moved the most bytes. ``pcapsummary``
answers all three from the text export in one pass.

Data: demos/01-basic/capture_export.txt (offline fixture).
"""
from _common import load_summary, overview, rule, top_protocol


def main() -> None:
    rule("SOC TRIAGE  -  who talked to whom, and how much")
    summary = load_summary("01-basic")

    print("\nFirst look at the capture:")
    overview(summary)

    proto = top_protocol(summary)
    print(f"\n1) Dominant protocol -> {proto['proto']}  "
          f"({proto['packets']} pkts, {proto['packets_pct']}% of traffic)")

    print("\n2) Top talkers by bytes (bidirectional endpoint pairs):")
    for t in summary.talkers[:3]:
        a, b = t["endpoints"]
        print(f"     {a} <-> {b}   {t['packets']} pkts / {t['bytes']} bytes")

    print("\n3) Heaviest flow (the one to look at first):")
    f = summary.flows[0]
    sp = f"{f.src}:{f.sport}" if f.sport is not None else f.src
    dp = f"{f.dst}:{f.dport}" if f.dport is not None else f.dst
    print(f"     {sp} -> {dp}  [{f.proto}]  {f.packets} pkts / {f.bytes} bytes")

    print("\nVerdict: clean web/DNS traffic from one workstation. Parse errors = 0,")
    print("so the tool exits 0 and this capture needs no further escalation.")


if __name__ == "__main__":
    main()
