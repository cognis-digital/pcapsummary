"""Scenario 3 - Incident responder / forensics: beacon + exfil.

During an investigation an IR analyst has two captures from a suspect host.
The first should show C2 beaconing: small, uniform TLS flows to one external IP
at a regular cadence. The second should show data exfiltration: an outbound
flow carrying far more bytes than its return. ``pcapsummary`` surfaces both
patterns from the flow and timing data.

Data: demos/03-beaconing + demos/04-exfil-volume (offline fixtures).
"""
from _common import load_summary, overview, rule


def beaconing() -> None:
    print("\n--- Capture A: periodic C2 beacon ---")
    summary = load_summary("03-beaconing")
    overview(summary)

    beacons = [
        f for f in summary.flows
        if f.dst == "203.0.113.45" and f.dport == 8443 and f.proto == "TLSV1.2"
    ]
    print(f"\n  {len(beacons)} separate TLSv1.2 flows to 203.0.113.45:8443, "
          "each a single packet:")
    for f in beacons:
        print(f"     {f.src} -> {f.dst}:{f.dport}  {f.packets} pkt / {f.bytes} bytes")
    print(f"  Spread evenly across a {round(summary.time_span)}s window -> "
          "uniform cadence is the beacon signature.")


def exfil() -> None:
    print("\n--- Capture B: outbound volume asymmetry ---")
    summary = load_summary("04-exfil-volume")
    overview(summary)

    out_flow = next(
        f for f in summary.flows
        if f.src == "192.168.5.40" and f.dst == "198.51.100.77" and f.proto == "TLSV1.3"
    )
    in_flow = next(
        f for f in summary.flows
        if f.src == "198.51.100.77" and f.dst == "192.168.5.40" and f.proto == "TLSV1.3"
    )
    ratio = out_flow.bytes / max(in_flow.bytes, 1)
    print(f"\n  Outbound {out_flow.src} -> {out_flow.dst}: {out_flow.bytes} bytes")
    print(f"  Return   {in_flow.src} -> {in_flow.dst}: {in_flow.bytes} bytes")
    print(f"  Upload/download ratio ~ {ratio:.1f}x -> upload-skewed, possible exfil.")


def main() -> None:
    rule("INCIDENT RESPONSE  -  beacon cadence + exfil asymmetry")
    beaconing()
    exfil()
    print("\nVerdict: regular beacon + heavy outbound = stage the host for "
          "containment and pull the full pcap.")


if __name__ == "__main__":
    main()
