"""Scenario 6 - Analyst: one-shot detector sweep over a suspect capture.

Rather than eyeballing flows, run the whole heuristic detector set
(``pcapsummary.detectors.run_all``) over a capture and let it name what it
finds, ranked by severity. Here the DNS-tunnel fixture trips both the tunnel
and the beacon detector — exactly what you want a first-pass triage tool to do.

Data: demos/05-dns-tunnel/capture_export.txt (offline fixture).
"""
from _common import load_summary, overview, rule
from pcapsummary.detectors import run_all


def main() -> None:
    rule("DETECTOR SWEEP  -  run every heuristic, ranked by severity")
    summary = load_summary("05-dns-tunnel")

    print("\nCapture overview:")
    overview(summary)

    findings = run_all(summary)
    print(f"\n{len(findings)} detection(s), highest severity first:")
    for f in findings:
        print(f"     [{f['severity'].upper():<6}] {f['type']:<11} {f['title']}")

    types = {f["type"] for f in findings}
    print(
        f"\nVerdict: sweep flagged {', '.join(sorted(types))}. "
        "DNS carrying most of the traffic on a uniform cadence is the tunnel tell."
    )


if __name__ == "__main__":
    main()
