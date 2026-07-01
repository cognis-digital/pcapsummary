"""Scenario 18 - SOC lead: full triage across every bundled capture.

A lead wants one pass over the whole capture set: summarize each, run the
detector sweep, and print a one-line verdict per capture (clean vs the named
detections). This is the shape of an end-of-shift triage board.

Data: every demos/NN-*/ fixture (offline).
"""
from _common import load_summary, rule
from pcapsummary.detectors import run_all

CAPTURES = [
    ("01-basic", "capture_export.txt"),
    ("02-port-scan", "capture_export.txt"),
    ("03-beaconing", "capture_export.txt"),
    ("04-exfil-volume", "capture_export.txt"),
    ("05-dns-tunnel", "capture_export.txt"),
    ("06-tab-export", "capture_export.tsv"),
    ("08-office-baseline", "capture_export.txt"),
    ("09-smb-lateral", "capture_export.txt"),
]


def main() -> None:
    rule("FULL TRIAGE  -  every capture, one verdict each")

    dirty = 0
    for name, fn in CAPTURES:
        summary = load_summary(name, filename=fn)
        findings = run_all(summary)
        if findings:
            dirty += 1
            types = sorted({f["type"] for f in findings})
            verdict = "FLAGGED: " + ", ".join(types)
        else:
            verdict = "clean"
        print(f"     {name:<20} {summary.total_packets:>3} pkts   {verdict}")

    print(
        f"\nVerdict: {dirty}/{len(CAPTURES)} captures tripped a detector. "
        "The clean ones need no further review; the flagged ones get pivoted on."
    )


if __name__ == "__main__":
    main()
