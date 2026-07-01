"""Scenario 7 - Detection engineer: tuning a detector's thresholds.

The same detector is a noisy hunt or a tight CI gate depending on its
thresholds. This scenario runs ``detect_port_scan`` over the port-scan fixture
at a loose threshold (fires) and a strict one (silent), showing how the knobs
turn one heuristic into either a broad sweep or a high-confidence gate.

Data: demos/02-port-scan/capture_export.txt (offline fixture).
"""
from _common import load_summary, rule
from pcapsummary.detectors import detect_port_scan


def main() -> None:
    rule("THRESHOLD TUNING  -  same detector, two postures")
    summary = load_summary("02-port-scan")

    loose = detect_port_scan(summary, min_ports=5)
    strict = detect_port_scan(summary, min_ports=100)

    print("\nLoose posture (min_ports=5) — catch early recon:")
    for f in loose:
        ev = f["evidence"]
        print(f"     {f['title']}  [{ev['distinct_dports']} ports]")
    print(f"     -> {len(loose)} finding(s)")

    print("\nStrict posture (min_ports=100) — only egregious sweeps:")
    print(f"     -> {len(strict)} finding(s) (fixture fans only ~20 ports)")

    print(
        "\nVerdict: one heuristic, two jobs. Loose for hunting, strict for a "
        f"low-false-positive CI gate. Fixture fired {len(loose)}/"
        f"{len(strict)} across the two."
    )


if __name__ == "__main__":
    main()
