"""Scenario 10 - Threat hunter: measuring C2 beacon cadence.

Human eyes miss regular timing; ``detect_beaconing`` measures it. It collapses
each channel's packets into distinct contacts, then reports channels whose
between-contact intervals have low jitter (the beacon tell). This scenario runs
it over the beacon fixture and prints the cadence and jitter behind the call,
then shows that ordinary bursty traffic (basic capture) does not trip it.

Data: demos/03-beaconing (beacon) + demos/01-basic (normal web/DNS).
"""
from _common import load_summary, overview, rule
from pcapsummary.detectors import detect_beaconing


def main() -> None:
    rule("BEACON CADENCE  -  low jitter is the C2 tell")
    summary = load_summary("03-beaconing")

    print("\nSuspect capture overview:")
    overview(summary)

    findings = detect_beaconing(summary)
    print(f"\n{len(findings)} beacon channel(s):")
    for f in findings:
        ev = f["evidence"]
        print(
            f"     {f['src']} -> {f['dst']}:{f['dport']}  "
            f"{ev['events']} contacts, every ~{ev['mean_interval']}s, "
            f"jitter {ev['jitter_ratio']}  [{f['severity']}]"
        )

    normal = detect_beaconing(load_summary("01-basic"))
    print(f"\nSame detector on normal web/DNS traffic: {len(normal)} finding(s).")

    print(
        "\nVerdict: evenly-spaced contact to one endpoint (near-zero jitter) is a "
        "beacon; irregular human traffic scatters and stays below the bar."
    )


if __name__ == "__main__":
    main()
