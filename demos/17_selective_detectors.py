"""Scenario 17 - Detection engineer: running a single detector by name.

``run_all(summary, only=[...])`` restricts the sweep to named detectors so a
targeted hunt doesn't drown in unrelated findings. This scenario runs only the
port-scan detector over a capture that would also trip others, and shows an
unknown name failing loud rather than silently doing nothing.

Data: demos/02-port-scan/capture_export.txt (offline fixture).
"""
from _common import load_summary, rule
from pcapsummary.detectors import DETECTORS, run_all


def main() -> None:
    rule("SELECTIVE DETECTORS  -  run exactly the hunt you want")
    summary = load_summary("02-port-scan")

    print(f"\nAvailable detectors: {', '.join(sorted(DETECTORS))}")

    only_scan = run_all(summary, only=["port_scan"])
    print(f"\nonly=['port_scan'] -> {len(only_scan)} finding(s):")
    for f in only_scan:
        print(f"     [{f['severity']}] {f['title']}")

    only_dns = run_all(summary, only=["dns_tunnel"])
    print(f"\nonly=['dns_tunnel'] on the same capture -> {len(only_dns)} finding(s).")

    try:
        run_all(summary, only=["typo_detector"])
        failed = False
    except KeyError:
        failed = True
    print(f"\nUnknown detector name raises KeyError: {failed}")

    print(
        "\nVerdict: name your detectors and typos fail loud - no silent empty "
        "results hiding a misconfigured hunt."
    )


if __name__ == "__main__":
    main()
