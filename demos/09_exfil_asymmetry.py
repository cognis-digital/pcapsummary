"""Scenario 9 - IR analyst: quantifying an outbound data-exfil skew.

An investigator wants a number, not a hunch. ``detect_exfil`` compares bytes in
each direction across every endpoint pair and reports the upload-skewed ones.
This scenario runs it over the exfil fixture and prints the byte ledger and
ratio behind the finding, then confirms a balanced baseline stays silent.

Data: demos/04-exfil-volume (skewed) + demos/08-office-baseline (balanced).
"""
from _common import load_summary, overview, rule
from pcapsummary.detectors import detect_exfil


def main() -> None:
    rule("EXFIL ASYMMETRY  -  put a number on the upload skew")
    summary = load_summary("04-exfil-volume")

    print("\nSuspect capture overview:")
    overview(summary)

    findings = detect_exfil(summary)
    print(f"\n{len(findings)} upload-skewed pair(s):")
    for f in findings:
        ev = f["evidence"]
        print(
            f"     {f['src']} -> {f['dst']}: out={ev['out_bytes']}B "
            f"in={ev['return_bytes']}B  ratio ~{ev['ratio']}x  [{f['severity']}]"
        )

    baseline = detect_exfil(load_summary("08-office-baseline"))
    print(f"\nSame detector on a balanced office baseline: {len(baseline)} finding(s).")

    print(
        "\nVerdict: a single pair moving ~10x more out than back is the exfil "
        "shape; a balanced baseline stays quiet, so the ratio is the signal."
    )


if __name__ == "__main__":
    main()
