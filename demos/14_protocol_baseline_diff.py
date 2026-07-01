"""Scenario 14 - Threat hunter: diffing a capture's protocol mix vs baseline.

Anomalies are obvious against a known-good baseline. This scenario computes the
per-protocol packet share for a healthy office capture and a DNS-tunnel capture
and prints the delta, making the tunnel's DNS surge fall right out.

Data: demos/08-office-baseline + demos/05-dns-tunnel (offline fixtures).
"""
from _common import load_summary, rule


def _shares(summary):
    return {p["proto"]: p["packets_pct"] for p in summary.protocols}


def main() -> None:
    rule("PROTOCOL BASELINE DIFF  -  spot the surge")
    base = _shares(load_summary("08-office-baseline"))
    suspect = _shares(load_summary("05-dns-tunnel"))

    protos = sorted(set(base) | set(suspect))
    print(f"\n  {'PROTO':<10}{'BASELINE%':>12}{'SUSPECT%':>12}{'DELTA':>10}")
    biggest = ("", 0.0)
    for p in protos:
        b, s = base.get(p, 0.0), suspect.get(p, 0.0)
        delta = round(s - b, 1)
        print(f"  {p:<10}{b:>12}{s:>12}{delta:>+10}")
        if delta > biggest[1]:
            biggest = (p, delta)

    print(
        f"\nVerdict: {biggest[0]} jumped +{biggest[1]} points over baseline - "
        "the clearest anomaly to pivot on."
    )


if __name__ == "__main__":
    main()
