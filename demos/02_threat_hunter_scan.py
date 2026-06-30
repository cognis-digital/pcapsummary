"""Scenario 2 - Threat hunter: spotting a vertical port scan.

A threat hunter is sweeping captured traffic for reconnaissance. The tell-tale
of a vertical port scan is one source touching many distinct destination ports
on a single target, each as a tiny one-packet flow. ``pcapsummary`` makes that
fan-out fall right out of the flow table.

Data: demos/02-port-scan/capture_export.txt (offline fixture).
"""
from collections import defaultdict

from _common import load_summary, overview, rule


def main() -> None:
    rule("THREAT HUNT  -  vertical port scan fan-out")
    summary = load_summary("02-port-scan")

    print("\nCapture overview:")
    overview(summary)

    # Count distinct destination ports each source aims at a single target.
    fanout = defaultdict(set)
    single_pkt = defaultdict(int)
    for f in summary.flows:
        fanout[(f.src, f.dst)].add(f.dport)
        if f.packets == 1:
            single_pkt[(f.src, f.dst)] += 1

    print("\nSource -> target pairs ranked by distinct ports touched:")
    ranked = sorted(fanout.items(), key=lambda kv: len(kv[1]), reverse=True)
    for (src, dst), ports in ranked[:3]:
        ports = {p for p in ports if p is not None}
        print(f"     {src} -> {dst}   {len(ports)} distinct dports, "
              f"{single_pkt[(src, dst)]} single-packet flows")

    scanner, target = ranked[0][0]
    n_ports = len({p for p in ranked[0][1] if p is not None})
    print(f"\nVerdict: {scanner} fanned across {n_ports} ports on {target} in "
          f"{round(summary.time_span, 3)}s -")
    print("classic vertical TCP scan. Pivot to the host and check what answered.")


if __name__ == "__main__":
    main()
