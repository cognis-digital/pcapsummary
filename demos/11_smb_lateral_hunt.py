"""Scenario 11 - SOC: SMB lateral-movement sweep by port-scan heuristic.

One internal host reaching many peers on tcp/445 is horizontal movement. The
same fan-out logic behind ``detect_port_scan`` (many destinations rather than
many ports) surfaces it; here we count distinct peers on 445 from the flow
table and confirm the sweeping source.

Data: demos/09-smb-lateral/capture_export.txt (offline fixture).
"""
from collections import defaultdict

from _common import load_summary, overview, rule


def main() -> None:
    rule("SMB LATERAL HUNT  -  one host, many peers on 445")
    summary = load_summary("09-smb-lateral")

    print("\nCapture overview:")
    overview(summary)

    peers_by_src = defaultdict(set)
    for f in summary.flows:
        if f.dport == 445:
            peers_by_src[f.src].add(f.dst)

    ranked = sorted(peers_by_src.items(), key=lambda kv: len(kv[1]), reverse=True)
    print("\nSources ranked by distinct tcp/445 peers:")
    for src, peers in ranked[:3]:
        print(f"     {src} -> {len(peers)} peers: {', '.join(sorted(peers))}")

    top_src, top_peers = ranked[0]
    print(
        f"\nVerdict: {top_src} swept {len(top_peers)} hosts on SMB in "
        f"{round(summary.time_span, 2)}s - classic lateral movement. Isolate it."
    )


if __name__ == "__main__":
    main()
