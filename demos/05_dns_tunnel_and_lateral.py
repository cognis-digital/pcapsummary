"""Scenario 5 - Threat hunter / SOC: DNS tunneling + SMB lateral movement.

Two more hunting patterns over offline captures. A DNS tunnel shows up as DNS
dominating the protocol mix far beyond a normal baseline. SMB lateral movement
shows up as one internal host touching many peers on port 445. ``pcapsummary``
exposes both through protocol distribution and the flow table - and an office
baseline is shown alongside so the anomaly is obvious by contrast.

Data: demos/05-dns-tunnel + demos/09-smb-lateral + demos/08-office-baseline.
"""
from _common import load_summary, overview, rule


def dns_tunnel() -> None:
    print("\n--- DNS tunneling: protocol dominance ---")
    baseline = load_summary("08-office-baseline")
    tunnel = load_summary("05-dns-tunnel")

    base_dns = next((p["packets_pct"] for p in baseline.protocols if p["proto"] == "DNS"), 0.0)
    tun_dns = next((p["packets_pct"] for p in tunnel.protocols if p["proto"] == "DNS"), 0.0)
    print(f"  DNS share in healthy office baseline : {base_dns}%")
    print(f"  DNS share in suspect capture         : {tun_dns}%")
    print(f"  -> {tun_dns}% DNS is a tunnel signature; normal hosts sit far lower.")


def smb_lateral() -> None:
    print("\n--- SMB lateral movement: one host, many peers on 445 ---")
    summary = load_summary("09-smb-lateral")
    overview(summary)

    peers = sorted({
        f.dst for f in summary.flows
        if f.src == "10.20.0.50" and f.dport == 445
    })
    print(f"\n  10.20.0.50 reached {len(peers)} distinct peers on tcp/445:")
    print("     " + ", ".join(peers))
    print("  -> one source sweeping SMB across the subnet = lateral movement.")


def main() -> None:
    rule("HUNT  -  DNS tunnel vs baseline, and SMB lateral sweep")
    dns_tunnel()
    smb_lateral()
    print("\nVerdict: both anomalies are visible without packet bytes - just from "
          "flows, protocols, and a known-good baseline to diff against.")


if __name__ == "__main__":
    main()
