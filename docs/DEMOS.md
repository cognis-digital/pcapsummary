# Demos

Five runnable scenarios live in [`../demos/`](../demos/), each narrating the
*real* `pcapsummary` API/CLI over a bundled, offline capture export for a
different audience. They print clear output and exit `0`, so they double as
smoke tests — `tests/test_demo_scripts.py` runs every one under `pytest`.

```bash
PYTHONUTF8=1 python demos/run_all.py            # all five, end to end
PYTHONUTF8=1 python demos/02_threat_hunter_scan.py   # or just one
```

Each scenario loads the same `demos/NN-*/capture_export.txt` fixtures the test
suite asserts against (private RFC 1918 / RFC 5737 documentation addresses).
**Static analysis of already-captured exports — no live capture, no network.**

## Audience map

| # | Scenario | Audience | Fixture(s) | What it shows |
|---|---|---|---|---|
| [01](../demos/01_soc_triage.py) | SOC triage | Network / SOC analyst | `01-basic` | Top talkers, dominant protocol, heaviest flow — pcap at a glance |
| [02](../demos/02_threat_hunter_scan.py) | Port-scan fan-out | Threat hunter | `02-port-scan` | One source touching 20 ports on one target = vertical TCP scan |
| [03](../demos/03_ir_beacon_and_exfil.py) | Beacon + exfil | IR / forensics | `03-beaconing`, `04-exfil-volume` | Uniform C2 cadence and upload-skewed byte asymmetry |
| [04](../demos/04_sysadmin_ci_gate.py) | CI exit-code gate | Sysadmin / DevOps | `08-office-baseline`, `07-malformed-ci` | Distinct `0`/`1`/`2` exit codes a pipeline can gate on |
| [05](../demos/05_dns_tunnel_and_lateral.py) | DNS tunnel + SMB sweep | Threat hunter / SOC | `05-dns-tunnel`, `09-smb-lateral`, `08-office-baseline` | Protocol dominance vs baseline; one host sweeping tcp/445 |

## 1. SOC triage — *who talked to whom, and how much*
Answers the three questions before opening Wireshark: dominant protocol, top
talkers by bytes (bidirectional pairs), and the single heaviest flow. Clean
capture → exit `0`, no escalation.

## 2. Port-scan fan-out — *the recon tell*
Ranks source→target pairs by distinct destination ports touched. The scanner
fans across 20 ports in half a second as single-packet flows — recon that falls
straight out of the flow table.

## 3. Beacon + exfil — *cadence and asymmetry*
Two suspect captures: five uniform single-packet TLS flows to one external IP
across a multi-minute window (beacon), and an outbound TLS flow carrying ~10×
the bytes of its return (possible exfil).

## 4. CI exit-code gate — *trust the exit code*
Drives the real CLI `main()` in-process over a clean capture (`0`), a corrupted
export (`1`), and a missing file (`2`) — the contract a pipeline gates on, the
same way it gates on a failing test.

## 5. DNS tunnel + SMB sweep — *diff against a baseline*
DNS at ~90% of packets versus ~20% in a healthy office baseline (tunnel
signature), and one internal host reaching six peers on tcp/445 (lateral
movement) — both visible from flows and protocols alone.

---

The `demos/NN-*/` folders hold the capture fixtures and a `SCENARIO.md`
documenting how each export was produced and what to expect from the CLI.
