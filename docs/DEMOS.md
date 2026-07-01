# Demos

Twenty runnable scenarios live in [`../demos/`](../demos/), each narrating the
*real* `pcapsummary` API/CLI over a bundled, offline capture export for a
different audience. They print clear output and exit `0`, so they double as
smoke tests — `tests/test_demo_scripts.py` runs every one under `pytest`.

```bash
PYTHONUTF8=1 python demos/run_all.py                  # all twenty, end to end
PYTHONUTF8=1 python demos/06_detector_sweep.py        # or just one
```

Each scenario loads the same `demos/NN-*/capture_export.txt` fixtures the test
suite asserts against (private RFC 1918 / RFC 5737 documentation addresses).
**Static analysis of already-captured exports — no live capture, no network.**

Scenarios 06–20 exercise the heuristic detectors in
[`pcapsummary/detectors.py`](../pcapsummary/detectors.py) — `detect_port_scan`,
`detect_beaconing`, `detect_exfil`, `detect_dns_tunnel`, and `run_all` — and the
`pcapsummary detect` CLI subcommand.

## Audience map

| # | Scenario | Audience | What it shows |
|---|---|---|---|
| [01](../demos/01_soc_triage.py) | SOC triage | SOC analyst | Top talkers, dominant protocol, heaviest flow — pcap at a glance |
| [02](../demos/02_threat_hunter_scan.py) | Port-scan fan-out | Threat hunter | One source touching 20 ports on one target = vertical TCP scan |
| [03](../demos/03_ir_beacon_and_exfil.py) | Beacon + exfil | IR / forensics | Uniform C2 cadence and upload-skewed byte asymmetry |
| [04](../demos/04_sysadmin_ci_gate.py) | CI exit-code gate | Sysadmin / DevOps | Distinct `0`/`1`/`2` exit codes a pipeline can gate on |
| [05](../demos/05_dns_tunnel_and_lateral.py) | DNS tunnel + SMB sweep | Threat hunter / SOC | Protocol dominance vs baseline; one host sweeping tcp/445 |
| [06](../demos/06_detector_sweep.py) | Detector sweep | Analyst | `run_all` names every finding, ranked by severity |
| [07](../demos/07_threshold_tuning.py) | Threshold tuning | Detection engineer | One detector as a loose hunt vs a strict CI gate |
| [08](../demos/08_detect_cli_gate.py) | `detect` CI gate | DevOps | `detect` exit codes: 1 on any detection, 0 clean, 2 error |
| [09](../demos/09_exfil_asymmetry.py) | Exfil asymmetry | IR analyst | `detect_exfil` byte ledger + upload ratio behind the call |
| [10](../demos/10_beacon_cadence.py) | Beacon cadence | Threat hunter | `detect_beaconing` interval + jitter behind the call |
| [11](../demos/11_smb_lateral_hunt.py) | SMB lateral hunt | SOC | One host reaching many peers on tcp/445 = lateral movement |
| [12](../demos/12_tab_export_ingest.py) | TSV ingest | Analyst | Comma/tab dialect autodetection + header mapping |
| [13](../demos/13_malformed_resilience.py) | Malformed resilience | Data engineer | Bad rows counted, good rows summarized, no crash |
| [14](../demos/14_protocol_baseline_diff.py) | Protocol baseline diff | Threat hunter | Per-protocol delta vs a known-good baseline |
| [15](../demos/15_top_talkers_report.py) | Top-talker report | Capacity / security review | Bidirectional pairs by bytes + heaviest flow |
| [16](../demos/16_json_pipeline.py) | JSON pipeline | Automation | Stable JSON parsed back into a derived metric |
| [17](../demos/17_selective_detectors.py) | Selective detectors | Detection engineer | `run_all(only=[...])`; unknown names fail loud |
| [18](../demos/18_full_triage.py) | Full triage board | SOC lead | One verdict per capture across the whole fixture set |
| [19](../demos/19_topn_focus.py) | Top-N focus | Analyst | `--top` trims talker/flow lists on a noisy capture |
| [20](../demos/20_empty_capture_guard.py) | Empty-capture guard | Robustness | Empty/comment-only input → defined exit code, no trace |

## Detector cheat sheet

| Detector | Fires when | Key knobs |
|---|---|---|
| `detect_port_scan` | one src → many dest ports on one dst, mostly tiny flows | `min_ports`, `max_flow_packets` |
| `detect_beaconing` | repeated evenly-spaced contact to one endpoint (low jitter) | `min_events`, `max_jitter_ratio` |
| `detect_exfil` | one direction of a pair carries ≫ the return bytes | `min_bytes`, `min_ratio` |
| `detect_dns_tunnel` | DNS dominates the packet mix beyond a baseline | `min_pct`, `min_packets` |

```bash
# Run detectors from the CLI; exit 1 if anything fires (CI-gateable):
PYTHONUTF8=1 python -m pcapsummary detect capture_export.txt
PYTHONUTF8=1 python -m pcapsummary detect capture.txt --only port_scan,exfil --format json
```

---

The `demos/NN-*/` folders hold the capture fixtures and a `SCENARIO.md`
documenting how each export was produced and what to expect from the CLI.
