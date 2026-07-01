"""Heuristic detectors over a parsed :class:`~pcapsummary.core.Summary`.

These are deliberately simple, explainable heuristics — not an IDS. They turn
the flow/protocol/timing shapes the summarizer already computes into named,
actionable findings a defender can triage:

* :func:`detect_port_scan`   — one source touching many destination ports on
  one target as tiny flows (vertical scan / recon).
* :func:`detect_beaconing`   — repeated, evenly-spaced small flows from one
  host to one external endpoint (C2 cadence).
* :func:`detect_exfil`       — a flow whose outbound byte volume dwarfs the
  return traffic on the same endpoint pair (upload-skewed / possible exfil).
* :func:`detect_dns_tunnel`  — DNS packets dominating the protocol mix well
  beyond a normal baseline (tunneling signature).

Every detector returns a list of plain ``dict`` findings with a stable schema:

    {
        "type":     "<detector name>",       # e.g. "port_scan"
        "severity": "low"|"medium"|"high",
        "title":    "<one-line human summary>",
        "src": ..., "dst": ...,               # when applicable
        "evidence": {...},                    # detector-specific numbers
    }

Findings are JSON-serializable and map cleanly onto the canonical
``cognis-connect`` Finding via :mod:`pcapsummary.connect`.

Static analysis only — nothing here touches the network. Thresholds are tunable
via keyword arguments so the same code serves both noisy hunts and tight CI
gates. All detectors accept a :class:`Summary`; :func:`run_all` runs the set.
"""

from __future__ import annotations

from collections import defaultdict
from typing import List, Optional

from .core import Summary

# Well-known ports whose repeated use is expected and should not, on its own,
# be read as beaconing (web/DNS/mail). Beaconing detection still fires on these
# when the *cadence* is suspiciously uniform, but the bar is higher.
_NOISY_SERVICE_PORTS = frozenset({53, 80, 123, 443})

Severity = str  # "low" | "medium" | "high"


def _finding(dtype: str, severity: Severity, title: str, **extra) -> dict:
    rec = {"type": dtype, "severity": severity, "title": title}
    rec.update(extra)
    return rec


def detect_port_scan(
    summary: Summary,
    *,
    min_ports: int = 15,
    max_flow_packets: int = 3,
) -> List[dict]:
    """Flag a source that fans across many destination ports on one target.

    A vertical scan shows up as one ``(src, dst)`` pair spread across many
    distinct destination ports, most of them tiny (one- to few-packet) flows —
    the connection attempts that never completed.

    ``min_ports``        distinct dest ports before a pair is flagged.
    ``max_flow_packets`` a flow at or below this size counts as "probe-like".
    """
    if min_ports < 1:
        raise ValueError("min_ports must be >= 1")

    ports_by_pair: dict = defaultdict(set)
    probes_by_pair: dict = defaultdict(int)
    for f in summary.flows:
        if f.dport is None:
            continue
        pair = (f.src, f.dst)
        ports_by_pair[pair].add(f.dport)
        if f.packets <= max_flow_packets:
            probes_by_pair[pair] += 1

    findings: List[dict] = []
    for (src, dst), ports in ports_by_pair.items():
        n_ports = len(ports)
        if n_ports < min_ports:
            continue
        probes = probes_by_pair[(src, dst)]
        # Mostly-probe traffic across a wide port range is a stronger signal
        # than a handful of established sessions on many ports.
        severity = "high" if probes >= n_ports * 0.8 else "medium"
        findings.append(
            _finding(
                "port_scan",
                severity,
                f"{src} touched {n_ports} ports on {dst} "
                f"({probes} probe-sized flows)",
                src=src,
                dst=dst,
                evidence={
                    "distinct_dports": n_ports,
                    "probe_flows": probes,
                    "ports_sample": sorted(p for p in ports if p is not None)[:20],
                },
            )
        )
    findings.sort(key=lambda r: r["evidence"]["distinct_dports"], reverse=True)
    return findings


def detect_beaconing(
    summary: Summary,
    *,
    min_events: int = 4,
    max_jitter_ratio: float = 0.25,
) -> List[dict]:
    """Flag evenly-spaced repeated contact from one host to one endpoint.

    Groups packets by ``(src, dst, dport)`` and looks at the inter-arrival
    gaps. Low jitter (small standard-deviation-to-mean ratio) across enough
    events is the beacon tell.

    ``min_events``       minimum contacts before cadence is assessed.
    ``max_jitter_ratio`` stddev/mean interval at or below this = "uniform".
    """
    if min_events < 2:
        raise ValueError("min_events must be >= 2 to measure an interval")
    if max_jitter_ratio < 0:
        raise ValueError("max_jitter_ratio must be >= 0")

    # Beacon cadence is the gap *between contacts* to an endpoint, not between
    # every packet within a session. Collapse each channel's packet timestamps
    # into distinct contact times (bursts within ``burst`` seconds are one
    # contact), then measure the jitter of the between-contact intervals.
    burst = 1.0
    times_by_channel: dict = defaultdict(list)
    for pkt in summary.packets:
        if pkt.time is None or pkt.dport is None:
            continue
        times_by_channel[(pkt.src, pkt.dst, pkt.dport)].append(pkt.time)

    for key, raw in list(times_by_channel.items()):
        raw = sorted(raw)
        contacts = [raw[0]]
        for t in raw[1:]:
            if t - contacts[-1] > burst:
                contacts.append(t)
        times_by_channel[key] = contacts

    findings: List[dict] = []
    for (src, dst, dport), times in times_by_channel.items():
        if len(times) < min_events:
            continue
        times = sorted(times)
        gaps = [b - a for a, b in zip(times, times[1:]) if b > a]
        if len(gaps) < min_events - 1:
            continue
        mean = sum(gaps) / len(gaps)
        if mean <= 0:
            continue
        var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
        stddev = var ** 0.5
        jitter = stddev / mean
        if jitter > max_jitter_ratio:
            continue
        # Beaconing on a noisy service port needs an even tighter cadence.
        if dport in _NOISY_SERVICE_PORTS and jitter > max_jitter_ratio / 2:
            continue
        severity = "high" if jitter <= max_jitter_ratio / 2 else "medium"
        findings.append(
            _finding(
                "beaconing",
                severity,
                f"{src} beaconed to {dst}:{dport} every ~{round(mean, 1)}s "
                f"({len(times)} contacts, jitter {round(jitter, 3)})",
                src=src,
                dst=dst,
                dport=dport,
                evidence={
                    "events": len(times),
                    "mean_interval": round(mean, 3),
                    "jitter_ratio": round(jitter, 3),
                },
            )
        )
    findings.sort(key=lambda r: r["evidence"]["jitter_ratio"])
    return findings


def detect_exfil(
    summary: Summary,
    *,
    min_bytes: int = 10_000,
    min_ratio: float = 5.0,
) -> List[dict]:
    """Flag endpoint pairs whose outbound volume dwarfs the return traffic.

    For each unordered endpoint pair, compares bytes sent in each direction.
    A large outbound total that is also a large multiple of the return is the
    upload-skew that can indicate exfiltration.

    ``min_bytes`` outbound floor before a pair is considered at all.
    ``min_ratio`` outbound/return byte ratio at or above which it is flagged.
    """
    if min_bytes < 0:
        raise ValueError("min_bytes must be >= 0")
    if min_ratio <= 0:
        raise ValueError("min_ratio must be > 0")

    # Directional byte totals keyed by ordered (src, dst).
    dir_bytes: dict = defaultdict(int)
    for f in summary.flows:
        dir_bytes[(f.src, f.dst)] += f.bytes

    findings: List[dict] = []
    seen: set = set()
    for (src, dst), out_bytes in dir_bytes.items():
        pair = frozenset((src, dst))
        if pair in seen:
            continue
        return_bytes = dir_bytes.get((dst, src), 0)
        # Only report the heavier direction as the "outbound" leg.
        if return_bytes > out_bytes:
            continue
        seen.add(pair)
        if out_bytes < min_bytes:
            continue
        ratio = out_bytes / max(return_bytes, 1)
        if ratio < min_ratio:
            continue
        severity = "high" if ratio >= min_ratio * 2 else "medium"
        findings.append(
            _finding(
                "exfil",
                severity,
                f"{src} sent {out_bytes} bytes to {dst} vs {return_bytes} back "
                f"(~{round(ratio, 1)}x upload skew)",
                src=src,
                dst=dst,
                evidence={
                    "out_bytes": out_bytes,
                    "return_bytes": return_bytes,
                    "ratio": round(ratio, 2),
                },
            )
        )
    findings.sort(key=lambda r: r["evidence"]["out_bytes"], reverse=True)
    return findings


def detect_dns_tunnel(
    summary: Summary,
    *,
    min_pct: float = 60.0,
    min_packets: int = 10,
) -> List[dict]:
    """Flag DNS dominating the protocol mix beyond a normal baseline.

    Tunneling drives DNS well past its usual small share of traffic. Reports at
    most one finding (DNS is a single protocol).

    ``min_pct``     DNS packet share at or above which to flag.
    ``min_packets`` minimum DNS packets so tiny captures don't false-positive.
    """
    if not 0 <= min_pct <= 100:
        raise ValueError("min_pct must be between 0 and 100")

    dns = next((p for p in summary.protocols if p["proto"] == "DNS"), None)
    if dns is None:
        return []
    if dns["packets"] < min_packets or dns["packets_pct"] < min_pct:
        return []
    severity = "high" if dns["packets_pct"] >= min(min_pct + 25, 100) else "medium"
    return [
        _finding(
            "dns_tunnel",
            severity,
            f"DNS is {dns['packets_pct']}% of packets "
            f"({dns['packets']} pkts) — well above a normal baseline",
            evidence={
                "dns_pct": dns["packets_pct"],
                "dns_packets": dns["packets"],
                "dns_bytes": dns["bytes"],
            },
        )
    ]


# Detector registry so callers (CLI, tests) can iterate by name.
DETECTORS = {
    "port_scan": detect_port_scan,
    "beaconing": detect_beaconing,
    "exfil": detect_exfil,
    "dns_tunnel": detect_dns_tunnel,
}


def run_all(summary: Summary, only: Optional[list] = None) -> List[dict]:
    """Run the detector set over ``summary`` and return combined findings.

    ``only`` optionally restricts to a subset of detector names (raises
    ``KeyError`` on an unknown name so typos fail loud rather than silent).
    Findings are ordered high → medium → low severity, stable within a rank.
    """
    names = list(DETECTORS) if only is None else list(only)
    findings: List[dict] = []
    for name in names:
        if name not in DETECTORS:
            raise KeyError(
                f"unknown detector {name!r}; known: {sorted(DETECTORS)}"
            )
        findings.extend(DETECTORS[name](summary))
    rank = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda r: rank.get(r.get("severity", "low"), 3))
    return findings
