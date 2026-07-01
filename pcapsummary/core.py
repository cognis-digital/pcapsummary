"""Core parsing + summarization engine for PCAPSUMMARY.

Input format: a text export such as produced by

    tshark -r capture.pcap -T fields -E separator=, \\
        -e frame.number -e frame.time_relative \\
        -e ip.src -e ip.dst -e _ws.col.Protocol \\
        -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport \\
        -e frame.len

We are intentionally permissive: we accept comma- OR tab-separated rows and
detect columns by header names when a header line is present, otherwise we
fall back to a documented positional layout. Everything is standard library
and operates on a static file (no live capture / no network).
"""

from __future__ import annotations

import csv
import io
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Optional

# Single source of truth for tool identity. ``__init__`` re-exports these; the
# CLI ``--version`` and table header read them. Keep in sync with the top-level
# ``VERSION`` file and ``pyproject.toml``.
TOOL_NAME = "pcapsummary"
TOOL_VERSION = "0.5.0"

# Canonical field names we try to populate per packet.
_FIELD_ALIASES = {
    "frame.number": "number",
    "no.": "number",
    "no": "number",
    "frame": "number",
    "frame.time_relative": "time",
    "time": "time",
    "ip.src": "src",
    "ipv6.src": "src",
    "source": "src",
    "src": "src",
    "ip.dst": "dst",
    "ipv6.dst": "dst",
    "destination": "dst",
    "dst": "dst",
    "_ws.col.protocol": "proto",
    "protocol": "proto",
    "proto": "proto",
    "tcp.srcport": "tcp_sport",
    "udp.srcport": "udp_sport",
    "srcport": "sport",
    "tcp.dstport": "tcp_dport",
    "udp.dstport": "udp_dport",
    "dstport": "dport",
    "frame.len": "length",
    "length": "length",
    "len": "length",
}

# Positional fallback when no header is recognized (matches the tshark
# command documented in the module docstring).
_POSITIONAL = [
    "number",
    "time",
    "src",
    "dst",
    "proto",
    "tcp_sport",
    "tcp_dport",
    "udp_sport",
    "udp_dport",
    "length",
]


@dataclass
class Packet:
    number: Optional[int] = None
    time: Optional[float] = None
    src: str = ""
    dst: str = ""
    proto: str = ""
    sport: Optional[int] = None
    dport: Optional[int] = None
    length: int = 0


@dataclass
class Flow:
    src: str
    dst: str
    proto: str
    sport: Optional[int]
    dport: Optional[int]
    packets: int = 0
    bytes: int = 0
    first_time: Optional[float] = None
    last_time: Optional[float] = None

    @property
    def key(self) -> tuple:
        return (self.src, self.dst, self.proto, self.sport, self.dport)

    @property
    def duration(self) -> float:
        if self.first_time is None or self.last_time is None:
            return 0.0
        return round(self.last_time - self.first_time, 6)

    def as_dict(self) -> dict:
        return {
            "src": self.src,
            "dst": self.dst,
            "proto": self.proto,
            "sport": self.sport,
            "dport": self.dport,
            "packets": self.packets,
            "bytes": self.bytes,
            "duration": self.duration,
        }


@dataclass
class Summary:
    packets: list = field(default_factory=list)
    flows: list = field(default_factory=list)
    talkers: list = field(default_factory=list)
    protocols: list = field(default_factory=list)
    total_packets: int = 0
    total_bytes: int = 0
    parse_errors: int = 0
    time_span: float = 0.0

    def as_dict(self) -> dict:
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "parse_errors": self.parse_errors,
            "time_span": round(self.time_span, 6),
            "flow_count": len(self.flows),
            "flows": [f.as_dict() for f in self.flows],
            "talkers": self.talkers,
            "protocols": self.protocols,
        }


def _to_int(value: str) -> Optional[int]:
    value = (value or "").strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        try:
            return int(float(value))
        except ValueError:
            return None


def _to_float(value: str) -> Optional[float]:
    value = (value or "").strip()
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _detect_dialect(sample: str) -> str:
    """Return 'tab' or 'comma' based on the first non-comment line."""
    for line in sample.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        return "tab" if line.count("\t") > line.count(",") else "comma"
    return "comma"


def _map_header(header: list) -> Optional[dict]:
    """Map a header row to column indexes. Returns None if unrecognized."""
    mapping: dict = {}
    matched = 0
    for idx, raw in enumerate(header):
        key = raw.strip().strip('"').lower()
        canon = _FIELD_ALIASES.get(key)
        if canon:
            matched += 1
            # Prefer first occurrence of a canonical field.
            mapping.setdefault(canon, idx)
    if matched >= 2:
        return mapping
    return None


def _row_to_packet_mapped(row: list, mapping: dict) -> Optional[Packet]:
    def get(name: str) -> str:
        idx = mapping.get(name)
        if idx is None or idx >= len(row):
            return ""
        return row[idx]

    src = get("src").strip()
    dst = get("dst").strip()
    if not src or not dst:
        return None
    # Coalesce protocol-specific port columns (tcp.* / udp.*) with any
    # generic srcport/dstport column; a given packet only populates one.
    sport = (
        _to_int(get("sport"))
        or _to_int(get("tcp_sport"))
        or _to_int(get("udp_sport"))
    )
    dport = (
        _to_int(get("dport"))
        or _to_int(get("tcp_dport"))
        or _to_int(get("udp_dport"))
    )
    return Packet(
        number=_to_int(get("number")),
        time=_to_float(get("time")),
        src=src,
        dst=dst,
        proto=(get("proto").strip() or "UNKNOWN").upper(),
        sport=sport,
        dport=dport,
        length=_to_int(get("length")) or 0,
    )


def _row_to_packet_positional(row: list) -> Optional[Packet]:
    cells = [c.strip() for c in row]
    if len(cells) < 5:
        return None
    field_vals = dict(zip(_POSITIONAL, cells))
    src = field_vals.get("src", "")
    dst = field_vals.get("dst", "")
    if not src or not dst:
        return None
    sport = _to_int(field_vals.get("tcp_sport", "")) or _to_int(
        field_vals.get("udp_sport", "")
    )
    dport = _to_int(field_vals.get("tcp_dport", "")) or _to_int(
        field_vals.get("udp_dport", "")
    )
    return Packet(
        number=_to_int(field_vals.get("number", "")),
        time=_to_float(field_vals.get("time", "")),
        src=src,
        dst=dst,
        proto=(field_vals.get("proto", "").strip() or "UNKNOWN").upper(),
        sport=sport,
        dport=dport,
        length=_to_int(field_vals.get("length", "")) or 0,
    )


def parse_export(text: str) -> tuple:
    """Parse a pcap text export into packets.

    Returns (packets, parse_errors).
    """
    dialect = _detect_dialect(text)
    delimiter = "\t" if dialect == "tab" else ","

    # Strip comment lines before feeding csv.
    cleaned_lines = [
        ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")
    ]
    if not cleaned_lines:
        return [], 0

    reader = list(csv.reader(io.StringIO("\n".join(cleaned_lines)), delimiter=delimiter))
    if not reader:
        return [], 0

    mapping = _map_header(reader[0])
    data_rows = reader[1:] if mapping is not None else reader

    packets: list = []
    errors = 0
    for row in data_rows:
        if not row or all(not c.strip() for c in row):
            continue
        try:
            if mapping is not None:
                pkt = _row_to_packet_mapped(row, mapping)
            else:
                pkt = _row_to_packet_positional(row)
        except Exception:
            pkt = None
        if pkt is None:
            errors += 1
            continue
        packets.append(pkt)
    return packets, errors


def _normalized_pair(a: str, b: str) -> tuple:
    """Order an endpoint pair deterministically for bidirectional talker stats."""
    return (a, b) if a <= b else (b, a)


def summarize(
    packets: Iterable[Packet],
    parse_errors: int = 0,
    top: int = 10,
) -> Summary:
    """Aggregate packets into flows, talkers, and protocol distribution."""
    if top < 0:
        raise ValueError("top must be >= 0")
    packets = list(packets)
    flows: dict = {}
    proto_packets: Counter = Counter()
    proto_bytes: Counter = Counter()
    talker_bytes: dict = defaultdict(int)
    talker_packets: dict = defaultdict(int)

    total_bytes = 0
    times: list = []

    for pkt in packets:
        total_bytes += pkt.length
        if pkt.time is not None:
            times.append(pkt.time)

        proto_packets[pkt.proto] += 1
        proto_bytes[pkt.proto] += pkt.length

        pair = _normalized_pair(pkt.src, pkt.dst)
        talker_bytes[pair] += pkt.length
        talker_packets[pair] += 1

        key = (pkt.src, pkt.dst, pkt.proto, pkt.sport, pkt.dport)
        flow = flows.get(key)
        if flow is None:
            flow = Flow(
                src=pkt.src,
                dst=pkt.dst,
                proto=pkt.proto,
                sport=pkt.sport,
                dport=pkt.dport,
            )
            flows[key] = flow
        flow.packets += 1
        flow.bytes += pkt.length
        if pkt.time is not None:
            if flow.first_time is None or pkt.time < flow.first_time:
                flow.first_time = pkt.time
            if flow.last_time is None or pkt.time > flow.last_time:
                flow.last_time = pkt.time

    flow_list = sorted(
        flows.values(), key=lambda f: (f.bytes, f.packets), reverse=True
    )

    talkers = []
    for pair, b in sorted(
        talker_bytes.items(), key=lambda kv: kv[1], reverse=True
    )[:top]:
        talkers.append(
            {
                "endpoints": list(pair),
                "packets": talker_packets[pair],
                "bytes": b,
            }
        )

    protocols = []
    for proto, count in proto_packets.most_common():
        pct = (count / len(packets) * 100.0) if packets else 0.0
        protocols.append(
            {
                "proto": proto,
                "packets": count,
                "bytes": proto_bytes[proto],
                "packets_pct": round(pct, 2),
            }
        )

    time_span = (max(times) - min(times)) if times else 0.0

    return Summary(
        packets=packets,
        flows=flow_list,
        talkers=talkers,
        protocols=protocols,
        total_packets=len(packets),
        total_bytes=total_bytes,
        parse_errors=parse_errors,
        time_span=time_span,
    )
