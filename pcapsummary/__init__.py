"""PCAPSUMMARY — summarize flows/talkers/protocols from a pcap text export.

Defensive / authorized-testing analysis only. Parses tshark-style text
exports (no live capture, no network access) and produces an at-a-glance
summary of conversations, top talkers, and protocol distribution.
"""

from .core import (
    Packet,
    Flow,
    parse_export,
    summarize,
    Summary,
)

TOOL_NAME = "pcapsummary"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Packet",
    "Flow",
    "parse_export",
    "summarize",
    "Summary",
    "TOOL_NAME",
    "TOOL_VERSION",
]
