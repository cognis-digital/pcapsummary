"""Shared helpers for the runnable demo scenarios.

Every scenario in this folder loads one of the bundled, offline capture
exports (the same ``demos/NN-*/capture_export.txt`` fixtures the test suite
asserts against), runs the *real* ``pcapsummary`` API over it, and narrates
the result for a specific audience. No live capture, no network, no fabricated
output — what the demos print is what the tool actually computes.
"""
from __future__ import annotations

import os
import sys

# Allow `python demos/NN_name.py` (or `python -m`) to import the package and
# the sibling demo modules from anywhere.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pcapsummary.core import parse_export, summarize, Summary  # noqa: E402

DEMOS_DIR = os.path.dirname(os.path.abspath(__file__))


def load_summary(fixture: str, top: int = 10, filename: str = "capture_export.txt") -> Summary:
    """Parse + summarize a bundled fixture export and return the Summary.

    ``fixture`` is a folder name under ``demos/`` such as ``"02-port-scan"``.
    This is exactly the path the CLI and tests exercise — same data, same API.
    """
    path = os.path.join(DEMOS_DIR, fixture, filename)
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    packets, errors = parse_export(text)
    return summarize(packets, parse_errors=errors, top=top)


def rule(title: str) -> None:
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def overview(summary: Summary) -> None:
    """Print the headline numbers every analyst checks first."""
    print(
        f"  {summary.total_packets} packets / {summary.total_bytes} bytes / "
        f"{len(summary.flows)} flows / span {round(summary.time_span, 1)}s / "
        f"{summary.parse_errors} parse error(s)"
    )


def top_protocol(summary: Summary):
    return summary.protocols[0] if summary.protocols else None
