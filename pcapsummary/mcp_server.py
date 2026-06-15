"""PCAPSUMMARY MCP server — exposes summarize() as an MCP tool for Cognis.Studio."""
from __future__ import annotations

import json

from pcapsummary.core import parse_export, summarize


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-pcapsummary[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        print("Install the MCP extra: pip install 'cognis-pcapsummary[mcp]'")
        return 1
    app = FastMCP("pcapsummary")

    @app.tool()
    def pcapsummary_scan(export_text: str) -> str:
        """Summarize flows/talkers/protocols from a pcap text export.

        Returns JSON findings.
        """
        packets, errors = parse_export(export_text)
        summary = summarize(packets, parse_errors=errors)
        return json.dumps(summary.as_dict(), indent=2, sort_keys=True)

    app.run()
    return 0
