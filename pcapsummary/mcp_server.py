"""PCAPSUMMARY MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from pcapsummary.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-pcapsummary[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-pcapsummary[mcp]'")
        return 1
    app = FastMCP("pcapsummary")

    @app.tool()
    def pcapsummary_scan(target: str) -> str:
        """Summarize flows/talkers/protocols from a pcap text export. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
