"""Scenario 16 - Automation: piping JSON output into a downstream tool.

pcapsummary's JSON is stable and self-describing, so it drops straight into a
script. This scenario runs the real CLI, captures its JSON, parses it back, and
computes a derived metric (bytes-per-packet) the way a downstream job would.

Data: demos/04-exfil-volume/capture_export.txt (offline fixture).
"""
import contextlib
import io
import json

from _common import rule
from pcapsummary.cli import main as cli_main


def main() -> None:
    rule("JSON PIPELINE  -  machine-readable output for automation")

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        cli_main(["summarize", "demos/04-exfil-volume/capture_export.txt",
                  "--format", "json"])
    data = json.loads(buf.getvalue())

    total = data["total_packets"]
    byts = data["total_bytes"]
    bpp = byts / max(total, 1)
    print(f"\n  Parsed JSON: {total} packets, {byts} bytes, {data['flow_count']} flows.")
    print(f"  Derived metric: {bpp:.1f} bytes/packet (large mean => bulk transfer).")

    heaviest = data["flows"][0]
    print(f"  Heaviest flow from JSON: {heaviest['src']} -> {heaviest['dst']} "
          f"({heaviest['bytes']} bytes).")

    print(
        "\nVerdict: valid, sorted JSON means pcapsummary composes into pipelines "
        "without scraping human text."
    )


if __name__ == "__main__":
    main()
