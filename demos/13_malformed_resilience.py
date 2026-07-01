"""Scenario 13 - Data engineer: resilience to a corrupted export.

Real exports get truncated and mangled. The parser must count bad rows without
crashing and still summarize the good ones. This scenario shows the corrupted
fixture yielding a nonzero parse-error count alongside valid packets, and the
CLI signalling that with exit code 1.

Data: demos/07-malformed-ci/capture_export.txt (offline fixture).
"""
import contextlib
import io

from _common import load_summary, overview, rule
from pcapsummary.cli import main as cli_main


def main() -> None:
    rule("MALFORMED RESILIENCE  -  count the bad rows, keep the good ones")
    summary = load_summary("07-malformed-ci")

    print("\nCapture overview:")
    overview(summary)
    print(
        f"\n  {summary.total_packets} good packets parsed, "
        f"{summary.parse_errors} malformed row(s) skipped."
    )

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        rc = cli_main(["summarize", "demos/07-malformed-ci/capture_export.txt"])

    print(f"\n  CLI exit code = {rc} (1 = findings/parse errors present)")
    print(
        "\nVerdict: bad input degrades gracefully - the tool reports what it "
        f"could not parse instead of aborting. ({'as expected' if rc == 1 else 'unexpected'})"
    )


if __name__ == "__main__":
    main()
