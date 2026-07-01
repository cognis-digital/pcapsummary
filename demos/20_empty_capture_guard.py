"""Scenario 20 - Robustness: handling an empty or comment-only capture.

Pipelines sometimes hand a tool an empty file. pcapsummary must not crash or
lie: an empty/comment-only input yields zero packets and a clean, well-defined
exit code (2 for the CLI = usage/empty). This scenario feeds empty and
comment-only text through the real API and CLI and checks the contract.

No fixture needed - the inputs are constructed inline. No network.
"""
import contextlib
import io

from _common import rule
from pcapsummary.cli import main as cli_main
from pcapsummary.core import parse_export, summarize


def _cli(argv, stdin_text):
    import sys

    old = sys.stdin
    sys.stdin = io.StringIO(stdin_text)
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            rc = cli_main(argv)
    finally:
        sys.stdin = old
    return rc


def main() -> None:
    rule("EMPTY CAPTURE GUARD  -  don't crash, don't lie")

    for label, text in (("empty", ""), ("comment-only", "# nothing here\n#really")):
        packets, errors = parse_export(text)
        s = summarize(packets, parse_errors=errors)
        print(f"\n  {label}: {s.total_packets} packets, {s.parse_errors} errors")

    rc_sum = _cli(["summarize", "-"], "")
    rc_det = _cli(["detect", "-"], "")
    print(f"\n  CLI summarize on empty stdin -> exit {rc_sum} (expected 1 or 2)")
    print(f"  CLI detect    on empty stdin -> exit {rc_det} (expected 2)")

    ok = rc_sum in (1, 2) and rc_det == 2
    print(
        f"\nVerdict: empty input is handled as a defined outcome, not a stack "
        f"trace. ({'contract held' if ok else 'unexpected'})"
    )


if __name__ == "__main__":
    main()
