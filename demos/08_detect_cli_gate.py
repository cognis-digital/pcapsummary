"""Scenario 8 - DevOps: gating CI on the `detect` exit code.

The ``detect`` subcommand has a scriptable contract: exit 1 when any detector
fires, exit 0 on a clean capture, exit 2 on a usage/empty error. This demo
drives the real CLI ``main()`` in-process over a malicious capture (blocked)
and a clean baseline (allowed) — the same way a pipeline would gate a build.

Data: demos/02-port-scan (malicious) + demos/08-office-baseline (clean).
"""
import contextlib
import io

from _common import rule
from pcapsummary.cli import main as cli_main


def run(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        rc = cli_main(argv)
    return rc, buf.getvalue()


def main() -> None:
    rule("DETECT CI GATE  -  block the build when a detector fires")

    print("\n1) A capture with a port scan should trip the gate:")
    rc_bad, _ = run(["detect", "demos/02-port-scan/capture_export.txt"])
    print(f"     exit code = {rc_bad}  -> {'BLOCK' if rc_bad == 1 else 'unexpected'} (expected 1)")

    print("\n2) A clean office baseline should pass:")
    rc_ok, _ = run(["detect", "demos/08-office-baseline/capture_export.txt"])
    print(f"     exit code = {rc_ok}  -> {'PASS' if rc_ok == 0 else 'unexpected'} (expected 0)")

    print("\n3) A missing file is a usage error, not a clean pass:")
    rc_missing, _ = run(["detect", "demos/nope.txt"])
    print(f"     exit code = {rc_missing}  -> {'usage error' if rc_missing == 2 else 'unexpected'} (expected 2)")

    ok = rc_bad == 1 and rc_ok == 0 and rc_missing == 2
    print(
        f"\nVerdict: distinct 1/0/2 exit codes let a pipeline fail on detections "
        f"and only on detections. ({'all expected' if ok else 'mismatch'})"
    )


if __name__ == "__main__":
    main()
