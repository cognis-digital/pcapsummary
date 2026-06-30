"""Scenario 4 - Sysadmin / DevOps: a CI gate over captures.

A sysadmin wires ``pcapsummary`` into a pipeline that summarizes captures
pulled from the fleet. The contract is simple and scriptable: exit 0 when a
capture parses cleanly, exit 1 when it has parse errors or yields no packets.
This demo drives the real CLI ``main()`` in-process and checks the exit codes a
CI job would gate on - no network, no subprocess.

Data: demos/08-office-baseline (clean) + demos/07-malformed-ci (corrupted).
"""
import contextlib
import io

from _common import rule
from pcapsummary.cli import main as cli_main


def run(argv):
    """Invoke the real CLI, capturing its output, and return (exit_code)."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        rc = cli_main(argv)
    return rc, buf.getvalue()


def main() -> None:
    rule("CI GATE  -  exit codes a pipeline can trust")

    print("\n1) A clean business-hours capture should pass the gate:")
    rc, _ = run(["summarize", "demos/08-office-baseline/capture_export.txt",
                 "--format", "json"])
    print(f"     exit code = {rc}  -> {'PASS' if rc == 0 else 'FAIL'} (expected 0)")

    print("\n2) A corrupted export should fail the gate:")
    rc_bad, _ = run(["summarize", "demos/07-malformed-ci/capture_export.txt"])
    print(f"     exit code = {rc_bad}  -> "
          f"{'BLOCK' if rc_bad == 1 else 'unexpected'} (expected 1)")

    print("\n3) A missing file is a usage error, not a finding:")
    rc_missing, _ = run(["summarize", "demos/does-not-exist.txt"])
    print(f"     exit code = {rc_missing}  -> "
          f"{'usage error' if rc_missing == 2 else 'unexpected'} (expected 2)")

    ok = rc == 0 and rc_bad == 1 and rc_missing == 2
    print(f"\nVerdict: distinct 0/1/2 exit codes => you can gate CI on a capture "
          f"the way you gate on a failing test. ({'all expected' if ok else 'mismatch'})")


if __name__ == "__main__":
    main()
