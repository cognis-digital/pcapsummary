"""Run every runnable demo scenario end to end.

    python demos/run_all.py

Each scenario loads a bundled offline capture export, runs the real
``pcapsummary`` API/CLI over it, and narrates the result. Scenarios are
independent and can be run on their own. Exits 0 when all complete.
"""
import importlib
import os
import sys

DEMOS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(DEMOS_DIR)
sys.path.insert(0, DEMOS_DIR)
sys.path.insert(0, REPO_ROOT)
# The CI-gate demo passes relative `demos/...` paths to the CLI, so run from root.
os.chdir(REPO_ROOT)

SCENARIOS = [
    "01_soc_triage",
    "02_threat_hunter_scan",
    "03_ir_beacon_and_exfil",
    "04_sysadmin_ci_gate",
    "05_dns_tunnel_and_lateral",
]


def main() -> int:
    for name in SCENARIOS:
        mod = importlib.import_module(name)
        mod.main()
    print("\n" + "=" * 70)
    print("  All demo scenarios completed.")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
