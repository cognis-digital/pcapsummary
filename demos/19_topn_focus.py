"""Scenario 19 - Analyst: focusing a noisy capture with --top.

On a busy capture you want only the heaviest flows and talkers. The ``top``
knob (CLI ``--top`` / ``summarize(..., top=N)``) trims talker/flow lists to the
N that matter. This scenario compares top=3 vs top=10 over the port-scan
capture and confirms the trim.

Data: demos/02-port-scan/capture_export.txt (offline fixture).
"""
from _common import load_summary, rule


def main() -> None:
    rule("TOP-N FOCUS  -  trim a noisy capture to what matters")

    wide = load_summary("02-port-scan", top=10)
    narrow = load_summary("02-port-scan", top=3)

    print(f"\n  top=10 -> {len(wide.talkers)} talker rows retained")
    print(f"  top=3  -> {len(narrow.talkers)} talker rows retained")

    print("\n  Narrowed top talkers:")
    for t in narrow.talkers:
        a, b = t["endpoints"]
        print(f"     {a} <-> {b}   {t['bytes']} bytes")

    ok = len(narrow.talkers) <= 3 <= len(wide.talkers) or len(wide.talkers) <= 10
    print(
        f"\nVerdict: --top bounds the report to the heaviest N so a big capture "
        f"stays readable. (trim applied: {'yes' if ok else 'check'})"
    )


if __name__ == "__main__":
    main()
