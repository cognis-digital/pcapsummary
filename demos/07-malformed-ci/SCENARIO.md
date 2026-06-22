# Demo 07 — parse errors & CI exit-code gating

Exports get corrupted: a capture tool crashes mid-write, a log-shipper truncates
rows, or a field is missing on some frames. This demo shows how `pcapsummary`
**parses what it can, counts what it cannot, and signals failure via exit code**
so a pipeline can fail the build instead of silently summarizing garbage.

## The input

`capture_export.txt` has 7 data rows, three of which are unusable:

- Row 3 — empty `ip.src` **and** `ip.dst`
- Row 5 — a truncated line with no fields at all
- Row 6 — empty `ip.dst`

The four good rows parse normally.

## Run it

```
python -m pcapsummary summarize demos/07-malformed-ci/capture_export.txt
echo "exit code: $?"
```

## What to expect

- **Packets parsed: 4**, **Parse errors: 3** in the report header.
- The process exits **`1`** — the documented "findings" code (parse errors or
  empty input), distinct from `0` (clean) and `2` (usage/file IO error).

## Use it as a CI gate

```bash
pcapsummary summarize export.txt --format json > pcap.json
if [ $? -ne 0 ]; then
  echo "::error::pcap export had parse errors or was empty — investigate"
  exit 1
fi
```

Or gate strictly on a clean parse before downstream ingest:

```bash
pcapsummary summarize export.txt --format csv > flows.csv || {
  echo "refusing to ingest a partially-parsed export"; exit 1; }
```

## How to act

A non-zero exit means the export itself is suspect. Re-run the capture/export,
check disk space and the shipper, and confirm the column layout matches before
trusting the summary.

## Scope

Static analysis of an already-captured export. No live capture.
