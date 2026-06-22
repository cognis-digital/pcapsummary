# Demo 08 — healthy office-hours baseline

Before you can spot anomalies you need to know what *normal* looks like. This is
a short slice of an ordinary corporate LAN during business hours: a few
workstations doing DNS, HTTPS to well-known services, an internal SMB file
access, plus the usual broadcast/multicast housekeeping. **No finding here** —
that is the point.

The public destinations are real, documented service addresses:
`140.82.112.3` (GitHub), `142.250.80.46` (Google), `17.253.144.10` (Apple NTP).

## How the export was produced

```
tshark -r office-0900.pcap -T fields -E separator=, -E header=y \
    -e frame.number -e frame.time_relative \
    -e ip.src -e ip.dst -e _ws.col.Protocol \
    -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport \
    -e frame.len > capture_export.txt
```

## Run it

```
python -m pcapsummary summarize demos/08-office-baseline/capture_export.txt
python -m pcapsummary summarize demos/08-office-baseline/capture_export.txt --format json | jq '.protocols'
```

## What to expect

- A **balanced protocol mix** (TLSv1.3, TCP, DNS, SMB2, NBNS, MDNS, NTP) — no
  single protocol or talker dominates the way it does in the scan / beacon /
  tunnel demos.
- **Multiple distinct workstations** (`.101`–`.104`) each with short, balanced
  sessions to reputable destinations.
- Exits `0`. Use this as the reference profile to diff the suspicious demos
  against.

## How to act

Save a baseline like this per network segment. When a later capture shows one
protocol at 90% (DNS — Demo 05), one talker hoarding bytes (Demo 04), or a fan
of single-packet flows (Demo 02), the deviation from this baseline is the
signal.

## Scope

Static analysis of an authorized capture. No live capture.
