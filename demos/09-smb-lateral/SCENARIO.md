# Demo 09 — SMB horizontal sweep (lateral-movement shape)

After an endpoint alert on `10.20.0.50`, the IR team wants to know whether that
host started reaching out to its neighbors on SMB (`tcp/445`) — the classic
lateral-movement / share-enumeration pattern. They exported the segment's
`tcp.port==445` frames to text.

## How the export was produced

```
tshark -r segment.pcap -Y "tcp.port==445" -T fields -E separator=, -E header=y \
    -e frame.number -e frame.time_relative \
    -e ip.src -e ip.dst -e _ws.col.Protocol \
    -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport \
    -e frame.len > capture_export.txt
```

`10.20.0.50` opens an SMB2 session to **six different internal hosts**
(`10.20.0.11`–`.16`) in under a second, each with the same connect-then-SMB2
3-packet shape. A single benign SMB file read (`10.20.0.60 -> .11`) is included
for contrast.

## Run it

```
python -m pcapsummary summarize demos/09-smb-lateral/capture_export.txt
python -m pcapsummary summarize demos/09-smb-lateral/capture_export.txt --format csv
```

## What to expect

- The **talker table fans out**: `10.20.0.50` pairs with `.11` through `.16`,
  each a small, near-identical 3-packet / ~544-byte exchange.
- One source touching many internal peers on `445` in a tight window — a
  one-to-many SMB pattern — is the lateral-movement signal. Contrast with the
  benign `.60 <-> .11` pair which moves real data (one peer, larger transfer).
- Exits `0`; the finding is the fan-out topology, not a parse error.

## How to act

Confirm whether `10.20.0.50` has a legitimate reason to enumerate shares (backup
agent, admin tooling). If not, treat as lateral movement: review the SMB session
setups for the account used, check for follow-on writes (e.g. service/scheduled-
task creation), and contain the source.

## Scope

Static analysis of an authorized capture for IR. No live capture.
