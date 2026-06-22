# Demo 04 — outbound volume asymmetry (possible exfiltration)

A DLP alert fired on `192.168.5.40` pushing an unusually large amount of data
*outbound* over HTTPS to an external host. The analyst exported the surrounding
frames to characterize the upload-vs-download ratio.

> The external IP `198.51.100.77` is from the **RFC 5737 TEST-NET-2 range**
> (`198.51.100.0/24`) — a documentation placeholder, not a real destination.

## How the export was produced

```
tshark -r dlp-window.pcap -T fields -E separator=, -E header=y \
    -e frame.number -e frame.time_relative \
    -e ip.src -e ip.dst -e _ws.col.Protocol \
    -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport \
    -e frame.len > capture_export.txt
```

The capture shows a burst of full-MTU (1454-byte) TLS records flowing **from**
`192.168.5.40` **to** `198.51.100.77:443`, with only tiny ACK-sized frames
coming back — a strongly upload-skewed transfer. A normal, balanced browsing
session to `93.184.216.34` is included as a contrast.

## Run it

```
python -m pcapsummary summarize demos/04-exfil-volume/capture_export.txt --format csv
python -m pcapsummary summarize demos/04-exfil-volume/capture_export.txt --format json | jq '.flows[0]'
```

## What to expect

- The heaviest flow by far is `192.168.5.40:52000 -> 198.51.100.77:443`,
  ~**15 KB** in ~0.17 s, while the reverse flow carries only ~1.4 KB.
- That up/down byte asymmetry on a single outbound TLS flow is the
  actionable signal — compare it against the balanced `93.184.216.34` browsing
  flow in the same capture.
- Exits `0`; the finding is in the flow byte counts, not a parse error.

## How to act

Identify what `192.168.5.40` was uploading and to where. Resolve / reputation-
check the destination, confirm whether the egress is sanctioned (backup, SaaS
sync) or anomalous, and review host artifacts for the responsible process.

## Scope

Static analysis of an authorized capture for DLP/IR triage. No live capture.
