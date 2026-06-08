# Demo 01 — basic pcap triage

A defensive analyst has exported a short capture from an authorized host to a
text file using tshark, and wants to understand it at a glance: who talked to
whom, which protocols dominated, and which flows moved the most bytes — without
opening Wireshark.

## How the export was produced

```
tshark -r capture.pcap -T fields -E separator=, -E header=y \
    -e frame.number -e frame.time_relative \
    -e ip.src -e ip.dst -e _ws.col.Protocol \
    -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport \
    -e frame.len > capture_export.txt
```

`capture_export.txt` in this folder is a realistic 20-packet sample containing:

- A DNS lookup to the local resolver (`192.168.1.1`) and to `8.8.8.8`.
- A TLS 1.3 session from `192.168.1.50` to `93.184.216.34` (web traffic).
- An SSH session from `192.168.1.50` to an internal host `10.0.0.99`.
- mDNS and NBNS broadcast/multicast chatter.

## Run it

Human-readable table:

```
python -m pcapsummary summarize demos/01-basic/capture_export.txt
```

Machine-readable JSON (for piping into jq, SIEM ingest, or CI checks):

```
python -m pcapsummary summarize demos/01-basic/capture_export.txt --format json
```

Show only the top 3 talkers/flows:

```
python -m pcapsummary summarize demos/01-basic/capture_export.txt --top 3
```

## What to expect

- **Top talker** by bytes is `192.168.1.50 <-> 93.184.216.34` (the TLS session).
- **Protocol distribution** is dominated by TLSv1.3, with DNS/TCP/SSH/MDNS/NBNS
  making up the remainder.
- The tool exits `0` because every row parsed cleanly.

## Exit codes

- `0` — packets parsed cleanly, no problems
- `1` — findings: parse errors encountered, or input yielded no packets
- `2` — usage / file IO error

## Scope

This is analysis/triage of a **static, already-captured** export. The tool does
no live capture and makes no network connections — appropriate for authorized
incident-response and defensive review only.
