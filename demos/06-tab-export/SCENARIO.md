# Demo 06 — tab-separated export & the Wireshark column layout

Not every export is comma-separated. This demo uses the **tab-separated**
columns you get from Wireshark's *File → Export Packet Dissections → As CSV*
(which is really tab-delimited) or from a copied packet-list view:
`No. / Time / Source / Destination / Protocol / Length`. It proves the parser
auto-detects the delimiter and maps friendly column names — no `ip.src`-style
field strings required.

## How the export was produced

In Wireshark: select packets, **File → Export Packet Dissections → As CSV**, or
with tshark using friendly headers:

```
tshark -r lan.pcap -T tabs -e frame.number -e frame.time_relative \
    -e ip.src -e ip.dst -e _ws.col.Protocol -e frame.len > capture_export.tsv
```

The file mixes link-layer and L3 chatter you'd see on a quiet LAN segment: ARP,
ICMP echo, IGMP, IPv6 `ICMPv6` (note the `fe80::`/`ff02::` link-local
addresses), NBNS broadcast, and a short TCP exchange.

## Run it

```
python -m pcapsummary summarize demos/06-tab-export/capture_export.tsv
python -m pcapsummary summarize demos/06-tab-export/capture_export.tsv --format csv
```

## What to expect

- The parser **auto-detects tabs**, recognizes the `No./Source/Destination/...`
  header, and parses all 12 packets with **0 parse errors**.
- Protocol distribution spans ARP/ICMP/IGMP/ICMPv6/NBNS/TCP — a healthy mix of
  baseline LAN noise.
- IPv6 endpoints (`fe80::1`, `ff02::1`) appear correctly in talkers/flows.

## How to act

This is a baseline-familiarization demo: use it to confirm the tool ingests
your existing Wireshark CSV/TSV exports as-is. The takeaway is operational
(format compatibility), not a security finding.

## Scope

Static analysis of an already-captured export. No live capture.
