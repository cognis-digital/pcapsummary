# Demo 05 — DNS-heavy traffic (possible tunneling)

A host (`192.168.20.15`) is generating a steady stream of DNS queries that are
far larger than a normal lookup, all to the internal resolver, with no
corresponding web traffic. The analyst exported a one-second slice to see how
dominant DNS had become.

## How the export was produced

```
tshark -r resolver.pcap -T fields -E separator=, -E header=y \
    -e frame.number -e frame.time_relative \
    -e ip.src -e ip.dst -e _ws.col.Protocol \
    -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport \
    -e frame.len > capture_export.txt
```

`192.168.20.15` issues eight back-to-back DNS queries of **~310-324 bytes
each** (a normal A-record query is well under 100 bytes — see the benign
`192.168.20.20` lookup at 78 bytes for comparison). Oversized, high-rate DNS to
a single resolver with large request payloads is a hallmark of DNS tunneling /
exfiltration over the query name.

## Run it

```
python -m pcapsummary summarize demos/05-dns-tunnel/capture_export.txt
python -m pcapsummary summarize demos/05-dns-tunnel/capture_export.txt --format json | jq '.protocols'
```

## What to expect

- **DNS is ~90% of all packets** in the protocol distribution — anomalous for a
  single workstation in a one-second window.
- The `192.168.20.1 <-> 192.168.20.15` talker pair dominates by bytes.
- Per-query size (~310+ bytes) is many times a normal lookup; that size
  inflation on the *query* side is the actionable signal.

## How to act

Inspect the actual query names for `192.168.20.15` (long, high-entropy labels
under one parent domain indicate tunneling). Check the parent domain's
reputation and registration age, and review the host for the tunneling client.

## Scope

Static analysis of an authorized resolver capture. No live capture or lookups.
