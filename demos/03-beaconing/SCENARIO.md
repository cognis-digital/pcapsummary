# Demo 03 — periodic C2-style beaconing

A workstation (`192.168.10.23`) keeps making short TLS connections to the same
external IP on a non-standard HTTPS port (`8443`) at a suspiciously regular
cadence. The analyst exported a 4-minute slice to text to confirm the
periodicity before pulling the host for forensics.

> The external IP `203.0.113.45` is from the **RFC 5737 TEST-NET-3
> documentation range** (`203.0.113.0/24`) — a deliberately non-routable
> placeholder, not a real C2. The *pattern*, not the address, is the lesson.

## How the export was produced

```
tshark -r host-egress.pcap -Y "ip.dst==203.0.113.45 || dns" -T fields \
    -E separator=, -E header=y \
    -e frame.number -e frame.time_relative \
    -e ip.src -e ip.dst -e _ws.col.Protocol \
    -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport \
    -e frame.len > capture_export.txt
```

The capture shows **five near-identical TLS exchanges to `203.0.113.45:8443`,
spaced ~60 seconds apart** (relative times 0, 60, 120, 180, 240), each with the
same byte profile (66/66/180/140) and a freshly rotated ephemeral source port.
A single benign DNS lookup is mixed in.

## Run it

```
python -m pcapsummary summarize demos/03-beaconing/capture_export.txt
python -m pcapsummary summarize demos/03-beaconing/capture_export.txt --format json | jq '.talkers'
```

## What to expect

- **Top talker:** `192.168.10.23 <-> 203.0.113.45` (20 of 22 packets).
- The flow list shows **many separate, byte-for-byte uniform flows** to the same
  `dst:dport` — low jitter, low data volume, high regularity. Uniform tiny flows
  repeating on a fixed interval to one external endpoint is the classic beacon
  fingerprint (low variance in size *and* timing).
- `time_span` of ~240 s across 5 connection bursts implies a ~60 s callback
  interval.

## How to act

Pivot on `203.0.113.45`: reputation/threat-intel lookup, check whether the
destination resolves from a recently-registered domain, and review the host's
process/parent for the beaconing binary. The fixed interval + uniform size is
the actionable signal.

## Scope

Static analysis of an authorized egress capture. No live capture, no lookups
performed by the tool itself.
