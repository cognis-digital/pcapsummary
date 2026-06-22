# Demo 02 — TCP port-scan fan-out

An IDS sensor flagged a burst of short TCP connection attempts from an internal
workstation (`10.0.0.66`) toward a server (`10.0.0.10`) inside a ~15 ms window.
The on-call analyst pulled the matching frames from the day's capture and
exported them to text to confirm whether this is a horizontal/vertical scan
before escalating.

## How the export was produced

```
tshark -r incident.pcap -Y "ip.addr==10.0.0.66" -T fields -E separator=, -E header=y \
    -e frame.number -e frame.time_relative \
    -e ip.src -e ip.dst -e _ws.col.Protocol \
    -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport \
    -e frame.len > capture_export.txt
```

`capture_export.txt` contains a single host probing **20 distinct destination
ports** (21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433,
3306, 3389, 5432, 5900, 8080) with tiny 58-byte SYN-sized frames, each with a
fresh ephemeral source port — the textbook shape of a vertical port scan. A
small amount of benign TLS traffic is mixed in.

## Run it

```
python -m pcapsummary summarize demos/02-port-scan/capture_export.txt
python -m pcapsummary summarize demos/02-port-scan/capture_export.txt --format csv
```

## What to expect

- **`10.0.0.66 <-> 10.0.0.10` is the top talker** by packets (24 frames).
- The CSV / flow view shows **~24 separate one-packet flows** to the same
  destination IP across many different `dport` values — many flows, almost no
  bytes each. That fan-out of single-packet flows to sequential well-known
  ports is the scan fingerprint.
- Note the asymmetry: only a few ports answer (22/80/443/445), consistent with a
  scanner enumerating which services are actually open.
- Exits `0` (all rows parsed); the *finding* lives in the shape of the flows,
  not in a parse error.

## How to act

Correlate the source against your asset inventory. If `10.0.0.66` is not an
authorized scanner (Nessus/OpenVAS/etc.), treat as recon: isolate the host,
check for follow-on connections to the open ports, and preserve the full pcap.

## Scope

Static, post-hoc analysis of an already-captured export for authorized
incident response. No live capture, no network connections.
