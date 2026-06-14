"""Native cognis-connect emit for pcapsummary — forward findings to any platform.

Maps pcapsummary's JSON output to the canonical `Finding` and forwards it via
`cognis-connect` (STIX/TAXII, MISP, Sigma, Splunk, Elastic, Slack/Discord, webhook, or a
`/v1` brief). cognis-connect is a soft dependency:
    pip install "git+https://github.com/cognis-digital/cognis-connect.git"

Usage:
    pcapsummary ... --format json | pcapsummary-emit --to stix
    pcapsummary-emit --to slack --url $WEBHOOK --dry-run < findings.json
"""

from __future__ import annotations

import argparse
import json
import sys

SOURCE = "pcapsummary"


def map_record(rec: dict) -> dict:
    """Tool-specific mapping (fleet-contributed, validated; safe-fallback)."""
    try:
        out = dict(rec)
        out.pop('flow_id', None)
        out.pop('src', None)
        out.pop('dst', None)
        out.pop('sport', None)
        out.pop('dport', None)
        out.pop('proto', None)
        out.pop('time', None)
        out.pop('packets', None)
        out.pop('bytes', None)
        out.pop('direction', None)
        out.pop('src_mac', None)
        out.pop('dst_mac', None)
        out.pop('vlan', None)
        out.pop('ip_version', None)
        out.pop('tcp_flags', None)
        out.pop('http_method', None)
        out.pop('http_status', None)
        out.pop('http_user_agent', None)
        out.pop('http_referer', None)
        out.pop('http_content_type', None)
        out.pop('http_content_length', None)
        out.pop('dns_query', None)
        out.pop('dns_answer', None)
        out.pop('smtp_from', None)
        out.pop('smtp_to', None)
        out.pop('smtp_subject', None)
        out.pop('smtp_date', None)
        out.pop('smtp_body', None)
        out.pop('smtp_header', None)
        out.pop('smtp_footer', None)
        out.pop('smtp_attachment', None)
        out.pop('smtp_mime_type', None)
        out.pop('smtp_encoding', None)
        out.pop('smtp_content_transfer_encoding', None)
        out.pop('smtp_content_disposition', None)
        out.pop('smtp_content_id', None)
        out.pop('smtp_content_location', None)
        out.pop('smtp_content_language', None)
        out.pop('smtp_content_description', None)
        out.pop('smtp_content_type', None)
        out.pop('smtp_content_transfer_encoding', None)
        out.pop('smtp_content_disposition', None)
        out.pop('smtp_content_id', None)
        out.pop('smtp_content_location', None)
        out.pop('smtp_content_language', None)
        out.pop('smtp_content_description', None)
        out.pop('smtp_content_type', None)
        return out
    except Exception:
        return rec


def _findings(text: str):
    from cognis_connect.findings import normalize, load
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return load(text, source=SOURCE)
    if isinstance(data, dict):
        data = data.get("findings") or data.get("results") or data.get("watchlist") or [data]
    return [normalize(map_record(r), source=SOURCE) if isinstance(r, dict) else r for r in data]


def emit_main(argv=None) -> int:
    p = argparse.ArgumentParser(prog=f"{SOURCE}-emit",
                                description=f"forward {SOURCE} JSON findings to a platform via cognis-connect")
    p.add_argument("--to", required=True,
                   choices=["stix", "taxii", "misp", "sigma", "splunk", "elastic",
                            "slack", "discord", "webhook", "brief", "findings"])
    p.add_argument("input", nargs="?", default="-", help="findings JSON file (default: stdin)")
    p.add_argument("--url", default=None)
    p.add_argument("--token", default=None)
    p.add_argument("--dry-run", action="store_true")
    a = p.parse_args(argv)
    try:
        from cognis_connect import misp, notify, sigma, siem, stix, edgemesh
    except ImportError:
        print("needs cognis-connect: pip install "
              "git+https://github.com/cognis-digital/cognis-connect.git", file=sys.stderr)
        return 1
    text = sys.stdin.read() if a.input == "-" else open(a.input, encoding="utf-8").read()
    fs = _findings(text)
    try:
        if a.to == "stix":
            print(json.dumps(stix.to_bundle(fs), indent=2))
        elif a.to == "taxii":
            print(json.dumps(stix.push_taxii(fs, a.url, token=a.token, dry_run=a.dry_run), indent=2))
        elif a.to == "misp":
            print(json.dumps(misp.push(fs, a.url, a.token or "", dry_run=a.dry_run) if a.url
                             else misp.to_event(fs), indent=2))
        elif a.to == "sigma":
            print(sigma.to_rules(fs))
        elif a.to == "splunk":
            print(json.dumps(siem.send_splunk(fs, a.url, a.token or "", dry_run=a.dry_run), indent=2))
        elif a.to == "elastic":
            print(json.dumps(siem.send_elastic(fs, a.url, token=a.token, dry_run=a.dry_run), indent=2))
        elif a.to == "slack":
            print(json.dumps(notify.send_slack(fs, a.url, dry_run=a.dry_run), indent=2))
        elif a.to == "discord":
            print(json.dumps(notify.send_discord(fs, a.url, dry_run=a.dry_run), indent=2))
        elif a.to == "webhook":
            print(json.dumps(siem.send_webhook(fs, a.url, token=a.token, dry_run=a.dry_run), indent=2))
        elif a.to == "brief":
            print(edgemesh.summarize(fs, base=a.url))
        elif a.to == "findings":
            from cognis_connect.findings import dump
            print(dump(fs))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(emit_main())
