"""
Send Suricata alerts to SOAR-Lite as incidents.

Reads Suricata's eve.json, takes every alert event (by default only those
from the NetScan rules, SIDs 1000001-1000099) and posts each to SOAR-Lite's
SIEM webhook (https://github.com/AhmedDAH1/soar-lite), where it becomes an
incident with the scanner's address extracted as an IOC.

    export SOAR_WEBHOOK_SECRET=<SOAR-Lite's WEBHOOK_SECRET>
    suricata -r capture.pcap -S detections/suricata/netscan.rules -l out/ -k none
    python3 detections/forward_alerts.py out/eve.json --soar http://localhost:8000

SOAR-Lite only accepts signed requests:
    X-Webhook-Timestamp: <unix time>
    X-Webhook-Signature: sha256=<HMAC-SHA256 of "<timestamp>." + body>
"""

import argparse
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

SIEM_WEBHOOK_PATH = "/api/webhooks/siem"
NETSCAN_SIDS = range(1000001, 1000100)
# Suricata severity: 1 is the most severe (from the rule's classtype priority)
SEVERITY = {1: "high", 2: "medium", 3: "low"}
TIMEOUT_SECONDS = 10


def sign(body: bytes, secret: str, timestamp: int) -> str:
    """The X-Webhook-Signature value SOAR-Lite expects for this body."""
    message = f"{timestamp}.".encode() + body
    return "sha256=" + hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


def read_alerts(eve_path, all_sids=False):
    """Alert events from an eve.json file (one JSON object per line)."""
    alerts = []
    with open(eve_path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            event = json.loads(line)
            if event.get("event_type") != "alert":
                continue
            if all_sids or event["alert"]["signature_id"] in NETSCAN_SIDS:
                alerts.append(event)
    return alerts


def alert_payload(event):
    """A Suricata alert in SOAR-Lite's SIEM webhook format."""
    alert = event["alert"]
    src = f"{event.get('src_ip')}:{event.get('src_port')}"
    dest = f"{event.get('dest_ip')}:{event.get('dest_port')}"
    result = {
        "detector": "suricata",
        "signature_id": alert["signature_id"],
        "rev": alert.get("rev"),
        "category": alert.get("category"),
        "src_ip": event.get("src_ip"),
        "src_port": event.get("src_port"),
        "dest_ip": event.get("dest_ip"),
        "dest_port": event.get("dest_port"),
        "proto": event.get("proto"),
        "timestamp": event.get("timestamp"),
        "mitre_technique_id": (alert.get("metadata") or {}).get("mitre_technique_id"),
    }
    if "http" in event:
        result["http_user_agent"] = event["http"].get("http_user_agent")
    return {
        "search_name": alert["signature"],
        "description": f"Suricata sid {alert['signature_id']}: {src} -> {dest} ({event.get('proto')})",
        "severity": SEVERITY.get(alert.get("severity"), "medium"),
        "result": result,
    }


def forward(event, base_url, secret):
    """Send one alert. Returns (accepted, message); network errors are reported, not raised."""
    url = base_url.rstrip("/") + SIEM_WEBHOOK_PATH
    body = json.dumps(alert_payload(event)).encode()
    timestamp = int(time.time())
    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Timestamp": str(timestamp),
        "X-Webhook-Signature": sign(body, secret, timestamp),
    }
    if urlparse(url).scheme not in ("http", "https"):
        raise ValueError(f"not an http(s) URL: {base_url!r}")
    # S310: the scheme is checked above, so file:// and similar can't be opened
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
            reply = json.load(response)
    except urllib.error.HTTPError as e:
        return False, f"refused: HTTP {e.code} {e.read()[:200].decode(errors='replace')}"
    except (urllib.error.URLError, OSError) as e:
        return False, f"could not reach SOAR-Lite at {url} ({e.__class__.__name__})"
    return True, f"incident #{reply.get('incident_id')}"


def main(argv=None):
    parser = argparse.ArgumentParser(description="Send Suricata alerts from eve.json to SOAR-Lite.")
    parser.add_argument("eve", help="Path to Suricata's eve.json")
    parser.add_argument("--soar", required=True, metavar="URL", help="SOAR-Lite URL, e.g. http://localhost:8000")
    parser.add_argument("--all-sids", action="store_true", help="Forward every alert, not only NetScan's rules")
    args = parser.parse_args(argv)

    parsed = urlparse(args.soar)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        sys.exit(f"--soar: not an http(s) URL: {args.soar!r}")
    secret = os.environ.get("SOAR_WEBHOOK_SECRET", "")
    if not secret:
        sys.exit("Set SOAR_WEBHOOK_SECRET to the WEBHOOK_SECRET configured in SOAR-Lite")

    alerts = read_alerts(args.eve, all_sids=args.all_sids)
    accepted = 0
    for event in alerts:
        ok, message = forward(event, args.soar, secret)
        accepted += ok
        print(f"[{'+' if ok else '!'}] sid {event['alert']['signature_id']} from {event.get('src_ip')}: {message}")
    print(f"{accepted}/{len(alerts)} alert(s) accepted by SOAR-Lite")
    return 0 if accepted == len(alerts) else 1


if __name__ == "__main__":
    sys.exit(main())
