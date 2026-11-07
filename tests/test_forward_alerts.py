"""
detections/forward_alerts.py: Suricata alerts sent to SOAR-Lite as incidents.
"""

import hashlib
import hmac
import json
import shutil
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

DETECTIONS = Path(__file__).resolve().parent.parent / "detections"
sys.path.insert(0, str(DETECTIONS))
import forward_alerts  # noqa: E402
from forward_alerts import alert_payload, read_alerts, sign  # noqa: E402

SECRET = "shared-secret"  # noqa: S105 - test value

SCAN_ALERT = {
    "timestamp": "2026-11-07T23:44:37.806599+0800", "event_type": "alert",
    "src_ip": "10.99.0.1", "src_port": 20, "dest_ip": "10.99.0.10", "dest_port": 1, "proto": "TCP",
    "alert": {"signature_id": 1000001, "rev": 1, "severity": 2, "category": "Attempted Information Leak",
              "signature": "NETSCAN Scapy-default TCP SYN probe (sport 20, seq 0, win 8192, no options)",
              "metadata": {"mitre_technique_id": ["T1046"]}},
}
OTHER_ALERT = dict(SCAN_ALERT, alert=dict(SCAN_ALERT["alert"], signature_id=2001219, signature="ET SCAN"))


class FakeSoarLite(BaseHTTPRequestHandler):
    received = []
    status = 201

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        FakeSoarLite.received.append((self.path, dict(self.headers), body))
        self.send_response(FakeSoarLite.status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"incident_id": len(FakeSoarLite.received)}).encode())

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def soar_url():
    server = HTTPServer(("127.0.0.1", 0), FakeSoarLite)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture(autouse=True)
def reset_fake():
    FakeSoarLite.received = []
    FakeSoarLite.status = 201


@pytest.fixture
def eve(tmp_path):
    path = tmp_path / "eve.json"
    lines = [{"event_type": "flow"}, SCAN_ALERT, OTHER_ALERT]
    path.write_text("\n".join(json.dumps(e) for e in lines) + "\n")
    return path


def test_payload_matches_soar_lite_siem_format():
    payload = alert_payload(SCAN_ALERT)
    assert payload["search_name"].startswith("NETSCAN Scapy-default TCP SYN probe")
    assert payload["severity"] == "medium"
    assert "10.99.0.1" in payload["description"]
    assert payload["result"]["signature_id"] == 1000001
    assert payload["result"]["mitre_technique_id"] == ["T1046"]


def test_only_netscan_alerts_by_default(eve):
    assert [a["alert"]["signature_id"] for a in read_alerts(eve)] == [1000001]
    assert len(read_alerts(eve, all_sids=True)) == 2


def test_signature_matches_soar_lite_scheme():
    body, ts = b'{"a": 1}', 1700000000
    expected = hmac.new(SECRET.encode(), b"1700000000." + body, hashlib.sha256).hexdigest()
    assert sign(body, SECRET, ts) == "sha256=" + expected


def test_sends_signed_requests(eve, soar_url, monkeypatch):
    monkeypatch.setenv("SOAR_WEBHOOK_SECRET", SECRET)
    assert forward_alerts.main([str(eve), "--soar", soar_url]) == 0
    path, headers, body = FakeSoarLite.received[0]
    assert path == "/api/webhooks/siem"
    ts = int(headers["X-Webhook-Timestamp"])
    assert abs(time.time() - ts) < 5
    assert headers["X-Webhook-Signature"] == sign(body, SECRET, ts)


def test_refused_alerts_give_a_failing_exit_code(eve, soar_url, monkeypatch):
    monkeypatch.setenv("SOAR_WEBHOOK_SECRET", SECRET)
    FakeSoarLite.status = 401
    assert forward_alerts.main([str(eve), "--soar", soar_url]) == 1


def test_unreachable_soar_lite_is_reported_not_raised():
    ok, message = forward_alerts.forward(SCAN_ALERT, "http://127.0.0.1:9", SECRET)
    assert not ok and "could not reach" in message


def test_secret_is_required(eve, soar_url, monkeypatch):
    monkeypatch.delenv("SOAR_WEBHOOK_SECRET", raising=False)
    with pytest.raises(SystemExit):
        forward_alerts.main([str(eve), "--soar", soar_url])


@pytest.mark.parametrize("url", ["ftp://host", "localhost:8000"])
def test_only_http_urls(eve, url, monkeypatch):
    monkeypatch.setenv("SOAR_WEBHOOK_SECRET", SECRET)
    with pytest.raises(SystemExit):
        forward_alerts.main([str(eve), "--soar", url])


SURICATA = shutil.which("suricata")


@pytest.mark.skipif(SURICATA is None, reason="Suricata is not installed (CI installs it)")
def test_recorded_scan_becomes_two_incidents(tmp_path, soar_url, monkeypatch):
    # End to end: the real NetScan capture, the real rules, the real eve.json.
    subprocess.run(  # noqa: S603 - fixed binary and arguments
        [SURICATA, "-r", str(DETECTIONS / "tests" / "netscan_scan.pcap"),
         "-S", str(DETECTIONS / "suricata" / "netscan.rules"), "-l", str(tmp_path), "-k", "none"],
        check=True, capture_output=True,
    )
    monkeypatch.setenv("SOAR_WEBHOOK_SECRET", SECRET)
    assert forward_alerts.main([str(tmp_path / "eve.json"), "--soar", soar_url]) == 0
    titles = sorted(json.loads(body)["search_name"] for _, _, body in FakeSoarLite.received)
    assert len(titles) == 2
    assert titles[0].startswith("NETSCAN HTTP service probe")
    assert titles[1].startswith("NETSCAN Scapy-default TCP SYN probe")
