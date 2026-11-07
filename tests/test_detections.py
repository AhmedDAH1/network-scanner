"""
The detections in detections/: every rule must fire on recorded NetScan
traffic and stay quiet on a benign baseline (see detections/TESTING.md).

Suricata tests run when the `suricata` binary is installed (CI installs it).
Sigma rules are converted by pySigma and executed with its SQLite backend on
log records built from the same captures.
"""

import json
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest
from scapy.all import TCP, rdpcap
from sigma.backends.elasticsearch import ESQLBackend, LuceneBackend
from sigma.backends.splunk import SplunkBackend
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection

DETECTIONS = Path(__file__).resolve().parent.parent / "detections"
SCAN = DETECTIONS / "tests" / "netscan_scan.pcap"
BENIGN = DETECTIONS / "tests" / "benign_baseline.pcap"
RULES = DETECTIONS / "suricata" / "netscan.rules"

sys.path.insert(0, str(DETECTIONS / "tests"))
from pcap_to_logs import logs_from_pcap  # noqa: E402

# ── The test data is what it claims to be ─────────────────────────

def test_benign_baseline_contains_the_false_positive_traps():
    # Without these, "no alerts on benign traffic" would prove little.
    packets = rdpcap(str(BENIGN))
    port20_syns = [p for p in packets if TCP in p and p[TCP].sport == 20 and p[TCP].flags == "S"]
    assert port20_syns, "expected active-FTP-style SYNs from port 20"
    states = {r["conn_state"] for r in logs_from_pcap(str(BENIGN)) if "conn_state" in r}
    assert "REJ" in states, "expected some rejected connections"


# ── Suricata ──────────────────────────────────────────────────────

SURICATA = shutil.which("suricata")
needs_suricata = pytest.mark.skipif(SURICATA is None, reason="Suricata is not installed (CI installs it)")


def suricata_alerts(pcap, log_dir):
    subprocess.run(  # noqa: S603 - fixed binary from PATH lookup above, fixed arguments
        [SURICATA, "-r", str(pcap), "-S", str(RULES), "-l", str(log_dir), "-k", "none"],
        check=True, capture_output=True,
    )
    events = (json.loads(line) for line in (log_dir / "eve.json").read_text().splitlines())
    return sorted(e["alert"]["signature_id"] for e in events if e.get("event_type") == "alert")


@needs_suricata
def test_suricata_rules_load_cleanly(tmp_path):
    result = subprocess.run(  # noqa: S603
        [SURICATA, "-T", "-S", str(RULES), "-l", str(tmp_path)], capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr[-2000:]


@needs_suricata
def test_suricata_rules_fire_on_netscan_traffic(tmp_path):
    # One alert per rule: the fingerprint rule is limited to one per source per minute.
    assert suricata_alerts(SCAN, tmp_path) == [1000001, 1000002]


@needs_suricata
def test_suricata_rules_stay_quiet_on_benign_traffic(tmp_path):
    assert suricata_alerts(BENIGN, tmp_path) == []


# ── Sigma ─────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def sigma_rules():
    return SigmaCollection.load_ruleset([str(p) for p in sorted((DETECTIONS / "sigma").glob("*.yml"))])


@pytest.fixture(scope="module")
def sql(sigma_rules):
    queries = sqliteBackend().convert(sigma_rules)
    return {
        "user_agent": next(q for q in queries if "cs-user-agent" in q),
        "port_scan": next(q for q in queries if "id.resp_p" in q),
    }


def matches(query, records):
    columns = sorted({key for record in records for key in record})
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE logs (" + ", ".join(f'"{c}"' for c in columns) + ")")
    db.executemany(
        f"INSERT INTO logs VALUES ({', '.join('?' * len(columns))})",  # noqa: S608 - only placeholders
        [[record.get(c) for c in columns] for record in records],
    )
    return db.execute(query).fetchall()


def test_sigma_rules_convert_for_splunk_and_elastic(sigma_rules):
    assert len(SplunkBackend().convert(sigma_rules)) == 2       # user agent + port scan correlation
    assert len(ESQLBackend().convert(sigma_rules)) == 2
    web_rule = SigmaCollection([r for r in sigma_rules.rules if r.title.startswith("NetScan")])
    assert LuceneBackend().convert(web_rule) == ['cs-user-agent:netscan\\/*']


@pytest.mark.parametrize(("pcap", "rule", "should_fire"), [
    (SCAN, "user_agent", True),
    (SCAN, "port_scan", True),
    (BENIGN, "user_agent", False),
    (BENIGN, "port_scan", False),
], ids=["user-agent fires on scan", "port-scan fires on scan",
        "user-agent quiet on benign", "port-scan quiet on benign"])
def test_sigma_rules_on_recorded_traffic(sql, pcap, rule, should_fire):
    assert bool(matches(sql[rule], logs_from_pcap(str(pcap)))) is should_fire


def rejected_connections(distinct_ports):
    return [{"timestamp": f"2026-11-07T12:00:{i:02d}.000000Z", "proto": "tcp", "conn_state": "REJ",
             "id.orig_h": "10.0.0.5", "id.orig_p": 40000 + i, "id.resp_h": "10.0.0.9", "id.resp_p": 1000 + i}
            for i in range(distinct_ports)]


@pytest.mark.parametrize(("ports", "should_fire"), [(24, False), (25, True)])
def test_port_scan_threshold_is_25_distinct_ports(sql, ports, should_fire):
    assert bool(matches(sql["port_scan"], rejected_connections(ports))) is should_fire


def test_many_connections_to_one_port_are_not_a_port_scan(sql):
    # A client retrying one service many times is not scanning.
    retries = [dict(r, **{"id.resp_p": 443}) for r in rejected_connections(60)]
    assert matches(sql["port_scan"], retries) == []
