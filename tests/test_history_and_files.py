"""
Scan history, demo data and safe file writing (Phase 1, Step 4).
"""

import json
import os
from datetime import datetime

import pytest

import web_app
from scanner import fileutil

# ── History ───────────────────────────────────────────────────────

def test_history_is_saved_newest_first(data_dir):
    web_app.save_history({"ts": "first"})
    web_app.save_history({"ts": "second"})

    assert [e["ts"] for e in web_app.load_history()] == ["second", "first"]


def test_history_keeps_only_the_latest_scans(data_dir):
    for i in range(web_app.MAX_HISTORY + 5):
        web_app.save_history({"ts": i})

    history = web_app.load_history()
    assert len(history) == web_app.MAX_HISTORY
    assert history[0]["ts"] == web_app.MAX_HISTORY + 4


def test_damaged_history_is_moved_aside_not_overwritten(data_dir):
    damaged = '[{"ts": "2026-11-01", "results": ['
    (data_dir / "scan_history.json").write_text(damaged)

    assert web_app.load_history() == []

    backups = list(data_dir.glob("scan_history.json.corrupt-*"))
    assert len(backups) == 1
    assert backups[0].read_text() == damaged     # the old scans can be recovered


def test_history_that_is_not_a_list_is_ignored(data_dir):
    (data_dir / "scan_history.json").write_text('{"not": "a list"}')
    assert web_app.load_history() == []


# ── Demo data ─────────────────────────────────────────────────────
# Regression: the old demo seed used different field names than the scanner
# (timestamp/ip/ports), so the live demo showed "Invalid Date" and NaN CVEs.

def test_demo_seed_uses_the_scanners_real_format(data_dir, monkeypatch):
    monkeypatch.setattr(web_app, "DEMO_MODE", True)
    web_app.seed_demo_history()

    [entry] = web_app.load_history()
    datetime.fromisoformat(entry["ts"])                      # a real timestamp
    assert entry["results"], "sample scan has no hosts"
    for host in entry["results"]:
        assert {"host", "mac", "vendor", "os", "device", "tcp_ports", "udp_ports"} <= host.keys()
        for port in host["tcp_ports"]:
            assert isinstance(port["port"], int)
            for cve in port["cves"]:
                assert cve["id"].startswith("CVE-")
                assert cve["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


def test_demo_seed_does_not_overwrite_existing_history(data_dir, monkeypatch):
    monkeypatch.setattr(web_app, "DEMO_MODE", True)
    web_app.save_history({"ts": "real scan"})

    web_app.seed_demo_history()

    assert [e["ts"] for e in web_app.load_history()] == ["real scan"]


# ── Atomic writes ─────────────────────────────────────────────────

def test_write_json_atomic_writes_valid_json_and_cleans_up(tmp_path):
    target = tmp_path / "out.json"

    fileutil.write_json_atomic(str(target), {"hosts": [1, 2, 3]})

    assert json.loads(target.read_text()) == {"hosts": [1, 2, 3]}
    assert [p.name for p in tmp_path.iterdir()] == ["out.json"]   # no temp files left


def test_failed_write_leaves_the_old_file_intact(tmp_path):
    target = tmp_path / "out.json"
    target.write_text('{"old": true}')

    with pytest.raises(TypeError):
        fileutil.write_json_atomic(str(target), {"bad": {1, 2}})   # sets aren't JSON

    assert json.loads(target.read_text()) == {"old": True}
    assert [p.name for p in tmp_path.iterdir()] == ["out.json"]


# ── Files created under sudo go back to the real user ─────────────

@pytest.fixture
def chown_calls(monkeypatch):
    calls = []
    monkeypatch.setattr(os, "chown", lambda path, uid, gid: calls.append((path, uid, gid)))
    return calls


def test_files_created_under_sudo_are_given_back(monkeypatch, chown_calls):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "501")
    monkeypatch.setenv("SUDO_GID", "20")

    fileutil.give_to_invoking_user("data/report.html")

    assert chown_calls == [("data/report.html", 501, 20)]


def test_real_root_without_sudo_is_left_alone(monkeypatch, chown_calls):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("SUDO_GID", raising=False)

    fileutil.give_to_invoking_user("data/report.html")

    assert chown_calls == []


def test_normal_user_is_left_alone(monkeypatch, chown_calls):
    monkeypatch.setattr(os, "geteuid", lambda: 501)
    monkeypatch.setenv("SUDO_UID", "501")
    monkeypatch.setenv("SUDO_GID", "20")

    fileutil.give_to_invoking_user("data/report.html")

    assert chown_calls == []
