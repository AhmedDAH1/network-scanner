"""
Web dashboard security (Phase 1, Step 3 and the redesign).

These tests make sure the protections can't be removed by accident:
the CSRF / DNS-rebinding guard, the security headers and CSP, demo mode,
one scan at a time, and the deleted /history/save endpoint.
"""

import re

import pytest

import web_app

LOCAL = "http://localhost:8000"
# An invalid target: when a request is allowed, the server answers with a
# validation error instead of starting a scan, so no scan ever runs here.
STREAM = "/scan/stream?target=not-an-ip"


# ── CSRF and DNS rebinding ────────────────────────────────────────

ALLOWED = {
    "curl (no browser headers)":  ({}, LOCAL),
    "our own page":               ({"Sec-Fetch-Site": "same-origin"}, LOCAL),
    "URL typed in address bar":   ({"Sec-Fetch-Site": "none"}, "http://127.0.0.1:8000"),
    "matching Origin header":     ({"Origin": LOCAL}, LOCAL),
}

BLOCKED = {
    "another website":            ({"Sec-Fetch-Site": "cross-site"}, LOCAL),
    "a sibling site":             ({"Sec-Fetch-Site": "same-site"}, LOCAL),
    "foreign Origin (old browser)": ({"Origin": "https://evil.example"}, LOCAL),
    "Origin null (sandboxed page)": ({"Origin": "null"}, LOCAL),
    "DNS rebinding (attacker Host)": ({"Sec-Fetch-Site": "same-origin"}, "http://rebind.evil.example:8000"),
}


@pytest.mark.parametrize(("headers", "base_url"), ALLOWED.values(), ids=ALLOWED.keys())
def test_legitimate_requests_are_allowed(client, no_scanner, headers, base_url):
    assert client.get(STREAM, headers=headers, base_url=base_url).status_code == 200
    assert client.post("/scan/stop", headers=headers, base_url=base_url).status_code == 200


@pytest.mark.parametrize(("headers", "base_url"), BLOCKED.values(), ids=BLOCKED.keys())
def test_cross_origin_requests_are_refused(client, no_scanner, headers, base_url):
    assert client.get(STREAM, headers=headers, base_url=base_url).status_code == 403
    assert client.post("/scan/stop", headers=headers, base_url=base_url).status_code == 403


# ── Input handling ────────────────────────────────────────────────

def test_invalid_input_is_reported_and_never_reaches_the_scanner(client, no_scanner):
    response = client.get("/scan/stream?target=10.0.0.1;id", base_url=LOCAL)

    assert response.mimetype == "text/event-stream"
    assert "Invalid target IP address" in response.get_data(as_text=True)


def test_only_one_scan_runs_at_a_time(client, no_scanner):
    web_app._scan_lock.acquire()          # pretend a scan is already running
    try:
        body = client.get("/scan/stream?target=10.0.0.1&ports=80", base_url=LOCAL).get_data(as_text=True)
    finally:
        web_app._scan_lock.release()

    assert "A scan is already running." in body


def test_demo_mode_refuses_to_scan(client, no_scanner, monkeypatch):
    monkeypatch.setattr(web_app, "DEMO_MODE", True)

    assert client.get("/scan/stream?target=10.0.0.1", base_url=LOCAL).status_code == 403
    assert client.post("/scan/stop", base_url=LOCAL).status_code == 403


def test_history_can_no_longer_be_written_by_the_browser(client):
    # Anyone could write fake history through this endpoint; it was deleted.
    assert client.post("/history/save", json={"results": []}).status_code == 404


# ── Security headers ──────────────────────────────────────────────

@pytest.mark.parametrize("path", ["/", "/history", "/static/css/app.css", "/favicon.ico"])
def test_every_response_has_security_headers(client, data_dir, path):
    headers = client.get(path).headers

    csp = headers["Content-Security-Policy"]
    assert "script-src 'self'" in csp
    assert "style-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "unsafe-inline" not in csp
    assert "unsafe-eval" not in csp
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"


def test_page_has_no_inline_code_the_csp_would_block(client):
    # The strict CSP only works if the page itself has no inline scripts,
    # event handlers or style attributes.
    html = client.get("/").get_data(as_text=True)

    scripts = re.findall(r"<script\b[^>]*>", html)
    assert scripts, "expected script tags"
    assert all('src="' in tag for tag in scripts), "inline <script> found"
    assert not re.search(r"\son[a-z]+\s*=", html), "inline event handler found"
    assert not re.search(r"\sstyle\s*=", html), "inline style attribute found"


def test_page_loads_nothing_from_other_servers(client):
    # Fonts and scripts are bundled: the page must work offline and in China.
    html = client.get("/").get_data(as_text=True)
    assert not re.search(r'(src|href)="https?://(?!github\.com/AhmedDAH1)', html)


def test_favicon_is_served(client):
    response = client.get("/favicon.ico")
    assert response.status_code == 200
    assert response.mimetype == "image/vnd.microsoft.icon"
