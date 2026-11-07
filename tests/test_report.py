"""
The HTML report (Phase 1, Step 2 and the redesign).

Scan data comes from the scanned devices, so it is attacker-controlled. These
tests check it can't break out of the report's <script> block and can't
trigger the template's placeholders.
"""

import json
from pathlib import Path

import pytest

import scanner_cli

HOSTILE_BANNER = "</script><script>alert(1)</script>"


@pytest.fixture
def make_report(tmp_path):
    def _make(results, meta=None):
        path = tmp_path / "report.html"
        scanner_cli.save_html(results, meta=meta or {}, path=str(path))
        return path.read_text(encoding="utf-8")
    return _make


def host(**overrides):
    base = {"host": "10.0.0.5", "mac": "", "vendor": "Unknown", "os": "Unknown",
            "device": "Unknown", "tcp_ports": [], "udp_ports": []}
    return {**base, **overrides}


def test_json_for_script_tag_hides_html_but_keeps_the_data():
    data = {"banner": HOSTILE_BANNER, "amp": "a & b"}

    encoded = scanner_cli.json_for_script_tag(data)

    assert "<" not in encoded and ">" not in encoded and "&" not in encoded
    assert json.loads(encoded) == data          # the browser gets the original text back


def test_banner_cannot_close_the_script_block(make_report):
    template = (Path(scanner_cli.APP_DIR) / "report_template.html").read_text(encoding="utf-8")
    results = [host(tcp_ports=[{"port": 21, "service": "FTP", "banner": HOSTILE_BANNER, "cves": []}])]

    html = make_report(results)

    # The only </script> tags are the template's own.
    assert html.count("</script>") == template.count("</script>")


def test_placeholder_text_in_scan_data_is_not_replaced(make_report):
    # A device could name itself "__SCAN_META__". With chained str.replace()
    # calls, the meta JSON would be pasted into the middle of the scan data.
    html = make_report([host(hostname="__SCAN_META__ and __FONT_FACES__")], meta={"target": "10.0.0.0/24"})

    assert "__SCAN_META__ and __FONT_FACES__" in html
    assert html.count('"target": "10.0.0.0/24"') == 1


def test_report_is_self_contained(make_report):
    html = make_report([host()])

    assert html.count("data:font/woff2;base64,") == len(scanner_cli.REPORT_FONTS)
    assert "fonts.googleapis.com" not in html
    assert "__FONT_FACES__" not in html and "__SCAN_DATA__" not in html
