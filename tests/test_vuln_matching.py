"""
Version-aware CVE matching (2.1.0).

The old lookup attached CVEs to a port number: every port 53 "had" SIGRed,
every port 80 had the same Apache CVEs. These tests make sure a CVE is only
reported when the banner names the product and an affected version.
"""

import re
import socket
import threading

import pytest

from scanner import service_detection, vuln_scan
from scanner.banner_parser import clean_banner, http_server_header, identify_software
from scanner.vuln_scan import (
    KNOWN_VULNS,
    cpe_name,
    lookup_cves,
    parse_nvd_response,
    scan_vulnerabilities,
    version_key,
)

# ── Banner parsing ────────────────────────────────────────────────

@pytest.mark.parametrize(("service", "banner", "product", "version"), [
    ("SSH",   "SSH-2.0-OpenSSH_7.4p1 Raspbian-10+deb9u7",  "OpenSSH",      "7.4p1"),
    ("SSH",   "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13",     "OpenSSH",      "9.6p1"),
    ("SSH",   "SSH-2.0-dropbear_2019.78",                   "Dropbear SSH", "2019.78"),
    ("FTP",   "220 (vsFTPd 2.3.4)",                         "vsftpd",       "2.3.4"),
    ("FTP",   "220 ProFTPD 1.3.5a Server (Debian)",         "ProFTPD",      "1.3.5a"),
    ("HTTP",  "Apache/2.4.49 (Unix)",                       "Apache httpd", "2.4.49"),
    ("HTTP",  "nginx/1.18.0 (Ubuntu)",                      "nginx",        "1.18.0"),
    ("HTTP",  "Microsoft-IIS/10.0",                         "Microsoft IIS", "10.0"),
    ("SMTP",  "220 mx.example.com ESMTP Exim 4.89 Mon",     "Exim",         "4.89"),
    ("MySQL", "5.0.51a-3ubuntu5",                           "MySQL",        "5.0.51a"),
    ("MySQL", "5.5.5-10.3.23-MariaDB-0+deb10u1",            "MariaDB",      "10.3.23"),
    ("HTTP",  "Apache",                                     "Apache httpd", None),   # name, no version
    ("HTTP",  "nginx",                                      "nginx",        None),
    ("DNS",   None,                                         None,           None),
    ("HTTP",  "HTTP/1.1 200 OK",                            None,           None),
])
def test_banners_are_identified(service, banner, product, version):
    assert identify_software(service, banner) == {"product": product, "version": version}


def test_a_dotted_number_is_only_trusted_as_mysql_on_the_mysql_port():
    assert identify_software("Unknown", "build 5.7.33 ready") == {"product": None, "version": None}


def test_banners_cannot_carry_terminal_escape_codes():
    # A hostile service could clear or rewrite the analyst's terminal.
    cleaned = clean_banner(b"220 ok\x1b[2J\x1b[31mfake\x07\r\n\x00")
    assert cleaned == "220 ok [2J [31mfake"
    assert not re.search(r"[^\x20-\x7e]", cleaned)


def test_banners_are_capped():
    assert len(clean_banner("A" * 5000)) == 200
    assert clean_banner(b"   \r\n ") is None
    assert clean_banner(None) is None


def test_http_server_header_is_read_from_headers_only():
    response = (b"HTTP/1.1 200 OK\r\nDate: today\r\nSERVER: Apache/2.4.49 (Unix)\r\n\r\n"
                b"Server: nginx/9.9 (in the body, must be ignored)")
    assert http_server_header(response) == "Apache/2.4.49 (Unix)"


def test_http_without_server_header_falls_back_to_status_line():
    assert http_server_header(b"HTTP/1.0 302 Found\r\nLocation: /\r\n\r\n") == "HTTP/1.0 302 Found"
    assert http_server_header(b"not http at all") is None


# ── Versions ──────────────────────────────────────────────────────

@pytest.mark.parametrize(("older", "newer"), [
    ("7.4p1", "7.8"),
    ("8.5p1", "9.6p1"),
    ("9.7p1", "9.8p1"),
    ("2.4.49", "2.4.50"),
    ("2.4.9", "2.4.10"),          # numeric, not alphabetical
    ("1.3.5", "1.3.5a"),
    ("1.3.5a", "1.3.5b"),
    ("1.3.5rc1", "1.3.5"),        # release candidates come first
])
def test_versions_sort_correctly(older, newer):
    assert version_key(older) < version_key(newer)


# ── Matching ──────────────────────────────────────────────────────

def ids(product, version):
    return {c["id"] for c in lookup_cves(product, version, use_api=False)[0]}


@pytest.mark.parametrize(("product", "version", "expected"), [
    # OpenSSH: three CVEs with different ranges
    ("OpenSSH", "3.9p1", {"CVE-2024-6387", "CVE-2018-15473"}),    # old regreSSHion range
    ("OpenSSH", "4.7p1", {"CVE-2018-15473"}),                     # too old for Terrapin
    ("OpenSSH", "7.4p1", {"CVE-2023-48795", "CVE-2018-15473"}),
    ("OpenSSH", "7.7p1", {"CVE-2023-48795", "CVE-2018-15473"}),   # last affected by 15473
    ("OpenSSH", "7.8p1", {"CVE-2023-48795"}),
    ("OpenSSH", "8.5p1", {"CVE-2023-48795", "CVE-2024-6387"}),    # regreSSHion returns
    ("OpenSSH", "9.6p1", {"CVE-2024-6387"}),                      # Terrapin fixed in 9.6
    ("OpenSSH", "9.8p1", set()),
    # Apache 2.4.49 / 2.4.50
    ("Apache httpd", "2.4.48", set()),
    ("Apache httpd", "2.4.49", {"CVE-2021-41773", "CVE-2021-42013"}),
    ("Apache httpd", "2.4.50", {"CVE-2021-42013"}),
    ("Apache httpd", "2.4.51", set()),
    # exact versions
    ("vsftpd", "2.3.4", {"CVE-2011-2523"}),
    ("vsftpd", "3.0.3", set()),
    ("ProFTPD", "1.3.5", {"CVE-2015-3306"}),
    ("ProFTPD", "1.3.5a", set()),
    ("Exim", "4.86", set()),
    ("Exim", "4.91", {"CVE-2019-10149"}),
    ("Exim", "4.92", set()),
    ("lighttpd", "1.4.59", set()),                                # not in the offline list
])
def test_cves_match_only_affected_versions(product, version, expected):
    assert ids(product, version) == expected


def test_most_severe_cve_comes_first():
    cves, _ = lookup_cves("OpenSSH", "3.9p1", use_api=False)
    assert [c["severity"] for c in cves] == ["HIGH", "MEDIUM"]


def test_a_port_without_a_version_gets_no_cves():
    # Regression: port 53 used to get SIGRed (a Windows DNS server bug) on
    # every device, including routers, purely because of the port number.
    hosts = [{"host": "10.0.0.1", "tcp_ports": [
        {"port": 53, "service": "DNS", "banner": None, "product": None, "version": None},
        {"port": 80, "service": "HTTP", "banner": "nginx", "product": "nginx", "version": None},
        {"port": 3389, "service": "RDP", "banner": None, "product": None, "version": None},
    ]}]

    scan_vulnerabilities(hosts, use_api=False)

    for port in hosts[0]["tcp_ports"]:
        assert port["cves"] == []
        assert port["vuln_source"] == "unidentified"


def test_identified_ports_record_what_was_checked():
    hosts = [{"host": "10.0.0.42", "tcp_ports": [
        {"port": 21, "service": "FTP", "banner": "220 (vsFTPd 2.3.4)", "product": "vsftpd", "version": "2.3.4"},
    ]}]
    scan_vulnerabilities(hosts, use_api=False)
    [port] = hosts[0]["tcp_ports"]
    assert port["vuln_source"] == "offline"
    assert [c["id"] for c in port["cves"]] == ["CVE-2011-2523"]


def test_offline_list_is_well_formed():
    for product, entries in KNOWN_VULNS.items():
        for entry in entries:
            assert re.fullmatch(r"CVE-\d{4}-\d{4,7}", entry["id"]), entry
            assert entry["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}, entry
            assert entry.get("ranges") or entry.get("versions"), f"{entry['id']} has no affected versions"
            for first, fixed in entry.get("ranges", []):
                assert first is None or version_key(first) < version_key(fixed), entry
        assert product in vuln_scan.PRODUCT_CPE


# ── NVD (online) ──────────────────────────────────────────────────

@pytest.mark.parametrize(("product", "version", "expected"), [
    ("OpenSSH", "7.4p1", "cpe:2.3:a:openbsd:openssh:7.4:p1:*:*:*:*:*:*"),
    ("ProFTPD", "1.3.5a", "cpe:2.3:a:proftpd:proftpd:1.3.5:a:*:*:*:*:*:*"),
    ("Apache httpd", "2.4.49", "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"),
    ("Unknown Thing", "1.0", None),
    ("OpenSSH", "7.4:*:evil", None),          # banner data can't inject CPE fields
    ("OpenSSH", None, None),
])
def test_cpe_names(product, version, expected):
    assert cpe_name(product, version) == expected


def nvd_item(cve_id, metrics, desc="A bug."):
    return {"cve": {"id": cve_id, "descriptions": [{"lang": "en", "value": desc}], "metrics": metrics}}


def v31(severity):
    return {"cvssMetricV31": [{"cvssData": {"baseSeverity": severity}}]}


def test_nvd_response_is_parsed_and_ranked():
    data = {"vulnerabilities": [
        nvd_item("CVE-2020-0001", v31("MEDIUM")),
        nvd_item("CVE-2020-0002", {"cvssMetricV2": [{"cvssData": {"baseScore": 9.3}}]}),
        nvd_item("CVE-2020-0003", {}),                        # not scored yet: skipped
        nvd_item("CVE-2020-0004", v31("HIGH"), desc="x" * 500),
    ]}

    cves = parse_nvd_response(data, "OpenSSH", "7.4p1")

    assert [(c["id"], c["severity"]) for c in cves] == [
        ("CVE-2020-0002", "CRITICAL"), ("CVE-2020-0004", "HIGH"), ("CVE-2020-0001", "MEDIUM")]
    assert all(c["source"] == "nvd" for c in cves)
    assert len(cves[1]["desc"]) <= 161


def test_nvd_own_score_wins_over_the_vendors():
    # Found with a live lookup: NVD rates CVE-2021-41773 9.8 CRITICAL, the
    # vendor's score is lower. The order of the two entries isn't guaranteed.
    metrics = {"cvssMetricV31": [
        {"type": "Secondary", "cvssData": {"baseSeverity": "HIGH"}},
        {"type": "Primary", "cvssData": {"baseSeverity": "CRITICAL"}},
    ]}
    [cve] = parse_nvd_response({"vulnerabilities": [nvd_item("CVE-2021-41773", metrics)]}, "Apache httpd", "2.4.49")
    assert cve["severity"] == "CRITICAL"


def test_nvd_results_are_capped():
    data = {"vulnerabilities": [nvd_item(f"CVE-2020-{i:04d}", v31("LOW")) for i in range(20)]}
    assert len(parse_nvd_response(data, "OpenSSH", "7.4p1")) == vuln_scan.MAX_NVD


@pytest.fixture
def no_delay(monkeypatch):
    monkeypatch.setattr(vuln_scan.time, "sleep", lambda seconds: None)


def test_nvd_results_are_merged_and_offline_notes_win(monkeypatch, no_delay):
    online = [
        {"id": "CVE-2011-2523", "severity": "CRITICAL", "desc": "from NVD", "note": "nvd note", "source": "nvd"},
        {"id": "CVE-2099-0001", "severity": "LOW", "desc": "extra", "note": "", "source": "nvd"},
    ]
    monkeypatch.setattr(vuln_scan, "nvd_matches", lambda product, version: online)

    cves, source = lookup_cves("vsftpd", "2.3.4", use_api=True)

    assert source == "nvd"
    assert [c["id"] for c in cves] == ["CVE-2011-2523", "CVE-2099-0001"]
    assert cves[0]["source"] == "offline"          # the hand-checked entry and its note are kept


def test_offline_list_still_works_when_nvd_is_unreachable(monkeypatch, no_delay):
    monkeypatch.setattr(vuln_scan, "nvd_matches", lambda product, version: None)

    cves, source = lookup_cves("vsftpd", "2.3.4", use_api=True)

    assert source == "offline"
    assert [c["id"] for c in cves] == ["CVE-2011-2523"]


def test_each_product_version_is_looked_up_once_per_scan(monkeypatch, no_delay):
    calls = []
    monkeypatch.setattr(vuln_scan, "nvd_matches", lambda product, version: calls.append((product, version)) or [])
    port = {"service": "SSH", "banner": "x", "product": "OpenSSH", "version": "9.8p1"}
    hosts = [{"host": f"10.0.0.{i}", "tcp_ports": [dict(port, port=22)]} for i in range(5)]

    scan_vulnerabilities(hosts, use_api=True)

    assert calls == [("OpenSSH", "9.8p1")]


# ── Banner grabbing over a real socket ────────────────────────────

@pytest.fixture
def fake_service():
    """A one-shot TCP server on localhost that answers with canned bytes."""
    servers = []

    def start(reply, wait_for_request=False):
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        servers.append(server)

        def serve():
            conn, _ = server.accept()
            with conn:
                if wait_for_request:
                    conn.recv(1024)
                conn.sendall(reply)
        threading.Thread(target=serve, daemon=True).start()
        return server.getsockname()[1]

    yield start
    for server in servers:
        server.close()


def test_http_ports_get_a_head_request_and_report_the_server_header(fake_service, monkeypatch):
    port = fake_service(b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n\r\n", wait_for_request=True)
    monkeypatch.setattr(service_detection, "HTTP_PORTS", {port})

    assert service_detection.grab_banner("127.0.0.1", port) == "Apache/2.4.49 (Unix)"


def test_other_ports_read_the_greeting_and_clean_it(fake_service):
    port = fake_service(b"220 (vsFTPd 2.3.4)\x1b[2J\r\n")

    info = service_detection.detect_service("127.0.0.1", port)

    assert info["banner"] == "220 (vsFTPd 2.3.4) [2J"
    assert (info["product"], info["version"]) == ("vsftpd", "2.3.4")


def test_closed_port_gives_no_banner():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        free_port = s.getsockname()[1]          # nothing listens here after close
    assert service_detection.grab_banner("127.0.0.1", free_port, timeout=1) is None
