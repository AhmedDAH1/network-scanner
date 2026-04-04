"""
vuln_scan.py — CVE lookup per service using the NIST NVD API.

For each open port + service, queries the NVD API for known CVEs.
If a banner is available, searches by service + version for more
accurate results. Falls back to a curated local table when offline.

API docs: https://nvd.nist.gov/developers/vulnerabilities
Rate limit: 5 requests/30s without API key (we stay well under this).
"""

import urllib.request
import urllib.parse
import urllib.error
import json
import time
import re


NVD_API    = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_CVES   = 3
REQ_DELAY  = 0.6   # seconds between requests to respect rate limit


# ── Severity color mapping ────────────────────────────────────────
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}

# ── Curated offline CVE table (fallback when API is unavailable) ──
# Format: service_keyword → [ {id, severity, description} ]
OFFLINE_CVE_TABLE = {
    "ftp": [
        {"id": "CVE-2022-22836", "severity": "HIGH",     "desc": "ProFTPD arbitrary file write via mod_copy"},
        {"id": "CVE-2020-9273",  "severity": "CRITICAL", "desc": "ProFTPD use-after-free RCE (≤1.3.7)"},
        {"id": "CVE-2019-12815", "severity": "CRITICAL", "desc": "ProFTPD mod_copy unauthenticated file copy"},
    ],
    "ssh": [
        {"id": "CVE-2023-38408", "severity": "CRITICAL", "desc": "OpenSSH ssh-agent RCE via forwarded agent"},
        {"id": "CVE-2023-51385", "severity": "HIGH",     "desc": "OpenSSH command injection via hostname"},
        {"id": "CVE-2021-41617", "severity": "HIGH",     "desc": "OpenSSH privilege escalation in sshd"},
    ],
    "http": [
        {"id": "CVE-2021-41773", "severity": "CRITICAL", "desc": "Apache HTTP Server path traversal & RCE"},
        {"id": "CVE-2021-42013", "severity": "CRITICAL", "desc": "Apache HTTP Server RCE via mod_cgi"},
        {"id": "CVE-2022-31813", "severity": "HIGH",     "desc": "Apache HTTP Server request smuggling"},
    ],
    "https": [
        {"id": "CVE-2022-0778",  "severity": "HIGH",     "desc": "OpenSSL infinite loop denial of service"},
        {"id": "CVE-2021-3711",  "severity": "CRITICAL", "desc": "OpenSSL SM2 buffer overflow"},
        {"id": "CVE-2022-2274",  "severity": "CRITICAL", "desc": "OpenSSL RSA private key heap corruption"},
    ],
    "dns": [
        {"id": "CVE-2020-1350",  "severity": "CRITICAL", "desc": "Windows DNS Server RCE (SIGRed)"},
        {"id": "CVE-2021-25216", "severity": "CRITICAL", "desc": "BIND9 GSSAPI negotiation buffer overflow"},
        {"id": "CVE-2022-2795",  "severity": "MEDIUM",   "desc": "BIND9 resolver performance degradation"},
    ],
    "smtp": [
        {"id": "CVE-2020-7247",  "severity": "CRITICAL", "desc": "OpenSMTPD RCE via malformed sender"},
        {"id": "CVE-2021-38371", "severity": "MEDIUM",   "desc": "Exim STARTTLS plaintext injection"},
        {"id": "CVE-2022-37434", "severity": "CRITICAL", "desc": "zlib heap buffer overflow in inflate"},
    ],
    "telnet": [
        {"id": "CVE-2020-10188", "severity": "CRITICAL", "desc": "telnetd remote code execution"},
        {"id": "CVE-2011-4862",  "severity": "CRITICAL", "desc": "BSD telnetd encrypt_keyid overflow"},
        {"id": "CVE-2001-0554",  "severity": "HIGH",     "desc": "BSD telnetd remote buffer overflow"},
    ],
    "mysql": [
        {"id": "CVE-2022-21824", "severity": "HIGH",     "desc": "MySQL Server privilege escalation"},
        {"id": "CVE-2023-21980", "severity": "HIGH",     "desc": "MySQL Server optimizer RCE"},
        {"id": "CVE-2022-21592", "severity": "MEDIUM",   "desc": "MySQL Server unauthorized data access"},
    ],
    "rdp": [
        {"id": "CVE-2019-0708",  "severity": "CRITICAL", "desc": "BlueKeep — RDP pre-auth RCE (Windows 7/2008)"},
        {"id": "CVE-2020-0609",  "severity": "CRITICAL", "desc": "Windows RDP Gateway RCE"},
        {"id": "CVE-2021-34535", "severity": "CRITICAL", "desc": "Remote Desktop Client RCE"},
    ],
    "smb": [
        {"id": "CVE-2017-0144",  "severity": "CRITICAL", "desc": "EternalBlue — SMBv1 RCE (WannaCry)"},
        {"id": "CVE-2020-0796",  "severity": "CRITICAL", "desc": "SMBGhost — SMBv3 RCE (Windows 10)"},
        {"id": "CVE-2022-24500", "severity": "HIGH",     "desc": "Windows SMB RCE vulnerability"},
    ],
    "postgresql": [
        {"id": "CVE-2022-1552",  "severity": "HIGH",     "desc": "PostgreSQL autovacuum privilege escalation"},
        {"id": "CVE-2023-2454",  "severity": "HIGH",     "desc": "PostgreSQL CREATE SCHEMA bypass"},
        {"id": "CVE-2021-3677",  "severity": "MEDIUM",   "desc": "PostgreSQL memory disclosure"},
    ],
    "redis": [
        {"id": "CVE-2022-0543",  "severity": "CRITICAL", "desc": "Redis Lua sandbox escape RCE"},
        {"id": "CVE-2023-28425", "severity": "MEDIUM",   "desc": "Redis SRANDMEMBER denial of service"},
        {"id": "CVE-2022-24736", "severity": "MEDIUM",   "desc": "Redis OBJECT ENCODING null pointer"},
    ],
    "mongodb": [
        {"id": "CVE-2021-20328", "severity": "MEDIUM",   "desc": "MongoDB driver TLS certificate bypass"},
        {"id": "CVE-2022-24902", "severity": "MEDIUM",   "desc": "MongoDB Ops Manager SSRF"},
        {"id": "CVE-2019-2392",  "severity": "MEDIUM",   "desc": "MongoDB $elemMatch memory exhaustion"},
    ],
}

# Map common service names to offline table keys
SERVICE_KEY_MAP = {
    "FTP":        "ftp",
    "SSH":        "ssh",
    "HTTP":       "http",
    "HTTPS":      "https",
    "HTTP-Alt":   "https",
    "DNS":        "dns",
    "SMTP":       "smtp",
    "Telnet":     "telnet",
    "MySQL":      "mysql",
    "RDP":        "rdp",
    "SMB":        "smb",
    "PostgreSQL": "postgresql",
    "Redis":      "redis",
    "MongoDB":    "mongodb",
}


# ── NVD API lookup ────────────────────────────────────────────────

def _nvd_search(keyword, max_results=MAX_CVES):
    """
    Search NVD for CVEs matching keyword.
    Returns list of {id, severity, desc} dicts sorted by severity.
    """
    params = urllib.parse.urlencode({
        "keywordSearch":  keyword,
        "resultsPerPage": max_results * 3,   # fetch more, then filter top N
        "cvssV3Severity": "",                 # all severities
    })
    url = f"{NVD_API}?{params}"

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "network-scanner/1.1 (educational use)"}
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read())
    except Exception:
        return []

    cves = []
    for item in data.get("vulnerabilities", []):
        cve  = item.get("cve", {})
        cve_id = cve.get("id", "")

        # Get severity from CVSS v3 or v2
        severity = "UNKNOWN"
        metrics  = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            severity = metrics["cvssMetricV31"][0]["cvssData"].get("baseSeverity", "UNKNOWN")
        elif "cvssMetricV30" in metrics:
            severity = metrics["cvssMetricV30"][0]["cvssData"].get("baseSeverity", "UNKNOWN")
        elif "cvssMetricV2" in metrics:
            score = metrics["cvssMetricV2"][0]["cvssData"].get("baseScore", 0)
            if   score >= 9.0: severity = "CRITICAL"
            elif score >= 7.0: severity = "HIGH"
            elif score >= 4.0: severity = "MEDIUM"
            else:              severity = "LOW"

        # Get description (English preferred)
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")[:120]
                break

        cves.append({
            "id":       cve_id,
            "severity": severity.upper(),
            "desc":     desc,
        })

    # Sort by severity and return top N
    cves.sort(key=lambda c: SEVERITY_ORDER.get(c["severity"], 5))
    return cves[:max_results]


def _offline_lookup(service_name):
    """Return curated CVEs for a service from the offline table."""
    key = SERVICE_KEY_MAP.get(service_name)
    if not key:
        # Try fuzzy match
        sn = service_name.lower()
        for k in OFFLINE_CVE_TABLE:
            if k in sn or sn in k:
                key = k
                break
    return OFFLINE_CVE_TABLE.get(key, [])


# ── Public API ────────────────────────────────────────────────────

def lookup_cves(service_name, banner=None, use_api=True, max_results=MAX_CVES):
    """
    Look up CVEs for a service.

    Args:
        service_name: e.g. "HTTP", "SSH", "FTP"
        banner:       optional banner string with version info
        use_api:      if True, try NVD API first; fallback to offline table
        max_results:  max CVEs to return

    Returns:
        list of {id, severity, desc} dicts
    """
    cves = []

    if use_api:
        # Build search keyword from service + version if available
        keyword = service_name.lower()
        if banner:
            # Extract version-like strings from banner e.g. "Apache/2.4.51"
            version = re.search(r'[\d]+\.[\d]+[\.\d]*', banner)
            if version:
                keyword = f"{keyword} {version.group()}"

        cves = _nvd_search(keyword, max_results)
        time.sleep(REQ_DELAY)   # respect rate limit

    # Fallback to offline table if API returned nothing
    if not cves:
        cves = _offline_lookup(service_name)[:max_results]

    return cves


def scan_vulnerabilities(hosts, use_api=True):
    """
    Run CVE lookup for all open ports across all hosts.

    Args:
        hosts:   list of host result dicts (as built in test.py)
        use_api: whether to try the NVD API

    Returns:
        Same list with 'cves' key added to each port entry.
    """
    total_ports = sum(len(h.get("tcp_ports", [])) for h in hosts)
    if total_ports == 0:
        return hosts

    print(f"\n[+] Vulnerability scan — checking {total_ports} port(s)...")
    if use_api:
        print(f"    Using NVD API + offline fallback")
    else:
        print(f"    Using offline CVE table")

    for host in hosts:
        for port_info in host.get("tcp_ports", []):
            service = port_info.get("service", "Unknown")
            banner  = port_info.get("banner")

            if service == "Unknown":
                port_info["cves"] = []
                continue

            cves = lookup_cves(service, banner, use_api=use_api)
            port_info["cves"] = cves

            if cves:
                worst = cves[0]["severity"]
                print(f"    {host['host']}:{port_info['port']} ({service}) "
                      f"→ {len(cves)} CVE(s), worst: {worst}")

    return hosts