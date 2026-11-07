"""
vuln_scan.py — match open services to known CVEs by product and version.

A CVE is only reported when the service banner names the product AND a
version inside the CVE's affected range. A port whose software or version
can't be identified gets no CVEs: guessing from the port number alone (every
port 53 "has" a Windows DNS server bug) produced false positives.

Two sources:
  * KNOWN_VULNS, a small offline list of well-known CVEs with affected
    version ranges checked against public advisories. Always used.
  * The NIST NVD API, queried by the exact CPE name of the product and
    version (never by keyword). Optional; if it fails, the offline list
    still applies, so the worst case is a missed CVE, never a wrong one.

API docs: https://nvd.nist.gov/developers/vulnerabilities
Rate limit without an API key: 5 requests per 30 seconds.
"""

import json
import re
import time
import urllib.parse
import urllib.request

from scanner import __version__

NVD_API   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_NVD   = 5        # most severe NVD results kept per product/version
REQ_DELAY = 6.5      # seconds between NVD requests (5 per 30 s without a key)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

BACKPORT_NOTE = ("Linux distributions often patch this without changing the "
                 "version number, so check the package's own advisories.")

# ── Offline knowledge base ────────────────────────────────────────
# Severities follow NVD's own (primary) CVSS score, the page each CVE links to.
# "ranges": (first affected, first fixed). None means "no lower bound".
# "versions": exact affected versions.
KNOWN_VULNS = {
    "OpenSSH": [
        {"id": "CVE-2024-6387", "severity": "HIGH",
         "desc": "regreSSHion: unauthenticated remote code execution in sshd",
         "ranges": [(None, "4.4p1"), ("8.5p1", "9.8p1")],
         "note": BACKPORT_NOTE},
        {"id": "CVE-2023-48795", "severity": "MEDIUM",
         "desc": "Terrapin: SSH handshake prefix truncation weakens connection integrity",
         "ranges": [("6.2", "9.6")],
         "note": "Only when ChaCha20-Poly1305 or an Encrypt-then-MAC mode is negotiated. " + BACKPORT_NOTE},
        {"id": "CVE-2018-15473", "severity": "MEDIUM",
         "desc": "Username enumeration: attackers can test which accounts exist",
         "ranges": [(None, "7.8")],
         "note": BACKPORT_NOTE},
    ],
    "Apache httpd": [
        {"id": "CVE-2021-42013", "severity": "CRITICAL",
         "desc": "Path traversal and remote code execution (incomplete fix for CVE-2021-41773)",
         "ranges": [("2.4.49", "2.4.51")],
         "note": "Needs the default 'Require all denied' protection removed; code execution also needs CGI enabled."},
        {"id": "CVE-2021-41773", "severity": "CRITICAL",
         "desc": "Path traversal and file disclosure; remote code execution if CGI is enabled",
         "ranges": [("2.4.49", "2.4.50")],
         "note": "Needs the default 'Require all denied' protection removed."},
    ],
    "vsftpd": [
        {"id": "CVE-2011-2523", "severity": "CRITICAL",
         "desc": "Backdoor opens a root shell on port 6200",
         "versions": ["2.3.4"],
         "note": "Only in copies downloaded from the official site between 30 June and 3 July 2011."},
    ],
    "ProFTPD": [
        {"id": "CVE-2015-3306", "severity": "CRITICAL",
         "desc": "mod_copy lets unauthenticated users read and write arbitrary files",
         "versions": ["1.3.5"],
         "note": "Only when the mod_copy module is loaded."},
    ],
    "Exim": [
        {"id": "CVE-2019-10149", "severity": "CRITICAL",
         "desc": "'Return of the WIZard': command execution through a crafted recipient address",
         "ranges": [("4.87", "4.92")],
         "note": BACKPORT_NOTE},
    ],
}

# CPE vendor:product names, used for exact NVD lookups.
PRODUCT_CPE = {
    "OpenSSH":       "openbsd:openssh",
    "Apache httpd":  "apache:http_server",
    "nginx":         "f5:nginx",
    "lighttpd":      "lighttpd:lighttpd",
    "Microsoft IIS": "microsoft:internet_information_services",
    "vsftpd":        "beasts:vsftpd",
    "ProFTPD":       "proftpd:proftpd",
    "Exim":          "exim:exim",
    "MySQL":         "oracle:mysql",
    "MariaDB":       "mariadb:mariadb",
}


# ── Versions ──────────────────────────────────────────────────────

def version_key(version):
    """
    Turn a version string into something that sorts correctly.

        "7.4p1"  -> (7, 4, 1)      OpenSSH portable release p1
        "1.3.5a" -> (1, 3, 5, 1)   letter suffix after the release
        "2.4.49" -> (2, 4, 49)
    """
    key = []
    for part in re.findall(r"\d+|[a-z]+", str(version).lower()):
        if part.isdigit():
            key.append(int(part))
        elif part == "p":
            continue                     # OpenSSH "p" marks the portable build number
        elif part in ("rc", "beta", "alpha", "dev", "pre"):
            key.append(-1)               # pre-releases sort before the release
        else:
            key.append(ord(part[0]) - ord("a") + 1)
    # Pad with zeros so missing parts count as 0: otherwise Python treats
    # the longer tuple as bigger and "1.3.5rc1" (1,3,5,-1,1) beats "1.3.5".
    return tuple(key + [0] * (8 - len(key)))


def is_affected(version, entry):
    """True if `version` falls inside one of the entry's affected ranges."""
    if version in entry.get("versions", []):
        return True
    v = version_key(version)
    for first, fixed in entry.get("ranges", []):
        if (first is None or v >= version_key(first)) and v < version_key(fixed):
            return True
    return False


# ── Sources ───────────────────────────────────────────────────────

def offline_matches(product, version):
    """CVEs from the offline list that affect this exact product version."""
    return [
        {"id": e["id"], "severity": e["severity"], "desc": e["desc"],
         "note": e.get("note", ""), "source": "offline"}
        for e in KNOWN_VULNS.get(product, [])
        if is_affected(version, e)
    ]


def cpe_name(product, version):
    """
    The CPE 2.3 name NVD uses for a product version, or None.

        ("OpenSSH", "7.4p1")  -> cpe:2.3:a:openbsd:openssh:7.4:p1:*:*:*:*:*:*
        ("ProFTPD", "1.3.5a") -> cpe:2.3:a:proftpd:proftpd:1.3.5:a:*:*:*:*:*:*
    """
    vendor_product = PRODUCT_CPE.get(product)
    match = re.fullmatch(r"(\d+(?:\.\d+)*)([a-z]\w{0,8})?", str(version or ""), re.I)
    if not vendor_product or not match:
        return None
    release, update = match.group(1), (match.group(2) or "*").lower()
    return f"cpe:2.3:a:{vendor_product}:{release}:{update}:*:*:*:*:*:*"


def _primary(entries):
    """NVD can list several scores for one CVE: its own ("Primary") and the
    vendor's ("Secondary"). Use NVD's, so results match the linked NVD page."""
    return next((e for e in entries if e.get("type") == "Primary"), entries[0])


def _severity(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            return _primary(metrics[key])["cvssData"].get("baseSeverity", "").upper()
    if metrics.get("cvssMetricV2"):
        score = _primary(metrics["cvssMetricV2"])["cvssData"].get("baseScore", 0)
        return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW"
    return ""


def parse_nvd_response(data, product, version):
    """Turn an NVD API response into CVE dicts, most severe first."""
    cves = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        severity = _severity(cve.get("metrics", {}))
        if severity not in SEVERITY_ORDER:
            continue                     # not yet scored; can't rank it
        desc = next((d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
        cves.append({
            "id": cve.get("id", ""), "severity": severity,
            "desc": desc[:160] + ("…" if len(desc) > 160 else ""),
            "note": f"Listed by NVD for {product} {version}. " + BACKPORT_NOTE,
            "source": "nvd",
        })
    cves.sort(key=lambda c: SEVERITY_ORDER[c["severity"]])
    return cves[:MAX_NVD]


def nvd_matches(product, version, timeout=10):
    """
    CVEs NVD lists as affecting this exact product version (by CPE name).
    Returns None if the lookup failed, so callers can tell "none" from "unknown".
    """
    cpe = cpe_name(product, version)
    if not cpe:
        return []
    # isVulnerable: only CVEs where this product itself is vulnerable, not
    # ones where it merely appears as the platform something else runs on.
    url = f"{NVD_API}?cpeName={urllib.parse.quote(cpe, safe=':*')}&isVulnerable&resultsPerPage=200"
    request = urllib.request.Request(  # noqa: S310 - fixed https NVD URL; the CPE is built from validated parts
        url, headers={"User-Agent": f"netscan/{__version__} (+https://github.com/AhmedDAH1/network-scanner)"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return parse_nvd_response(json.loads(response.read()), product, version)
    except (OSError, ValueError):        # network errors, HTTP errors, bad JSON
        return None


# ── Public API ────────────────────────────────────────────────────

def lookup_cves(product, version, use_api=True, _cache=None):
    """
    CVEs for one product version: the offline list plus, optionally, NVD.
    Returns (cves, source) where source is "nvd" if NVD answered, else "offline".
    """
    found = {c["id"]: c for c in offline_matches(product, version)}
    source = "offline"
    if use_api:
        key = (product, version)
        if _cache is not None and key in _cache:
            online = _cache[key]
        else:
            online = nvd_matches(product, version)
            if _cache is not None:
                _cache[key] = online
            time.sleep(REQ_DELAY)
        if online is not None:
            source = "nvd"
            for cve in online:
                found.setdefault(cve["id"], cve)   # offline entries keep their hand-written notes
    cves = sorted(found.values(), key=lambda c: SEVERITY_ORDER.get(c["severity"], 9))
    return cves, source


def scan_vulnerabilities(hosts, use_api=True):
    """
    Add 'cves' and 'vuln_source' to every open TCP port.

    vuln_source tells the dashboard what was checked:
      "unidentified"  no product/version in the banner, so nothing was checked
      "offline"       checked against the offline list only
      "nvd"           checked against NVD and the offline list
    """
    ports = [(h, p) for h in hosts for p in h.get("tcp_ports", [])]
    if not ports:
        return hosts

    print(f"\n[+] Vulnerability check: {len(ports)} open port(s), "
          f"{'NVD + offline list' if use_api else 'offline list only'}")
    cache, unidentified = {}, 0

    for host, port in ports:
        product, version = port.get("product"), port.get("version")
        if not (product and version):
            port["cves"], port["vuln_source"] = [], "unidentified"
            unidentified += 1
            continue

        cves, source = lookup_cves(product, version, use_api=use_api, _cache=cache)
        port["cves"], port["vuln_source"] = cves, source
        if cves:
            print(f"    {host['host']}:{port['port']}  {product} {version}  "
                  f"-> {len(cves)} CVE(s), worst: {cves[0]['severity']}")

    if unidentified:
        print(f"    {unidentified} port(s) not checked: software version not identified from the banner")
    if use_api and cache and all(v is None for v in cache.values()):
        print("    [!] NVD could not be reached; used the offline list only")
    return hosts
