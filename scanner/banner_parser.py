"""
banner_parser.py — identify the software behind a service banner.

Turns raw banners such as "SSH-2.0-OpenSSH_7.4p1 Debian-10" or the HTTP
"Server: Apache/2.4.49 (Unix)" header into a product name and version, which
is what CVE matching needs. Pure functions with no network access, so every
pattern is unit-tested.

Banners come from the scanned device and are attacker-controlled: versions
are limited to a short run of letters, digits and dots before they are used
anywhere else.
"""

import re

# Characters that are safe to print or store. Everything else in a banner
# (control characters, terminal escape sequences, binary protocol bytes) is
# replaced, so a hostile service can't rewrite the analyst's terminal.
_UNPRINTABLE = re.compile(r"[^\x20-\x7e]+")

MAX_BANNER = 200
_VERSION = r"(\d+(?:\.\d+)+[a-z]?\d*)"     # 7.4p1, 2.4.49, 1.3.5a, 4.89

# (pattern, product). The first pattern that matches wins.
SIGNATURES = [
    (re.compile(r"OpenSSH[_-]" + _VERSION, re.I),              "OpenSSH"),
    (re.compile(r"dropbear[_-](\d{4}\.\d+)", re.I),             "Dropbear SSH"),
    (re.compile(r"vsFTPd " + _VERSION, re.I),                   "vsftpd"),
    (re.compile(r"ProFTPD " + _VERSION, re.I),                  "ProFTPD"),
    (re.compile(r"FileZilla Server(?: version)? " + _VERSION, re.I), "FileZilla Server"),
    (re.compile(r"Apache/" + _VERSION, re.I),                   "Apache httpd"),
    (re.compile(r"nginx/" + _VERSION, re.I),                    "nginx"),
    (re.compile(r"lighttpd/" + _VERSION, re.I),                 "lighttpd"),
    (re.compile(r"Microsoft-IIS/" + _VERSION, re.I),            "Microsoft IIS"),
    (re.compile(r"Exim " + _VERSION, re.I),                     "Exim"),
    (re.compile(r"(\d+\.\d+\.\d+)-MariaDB", re.I),              "MariaDB"),
]

# Product named in the banner, but without a version.
NAME_ONLY = [
    (re.compile(r"OpenSSH", re.I),        "OpenSSH"),
    (re.compile(r"\bApache\b", re.I),     "Apache httpd"),
    (re.compile(r"\bnginx\b", re.I),      "nginx"),
    (re.compile(r"\blighttpd\b", re.I),   "lighttpd"),
    (re.compile(r"Microsoft-IIS", re.I),  "Microsoft IIS"),
    (re.compile(r"\bPostfix\b", re.I),    "Postfix"),
    (re.compile(r"Pure-FTPd", re.I),      "Pure-FTPd"),
]


def clean_banner(raw):
    """Make a banner safe to display: printable ASCII only, single spaces, capped length."""
    if raw is None:
        return None
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
    text = _UNPRINTABLE.sub(" ", text)
    text = " ".join(text.split())
    return text[:MAX_BANNER] or None


def http_server_header(response):
    """Return the Server header from a raw HTTP response, else its status line."""
    text = response.decode("latin-1", errors="replace") if isinstance(response, bytes) else str(response)
    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    for line in lines[1:]:
        if not line:
            break                                   # end of headers
        name, _, value = line.partition(":")
        if name.strip().lower() == "server":
            return clean_banner(value)
    return clean_banner(lines[0]) if lines and lines[0].startswith("HTTP/") else None


def identify_software(service, banner):
    """Return {"product": str|None, "version": str|None} for a banner."""
    if banner:
        for pattern, product in SIGNATURES:
            match = pattern.search(banner)
            if match:
                return {"product": product, "version": match.group(1)}

        # MySQL's greeting is binary; after cleaning, the version is the first
        # dotted number. Only trust that on the MySQL port.
        if service == "MySQL":
            match = re.search(r"\b(\d+\.\d+\.\d+[a-z]?)", banner)
            if match:
                return {"product": "MySQL", "version": match.group(1)}

        for pattern, product in NAME_ONLY:
            if pattern.search(banner):
                return {"product": product, "version": None}

    return {"product": None, "version": None}
