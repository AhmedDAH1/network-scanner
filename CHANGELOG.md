# Changelog

All notable changes to NetScan. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and from 2.0.0 the
project uses [Semantic Versioning](https://semver.org/): MAJOR for breaking
changes, MINOR for new features, PATCH for fixes.

## [2.2.0] - 2026-11-07

Detections for NetScan itself: rules that catch this scanner from the
defender's side, tested against its real traffic.

### Added
- `detections/`: two Suricata rules (Scapy's default SYN fingerprint and the
  `netscan/` User-Agent) and two Sigma rules (the User-Agent in web server
  logs, and a tool-independent vertical port scan correlation over Zeek
  `conn` logs).
- Test captures: a real NetScan scan and a benign baseline with traffic
  chosen to trip naive rules (for example active-mode FTP from port 20),
  plus a script that re-records both in an isolated network namespace.
- Tests that run Suricata on both captures, execute the Sigma rules,
  check the port-scan threshold at 24 and 25 ports, and convert the rules
  to Splunk and Elasticsearch queries. CI installs Suricata.
- `detections/TESTING.md` with the method, results, the rule variants that
  were rejected and why, and limitations.

## [2.1.1] - 2026-11-07

### Fixed
- NVD responses can contain two scores for a CVE, NVD's own and the
  vendor's; the first one listed was used. NVD's primary score is now
  preferred, so results match the NVD page each CVE links to.
- CVE-2021-41773 is rated CRITICAL (NVD 9.8: code execution when CGI is
  enabled) instead of HIGH, matching NVD. Found by a live lookup.

## [2.1.0] - 2026-11-07

Vulnerability results you can trust: CVEs are matched by the product and
version a service reports, instead of by port number.

### Fixed
- False positives. CVEs were attached by port alone, so every port 53 got
  SIGRed (a Windows DNS server bug), every port 80 the same Apache CVEs and
  every 3389 BlueKeep. A CVE is now only reported when the banner names the
  product and a version inside the CVE's affected range.
- The offline CVE table contained entries for the wrong products; it was
  replaced by a small list of well-known CVEs with affected version ranges
  checked against public advisories.
- NVD lookups searched by keyword (e.g. "ssh 7.4") and waited 0.6 s between
  requests, well over NVD's limit of 5 per 30 s, so most requests failed.
  Lookups now use the exact CPE name of the product version, wait 6.5 s, and
  are cached per scan.

### Added
- Web servers are sent a `HEAD` request, so their `Server` header (e.g.
  `Apache/2.4.49`) becomes the banner.
- Product and version detection for OpenSSH, Dropbear, vsftpd, ProFTPD,
  FileZilla Server, Apache, nginx, lighttpd, IIS, Exim, MySQL and MariaDB.
- The CLI table, dashboard and report show the identified software, each
  CVE's conditions (for example "only when mod_copy is loaded"), and whether a
  port was checked at all ("Version not identified").

### Security
- Banners are reduced to printable characters before they are shown or
  stored, so a hostile service can't send terminal escape codes that rewrite
  the analyst's terminal.

## [2.0.0] - 2026-11-07

A security and quality release: the web dashboard was hardened against
attacks from both websites and scanned devices, every fix is covered by
tests, and the interface was redesigned.

### Breaking changes
- The dashboard listens on `127.0.0.1` only by default. Set
  `NETSCAN_HOST=0.0.0.0` inside containers (the Dockerfile does this).
- `POST /history/save` was removed. The server records scan history itself.
- Runtime files (history, `scan_results.json`, `scan_report.html` from the
  dashboard) now live in `data/` instead of the working directory.
- The scan form has a single Target field that accepts an IP address or a
  CIDR network.

### Security
- Fixed stored XSS: service banners, host names and vendors from scanned
  devices are escaped everywhere in the dashboard and the HTML report,
  including inside the report's `<script>` block.
- Added a strict Content-Security-Policy (no inline scripts, handlers or
  styles), plus `X-Content-Type-Options`, `X-Frame-Options` and
  `Referrer-Policy` headers.
- Scans can only be started or stopped from the dashboard's own page:
  requests from other websites (CSRF) and DNS-rebinding attempts are refused.
- Scan input is parsed with `ipaddress` before it reaches the scanner;
  networks larger than /16, invalid ports and argument-injection attempts are
  rejected.
- Helper binaries (`dns-sd`, `ifconfig`, `ip`) are run from absolute paths,
  never looked up through `PATH`; mDNS names that look like options are
  ignored.
- Docker Compose publishes the dashboard on the host's loopback only.

### Added
- Test suite (101 tests) covering input validation, web security, reports,
  network parsing and file handling; CI runs lint and tests on every push.
- `pyproject.toml`: `pip install -e .` provides `netscan` and `netscan-web`
  commands; `netscan --version`.
- `CHANGELOG.md`, and one version number shared by the CLI, dashboard and
  NVD requests.

### Changed
- Redesigned dashboard and HTML report: findings sorted by risk, severity
  meter, light and dark themes, network map drawn in SVG without d3, favicon.
- Fonts and scripts are bundled, so the dashboard works offline and in
  regions where Google Fonts is blocked. The report embeds its fonts.
- The demo uses a realistic sample scan in the scanner's real output format.
- Files written while running under `sudo` are handed back to the real user;
  JSON files are written atomically and a damaged history file is backed up
  instead of overwritten.

### Fixed
- mDNS device identification never worked on macOS (`select` was not
  imported and the error was silently swallowed).
- Interface detection always fell back to Scapy's default because of a
  misplaced `check=False`.
- The Stop button did not stop the scan; only one scan can now run at a time.
- The topology map crashed after every scan, so the results page never opened
  automatically.
- Reloading a scan from history never worked.
- The demo's sample data showed "Invalid Date", no IPs and `NaN` CVEs.
- MAC addresses written with dashes or dots crashed the randomized-MAC check
  and missed the vendor lookup.
- Docker scan history was not persisted by the `./data` volume.
- The HTML report showed the time it was opened instead of the scan time.

## [1.1.0] - 2026-05-24

Released after 1.3 under an inconsistent number; 2.0.0 restores ordering.

### Added
- Dockerfile (Python 3.10-slim) and docker-compose.yml with only the
  `NET_RAW` and `NET_ADMIN` capabilities, never `--privileged`.
- `DEMO_MODE` for the hosted portfolio demo; scanning endpoints return 403.
- `SECURITY.md` with an ethical-use clause.

### Fixed
- The dashboard launched a non-existent `test.py` instead of `scanner_cli.py`.

## [1.3] - 2026-04-04

### Added
- Flask web dashboard with live scan output (Server-Sent Events), scan
  history and a theme toggle.

## [1.2] - 2026-04-04

### Added
- Vulnerability lookup through the NVD API with an offline fallback table
  (`--vuln`, `--no-api`).
- mDNS/Bonjour device identification.

## [1.1] - 2026-04-01

### Added
- UDP scanning, MAC vendor lookup and randomized-MAC detection.

### Fixed
- ARP scanning on macOS with an active VPN.

## [1.0] - 2026-04-01

### Added
- Host discovery (ARP with ICMP fallback), TCP SYN scanning, service banners,
  TTL-based OS guess, JSON and HTML reports.

[2.2.0]: https://github.com/AhmedDAH1/network-scanner/compare/v2.1.1...v2.2.0
[2.1.1]: https://github.com/AhmedDAH1/network-scanner/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/AhmedDAH1/network-scanner/compare/v2.0.0...v2.1.0
[2.0.0]: https://github.com/AhmedDAH1/network-scanner/compare/v1.1.0...v2.0.0
[1.1.0]: https://github.com/AhmedDAH1/network-scanner/compare/v1.3...v1.1.0
[1.3]: https://github.com/AhmedDAH1/network-scanner/compare/v1.0...v1.3
[1.0]: https://github.com/AhmedDAH1/network-scanner/releases/tag/v1.0
