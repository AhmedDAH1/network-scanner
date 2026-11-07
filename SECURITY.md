# Security Policy

## Ethical use

NetScan performs active network reconnaissance: host discovery, port scanning,
service enumeration and vulnerability lookups. It is intended for:

- networks you own
- authorized penetration tests
- capture-the-flag exercises and isolated labs
- defensive teams auditing their own infrastructure

**Scanning networks without explicit permission is illegal in many
jurisdictions** (for example under the Computer Fraud and Abuse Act in the US
or the Computer Misuse Act in the UK). The author accepts no responsibility for
misuse. If you can't answer "yes" to *"Do I have explicit authorization to scan
this network?"*, don't run NetScan against it.

## Supported versions

| Version | Supported |
|---------|-----------|
| 2.x     | Yes       |
| < 2.0   | No: 1.x contains the vulnerabilities fixed in 2.0.0 (stored XSS, CSRF, exposure on all interfaces) |

## Reporting a vulnerability

Please **don't** open a public issue. Report privately instead:

- through [GitHub Security Advisories](https://github.com/AhmedDAH1/network-scanner/security/advisories/new), or
- through [LinkedIn](https://www.linkedin.com/in/ahmed-dahdouh)

You'll get an acknowledgement within 72 hours, and the fix will be coordinated
with you before anything is disclosed publicly.

## Security model

NetScan runs as root (raw sockets) and displays data written by the devices it
scans, so it treats scanned devices, other websites, other machines on the
network and all user input as untrusted. The defences are summarised in the
[README](README.md#security-design) and covered by the test suite:

- untrusted values are HTML-escaped, and a strict Content-Security-Policy
  blocks inline scripts as a second layer
- scans can only be started from the dashboard's own page (CSRF), with a
  `Host` allow-list against DNS rebinding
- the dashboard listens on `127.0.0.1` by default, and Docker Compose
  publishes it on the host's loopback only
- scan input is parsed with `ipaddress`; commands are built without a shell,
  and helper binaries run from absolute paths
- the container gets only `NET_RAW` and `NET_ADMIN`, never `--privileged`

## Known limitations

This is a portfolio and learning project, not a production penetration-testing
platform:

- The dashboard has **no authentication**. Its protection is that it is only
  reachable from your own machine. Don't expose it with `NETSCAN_HOST=0.0.0.0`
  outside a container whose port is published on loopback.
- It uses Flask's development server.
- Processes run as root inside the container, because Scapy needs raw sockets.
- CVE matching relies on the version a service reports: hidden versions mean
  missed CVEs, and fixes backported by Linux distributions can make a patched
  service look vulnerable.

The public demo (https://network-scanner-8ihy.onrender.com) runs with
`DEMO_MODE=1`: scanning is disabled and the data is a synthetic sample.

## Credentials and secrets

NetScan uses no API keys today. If future versions need them (for example an
NVD API key for higher rate limits), they will be read from environment
variables and never committed.
