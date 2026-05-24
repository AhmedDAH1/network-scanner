# Security Policy

## Ethical Use

This tool performs active network reconnaissance (host discovery, port scanning, service enumeration, vulnerability lookups). It is intended for:

- Scanning networks you own
- Authorized penetration testing engagements
- Capture-the-flag exercises in isolated lab environments
- Defensive security teams auditing their own infrastructure

**Unauthorized scanning of networks you do not own or have explicit written permission to test is illegal in most jurisdictions** (Computer Fraud and Abuse Act in the US, Computer Misuse Act in the UK, Article 303a StGB in Germany, etc.). The author assumes no responsibility for misuse.

If you cannot answer "yes" to *"Do I have explicit authorization to scan this network?"*, do not run this tool against it.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅        |
| < 1.0   | ❌        |

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please **do not** open a public GitHub issue. Instead, report it privately:

- Via [GitHub Security Advisories](https://github.com/AhmedDAH1/network-scanner/security/advisories), or
- Via [LinkedIn](https://www.linkedin.com/in/ahmed-dahdouh)

I will acknowledge receipt within 72 hours and coordinate a fix before any public disclosure.

## Scope

This is a learning project for a portfolio. It is **not intended for production penetration-testing engagements** without further hardening. Specifically:

- The web dashboard uses Flask's development server (not a production WSGI server)
- The container runs as root because Scapy requires raw socket access; production deployments should use Linux capabilities (CAP_NET_RAW + CAP_NET_ADMIN) instead
- No authentication on the dashboard — do not expose the local instance to untrusted networks
- The deployed live demo at https://network-scanner-8ihy.onrender.com runs in `DEMO_MODE=1`, which disables live scanning entirely

## Out of Scope

- The bundled sample scan results (visible in the demo deployment) — these are synthetic data, not real network discovery
- The intentional root-in-container design choice, documented above

## Credentials and Secrets

This project currently uses no external API keys. If future versions add CVE lookup APIs (NVD, VulnDB) or threat intelligence integrations, they will load keys from environment variables — never hardcoded.
