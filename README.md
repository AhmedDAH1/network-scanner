# 🔎 Network Scanner
 
![Python](https://img.shields.io/badge/python-3.8+-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-success)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS-lightgrey)
 
A **multi-threaded network scanner** built in Python with SYN scanning, UDP scanning, OS detection, MAC vendor lookup, service detection, and HTML/JSON reporting.
 
This project mimics core functionality of professional tools like Nmap while being implemented from scratch for learning purposes.
 
---
 
## 🚀 Features
 
| Feature | Status |
|---|---|
| Host Discovery (ARP + ICMP fallback) | ✅ |
| Auto Network Interface Detection | ✅ |
| TCP SYN Scan | ✅ |
| UDP Scan | ✅ |
| OS Fingerprinting (TTL-based) | ✅ |
| Service Detection | ✅ |
| MAC Vendor Lookup (offline) | ✅ |
| Randomized MAC Detection | ✅ |
| Banner Grabbing | ✅ |
| Multi-threading | ✅ |
| JSON Reports | ✅ |
| HTML Reports | ✅ |
| Vulnerability Scan | ❌ Planned |
| CSV Export | ❌ Planned |
| Web Interface | ❌ Planned |
 
---
 
## 📸 Example Output
 
```
###########################################
#        NETWORK SCANNER v1.0            #
#        Author: Ahmed Dahdouh           #
###########################################
 
[+] Discovering hosts in 192.168.1.0/24
[+] Detected active interface: en0 (192.168.1.13)
[+] Running ARP Scan on interface en0...
[+] ARP scan found 3 host(s).
 
─────────────────────────────────────────────
Scanning host: 192.168.1.1  [68:9a:21:2e:6a:a0]
─────────────────────────────────────────────
  OS:     Linux / macOS
  Device: Router / AP
  Vendor: Netgear
 
[+] TCP SYN Scan (1-1000)...
╒════════╤═══════════╤══════════╕
│   Port │ Service   │ Banner   │
╞════════╪═══════════╪══════════╡
│     53 │ DNS       │          │
├────────┼───────────┼──────────┤
│     80 │ HTTP      │          │
╘════════╧═══════════╧══════════╛
 
[+] JSON report saved → scan_results.json
[+] HTML report saved → scan_report.html
```
 
---
 
## 📦 Requirements
 
- Python 3.8+
- Scapy
- Tabulate
- Colorama
- Manuf
 
---
 
## ⚙️ Installation
 
Clone the repository:
 
```bash
git clone https://github.com/AhmedDAH1/network-scanner.git
cd network-scanner
```
 
Install dependencies:
 
```bash
pip install -r requirements.txt
```
 
> **Note:** SYN scanning and ARP host discovery require root privileges. Always run with `sudo`.
 
---
 
## 🧠 Usage
 
### Scan an entire network
```bash
sudo python3 test.py -n 192.168.1.0/24
```
 
### Scan a single host
```bash
sudo python3 test.py -t 192.168.1.1
```
 
### Scan a custom port range
```bash
sudo python3 test.py -t 192.168.1.1 -p 1-65535
```
 
### Enable UDP scan
```bash
sudo python3 test.py -t 192.168.1.1 --udp
```
 
### Combine options
```bash
sudo python3 test.py -n 192.168.1.0/24 -p 1-500 --udp
```
 
---
 
## ⚙️ Command Line Options
 
| Option | Description |
|---|---|
| `-n` | Scan a network range (e.g. `192.168.1.0/24`) |
| `-t` | Scan a single host |
| `-p` | Port range (default: `1-1000`) |
| `--udp` | Enable UDP scan on common ports |
| `-h` | Show help menu |
 
---
 
## 📁 Project Structure
 
```
network-scanner/
│
├── test.py                  # Main entry point & CLI
├── requirements.txt         # Python dependencies
├── scan_results.json        # Generated JSON report
├── scan_report.html         # Generated HTML report
│
└── scanner/
    ├── __init__.py
    ├── host_discovery.py    # ARP + ICMP host discovery, interface detection
    ├── syn_scan.py          # TCP SYN scanning (multi-threaded)
    ├── udp_scan.py          # UDP scanning (multi-threaded)
    ├── service_detection.py # Port-to-service mapping + banner grabbing
    ├── os_fingerprint.py    # TTL-based OS fingerprinting
    ├── device_detection.py  # MAC vendor lookup + device classification
    └── port_scanner.py      # TCP connect scan (fallback)
```
 
---
 
## 📄 JSON Output Example
 
```json
[
  {
    "host": "192.168.1.1",
    "mac": "68:9a:21:2e:6a:a0",
    "vendor": "Netgear",
    "os": "Linux / macOS",
    "device": "Router / AP",
    "tcp_ports": [
      { "port": 53, "service": "DNS", "banner": null },
      { "port": 80, "service": "HTTP", "banner": null }
    ],
    "udp_ports": [
      { "port": 53, "service": "DNS" }
    ]
  }
]
```
 
---
 
## 📊 HTML Report
 
After every scan an HTML report is automatically generated at `scan_report.html`. Open it with:
 
```bash
open scan_report.html       # macOS
xdg-open scan_report.html  # Linux
```
 
The report includes per-host sections with OS, vendor, device type, and separate TCP and UDP port tables.
 
---
 
## 🛠️ How It Works
 
**Host Discovery** — Sends ARP requests on the active network interface to find live hosts. Automatically detects the correct interface (skipping VPN tunnels). Falls back to ICMP ping if ARP fails.
 
**TCP SYN Scan** — Crafts raw SYN packets with Scapy and checks for SYN-ACK responses to identify open ports without completing the handshake. Runs with 100 concurrent threads.
 
**UDP Scan** — Sends UDP packets to common ports and interprets ICMP unreachable responses to determine closed vs. open/filtered status.
 
**OS Fingerprinting** — Analyses the TTL value in ICMP responses. TTL ≤ 64 → Linux/macOS, TTL ≤ 128 → Windows.
 
**MAC Vendor Lookup** — Uses a curated OUI table combined with the offline `manuf` library to identify device manufacturers without any internet dependency. Detects randomized/privacy MACs automatically.
 
**Service Detection** — Maps open ports to known service names and attempts banner grabbing to identify the exact software running.
 
---
 
## 🔮 Future Improvements
 
- Vulnerability detection (CVE lookup per service/version)
- CSV export
- Web interface / dashboard
- Stealth scan improvements
- IPv6 support
 
---
 
## 📌 Changelog
 
**v1.1**
- Added UDP scanning
- Added MAC vendor lookup (offline, via manuf + curated OUI table)
- Added randomized MAC detection
- Fixed ARP scan on macOS (VPN-aware interface detection)
- Improved HTML report (TCP + UDP tables, vendor/MAC info)
- Fixed service detection signature (ip, port)
- Fixed SYN scan function naming consistency
- Added colorized CLI output
 
**v1.0**
- Initial release
- Host discovery (ARP + ICMP)
- TCP SYN scanning
- OS fingerprinting
- Service detection
- HTML + JSON reporting
 
---
 
## 👨‍💻 Author
 
Ahmed Dahdouh
 
---
 
## ⚠️ Disclaimer
 
This tool is intended for **educational purposes only**.  
Only scan networks you own or have explicit permission to test.  
Unauthorized network scanning may be illegal in your jurisdiction.
 
---
 
## 📜 License
 
MIT License
