# 🔎 Network Scanner

![Python](https://img.shields.io/badge/python-3.10-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-success)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS-lightgrey)

A **multi-threaded network scanner** built in Python with **SYN scanning, OS detection, service detection, device fingerprinting, and reporting**.

This project mimics core functionality of professional network scanning tools and demonstrates **networking, cybersecurity, and software engineering skills**.

---

# 🚀 Features

| Feature | Status |
|--------|--------|
| Host Discovery | ✅ |
| SYN Scan | ✅ |
| OS Detection | ✅ |
| Service Detection | ✅ |
| Multi-threading | ✅ |
| HTML Reports | ✅ |
| UDP Scan | ❌ (Planned) |
| Vulnerability Scan | ❌ (Planned) |

---

# 📸 Example Output

```
###########################################
#        NETWORK SCANNER v1.0            #
#        Author: Ahmed Dahdouh           #
###########################################

Scanning host: 192.168.1.1
Operating System: Linux
Device Type: Router

╒═══════╤═════════╤══════════╕
│ Port  │ Service │ Banner   │
╞═══════╪═════════╪══════════╡
│ 53    │ DNS     │          │
│ 80    │ HTTP    │          │
╘═══════╧═════════╧══════════╛
```

Generated Files:

```
scan_results.json
scan_report.html
```

---

# 📦 Requirements

- Python 3.8+
- Scapy
- Tabulate
- tqdm
- colorama
  
# ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/AhmedDAH1/network-scanner.git
cd network-scanner
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# ⚙️ Command Line Options

| Option | Description |
|--------|-------------|
| -n | Scan network range |
| -t | Target single host |
| -p | Port range |
| -h | Help menu |

Example:

```bash
python3 test.py -t 192.168.1.1 -p 1-1000
```

---

# ⚡ Quick Start

Run a quick scan:

```bash
sudo python3 test.py -n 192.168.1.0/24
```

Results will be saved to:

```
scan_results.json
scan_report.html
```

# 💡 Why This Project?

This project was built to better understand:

- TCP/IP Networking
- Packet Crafting
- Port Scanning Techniques
- OS Fingerprinting
- Multi-threaded Python Applications

It mimics core functionality of tools like Nmap while being implemented from scratch for learning purposes.

# 🧠 Usage

Scan entire network:

```bash
sudo python3 test.py -n 192.168.1.0/24
```

Scan single host:

```bash
sudo python3 test.py -t 192.168.1.1
```

Scan port range:

```bash
sudo python3 test.py -t 192.168.1.1 -p 1-1000
```

---

# 📁 Project Structure

```
network-scanner/
│
├── test.py
│
└── scanner/
    ├── __init__.py
    ├── host_discovery.py
    ├── syn_scan.py
    ├── service_detection.py
    ├── os_fingerprint.py
    └── device_detection.py
```

---

# 📄 JSON Output Example

```json
[
  {
    "host": "192.168.1.1",
    "os": "Linux",
    "device": "Router",
    "ports": [
      {
        "port": 80,
        "service": "HTTP",
        "banner": ""
      }
    ]
  }
]
```

---

# 📊 HTML Report

After scanning, an HTML report is generated:

```
scan_report.html
```

Open it:

```bash
open scan_report.html
```

---

# 🛠️ Technologies Used

- Python
- Scapy
- Threading
- Networking (TCP/IP)
- CLI Development

---

# 🎯 Skills Demonstrated

- Network Programming
- Cybersecurity Fundamentals
- Multithreading
- CLI Tool Development
- OS Fingerprinting
- Service Detection
- Software Architecture

---

# 🔮 Future Improvements

- Stealth Scanning
- UDP Scanning
- Vulnerability Detection
- Web Interface
- Export to CSV

---

# 📌 Version

Current Version: 1.0

Changelog:
- v1.0 Initial release
- Host discovery
- SYN scanning
- OS detection
- HTML reporting

# 👨‍💻 Author

Ahmed Dahdouh

---

# ⚠️ Disclaimer

This tool is intended for **educational purposes only**.  
Only scan networks you own or have permission to test.

---

# 📜 License

MIT License
