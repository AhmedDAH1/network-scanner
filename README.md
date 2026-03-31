# 🔎 Network Scanner

A **multi-threaded network scanner** built in Python with **SYN scanning, OS detection, service detection, device fingerprinting, and reporting**.

This project mimics core functionality of professional network scanning tools and demonstrates **networking, cybersecurity, and software engineering skills**.

---

# 🚀 Features

- Host Discovery (ICMP Scan)
- SYN Port Scanning
- Service Detection
- Banner Grabbing
- OS Fingerprinting
- Device Type Detection
- Multi-threaded Scanning
- CLI Interface
- JSON Export
- HTML Report Generation
- Colored Output
- Progress Bar

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

# ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/network-scanner.git
cd network-scanner
```

Install dependencies:

```bash
pip install scapy tabulate tqdm colorama
```

---

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

# 👨‍💻 Author

Ahmed Dahdouh

---

# ⚠️ Disclaimer

This tool is intended for **educational purposes only**.  
Only scan networks you own or have permission to test.

---

# 📜 License

MIT License
