#!/usr/bin/env python3

import argparse
import json
import os
from tabulate import tabulate
from colorama import Fore, Style, init

from scanner.host_discovery import discover_hosts
from scanner.syn_scan import syn_scan
from scanner.udp_scan import udp_scan
from scanner.service_detection import detect_service
from scanner.os_fingerprint import os_fingerprint
from scanner.device_detection import detect_device

init(autoreset=True)


# ──────────────────────────────────────────
# Report Helpers
# ──────────────────────────────────────────

def save_json(all_results, path="scan_results.json"):
    with open(path, "w") as f:
        json.dump(all_results, f, indent=4)
    print(f"\n{Fore.GREEN}[+] JSON report saved → {path}")


def save_html(all_results, path="scan_report.html"):
    rows = ""
    for host in all_results:
        rows += f"<h2>{host['host']}</h2>"
        rows += f"<p><b>MAC:</b> {host.get('mac', 'Unknown')} &nbsp;|&nbsp; <b>Vendor:</b> {host.get('vendor', 'Unknown')}</p>"
        rows += f"<p><b>OS:</b> {host['os']} &nbsp;|&nbsp; <b>Device:</b> {host['device']}</p>"

        # TCP ports table
        if host["tcp_ports"]:
            rows += "<h3>TCP Ports</h3>"
            rows += "<table><tr><th>Port</th><th>Service</th><th>Banner</th></tr>"
            for p in host["tcp_ports"]:
                banner = p["banner"] or ""
                rows += f"<tr><td>{p['port']}</td><td>{p['service']}</td><td>{banner}</td></tr>"
            rows += "</table>"
        else:
            rows += "<p>No open TCP ports found.</p>"

        # UDP ports table
        if host.get("udp_ports"):
            rows += "<h3>UDP Ports (open|filtered)</h3>"
            rows += "<table><tr><th>Port</th><th>Service</th></tr>"
            for p in host["udp_ports"]:
                rows += f"<tr><td>{p['port']}</td><td>{p['service']}</td></tr>"
            rows += "</table>"

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Network Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f9f9f9; }}
        h1 {{ color: #333; }}
        h2 {{ color: #0066cc; border-bottom: 1px solid #ccc; padding-bottom: 4px; }}
        h3 {{ color: #444; margin-top: 16px; }}
        table {{ border-collapse: collapse; width: 70%; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #ccc; padding: 8px 12px; text-align: left; }}
        th {{ background-color: #e8e8e8; }}
        tr:nth-child(even) {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>Network Scan Results</h1>
    {rows}
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)
    print(f"{Fore.GREEN}[+] HTML report saved → {path}")


# ──────────────────────────────────────────
# Main
# ──────────────────────────────────────────

def print_banner():
    print(Fore.CYAN + """
###########################################
#        NETWORK SCANNER v1.0            #
#        Author: Ahmed Dahdouh           #
###########################################
""")


def main():
    print_banner()

    parser = argparse.ArgumentParser(description="Network Scanner v1.0")

    parser.add_argument("-n", "--network", help="Scan network range (e.g. 192.168.1.0/24)")
    parser.add_argument("-t", "--target",  help="Scan single host")
    parser.add_argument("-p", "--ports",   default="1-1000", help="Port range (default: 1-1000)")
    parser.add_argument("--udp",           action="store_true", help="Enable UDP scan")

    args = parser.parse_args()

    # ── Target resolution ──────────────────
    if args.network:
        print(f"{Fore.YELLOW}[+] Discovering hosts in {args.network}")
        discovered = discover_hosts(args.network)   # list of {ip, mac}
        if not discovered:
            print(f"{Fore.RED}[-] No live hosts found.")
            return
        ips = [h["ip"] for h in discovered]
        print(f"{Fore.GREEN}[+] Found {len(discovered)} host(s): {', '.join(ips)}")
        targets = discovered

    elif args.target:
        targets = [{"ip": args.target, "mac": None}]

    else:
        print(f"{Fore.RED}[!] Please specify a target (-t) or network (-n)")
        return

    # ── Port range ─────────────────────────
    try:
        start_port, end_port = map(int, args.ports.split("-"))
        tcp_ports = list(range(start_port, end_port + 1))
    except ValueError:
        print(f"{Fore.RED}[!] Invalid port range. Use format: 1-1000")
        return

    all_results = []

    # ── Scan each host ─────────────────────
    for host in targets:
        target = host["ip"]
        mac    = host.get("mac")

        print(f"\n{Fore.CYAN}{'─'*45}")
        print(f"{Fore.CYAN}Scanning host: {target}" + (f"  [{mac}]" if mac else ""))
        print(f"{Fore.CYAN}{'─'*45}")

        os_name     = os_fingerprint(target)
        dev_info    = detect_device(target, mac)
        device      = dev_info["device"]
        vendor      = dev_info["vendor"]

        print(f"  OS:     {os_name}")
        print(f"  Device: {device}")
        print(f"  Vendor: {vendor}")

        # TCP SYN scan
        print(f"\n{Fore.YELLOW}[+] TCP SYN Scan ({args.ports})...")
        open_tcp = syn_scan(target, tcp_ports)

        tcp_results = []
        for port in open_tcp:
            info = detect_service(target, port)   # returns {port, service, banner}
            tcp_results.append(info)

        if tcp_results:
            table_data = [(r["port"], r["service"], r["banner"] or "") for r in tcp_results]
            print(tabulate(table_data, headers=["Port", "Service", "Banner"], tablefmt="fancy_grid"))
        else:
            print(f"{Fore.RED}  No open TCP ports found.")

        # UDP scan
        udp_results = []
        if args.udp:
            udp_default_ports = [53, 67, 68, 69, 123, 161, 162, 500, 1900, 5353]
            print(f"\n{Fore.YELLOW}[+] UDP Scan on common ports...")
            open_udp = udp_scan(target, udp_default_ports)

            for port in open_udp:
                from scanner.service_detection import COMMON_PORTS
                service = COMMON_PORTS.get(port, "Unknown")
                udp_results.append({"port": port, "service": service})
                print(f"  {Fore.GREEN}UDP {port}/open|filtered  →  {service}")

            if not udp_results:
                print(f"{Fore.RED}  No open|filtered UDP ports found.")

        # Collect for reports
        all_results.append({
            "host":      target,
            "mac":       mac or "Unknown",
            "vendor":    vendor,
            "os":        os_name,
            "device":    device,
            "tcp_ports": tcp_results,
            "udp_ports": udp_results,
        })

    # ── Save reports ───────────────────────
    save_json(all_results)
    save_html(all_results)


if __name__ == "__main__":
    main()