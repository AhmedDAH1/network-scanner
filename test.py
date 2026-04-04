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
from scanner.mdns_probe import mdns_probe_hosts
from scanner.vuln_scan import scan_vulnerabilities

init(autoreset=True)


# ──────────────────────────────────────────
# Report Helpers
# ──────────────────────────────────────────

def save_json(all_results, path="scan_results.json"):
    with open(path, "w") as f:
        json.dump(all_results, f, indent=4)
    print(f"\n{Fore.GREEN}[+] JSON report saved → {path}")


def save_html(all_results, path="scan_report.html"):
    import json as _json

    # Load the HTML template
    template_path = os.path.join(os.path.dirname(__file__), "report_template.html")
    try:
        with open(template_path, "r") as f:
            template = f.read()
    except FileNotFoundError:
        print(f"{Fore.RED}[-] report_template.html not found — skipping HTML report.")
        return

    # Inject scan data into the template
    data_json = _json.dumps(all_results, indent=2)
    html = template.replace("__SCAN_DATA__", data_json)

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
    parser.add_argument("--vuln",          action="store_true", help="Enable CVE vulnerability scan")
    parser.add_argument("--no-api",        action="store_true", help="Use offline CVE table only (no NVD API)")

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

    # ── mDNS probe (runs once before scanning) ─────────────────────
    target_ips = [h["ip"] for h in targets]
    mdns_data  = mdns_probe_hosts(target_ips, timeout=8)

    # ── Scan each host ─────────────────────
    for host in targets:
        target = host["ip"]
        mac    = host.get("mac")

        print(f"\n{Fore.CYAN}{'─'*45}")
        print(f"{Fore.CYAN}Scanning host: {target}" + (f"  [{mac}]" if mac else ""))
        print(f"{Fore.CYAN}{'─'*45}")

        os_name  = os_fingerprint(target)
        dev_info = detect_device(target, mac)
        vendor   = dev_info["vendor"]

        # Merge mDNS results — override device if mDNS found something better
        mdns_info = mdns_data.get(target, {})
        mdns_device   = mdns_info.get("device")
        mdns_hostname = mdns_info.get("hostname")
        mdns_services = mdns_info.get("services", [])

        device = mdns_device or dev_info["device"]
        device_display = device.replace(" (Randomized MAC (Privacy Mode))", "").strip()

        print(f"  OS:       {os_name}")
        print(f"  Device:   {device_display}")
        print(f"  Vendor:   {vendor}")
        if mdns_hostname:
            print(f"  Hostname: {Fore.GREEN}{mdns_hostname}.local")
        if mdns_services:
            print(f"  Services: {', '.join(mdns_services)}")

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
            "hostname":  mdns_hostname or "",
            "services":  mdns_services,
            "tcp_ports": tcp_results,
            "udp_ports": udp_results,
        })

    # ── Vulnerability scan ────────────────────
    if args.vuln:
        use_api = not args.no_api
        all_results = scan_vulnerabilities(all_results, use_api=use_api)

    # ── Save reports ───────────────────────
    save_json(all_results)
    save_html(all_results)


if __name__ == "__main__":
    main()