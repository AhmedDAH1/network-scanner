#!/usr/bin/env python3

import argparse
import base64
import json
import os
import re
import sys
from datetime import datetime, timezone

from colorama import Fore, init
from tabulate import tabulate

from scanner import __version__
from scanner.device_detection import detect_device
from scanner.fileutil import give_to_invoking_user, write_json_atomic
from scanner.host_discovery import discover_hosts
from scanner.mdns_probe import mdns_probe_hosts
from scanner.os_fingerprint import os_fingerprint
from scanner.service_detection import detect_service
from scanner.syn_scan import syn_scan
from scanner.udp_scan import udp_scan
from scanner.vuln_scan import scan_vulnerabilities

init(autoreset=True)


# ──────────────────────────────────────────
# Report Helpers
# ──────────────────────────────────────────

def save_json(all_results, path="scan_results.json"):
    write_json_atomic(path, all_results, indent=4)
    print(f"\n{Fore.GREEN}[+] JSON report saved → {path}")


def json_for_script_tag(data):
    """Serialize data as JSON that is safe to embed inside a <script> tag.

    json.dumps alone is NOT enough: a banner containing "</script>" would end
    the script block early and let the rest of the banner run as HTML. JSON
    allows \\uXXXX escapes, so we replace <, > and & with them. The browser's
    JSON/JS parser turns them back into the original characters, but the HTML
    parser never sees a literal "<", so it can't find a closing tag.
    """
    return (
        json.dumps(data, indent=2)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )


APP_DIR = os.path.dirname(os.path.abspath(__file__))

# Fonts embedded into the HTML report, so it looks the same offline and
# when it's emailed to someone who doesn't have them installed.
REPORT_FONTS = [
    ("Atkinson Next", 400, "atkinson-hyperlegible-next-latin-400-normal.woff2"),
    ("Atkinson Next", 600, "atkinson-hyperlegible-next-latin-600-normal.woff2"),
    ("Atkinson Next", 700, "atkinson-hyperlegible-next-latin-700-normal.woff2"),
    ("Atkinson Mono", 400, "atkinson-hyperlegible-mono-latin-400-normal.woff2"),
    ("Atkinson Mono", 600, "atkinson-hyperlegible-mono-latin-600-normal.woff2"),
]


def embedded_font_css():
    """@font-face rules with the font files inlined as base64 data URLs.

    Returns "" if the font files are missing; the report then falls back to
    system fonts instead of failing.
    """
    rules = []
    for family, weight, filename in REPORT_FONTS:
        try:
            with open(os.path.join(APP_DIR, "static", "fonts", filename), "rb") as f:
                data = base64.b64encode(f.read()).decode("ascii")
        except OSError:
            continue
        rules.append(
            f'@font-face {{ font-family: "{family}"; font-weight: {weight}; font-display: swap; '
            f'src: url(data:font/woff2;base64,{data}) format("woff2"); }}'
        )
    return "\n".join(rules)


def save_html(all_results, meta=None, path="scan_report.html"):
    # Load the HTML template
    template_path = os.path.join(APP_DIR, "report_template.html")
    try:
        with open(template_path, encoding="utf-8") as f:
            template = f.read()
    except FileNotFoundError:
        print(f"{Fore.RED}[-] report_template.html not found — skipping HTML report.")
        return

    values = {
        "FONT_FACES": embedded_font_css(),
        "SCAN_DATA":  json_for_script_tag(all_results),   # escaped for a <script> context
        "SCAN_META":  json_for_script_tag(meta or {}),
    }
    # One pass over the TEMPLATE only. With chained str.replace() calls, a
    # banner containing the text "__SCAN_META__" would be replaced again by a
    # later call; re.sub never re-scans text it has already inserted.
    html = re.sub(r"__(FONT_FACES|SCAN_DATA|SCAN_META)__", lambda m: values[m.group(1)], template)

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    give_to_invoking_user(path)   # don't leave a root-owned report behind after sudo
    print(f"{Fore.GREEN}[+] HTML report saved → {path}")


# ──────────────────────────────────────────
# Main
# ──────────────────────────────────────────

def print_banner():
    print(Fore.CYAN + f"""
###########################################
#  NetScan {__version__:<31}#
#  Author: Ahmed Dahdouh                  #
###########################################
""")


def main():
    # The banner is for people at a terminal. When the output goes into
    # another program (like the web dashboard), skip it.
    if sys.stdout.isatty():
        print_banner()

    parser = argparse.ArgumentParser(prog="netscan", description=f"NetScan {__version__}: network discovery, port scanning and CVE lookup")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

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
            info = detect_service(target, port)   # {port, service, banner, product, version}
            tcp_results.append(info)

        if tcp_results:
            table_data = [
                (r["port"], r["service"],
                 " ".join(x for x in (r.get("product"), r.get("version")) if x),
                 r["banner"] or "")
                for r in tcp_results
            ]
            print(tabulate(table_data, headers=["Port", "Service", "Software", "Banner"], tablefmt="fancy_grid"))
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
    save_html(all_results, meta={
        "target":    args.network or args.target,
        "ports":     args.ports,
        "generated": datetime.now(timezone.utc).isoformat(),
        "tool":      "NetScan",
    })


if __name__ == "__main__":
    main()
