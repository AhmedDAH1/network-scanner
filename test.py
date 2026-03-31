import json
import argparse
import threading
from tabulate import tabulate
from tqdm import tqdm
from colorama import init, Fore, Style

init(autoreset=True)

from scanner.host_discovery import icmp_scan
from scanner.syn_scan import syn_scan_ports
from scanner.service_detection import detect_service, grab_banner
from scanner.os_fingerprint import os_fingerprint
from scanner.device_detection import detect_device


def print_banner():
    banner = f"""
{Fore.CYAN}
###########################################
#        NETWORK SCANNER v1.0            #
#        Author: Ahmed Dahdouh           #
###########################################
{Style.RESET_ALL}
"""
    print(banner)


def scan_host(host, port_range, results):
    print(f"{Fore.YELLOW}Scanning host: {host}{Style.RESET_ALL}")

    os_name = os_fingerprint(host)
    device = detect_device(host)

    print(f"{Fore.BLUE}Operating System: {os_name}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Device Type: {device}{Style.RESET_ALL}")

    open_ports = syn_scan_ports(host, port_range)
    table_data = []

    host_result = {
        "host": host,
        "os": os_name,
        "device": device,
        "ports": []
    }

    for port in open_ports:
        service = detect_service(port)
        banner = grab_banner(host, port)

        table_data.append([port, service, banner or ""])

        host_result["ports"].append({
            "port": port,
            "service": service,
            "banner": banner
        })

    if table_data:
        print(tabulate(
            table_data,
            headers=[Fore.MAGENTA + "Port", "Service", "Banner" + Style.RESET_ALL],
            tablefmt="fancy_grid"
        ))
    else:
        print(Fore.RED + "No open ports found" + Style.RESET_ALL)

    results.append(host_result)
    print("\n" + "-" * 50 + "\n")


def generate_html(results):

    html = """
    <html>
    <head>
        <title>Network Scan Report</title>
        <style>
        body { font-family: Arial; }
        table { border-collapse: collapse; width: 60%; }
        th, td { border: 1px solid black; padding: 8px; }
        th { background-color: #f2f2f2; }
        </style>
    </head>
    <body>
    <h1>Network Scan Results</h1>
    """

    for host in results:
        html += f"<h2>{host['host']}</h2>"
        html += f"<p><b>OS:</b> {host['os']}</p>"
        html += f"<p><b>Device:</b> {host.get('device','Unknown')}</p>"

        html += "<table>"
        html += "<tr><th>Port</th><th>Service</th><th>Banner</th></tr>"

        for port in host["ports"]:
            html += f"""
            <tr>
                <td>{port['port']}</td>
                <td>{port['service']}</td>
                <td>{port['banner']}</td>
            </tr>
            """

        html += "</table>"

    html += "</body></html>"

    with open("scan_report.html", "w") as f:
        f.write(html)


def main():

    print_banner()

    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument("-t", "--target", help="Target IP address")
    parser.add_argument("-n", "--network", help="Network range")
    parser.add_argument("-p", "--ports", help="Port range (example: 1-1000)")

    args = parser.parse_args()

    port_range = range(1, 1024)

    if args.ports:
        start, end = args.ports.split("-")
        port_range = range(int(start), int(end))

    if args.network:
        print(f"Discovering hosts on {args.network}...")
        hosts = icmp_scan(args.network)

    elif args.target:
        hosts = [args.target]

    else:
        print("Please provide target (-t) or network (-n)")
        return

    print(f"\nScanning {len(hosts)} hosts\n")

    results = []
    threads = []

    for host in tqdm(hosts, desc="Scanning hosts", ncols=100, colour="green"):
        thread = threading.Thread(
            target=scan_host,
            args=(host, port_range, results)
        )

        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # Save JSON
    with open("scan_results.json", "w") as f:
        json.dump(results, f, indent=4)

    # Generate HTML report
    generate_html(results)

    print(Fore.CYAN + "\nResults saved to scan_results.json")
    print(Fore.CYAN + "HTML report saved to scan_report.html\n")


if __name__ == "__main__":
    main()