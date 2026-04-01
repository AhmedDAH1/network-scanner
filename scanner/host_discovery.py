from scapy.all import ARP, Ether, srp, IP, ICMP, sr1, conf, get_if_list
import ipaddress
import subprocess
import re


def get_active_interface():
    """
    Detect the active physical network interface on macOS/Linux.
    Skips VPN/tunnel interfaces (utun*, tun*, ppp*).
    On macOS Wi-Fi is usually 'en0', on Linux 'eth0' or 'wlan0'.
    """
    # Interfaces to skip — VPN tunnels, loopback, virtual
    skip_prefixes = ("utun", "tun", "tap", "ppp", "lo", "veth", "docker", "br-", "vmnet")

    try:
        # macOS: list all interfaces with ifconfig and find one with a LAN IP
        result = subprocess.run(
            ["ifconfig"],
            capture_output=True, text=True
        )
        current_iface = None
        for line in result.stdout.splitlines():
            # New interface block
            iface_match = re.match(r"^(\S+):", line)
            if iface_match:
                current_iface = iface_match.group(1)
            # Look for a private LAN IP (192.168.x.x or 10.x.x.x or 172.16-31.x.x)
            if current_iface and "inet " in line:
                ip_match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", line)
                if ip_match:
                    ip = ip_match.group(1)
                    is_lan = (
                        ip.startswith("192.168.") or
                        ip.startswith("10.")      or
                        re.match(r"172\.(1[6-9]|2\d|3[01])\.", ip)
                    )
                    is_skip = any(current_iface.startswith(p) for p in skip_prefixes)
                    if is_lan and not is_skip:
                        print(f"[+] Detected active interface: {current_iface} ({ip})")
                        return current_iface
    except Exception:
        pass

    try:
        # Linux fallback: parse 'ip route'
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True
        )
        match = re.search(r"dev (\S+)", result.stdout)
        if match:
            iface = match.group(1)
            if not any(iface.startswith(p) for p in skip_prefixes):
                print(f"[+] Detected active interface: {iface}")
                return iface
    except Exception:
        pass

    # Last resort: use Scapy's default
    iface = conf.iface
    print(f"[+] Using Scapy default interface: {iface}")
    return iface


def arp_scan(target_ip, iface=None):
    """
    Scan network using ARP requests on the correct interface.
    """
    if iface is None:
        iface = get_active_interface()

    arp    = ARP(pdst=target_ip)
    ether  = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    try:
        result = srp(packet, iface=iface, timeout=2, verbose=0)[0]
    except Exception as e:
        print(f"[-] ARP scan failed on {iface}: {e}")
        return []

    clients = []
    for sent, received in result:
        clients.append({
            "ip":  received.psrc,
            "mac": received.hwsrc
        })

    return clients


def icmp_scan(network):
    """
    Discover hosts using ICMP ping (fallback for when ARP fails).
    Returns list of {ip, mac} dicts — mac is None since ICMP can't get MACs.
    """
    live_hosts = []

    for ip in ipaddress.IPv4Network(network, strict=False):
        try:
            packet   = IP(dst=str(ip)) / ICMP()
            response = sr1(packet, timeout=1, verbose=0)

            if response:
                live_hosts.append({"ip": str(ip), "mac": None})
        except Exception:
            pass

    return live_hosts


def discover_hosts(network):
    """
    Discover hosts — ARP first (faster, more reliable), ICMP fallback.
    Returns list of {ip, mac} dicts.
    """
    iface = get_active_interface()

    print(f"[+] Running ARP Scan on interface {iface}...")
    arp_results = arp_scan(network, iface=iface)

    if arp_results:
        print(f"[+] ARP scan found {len(arp_results)} host(s).")
        return arp_results  # already {ip, mac} dicts

    print("[-] ARP scan found no hosts, falling back to ICMP scan...")
    return icmp_scan(network)