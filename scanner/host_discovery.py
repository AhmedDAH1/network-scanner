from scapy.all import ARP, Ether, srp, IP, ICMP, sr1
import ipaddress


def arp_scan(target_ip):
    """
    Scan network using ARP requests
    """
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")

    packet = ether / arp

    result = srp(packet, timeout=2, verbose=0)[0]

    clients = []

    for sent, received in result:
        clients.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })

    return clients


def icmp_scan(network):
    """
    Discover hosts using ICMP ping
    """
    live_hosts = []

    for ip in ipaddress.IPv4Network(network, strict=False):
        try:
            packet = IP(dst=str(ip)) / ICMP()

            response = sr1(packet, timeout=1, verbose=0)

            if response:
                live_hosts.append(str(ip))

        except:
            pass

    return live_hosts