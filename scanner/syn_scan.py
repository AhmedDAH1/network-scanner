from scapy.all import IP, TCP, sr1
from concurrent.futures import ThreadPoolExecutor

def syn_scan(ip, port):
    """
    Perform SYN scan on a single port
    """
    try:
        packet = IP(dst=ip)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)

        if response:
            if response.haslayer(TCP):
                # SYN-ACK means port is open
                if response[TCP].flags == 0x12:
                    return port
    except:
        pass


def syn_scan_ports(ip, ports):
    """
    Scan multiple ports using threading
    """
    open_ports = []

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda port: syn_scan(ip, port), ports)

    for port in results:
        if port:
            open_ports.append(port)

    return open_ports