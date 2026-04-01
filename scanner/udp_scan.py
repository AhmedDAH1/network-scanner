from scapy.all import IP, UDP, ICMP, sr1
from concurrent.futures import ThreadPoolExecutor


def udp_scan_port(target, port, timeout=2):
    """
    Scan a single UDP port.
    Returns the port number if open|filtered, None if closed.
    """
    try:
        packet = IP(dst=target) / UDP(dport=port)
        response = sr1(packet, timeout=timeout, verbose=0)

        if response is None:
            # No response = open|filtered (common for UDP)
            return port

        elif response.haslayer(ICMP):
            icmp_type = response.getlayer(ICMP).type
            icmp_code = response.getlayer(ICMP).code

            # ICMP type 3, code 3 = Port Unreachable = closed
            if icmp_type == 3 and icmp_code == 3:
                return None

            # Other ICMP type 3 codes = filtered by firewall
            if icmp_type == 3 and icmp_code in (1, 2, 9, 10, 13):
                return None

        elif response.haslayer(UDP):
            # Got a UDP response = definitely open
            return port

    except Exception:
        pass

    return None


def udp_scan(target, ports, timeout=2):
    """
    Scan multiple UDP ports using threading.
    Returns list of open|filtered ports.
    """
    open_ports = []

    with ThreadPoolExecutor(max_workers=50) as executor:
        results = executor.map(
            lambda port: udp_scan_port(target, port, timeout), ports
        )

    for port in results:
        if port is not None:
            open_ports.append(port)

    return open_ports