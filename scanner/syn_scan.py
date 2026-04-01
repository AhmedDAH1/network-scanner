from scapy.all import IP, TCP, sr1
from concurrent.futures import ThreadPoolExecutor


def _syn_scan_port(ip, port):
    """
    Perform SYN scan on a single port.
    Returns the port number if open, None otherwise.
    """
    try:
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)

        if response and response.haslayer(TCP):
            # SYN-ACK (0x12) means port is open
            if response[TCP].flags == 0x12:
                # Send RST to close the half-open connection
                rst = IP(dst=ip) / TCP(dport=port, flags="R")
                sr1(rst, timeout=1, verbose=0)
                return port
    except Exception:
        pass

    return None


def syn_scan(ip, ports):
    """
    Scan multiple ports using SYN scan with threading.
    Returns list of open ports.
    """
    open_ports = []

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda port: _syn_scan_port(ip, port), ports)

    for port in results:
        if port is not None:
            open_ports.append(port)

    return open_ports