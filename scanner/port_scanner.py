import socket
from concurrent.futures import ThreadPoolExecutor

def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            return port
    except:
        pass

def scan_ports(ip, ports):
    open_ports = []

    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda port: scan_port(ip, port), ports)

    for port in results:
        if port:
            open_ports.append(port)

    return open_ports