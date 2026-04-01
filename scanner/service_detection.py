import socket


COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def grab_banner(ip, port):
    """
    Attempt to grab a service banner from an open port.
    """
    try:
        sock = socket.socket()
        sock.settimeout(2)
        sock.connect((ip, port))
        banner = sock.recv(1024)
        sock.close()
        return banner.decode(errors="ignore").strip()
    except Exception:
        return None


def detect_service(ip, port):
    """
    Identify service by port number, then try banner grabbing.
    Returns a dict with 'service' and 'banner' keys.
    """
    service = COMMON_PORTS.get(port, "Unknown")
    banner = grab_banner(ip, port)

    return {
        "port": port,
        "service": service,
        "banner": banner,
    }