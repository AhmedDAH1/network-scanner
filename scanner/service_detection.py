"""
service_detection.py — name a service by port and read its banner.
"""

import socket

from scanner import __version__
from scanner.banner_parser import clean_banner, http_server_header, identify_software

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
    587: "SMTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP-Alt",
    8008: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt",
    27017: "MongoDB",
}

# Web servers say nothing until they receive a request, so these ports get a
# HEAD request and the Server header becomes the banner.
HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8888}


def _recv_some(sock, limit=4096):
    """Read up to `limit` bytes until the peer stops sending or times out."""
    chunks, size = [], 0
    while size < limit:
        try:
            chunk = sock.recv(min(1024, limit - size))
        except TimeoutError:
            break
        if not chunk:
            break
        chunks.append(chunk)
        size += len(chunk)
    return b"".join(chunks)


def grab_banner(ip, port, timeout=2):
    """
    Read a service banner from an open TCP port.
    Returns a cleaned, printable string, or None.
    """
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            if port in HTTP_PORTS:
                request = (
                    f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n"
                    f"User-Agent: netscan/{__version__}\r\nConnection: close\r\n\r\n"
                )
                sock.sendall(request.encode("ascii"))
                return http_server_header(_recv_some(sock))
            return clean_banner(sock.recv(1024))
    except OSError:          # refused, reset, timed out, unreachable
        return None


def detect_service(ip, port):
    """
    Identify the service on an open port.
    Returns {port, service, banner, product, version}.
    """
    service = COMMON_PORTS.get(port, "Unknown")
    banner = grab_banner(ip, port)
    return {
        "port": port,
        "service": service,
        "banner": banner,
        **identify_software(service, banner),
    }
