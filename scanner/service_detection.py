import socket


def grab_banner(ip, port):
    """
    Grab banner from open port
    """
    try:
        sock = socket.socket()
        sock.settimeout(2)

        sock.connect((ip, port))

        banner = sock.recv(1024)

        sock.close()

        return banner.decode().strip()

    except:
        return None


def detect_service(port):
    """
    Identify common services by port
    """
    common_ports = {
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
        8080: "HTTP-Proxy"
    }

    return common_ports.get(port, "Unknown")