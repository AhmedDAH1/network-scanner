import socket

from scapy.all import ICMP, IP, sr1


def os_fingerprint(target):

    try:
        packet = IP(dst=target)/ICMP()
        response = sr1(packet, timeout=2, verbose=0)

        if response is None:
            return "Unknown"

        ttl = response.ttl

        # OS detection based on TTL
        if ttl <= 64:
            os = "Linux / macOS"
        elif ttl <= 128:
            os = "Windows"
        else:
            os = "Unknown"

        # Try device detection
        try:
            hostname = socket.gethostbyaddr(target)[0]

            if "router" in hostname.lower():
                return "Router"

            if "iphone" in hostname.lower():
                return "iPhone"

            if "android" in hostname.lower():
                return "Android"

        except Exception:
            pass

        return os

    except Exception:
        return "Unknown"
