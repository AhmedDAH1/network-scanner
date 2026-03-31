import socket

def detect_device(ip):

    try:
        hostname = socket.gethostbyaddr(ip)[0]

        if "router" in hostname.lower():
            return "Router"

        if "iphone" in hostname.lower():
            return "iPhone"

        if "android" in hostname.lower():
            return "Android"

        if "mac" in hostname.lower():
            return "Mac"

        return "Computer"

    except:
        return "Unknown"