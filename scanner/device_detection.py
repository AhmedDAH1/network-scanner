import socket

try:
    from manuf import manuf as manuf_lib
    _mac_parser = manuf_lib.MacParser()
except Exception:
    _mac_parser = None


# Curated OUI prefix → vendor name (covers common vendors manuf DB may miss)
OUI_TABLE = {
    "68:9a:21": "Netgear",
    "88:6e:dd": "TP-Link",
    "00:14:6c": "Netgear",
    "20:e5:2a": "Netgear",
    "a0:04:60": "Netgear",
    "c0:ff:d4": "Netgear",
    "9c:d3:6d": "TP-Link",
    "f4:f2:6d": "TP-Link",
    "50:c7:bf": "TP-Link",
    "b0:95:75": "TP-Link",
    "a4:08:f5": "TP-Link",
    "d8:0d:17": "TP-Link",
    "18:a6:f7": "TP-Link",
    "14:cc:20": "TP-Link",
    "b4:fb:e4": "TP-Link",
    "ac:84:c9": "TP-Link",
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "00:17:88": "Philips Hue",
    "ec:b5:fa": "Apple",
    "f0:18:98": "Apple",
    "a4:c3:f0": "Apple",
    "3c:06:30": "Apple",
    "00:1b:63": "Apple",
    "ac:de:48": "Apple",
    "28:cf:e9": "Apple",
    "f4:f1:5a": "Google",
    "54:60:09": "Google",
    "94:eb:2c": "Google",
    "3c:28:6d": "Amazon",
    "fc:a6:67": "Amazon",
    "00:fc:8b": "Amazon",
    "b4:7c:9c": "Samsung",
    "8c:77:12": "Samsung",
    "cc:07:ab": "Samsung",
    "00:1e:c2": "D-Link",
    "1c:7e:e5": "D-Link",
    "c8:be:19": "D-Link",
    "00:18:e7": "Cisco",
    "00:1b:d4": "Cisco",
    "00:1c:58": "Cisco",
    "dc:9f:db": "Ubiquiti",
    "24:a4:3c": "Ubiquiti",
    "f0:9f:c2": "Ubiquiti",
    "00:30:48": "Supermicro",
    "00:25:90": "Supermicro",
}


# Keyword hints to classify device type from vendor name
VENDOR_KEYWORDS = {
    "Apple":        "Apple Device",
    "iPhone":       "iPhone",
    "iPad":         "iPad",
    "Samsung":      "Samsung Device",
    "Google":       "Google Device",
    "Raspberry":    "Raspberry Pi",
    "Intel":        "PC / Laptop",
    "Dell":         "PC / Laptop",
    "Lenovo":       "PC / Laptop",
    "HP":           "PC / Laptop",
    "ASUSTek":      "PC / Laptop",
    "Cisco":        "Cisco Network Device",
    "Netgear":      "Router / AP",
    "TP-Link":      "Router / AP",
    "D-Link":       "Router / AP",
    "Ubiquiti":     "Router / AP",
    "AVM":          "Router / AP",
    "Aruba":        "Router / AP",
    "Synology":     "NAS",
    "QNAP":         "NAS",
    "Amazon":       "Amazon Device",
    "Roku":         "Streaming Device",
    "Sony":         "Sony Device",
    "LG":           "Smart TV",
    "TCL":          "Smart TV",
    "Xiaomi":       "Xiaomi Device",
    "Huawei":       "Huawei Device",
    "OnePlus":      "Android Phone",
    "Motorola":     "Android Phone",
    "Nintendo":     "Nintendo Console",
    "Microsoft":    "Microsoft Device",
    "VMware":       "Virtual Machine",
    "PCS Systemtechnik": "PC / Laptop",
}


def is_randomized_mac(mac):
    """
    Check if a MAC address is locally administered (randomized).
    Randomized MACs have the second-least-significant bit of the first octet set.
    """
    if not mac:
        return False
    first_octet = int(mac.split(":")[0], 16)
    return bool(first_octet & 0x02)


def mac_vendor_lookup(mac):
    """
    Look up vendor from MAC address using local OUI database (offline, via manuf).
    Returns vendor string or None if unknown/randomized.
    """
    if not mac:
        return None

    if is_randomized_mac(mac):
        return "Randomized MAC (Privacy Mode)"

    # Check curated OUI table first (covers vendors missing from manuf DB)
    prefix = mac.lower()[:8]
    if prefix in OUI_TABLE:
        return OUI_TABLE[prefix]

    # Fall back to manuf offline DB
    if _mac_parser is not None:
        try:
            vendor = _mac_parser.get_manuf(mac)
            if vendor:
                return vendor
        except Exception:
            pass

    return None


def classify_vendor(vendor):
    """
    Map a vendor string to a human-readable device type.
    """
    if not vendor:
        return None

    for keyword, device_type in VENDOR_KEYWORDS.items():
        if keyword.lower() in vendor.lower():
            return device_type

    return f"Unknown ({vendor})"


def detect_device(ip, mac=None):
    """
    Detect device type using:
    1. MAC vendor lookup (if MAC is available)
    2. Hostname-based hints (fallback)
    Returns a dict with 'device' and 'vendor' keys.
    """
    vendor  = None
    device  = "Unknown"

    # Try MAC vendor lookup first
    if mac:
        vendor = mac_vendor_lookup(mac)
        if vendor:
            classified = classify_vendor(vendor)
            if classified:
                device = classified

    # Hostname fallback
    if device == "Unknown":
        try:
            hostname = socket.gethostbyaddr(ip)[0].lower()
            if "router"  in hostname: device = "Router"
            elif "iphone" in hostname: device = "iPhone"
            elif "android"in hostname: device = "Android Phone"
            elif "mac"    in hostname: device = "Mac"
            elif "tv"     in hostname: device = "Smart TV"
        except Exception:
            pass

    return {
        "device": device,
        "vendor": vendor or "Unknown",
    }