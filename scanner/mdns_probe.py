"""
mdns_probe.py — mDNS/Bonjour device identification.

On macOS, port 5353 is owned by mDNSResponder so raw sockets miss most
traffic. Uses the built-in `dns-sd` CLI on macOS which talks directly to
the daemon. On Linux, falls back to raw socket probe.
"""

import subprocess
import socket
import struct
import time
import re
import platform
from collections import defaultdict

LISTEN_TIME = 8

SERVICE_LABELS = {
    "_airplay._tcp":         "Apple TV / AirPlay",
    "_apple-mobdev._tcp":    "iPhone / iPad",
    "_apple-mobdev2._tcp":   "iPhone / iPad",
    "_companion-link._tcp":  "iPhone / iPad",
    "_rdlink._tcp":          "iPhone / iPad",
    "_sleep-proxy._udp":     "Apple Device",
    "_smb._tcp":             "Mac / Windows PC",
    "_afpovertcp._tcp":      "Mac",
    "_device-info._tcp":     "Apple Device",
    "_device-info._udp":     "Apple Device",
    "_ssh._tcp":             "Linux / Mac",
    "_http._tcp":            "Web Server / Router",
    "_printer._tcp":         "Printer",
    "_ipp._tcp":             "Printer",
    "_googlecast._tcp":      "Chromecast / Google Device",
    "_spotify-connect._tcp": "Speaker / Spotify Device",
    "_raop._tcp":            "AirPlay Speaker",
    "_homekit._tcp":         "HomeKit Device",
    "_hap._tcp":             "HomeKit Device",
    "_miio._udp":            "Xiaomi Device",
    "_androidtvremote._tcp": "Android TV",
    "_roku._tcp":            "Roku",
    "_sonos._tcp":           "Sonos Speaker",
    "_workstation._tcp":     "Linux Workstation",
    "_nfs._tcp":             "NAS / File Server",
}

HOSTNAME_HINTS = [
    (r"iphone",      "iPhone"),
    (r"ipad",        "iPad"),
    (r"macbook",     "MacBook"),
    (r"imac",        "iMac"),
    (r"mac-mini",    "Mac Mini"),
    (r"mac-pro",     "Mac Pro"),
    (r"appletv",     "Apple TV"),
    (r"apple-tv",    "Apple TV"),
    (r"android",     "Android Phone"),
    (r"pixel",       "Google Pixel"),
    (r"samsung",     "Samsung Device"),
    (r"galaxy",      "Samsung Galaxy"),
    (r"router",      "Router"),
    (r"chromecast",  "Chromecast"),
    (r"roku",        "Roku"),
    (r"sonos",       "Sonos Speaker"),
    (r"echo",        "Amazon Echo"),
    (r"nintendo",    "Nintendo Switch"),
    (r"playstation", "PlayStation"),
    (r"xbox",        "Xbox"),
    (r"printer",     "Printer"),
    (r"raspberry",   "Raspberry Pi"),
    (r"synology",    "Synology NAS"),
    (r"qnap",        "QNAP NAS"),
]


def _read_lines(proc, duration):
    lines = []
    deadline = time.time() + duration
    while time.time() < deadline:
        ready = select.select([proc.stdout], [], [], 0.3)[0]
        if ready:
            line = proc.stdout.readline()
            if line:
                lines.append(line)
    return lines


def _dns_sd_browse(timeout):
    results = defaultdict(lambda: {"hostname": None, "services": set(), "raw_names": set()})

    # Step 1: discover service types
    # Output format: "0:00:00.000  Add  3  11 .   _tcp.local.   _airplay"
    # Service type = Instance_Name + "." + proto_col  e.g. _airplay._tcp
    service_types = set()
    try:
        proc = subprocess.Popen(
            ["dns-sd", "-B", "_services._dns-sd._udp", "local"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1
        )
        for line in _read_lines(proc, timeout * 0.4):
            # Match lines like: "Add  3  11 .   _tcp.local.   _airplay"
            m = re.search(r"Add\s+\d+\s+\d+\s+\S+\s+(_(?:tcp|udp))\.local\.\s+(_\S+)", line)
            if m:
                proto    = m.group(1)   # _tcp or _udp
                instance = m.group(2)   # _airplay, _raop, etc.
                service_types.add(f"{instance}.{proto}")
        proc.terminate()
        proc.wait(timeout=2)
    except Exception:
        pass

    if not service_types:
        return results

    # Step 2: find instances for each service type
    for svc in service_types:
        instances = []
        try:
            proc = subprocess.Popen(
                ["dns-sd", "-B", svc, "local"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1
            )
            for line in _read_lines(proc, 2):
                if "Add" in line:
                    # Format: "0:00:00  Add  3  11  local  _airplay._tcp.  Ahmed's iPhone"
                    # Instance name is the LAST field (everything after service type col)
                    m = re.search(r"Add\s+\d+\s+\d+\s+\S+\s+\S+\s+(.+)", line)
                    if m:
                        instance = m.group(1).strip()
                        if instance:
                            instances.append(instance)
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            pass

        # Step 3: resolve each instance to IP
        for instance in instances:
            try:
                proc = subprocess.Popen(
                    ["dns-sd", "-L", instance, svc, "local"],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    text=True, bufsize=1
                )
                hostname = None
                for line in _read_lines(proc, 2):
                    m = re.search(r'can be reached at ([^\s.:]+)\.local', line, re.IGNORECASE)
                    if m:
                        hostname = m.group(1).lower()
                        break
                proc.terminate()
                proc.wait(timeout=2)

                if hostname:
                    try:
                        ip = socket.gethostbyname(f"{hostname}.local")
                        results[ip]["hostname"] = hostname
                        results[ip]["raw_names"].add(instance)
                        label = SERVICE_LABELS.get(svc)
                        if label:
                            results[ip]["services"].add(label)
                    except Exception:
                        pass
            except Exception:
                continue

    return results


def _parse_dns_name(data, offset):
    labels, visited = [], set()
    while offset < len(data):
        if offset in visited:
            break
        visited.add(offset)
        length = data[offset]
        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            offset += 2
            name, _ = _parse_dns_name(data, ptr)
            labels.append(name)
            break
        else:
            offset += 1
            labels.append(data[offset:offset+length].decode("utf-8", errors="ignore"))
            offset += length
    return ".".join(labels), offset


def _parse_mdns_packet(data):
    records = []
    try:
        if len(data) < 12:
            return records
        qdcount = struct.unpack_from("!H", data, 4)[0]
        ancount = struct.unpack_from("!H", data, 6)[0]
        arcount = struct.unpack_from("!H", data, 10)[0]
        offset  = 12
        for _ in range(qdcount):
            _, offset = _parse_dns_name(data, offset)
            offset += 4
        for _ in range(ancount + arcount):
            if offset >= len(data):
                break
            name, offset = _parse_dns_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype, _, _, rdlen = struct.unpack_from("!HHIH", data, offset)
            offset += 10
            rdata = data[offset:offset+rdlen]
            offset += rdlen
            rdata_str = ""
            if rtype == 1 and len(rdata) == 4:
                rdata_str = socket.inet_ntoa(rdata)
            elif rtype == 12:
                rdata_str, _ = _parse_dns_name(data, offset - rdlen)
            if name:
                records.append((name, rtype, rdata_str))
    except Exception:
        pass
    return records


def _raw_socket_probe(timeout):
    MDNS_ADDR, MDNS_PORT = "224.0.0.251", 5353
    results = defaultdict(lambda: {"hostname": None, "services": set(), "raw_names": set()})
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass
        sock.bind(("", MDNS_PORT))
        mreq = struct.pack("4sL", socket.inet_aton(MDNS_ADDR), socket.INADDR_ANY)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        sock.settimeout(1.0)
        header = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
        qname  = b"".join(bytes([len(p)]) + p.encode() for p in ["_services","_dns-sd","_udp","local"]) + b"\x00"
        query  = header + qname + struct.pack("!HH", 12, 0x8001)
        ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        ss.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        ss.sendto(query, (MDNS_ADDR, MDNS_PORT))
        ss.close()
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
                src_ip = addr[0]
                for name, rtype, rdata in _parse_mdns_packet(data):
                    nl = name.lower()
                    results[src_ip]["raw_names"].add(name)
                    if rtype == 12:
                        for svc, label in SERVICE_LABELS.items():
                            if svc in nl:
                                results[src_ip]["services"].add(label)
                    if ".local" in nl and not results[src_ip]["hostname"]:
                        results[src_ip]["hostname"] = nl.replace(".local","").split(".")[0]
            except socket.timeout:
                continue
        sock.close()
    except Exception:
        pass
    return results


def _classify(info):
    device = None
    for label in info["services"]:
        if not device:
            device = label
        if "iPhone" in label or "iPad" in label:
            device = label
            break
    if not device and info["hostname"]:
        for pattern, label in HOSTNAME_HINTS:
            if re.search(pattern, info["hostname"].lower()):
                device = label
                break
    return device


def mdns_probe(timeout=LISTEN_TIME):
    is_mac = platform.system() == "Darwin"
    raw    = _dns_sd_browse(timeout) if is_mac else _raw_socket_probe(timeout)
    results = {}
    for ip, info in raw.items():
        results[ip] = {
            "hostname":  info["hostname"],
            "device":    _classify(info),
            "services":  sorted(info["services"]),
            "raw_names": sorted(info["raw_names"]),
        }
    return results


def mdns_probe_hosts(targets, timeout=LISTEN_TIME):
    print(f"[+] mDNS probe ({timeout}s) — listening for device announcements...")
    all_results = mdns_probe(timeout=timeout)
    filtered    = {ip: all_results[ip] for ip in targets if ip in all_results}
    found       = sum(1 for v in filtered.values() if v.get("device") or v.get("hostname"))
    print(f"[+] mDNS identified {found}/{len(targets)} host(s).")
    return filtered