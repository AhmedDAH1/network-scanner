"""
Turn a pcap into the log records the Sigma rules run on.

Zeek isn't needed: this builds Zeek-format conn records (the fields the
port-scan correlation uses) and web server access-log records from the same
captured packets the Suricata rules are tested with.

    python detections/tests/pcap_to_logs.py detections/tests/netscan_scan.pcap

Zeek connection states produced (the subset the rules depend on):
    S0   SYN seen, no reply
    REJ  SYN answered with RST (port closed)
    SF   handshake completed (any later teardown)
"""

import sys
from datetime import datetime, timezone

from scapy.all import IP, TCP, Raw, rdpcap

SYN, RST, ACK = 0x02, 0x04, 0x10


def _iso(ts):
    return datetime.fromtimestamp(float(ts), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def conn_records(packets):
    """One Zeek-style conn record per TCP connection attempt."""
    flows = {}                       # (orig, orig_port, resp, resp_port) -> state
    for pkt in packets:
        if IP not in pkt or TCP not in pkt:
            continue
        ip, tcp = pkt[IP], pkt[TCP]
        flags = int(tcp.flags)
        forward = (ip.src, tcp.sport, ip.dst, tcp.dport)
        reverse = (ip.dst, tcp.dport, ip.src, tcp.sport)

        if flags & SYN and not flags & ACK:              # a new attempt from the originator
            flows[forward] = {"ts": pkt.time, "replied": None}
        elif reverse in flows and flows[reverse]["replied"] is None:
            if flags & SYN and flags & ACK:
                flows[reverse]["replied"] = "synack"
            elif flags & RST:
                flows[reverse]["replied"] = "rst"

    states = {None: "S0", "rst": "REJ", "synack": "SF"}
    return [
        {"timestamp": _iso(f["ts"]), "proto": "tcp", "conn_state": states[f["replied"]],
         "id.orig_h": o, "id.orig_p": op, "id.resp_h": r, "id.resp_p": rp}
        for (o, op, r, rp), f in flows.items()
    ]


def webserver_records(packets):
    """One access-log record per HTTP request seen in the capture."""
    records = []
    for pkt in packets:
        if IP not in pkt or TCP not in pkt or Raw not in pkt:
            continue
        payload = bytes(pkt[Raw].load)
        head, _, _ = payload.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) != 3 or not parts[2].startswith("HTTP/"):
            continue
        headers = {k.strip().lower(): v.strip() for k, _, v in (line.partition(":") for line in lines[1:])}
        records.append({
            "timestamp": _iso(pkt.time), "c-ip": pkt[IP].src,
            "cs-method": parts[0], "cs-uri-stem": parts[1],
            "cs-user-agent": headers.get("user-agent", ""),
        })
    return records


def logs_from_pcap(path):
    packets = rdpcap(path)
    return conn_records(packets) + webserver_records(packets)


if __name__ == "__main__":
    import json
    for record in logs_from_pcap(sys.argv[1]):
        print(json.dumps(record))
