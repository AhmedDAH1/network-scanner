"""
Parsing network data: mDNS packets and interface detection.

mDNS packets are sent by any device on the network, so the parser must never
crash or hang on malformed input. Interface detection had a silent bug
(a misplaced `check=False` made it always fall back to Scapy's default).
"""

import random
import struct
import subprocess

import pytest

from scanner import host_discovery
from scanner.device_detection import classify_vendor, mac_vendor_lookup
from scanner.mdns_probe import _classify, _parse_mdns_packet

# ── mDNS packet parser ────────────────────────────────────────────

def dns_name(*labels):
    return b"".join(bytes([len(x)]) + x.encode() for x in labels) + b"\x00"


def mdns_response(*records):
    header = struct.pack("!HHHHHH", 0, 0x8400, 0, len(records), 0, 0)
    return header + b"".join(records)


def record(name, rtype, rdata):
    return name + struct.pack("!HHIH", rtype, 1, 120, len(rdata)) + rdata


def test_parses_a_record_into_an_ip():
    packet = mdns_response(record(dns_name("pihole", "local"), 1, bytes([10, 0, 0, 10])))

    assert _parse_mdns_packet(packet) == [("pihole.local", 1, "10.0.0.10")]


def test_parses_ptr_record_with_name_compression():
    # The PTR data "tv1" + pointer to offset 12 (the record's own name).
    packet = mdns_response(record(dns_name("_airplay", "_tcp", "local"), 12, b"\x03tv1\xc0\x0c"))

    assert _parse_mdns_packet(packet) == [("_airplay._tcp.local", 12, "tv1._airplay._tcp.local")]


@pytest.mark.parametrize("packet", [
    b"",
    b"\x00" * 11,                                        # shorter than a header
    mdns_response(b"\x05short"),                         # name runs off the end
    mdns_response(dns_name("x") + b"\x00\x01"),          # record header cut off
    struct.pack("!HHHHHH", 0, 0x8400, 0, 50, 0, 0),      # claims 50 records, has none
])
def test_malformed_packets_return_nothing_instead_of_crashing(packet):
    assert _parse_mdns_packet(packet) == []


def test_compression_pointer_loop_does_not_hang():
    # A name that points at itself would loop forever without the visited set.
    looping_name = b"\xc0\x0c"                           # pointer to offset 12: itself
    packet = mdns_response(record(looping_name, 1, bytes(4)))

    _parse_mdns_packet(packet)                           # must return


def test_parser_survives_random_garbage():
    # A tiny fuzz test: 2,000 random packets, fixed seed so it's repeatable.
    rng = random.Random(1337)  # noqa: S311 - fuzz data, not crypto; a fixed seed keeps failures reproducible
    for _ in range(2000):
        _parse_mdns_packet(bytes(rng.randrange(256) for _ in range(rng.randrange(80))))


def test_iphone_service_beats_other_labels():
    info = {"services": {"Apple Device", "iPhone / iPad"}, "hostname": None}
    assert _classify(info) == "iPhone / iPad"


def test_hostname_hint_used_when_no_services():
    assert _classify({"services": set(), "hostname": "ahmeds-macbook"}) == "MacBook"


# ── MAC vendor lookup ─────────────────────────────────────────────

@pytest.mark.parametrize("mac", ["b8:27:eb:9f:12:34", "B8-27-EB-9F-12-34", "b827.eb9f.1234"])
def test_vendor_lookup_works_in_every_notation(mac):
    assert mac_vendor_lookup(mac) == "Raspberry Pi"


def test_randomized_mac_has_no_vendor():
    assert mac_vendor_lookup("da:a1:19:4c:22:7e") == "Randomized MAC (Privacy Mode)"
    assert classify_vendor("Randomized MAC (Privacy Mode)") == "Unknown"


# ── Interface detection ───────────────────────────────────────────

MACOS_IFCONFIG = """\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet 10.8.0.2 --> 10.8.0.1 netmask 0xffffffff
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 172.20.10.2 netmask 0xfffffff0 broadcast 172.20.10.15
"""


@pytest.fixture
def fake_run(monkeypatch):
    """Replace subprocess.run; record the calls and return canned output."""
    calls = []

    def install(stdout):
        def run(args, **kwargs):
            calls.append((args, kwargs))
            return subprocess.CompletedProcess(args, 0, stdout=stdout, stderr="")
        monkeypatch.setattr(host_discovery.subprocess, "run", run)
        return calls
    return install


def test_macos_picks_the_wifi_interface_and_skips_the_vpn(monkeypatch, fake_run):
    # Regression: with the misplaced check=False, the ifconfig call itself
    # raised, the error was swallowed, and Scapy's default was used instead.
    monkeypatch.setattr(host_discovery, "IFCONFIG", "/sbin/ifconfig")
    calls = fake_run(MACOS_IFCONFIG)

    assert host_discovery.get_active_interface() == "en0"
    args, kwargs = calls[0]
    assert args == ["/sbin/ifconfig"]          # absolute path, never looked up via PATH
    assert kwargs["check"] is False


def test_linux_falls_back_to_the_default_route(monkeypatch, fake_run):
    monkeypatch.setattr(host_discovery, "IFCONFIG", None)
    monkeypatch.setattr(host_discovery, "IP_CMD", "/usr/sbin/ip")
    calls = fake_run("default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n")

    assert host_discovery.get_active_interface() == "wlan0"
    assert calls[0][0] == ["/usr/sbin/ip", "route", "show", "default"]
