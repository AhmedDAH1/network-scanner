"""
Tests for build_scan_args(): the validator between the browser and the scanner.

Everything in the query string is untrusted, and the result becomes the
command line of a process that runs as root. So this function gets the most
thorough tests in the project:

  1. valid input is accepted and normalised
  2. boundaries (the largest network, the lowest/highest port) behave exactly
  3. hostile or malformed input is always rejected
"""

import pytest

from web_app import ScanRequestError, build_scan_args

# ── 1. Valid input ────────────────────────────────────────────────
# Every test has the same shape (Arrange, Act, Assert):
#   set up the input, call the function once, check the result.


def test_single_target_and_single_port():
    # Arrange
    target, port = "10.0.0.1", "80"

    # Act
    args = build_scan_args(network="", target=target, ports=port)

    # Assert: a single port becomes a one-port range, which the CLI expects
    assert args == ["-t", "10.0.0.1", "-p", "80-80"]


def test_network_is_normalised_to_its_base_address():
    # Someone types their own IP with a mask; we scan the whole network.
    args = build_scan_args(network="192.168.1.77/24", target="", ports="1-1000")

    assert args == ["-n", "192.168.1.0/24", "-p", "1-1000"]


def test_whitespace_is_trimmed_and_ports_default_to_1_1000():
    args = build_scan_args(network="", target="  10.0.0.1  ", ports="")

    assert args == ["-t", "10.0.0.1", "-p", "1-1000"]


def test_option_flags_are_added_at_the_end():
    args = build_scan_args("", "10.0.0.1", "1-2", udp=True, vuln=True, no_api=True)

    assert args[-3:] == ["--udp", "--vuln", "--no-api"]


# ── 2. Boundaries ─────────────────────────────────────────────────
# Bugs hide at the edges, so test the exact limit AND one step past it.


def test_slash_16_is_the_largest_network_allowed():
    assert build_scan_args("10.0.0.0/16", "", "80")[1] == "10.0.0.0/16"

    with pytest.raises(ScanRequestError, match="too large"):
        build_scan_args("10.0.0.0/15", "", "80")


@pytest.mark.parametrize("ports", ["1", "65535", "1-65535"])
def test_lowest_and_highest_ports_are_allowed(ports):
    build_scan_args("", "10.0.0.1", ports)   # must not raise


# ── 3. Hostile or malformed input ─────────────────────────────────
# parametrize runs the same test once per value, and the report shows
# exactly which value failed.


@pytest.mark.parametrize("target", [
    "-p",                     # would be read as a CLI option (argument injection)
    "--udp",
    "10.0.0.1; rm -rf ~",     # shell metacharacters
    "$(id)",
    "10.0.0.1 -p 1-65535",    # smuggling extra arguments
    "10.0.0.256",             # not a real address
    "example.com",            # host names aren't supported
    "::1",                    # IPv6 isn't supported
])
def test_invalid_targets_are_rejected(target):
    with pytest.raises(ScanRequestError, match="Invalid target"):
        build_scan_args(network="", target=target, ports="80")


@pytest.mark.parametrize("network", [
    "0.0.0.0/0",              # the whole internet
    "10.0.0.0/8",             # far too large
    "10.0.0.0/33",            # impossible mask
    "10.0.0.0/24 --vuln",
    "not-a-network/24",
])
def test_invalid_networks_are_rejected(network):
    with pytest.raises(ScanRequestError):
        build_scan_args(network=network, target="", ports="80")


@pytest.mark.parametrize("ports", [
    "0", "0-10",              # port 0 doesn't exist
    "1-65536",                # above the highest port
    "10-5",                   # backwards range
    "80,443",                 # lists aren't supported
    "-1",
    "1-1000 --vuln",          # smuggling an extra flag
    "abc",
])
def test_invalid_port_ranges_are_rejected(ports):
    with pytest.raises(ScanRequestError, match="[Pp]ort"):
        build_scan_args(network="", target="10.0.0.1", ports=ports)


@pytest.mark.parametrize(("network", "target"), [
    ("", ""),                          # neither
    ("10.0.0.0/24", "10.0.0.1"),       # both
])
def test_exactly_one_of_network_or_target_is_required(network, target):
    with pytest.raises(ScanRequestError, match="either"):
        build_scan_args(network=network, target=target, ports="80")
