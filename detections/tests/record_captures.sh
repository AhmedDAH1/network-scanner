#!/usr/bin/env bash
# Re-record the test captures in this folder. Linux only, run as root.
#
# Builds a two-host lab with network namespaces: the scanner (10.99.0.1) and
# a target (10.99.0.10) running a web server and an SSH-style banner. Then:
#   netscan_scan.pcap      a real NetScan scan of ports 1-100
#   benign_baseline.pcap   normal traffic that must not alert, including
#                          active-FTP-style connections from source port 20
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

cleanup() {
    pkill -f "http.server 80 --bind 10.99.0.10" 2>/dev/null || true
    pkill -f "fake-ssh-banner" 2>/dev/null || true
    ip netns del lab 2>/dev/null || true
    ip link del veth-scan 2>/dev/null || true
}
cleanup
trap cleanup EXIT

ip netns add lab
ip link add veth-scan type veth peer name veth-lab
ip link set veth-lab netns lab
ip addr add 10.99.0.1/24 dev veth-scan && ip link set veth-scan up
ip netns exec lab ip addr add 10.99.0.10/24 dev veth-lab
ip netns exec lab ip link set veth-lab up
ip netns exec lab ip link set lo up
ip netns exec lab python3 -m http.server 80 --bind 10.99.0.10 >/dev/null 2>&1 &
ip netns exec lab python3 -c '
import socket  # fake-ssh-banner
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("10.99.0.10", 22)); s.listen(50)
while True:
    c, _ = s.accept()
    c.sendall(b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n"); c.close()
' >/dev/null 2>&1 &
sleep 1

record() {   # record <file> <command...>
    local out="$1"; shift
    tcpdump -i veth-scan -U -w "$out" not port 5353 >/dev/null 2>&1 &
    local pid=$!; sleep 1
    "$@"
    sleep 1; kill "$pid"; wait "$pid" 2>/dev/null || true
}

scan() {
    (cd "$(mktemp -d)" && python3 "$REPO/scanner_cli.py" -t 10.99.0.10 -p 1-100 --vuln --no-api >/dev/null)
}

benign() {
    for _ in $(seq 1 10); do curl -s -o /dev/null http://10.99.0.10/; done
    curl -s -o /dev/null -I http://10.99.0.10/
    curl -s -o /dev/null -I -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15" http://10.99.0.10/
    python3 -c "import urllib.request; urllib.request.urlopen(urllib.request.Request('http://10.99.0.10/', method='HEAD')).read()"
    for p in 22 22 22 23 25 443 8443; do timeout 1 bash -c "exec 3<>/dev/tcp/10.99.0.10/$p" 2>/dev/null || true; done
    python3 -c '
import socket
for dport in (22, 80, 21):   # active-mode FTP data connections come FROM port 20
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("10.99.0.1", 20)); s.settimeout(1)
    try: s.connect(("10.99.0.10", dport))
    except OSError: pass
    s.close()
'
}

record "$HERE/netscan_scan.pcap" scan
record "$HERE/benign_baseline.pcap" benign
echo "Recorded $HERE/netscan_scan.pcap and $HERE/benign_baseline.pcap"
