# Testing the NetScan detections

A rule is only as good as the evidence that it fires when it should and
stays quiet when it shouldn't. Every rule here was tested against two
recorded captures, and those tests run in CI on every push
([tests/test_detections.py](../tests/test_detections.py)).

## Test data

Both captures were recorded on Linux in an isolated network namespace (a
scanner at `10.99.0.1`, a target at `10.99.0.10`), so they contain nothing
but the traffic being tested. [record_captures.sh](tests/record_captures.sh)
re-records them.

**True-positive capture: [netscan_scan.pcap](tests/netscan_scan.pcap)**
(228 packets). A real NetScan run:
`scanner_cli.py -t 10.99.0.10 -p 1-100 --vuln --no-api`. The target runs a
web server on port 80 and an SSH service on port 22 announcing
`OpenSSH_7.4p1`, so the scan probes 100 ports, grabs both banners and sends
its HTTP `HEAD` request. 98 ports answered with a reset.

**False-positive capture: [benign_baseline.pcap](tests/benign_baseline.pcap)**
(190 packets). Normal traffic, chosen to look as much like the rules'
targets as possible without being a scan:

| Traffic | Why it's in the baseline |
|---|---|
| `curl` GET and HEAD requests, a browser User-Agent, `Python-urllib` HEAD | Other HTTP clients, including another tool sending HEAD requests |
| Connection attempts from the kernel to closed ports 22, 23, 25, 443, 8443 | Real operating-system SYNs, and some rejected connections (REJ) |
| SYNs from **source port 20** | Active-mode FTP connects from port 20, the trap for a naive fingerprint rule |

A test checks that the baseline really contains the port-20 SYNs and the
rejected connections, so it can't be quietly replaced by something easier.

## How the rules are run

- **Suricata 7** reads each capture with the rules (`suricata -r`), and the
  alerts are read from `eve.json`. Tested with 7.0.3 locally and the Ubuntu
  24.04 package in CI. A further test loads the rules with `suricata -T`.
- **Sigma** rules need logs, not packets. Zeek isn't available in CI, so
  [pcap_to_logs.py](tests/pcap_to_logs.py) builds Zeek-format `conn` records
  (states `S0`, `REJ`, `SF`) and web server access-log records from the same
  captures. pySigma converts the rules to SQL with its SQLite backend, and
  the SQL is executed on those records. The same rules are converted for
  Splunk and Elasticsearch to check the conversions still work.

## Results

| Rule | NetScan capture | Benign baseline |
|---|---|---|
| Suricata 1000001: Scapy SYN fingerprint | 1 alert | 0 |
| Suricata 1000002: `netscan/` User-Agent | 1 alert | 0 |
| Sigma: `netscan/` User-Agent (web server) | 1 match | 0 |
| Sigma: vertical port scan (Zeek conn) | fires (98 distinct ports) | 0 (5 distinct ports) |

### Threshold boundary

The port-scan correlation is tested on generated records at its edge:

| Rejected connections from one source to one host in a minute | Result |
|---|---|
| 24 distinct ports | no alert |
| 25 distinct ports | alert |
| 60 connections to one port | no alert: retrying one service is not scanning |

### Why the fingerprint rule needs all four conditions

Weaker versions of sid 1000001 were run on the same captures before settling
on the final rule:

| Variant | NetScan capture | Benign baseline | Problem |
|---|---|---|---|
| SYN from source port 20 | fires | **3 false positives** | Active-mode FTP |
| Final rule without the threshold | **100 alerts** | 0 | One alert per probed port floods the queue |
| Sequence number 0 only, or window 8192 only | fires | 0 | Clean on this baseline, but window 8192 is a common Windows default; one field is too little to rely on |
| **Final rule** (port 20, seq 0, window 8192, 20-byte header, 1 alert per source per minute) | 1 alert | 0 | |

The 20-byte TCP header (`tcp.hdr; bsize:20`) means "no TCP options".
Operating systems always send options such as MSS and SACK with a SYN, so
this condition is what separates a hand-built packet from a real client.

## Limitations

- **The baseline is small.** It covers the obvious false-positive traps, not
  the variety of a real network. Before deploying the port-scan rule, run it
  against a week of your own Zeek logs and allowlist known scanners
  (vulnerability scanners, monitoring).
- **The Sigma rules run on generated logs**, built from the captures by
  `pcap_to_logs.py`, not on logs from a real Zeek sensor or web server. The
  field names follow Zeek's `conn.log` and W3C web server logs.
- **Evasion.** A slow scan (under 25 ports a minute per host) evades the
  correlation; a horizontal scan (one port across many hosts) is a
  different pattern this rule doesn't cover. The Splunk and ES|QL
  conversions use fixed one-minute buckets, so a scan split across a minute
  boundary counts towards two buckets.
- **The Sentinel KQL** in [README.md](README.md) is hand-written and not
  executed in CI.

## Re-recording the captures

On Linux, as root, from the repository root:

```bash
sudo bash detections/tests/record_captures.sh
python3 -m pytest tests/test_detections.py
```

The script creates a temporary network namespace and removes it when it
finishes. Re-record after changing how NetScan builds packets or HTTP
requests; if the tests then fail, the rules need updating too.
