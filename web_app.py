"""
web_app.py — Flask web interface for network-scanner.
Run with: sudo python3 web_app.py
Then open: http://localhost:8000
"""

import contextlib
import functools
import ipaddress
import json
import os
import re
import subprocess
import sys
import threading
from datetime import datetime, timezone
from urllib.parse import urlsplit

from flask import (
    Flask,
    Response,
    jsonify,
    render_template,
    request,
    stream_with_context,
)

from scanner.fileutil import ensure_dir, write_json_atomic

app = Flask(__name__)

# Demo mode: when set, disables live scanning and shows pre-loaded sample data.
# Used for the deployed portfolio dashboard where raw sockets aren't available
# (e.g., Render, Fly.io free tiers). Local Docker runs leave this unset and
# get full scanning functionality.
DEMO_MODE = os.environ.get("DEMO_MODE", "0") == "1"

APP_VERSION = "1.3"

# ── Files ───────────────────────────────────────────────────────
# All runtime data lives in one folder (default: ./data next to this file),
# whatever directory the server is started from. docker-compose mounts
# ./data into the container, so scan history survives restarts.
APP_DIR      = os.path.dirname(os.path.abspath(__file__))
DATA_DIR     = os.environ.get("NETSCAN_DATA_DIR", os.path.join(APP_DIR, "data"))
HISTORY_FILE = os.path.join(DATA_DIR, "scan_history.json")
RESULTS_FILE = os.path.join(DATA_DIR, "scan_results.json")   # written by scanner_cli.py
SCANNER_CLI  = os.path.join(APP_DIR, "scanner_cli.py")
DEMO_SAMPLE  = os.path.join(APP_DIR, "demo", "sample_scan.json")
MAX_HISTORY  = 20

# ── Network exposure ──────────────────────────────────────────────
# The dashboard has no login, so by default it only listens on loopback:
# nothing else on the network (or on a VPN adapter) can reach it.
# Inside a container it must listen on all interfaces so Docker's port
# mapping can reach it; the Dockerfile sets NETSCAN_HOST for that, and
# docker-compose publishes the port on the host's 127.0.0.1 only.
BIND_HOST = os.environ.get("NETSCAN_HOST", "127.0.0.1")
PORT      = 8000

# Host names the browser may use to reach the dashboard. Requests that
# trigger scans with any other Host header are refused (DNS rebinding).
ALLOWED_HOSTS = {
    h.strip().lower()
    for h in os.environ.get("NETSCAN_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
    if h.strip()
}

# Largest network the dashboard will scan: /16 = 65,536 addresses.
MIN_PREFIXLEN = 16

_scan_lock  = threading.Lock()     # only one scan at a time
_scan_state = {"proc": None}       # the running scanner subprocess, if any


# ── History helpers ───────────────────────────────────────────────

def load_history():
    """Return the saved scans, newest first ([] if there are none yet)."""
    try:
        with open(HISTORY_FILE, encoding="utf-8") as f:
            history = json.load(f)
    except FileNotFoundError:
        return []
    except ValueError as e:
        # Damaged JSON. Don't treat it as "no history" and let the next save
        # overwrite it: move it aside so the old scans can still be recovered.
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = f"{HISTORY_FILE}.corrupt-{stamp}"
        with contextlib.suppress(OSError):
            os.replace(HISTORY_FILE, backup)
        print(f"[!] {HISTORY_FILE} was damaged ({e}); moved it to {backup}")
        return []
    except OSError as e:
        print(f"[!] Could not read {HISTORY_FILE}: {e}")
        return []
    return history if isinstance(history, list) else []


def save_history(entry):
    ensure_dir(DATA_DIR)
    history = [entry, *load_history()][:MAX_HISTORY]   # newest first
    write_json_atomic(HISTORY_FILE, history)



# ── Input validation ──────────────────────────────────────────────

class ScanRequestError(ValueError):
    """Scan parameters from the browser are missing or invalid."""


def build_scan_args(network, target, ports, udp=False, vuln=False, no_api=False):
    """Turn untrusted scan parameters into scanner_cli.py arguments.

    Parse, don't just check: every value is parsed into a real type
    (IPv4Network / IPv4Address / int), and the argument list is built from
    the *parsed* value, never from the raw string the browser sent. A value
    like "-p" or "10.0.0.1; rm -rf ~" can't survive parsing, so it can never
    reach the command line.
    """
    network = (network or "").strip()
    target  = (target or "").strip()
    ports   = (ports or "").strip() or "1-1000"

    if bool(network) == bool(target):
        raise ScanRequestError("Enter either a network range or a single target (not both).")

    args = []
    if network:
        try:
            net = ipaddress.IPv4Network(network, strict=False)
        except ValueError:
            raise ScanRequestError(f"Invalid network range: {network!r} (example: 192.168.1.0/24)") from None
        if net.prefixlen < MIN_PREFIXLEN:
            raise ScanRequestError(
                f"Network /{net.prefixlen} is too large; use /{MIN_PREFIXLEN} or smaller."
            )
        args += ["-n", str(net)]
    else:
        try:
            ip = ipaddress.IPv4Address(target)
        except ValueError:
            raise ScanRequestError(f"Invalid target IP address: {target!r} (example: 192.168.1.1)") from None
        args += ["-t", str(ip)]

    match = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", ports)
    if not match:
        raise ScanRequestError(f"Invalid port range: {ports!r} (examples: 80 or 1-1000)")
    start = int(match.group(1))
    end   = int(match.group(2) or start)
    if not 1 <= start <= end <= 65535:
        raise ScanRequestError(f"Port range must be within 1-65535 and start <= end: {ports!r}")
    args += ["-p", f"{start}-{end}"]

    if udp:
        args.append("--udp")
    if vuln:
        args.append("--vuln")
    if no_api:
        args.append("--no-api")
    return args


# ── Same-origin guard (CSRF + DNS rebinding) ──────────────────────

def _request_is_same_origin():
    """True only if this request came from the dashboard's own page.

    1. Host check (DNS rebinding): a malicious site can point its own domain
       at 127.0.0.1. The browser then thinks the request is same-origin, but
       the Host header still says the attacker's domain, so we refuse it.
    2. Sec-Fetch-Site (CSRF): modern browsers (Chrome 76+, Firefox 90+,
       Safari 16.4+) tell the server where a request came from. Anything
       other than our own page ("same-origin") or the user typing the URL
       ("none") is refused, e.g. another website's <img src=".../scan/stream">.
    3. Origin (CSRF, older browsers): when present, it must match our host.
    """
    host = (request.host or "").lower()
    hostname = host.rsplit(":", 1)[0] if not host.endswith("]") else host
    if hostname not in ALLOWED_HOSTS:
        return False

    fetch_site = request.headers.get("Sec-Fetch-Site")
    if fetch_site is not None and fetch_site not in ("same-origin", "none"):
        return False

    origin = request.headers.get("Origin")
    return not (origin is not None and urlsplit(origin).netloc.lower() != host)


def same_origin_only(view):
    """Decorator: refuse requests that didn't come from our own page."""
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        if not _request_is_same_origin():
            return jsonify({"error": "Cross-origin request refused."}), 403
        return view(*args, **kwargs)
    return wrapper


def _sse(data):
    """Format one Server-Sent Events message."""
    return f"data: {json.dumps(data)}\n\n"


# ── Routes ────────────────────────────────────────────────────────

# ── Security headers ──────────────────────────────────────────────
# The page's HTML, CSS, JS and fonts all come from this server, so the
# browser can be told to refuse everything else. Even if some scan data
# slipped past escaping, an injected <script> or onerror= handler would be
# blocked: only script files served from 'self' may run, and inline
# scripts, inline event handlers and inline styles are not allowed.
CONTENT_SECURITY_POLICY = "; ".join([
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])


@app.after_request
def add_security_headers(response):
    response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    return response


@app.route("/")
def index():
    return render_template("index.html", demo_mode=DEMO_MODE, version=APP_VERSION)


@app.route("/scan/stream")
@same_origin_only
def scan_stream():
    if DEMO_MODE:
        return jsonify({
            "error": "Live scanning is disabled in demo mode. "
                     "Clone the repo and run locally with Docker to perform real scans."
        }), 403

    udp    = request.args.get("udp") == "true"
    vuln   = request.args.get("vuln") == "true"
    no_api = request.args.get("noApi") == "true"
    try:
        args = build_scan_args(
            request.args.get("network"), request.args.get("target"),
            request.args.get("ports"), udp=udp, vuln=vuln, no_api=no_api,
        )
    except ScanRequestError as e:
        # Shown in the dashboard terminal via textContent, so it can't inject HTML.
        error_stream = iter([_sse({"type": "error", "text": str(e)})])
        return Response(error_stream, mimetype="text/event-stream")

    # Saved with the history entry: the validated values, not the raw input.
    params = {
        "network": args[1] if args[0] == "-n" else "",
        "target":  args[1] if args[0] == "-t" else "",
        "ports":   args[3],
        "udp": udp, "vuln": vuln, "no_api": no_api,
    }
    # -u: unbuffered output, so lines stream to the browser as they happen.
    cmd = [sys.executable, "-u", SCANNER_CLI, *args]

    def generate():
        # The lock is taken inside the generator so it's always released by
        # the finally below, even if the browser disconnects mid-scan.
        if not _scan_lock.acquire(blocking=False):
            yield _sse({"type": "error", "text": "A scan is already running."})
            return

        proc = None
        try:
            # Never show results left over from a previous scan.
            with contextlib.suppress(FileNotFoundError):
                os.remove(RESULTS_FILE)

            # Every argument was rebuilt from a parsed IP/network/port value
            # (see build_scan_args), and no shell is involved.
            proc = subprocess.Popen(  # noqa: S603
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                cwd=ensure_dir(DATA_DIR),   # scan_results.json + scan_report.html land in data/
            )
            _scan_state["proc"] = proc

            for raw_line in proc.stdout:
                line = raw_line.rstrip()
                if line:
                    yield _sse({"type": "line", "text": line})

            proc.wait()
            if proc.returncode != 0:
                text = "Scan stopped." if proc.returncode < 0 else f"Scanner exited with code {proc.returncode}."
                yield _sse({"type": "error", "text": text})
                return

            results = []
            if os.path.exists(RESULTS_FILE):
                with open(RESULTS_FILE, encoding="utf-8") as f:
                    results = json.load(f)

            # The server records history itself; the browser never writes it.
            save_history({
                "ts": datetime.now(timezone.utc).isoformat(),
                "params": params,
                "results": results,
            })
            yield _sse({"type": "done", "results": results})

        except (OSError, ValueError) as e:
            yield _sse({"type": "error", "text": f"Scan failed: {e}"})
        finally:
            # Runs on success, error, Stop, or browser disconnect.
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
            _scan_state["proc"] = None
            _scan_lock.release()

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


@app.route("/scan/stop", methods=["POST"])
@same_origin_only
def scan_stop():
    if DEMO_MODE:
        return jsonify({"error": "Live scanning is disabled in demo mode"}), 403
    proc = _scan_state["proc"]
    if proc is None or proc.poll() is not None:
        return jsonify({"ok": True, "stopped": False})
    proc.terminate()   # the stream sees the scanner exit and reports "Scan stopped."
    return jsonify({"ok": True, "stopped": True})


@app.route("/history")
def get_history():
    return jsonify(load_history())


def seed_demo_history():
    """In demo mode, start with one sample scan so visitors see real-looking
    results without running a scan.

    The sample lives in demo/sample_scan.json in the exact format that
    scanner_cli.py produces, so the dashboard renders it like any real scan.
    Skips seeding if history already exists (e.g. a mounted ./data volume).
    """
    if not DEMO_MODE or os.path.exists(HISTORY_FILE):
        return
    with open(DEMO_SAMPLE, encoding="utf-8") as f:
        sample = json.load(f)
    save_history({
        "ts": datetime.now(timezone.utc).isoformat(),
        "params": sample["params"],
        "results": sample["results"],
        "sample": True,
    })


if __name__ == "__main__":
    print("\n" + "─" * 50)
    print("  NetScan Web Dashboard")
    if DEMO_MODE:
        print("  🎓 DEMO MODE — live scanning disabled")
    print(f"  Open → http://localhost:{PORT}")
    if BIND_HOST not in ("127.0.0.1", "localhost", "::1"):
        print(f"  ⚠  Listening on {BIND_HOST}: the dashboard has NO authentication.")
        print("     Only do this inside a container whose port is published on 127.0.0.1.")
    print(f"  Data   → {DATA_DIR}")
    print("─" * 50 + "\n")
    ensure_dir(DATA_DIR)
    seed_demo_history()
    app.run(host=BIND_HOST, port=PORT, debug=False, threaded=True)
