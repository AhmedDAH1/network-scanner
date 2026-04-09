"""
web_app.py — Flask web interface for network-scanner.
Run with: sudo python3 web_app.py
Then open: http://localhost:8000
"""

import json
import os
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime
from flask import Flask, Response, jsonify, render_template_string, request, stream_with_context

app = Flask(__name__)

HISTORY_FILE = "scan_history.json"
_scan_lock   = threading.Lock()
_active_scan = {"running": False, "output": [], "id": None}


# ── History helpers ───────────────────────────────────────────────

def load_history():
    if os.path.exists(HISTORY_FILE):
        try:
            with open(HISTORY_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return []


def save_history(entry):
    history = load_history()
    history.insert(0, entry)
    history = history[:20]   # keep last 20 scans
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)


# ── HTML template ─────────────────────────────────────────────────

HTML = r"""
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetScan Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
/* ── Theme variables ── */
[data-theme="dark"] {
    --bg:        #070b10;
    --bg2:       #0c1420;
    --bg3:       #101c2e;
    --border:    #1a2d45;
    --accent:    #00d4ff;
    --green:     #00ff88;
    --red:       #ff4466;
    --yellow:    #ffcc00;
    --orange:    #ff6622;
    --text:      #c8daf0;
    --text-dim:  #4a6a8a;
    --text-mid:  #7a9ab8;
    --shadow:    rgba(0,212,255,0.08);
}
[data-theme="light"] {
    --bg:        #f0f4f8;
    --bg2:       #ffffff;
    --bg3:       #e8eef5;
    --border:    #ccd8e8;
    --accent:    #0077cc;
    --green:     #00aa55;
    --red:       #cc2244;
    --yellow:    #cc8800;
    --orange:    #cc5500;
    --text:      #1a2a3a;
    --text-dim:  #7a90a8;
    --text-mid:  #4a6a8a;
    --shadow:    rgba(0,100,200,0.08);
}

* { margin:0; padding:0; box-sizing:border-box; }

body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Rajdhani', sans-serif;
    font-size: 15px;
    min-height: 100vh;
    transition: background 0.3s, color 0.3s;
}

[data-theme="dark"] body::before {
    content: '';
    position: fixed; inset: 0;
    background-image:
        linear-gradient(rgba(0,212,255,0.025) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,212,255,0.025) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none; z-index: 0;
}

.app { position:relative; z-index:1; display:grid; grid-template-columns:280px 1fr; min-height:100vh; }

/* ── Sidebar ── */
.sidebar {
    background: var(--bg2);
    border-right: 1px solid var(--border);
    padding: 24px 0;
    display: flex;
    flex-direction: column;
    position: sticky; top: 0; height: 100vh;
    overflow-y: auto;
}

.logo {
    padding: 0 24px 24px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 24px;
}

.logo-tag {
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    color: var(--accent);
    letter-spacing: 3px;
    text-transform: uppercase;
    margin-bottom: 6px;
}

.logo-title {
    font-size: 22px;
    font-weight: 700;
    color: var(--text);
    letter-spacing: 0.5px;
}

.logo-title span { color: var(--accent); }

.nav-section {
    padding: 0 16px;
    margin-bottom: 8px;
}

.nav-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 9px;
    letter-spacing: 2px;
    color: var(--text-dim);
    text-transform: uppercase;
    padding: 0 8px;
    margin-bottom: 6px;
}

.nav-btn {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    padding: 10px 12px;
    background: none;
    border: none;
    color: var(--text-mid);
    font-family: 'Rajdhani', sans-serif;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    border-radius: 4px;
    text-align: left;
    transition: all 0.15s;
}

.nav-btn:hover  { background: var(--bg3); color: var(--text); }
.nav-btn.active { background: rgba(0,212,255,0.08); color: var(--accent); }
.nav-btn .icon  { font-size: 16px; width: 20px; text-align: center; }

.sidebar-footer {
    margin-top: auto;
    padding: 16px 24px;
    border-top: 1px solid var(--border);
}

.theme-toggle {
    display: flex;
    align-items: center;
    gap: 10px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    color: var(--text-dim);
    cursor: pointer;
    background: none;
    border: none;
    width: 100%;
}

.toggle-track {
    width: 36px; height: 20px;
    background: var(--border);
    border-radius: 10px;
    position: relative;
    transition: background 0.2s;
    flex-shrink: 0;
}

.toggle-thumb {
    width: 14px; height: 14px;
    background: var(--accent);
    border-radius: 50%;
    position: absolute;
    top: 3px; left: 3px;
    transition: transform 0.2s;
}

[data-theme="light"] .toggle-thumb { transform: translateX(16px); }

/* ── Main content ── */
.main { padding: 32px; overflow-y: auto; }

.page { display: none; }
.page.active { display: block; }

/* ── Page header ── */
.page-header {
    margin-bottom: 28px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 12px;
}

.page-title {
    font-size: 26px;
    font-weight: 700;
    color: var(--text);
}

.page-title span { color: var(--accent); }

/* ── Scan form ── */
.scan-card {
    background: var(--bg2);
    border: 1px solid var(--border);
    padding: 28px;
    margin-bottom: 24px;
}

.form-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 16px;
    margin-bottom: 20px;
}

.form-group { display: flex; flex-direction: column; gap: 6px; }
.form-group.full { grid-column: 1 / -1; }

.form-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    letter-spacing: 2px;
    color: var(--text-dim);
    text-transform: uppercase;
}

.form-input {
    background: var(--bg3);
    border: 1px solid var(--border);
    color: var(--text);
    font-family: 'Share Tech Mono', monospace;
    font-size: 13px;
    padding: 10px 14px;
    outline: none;
    transition: border-color 0.2s;
}

.form-input:focus { border-color: var(--accent); }

.form-row {
    display: flex;
    gap: 20px;
    flex-wrap: wrap;
    margin-bottom: 20px;
}

.checkbox-label {
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
    font-size: 14px;
    font-weight: 600;
    color: var(--text-mid);
    user-select: none;
}

.checkbox-label input { display: none; }

.checkbox-box {
    width: 18px; height: 18px;
    border: 1px solid var(--border);
    background: var(--bg3);
    display: flex; align-items: center; justify-content: center;
    font-size: 11px;
    color: var(--accent);
    transition: all 0.15s;
    flex-shrink: 0;
}

.checkbox-label input:checked ~ .checkbox-box {
    border-color: var(--accent);
    background: rgba(0,212,255,0.1);
}

.scan-btn {
    background: var(--accent);
    color: #000;
    border: none;
    padding: 12px 32px;
    font-family: 'Rajdhani', sans-serif;
    font-size: 15px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
    cursor: pointer;
    transition: all 0.2s;
}

.scan-btn:hover   { opacity: 0.85; }
.scan-btn:disabled { opacity: 0.4; cursor: not-allowed; }
.scan-btn.running { background: var(--red); color: #fff; }

/* ── Terminal ── */
.terminal {
    background: #050810;
    border: 1px solid var(--border);
    border-top: 2px solid var(--accent);
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px;
    padding: 16px;
    height: 280px;
    overflow-y: auto;
    line-height: 1.8;
    display: none;
}

.terminal.visible { display: block; }
.terminal-line { color: #7a9ab8; }
.terminal-line.ok   { color: #00ff88; }
.terminal-line.warn { color: #ffcc00; }
.terminal-line.err  { color: #ff4466; }
.terminal-line.info { color: #00d4ff; }
.terminal-cursor { display: inline-block; width: 8px; height: 14px; background: var(--accent); animation: blink 1s step-end infinite; vertical-align: middle; }
@keyframes blink { 50% { opacity: 0; } }

/* ── Results ── */
.results-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 12px;
    margin-bottom: 24px;
}

.stat-card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-top: 2px solid var(--accent);
    padding: 16px 20px;
}

.stat-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    letter-spacing: 2px;
    color: var(--text-dim);
    text-transform: uppercase;
    margin-bottom: 6px;
}

.stat-value {
    font-size: 28px;
    font-weight: 700;
    color: var(--accent);
    font-family: 'Share Tech Mono', monospace;
}

.host-card {
    background: var(--bg2);
    border: 1px solid var(--border);
    margin-bottom: 12px;
    animation: slideIn 0.3s ease both;
}

@keyframes slideIn {
    from { opacity:0; transform: translateY(6px); }
    to   { opacity:1; transform: translateY(0); }
}

.host-head {
    padding: 14px 20px;
    background: var(--bg3);
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 10px;
    cursor: pointer;
}

.host-head:hover { background: var(--bg); }

.host-ip {
    font-family: 'Share Tech Mono', monospace;
    font-size: 16px;
    color: var(--text);
    display: flex; align-items: center; gap: 10px;
}

.host-ip::before { content: '▶'; font-size: 8px; color: var(--accent); }

.host-meta {
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    color: var(--text-dim);
    margin-top: 2px;
}

.badges { display:flex; gap:6px; flex-wrap:wrap; }

.badge {
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    padding: 2px 8px;
    border: 1px solid;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.badge-os   { color: var(--yellow); border-color: rgba(255,204,0,0.3); }
.badge-dev  { color: var(--accent);  border-color: rgba(0,212,255,0.3); }
.badge-vend { color: var(--green);   border-color: rgba(0,255,136,0.3); }
.badge-rand { color: var(--text-dim);border-color: var(--border); }

.host-body { padding: 16px 20px; display: none; }
.host-body.open { display: block; }

.port-table {
    width: 100%;
    border-collapse: collapse;
    font-family: 'Share Tech Mono', monospace;
    font-size: 12px;
    margin-bottom: 12px;
}

.port-table th {
    text-align: left;
    padding: 6px 12px;
    font-size: 9px;
    letter-spacing: 2px;
    color: var(--text-dim);
    text-transform: uppercase;
    border-bottom: 1px solid var(--border);
    font-family: 'Rajdhani', sans-serif;
    font-weight: 600;
}

.port-table td {
    padding: 8px 12px;
    border-bottom: 1px solid rgba(26,45,69,0.4);
    vertical-align: top;
}

.port-table tr:last-child td { border-bottom: none; }
.port-num  { color: var(--accent); font-weight: bold; }
.proto-tcp { color: var(--green); }
.proto-udp { color: var(--yellow); }

.cve-list { margin-top: 4px; }
.cve-row  { display: flex; gap: 8px; padding: 3px 0; font-size: 11px; }
.cve-id   { color: var(--accent); white-space: nowrap; }
.sev-CRITICAL { color: #ff2244; font-weight: bold; }
.sev-HIGH     { color: var(--orange); font-weight: bold; }
.sev-MEDIUM   { color: var(--yellow); }
.sev-LOW      { color: var(--text-dim); }
.cve-desc { color: var(--text-mid); }

.no-ports { font-family: 'Share Tech Mono', monospace; font-size: 12px; color: var(--text-dim); padding: 8px 0; }

/* ── History ── */
.history-item {
    background: var(--bg2);
    border: 1px solid var(--border);
    padding: 16px 20px;
    margin-bottom: 10px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 10px;
    cursor: pointer;
    transition: border-color 0.15s;
}

.history-item:hover { border-color: var(--accent); }

.history-meta {
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    color: var(--text-dim);
    margin-top: 4px;
}

.history-target {
    font-size: 16px;
    font-weight: 700;
    color: var(--text);
}

.history-badges { display: flex; gap: 8px; align-items: center; }

.pill {
    font-family: 'Share Tech Mono', monospace;
    font-size: 11px;
    padding: 3px 10px;
    border: 1px solid var(--border);
    color: var(--text-mid);
}

.pill-accent { border-color: rgba(0,212,255,0.4); color: var(--accent); }

.empty-state {
    text-align: center;
    padding: 60px 20px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 13px;
    color: var(--text-dim);
}

.empty-state .icon { font-size: 40px; margin-bottom: 16px; }

/* ── Misc ── */
.divider {
    font-family: 'Share Tech Mono', monospace;
    font-size: 10px;
    letter-spacing: 3px;
    color: var(--text-dim);
    text-transform: uppercase;
    display: flex; align-items: center; gap: 10px;
    margin: 20px 0 12px;
}
.divider::after { content:''; flex:1; height:1px; background: var(--border); }

.badge-vuln { color: var(--red); border-color: rgba(255,68,102,0.3); }

@media (max-width: 768px) {
    .app { grid-template-columns: 1fr; }
    .sidebar { position: relative; height: auto; }
    .form-grid { grid-template-columns: 1fr; }
}
</style>
<script src="https://cdnjs.cloudflare.com/ajax/libs/d3/7.8.5/d3.min.js"></script>
</head>
<body>
<div class="app">

<!-- ── Sidebar ── -->
<aside class="sidebar">
    <div class="logo">
        <div class="logo-tag">// network recon</div>
        <div class="logo-title">Net<span>Scan</span></div>
    </div>

    <div class="nav-section">
        <div class="nav-label">Navigation</div>
        <button class="nav-btn active" onclick="showPage('scan')" id="nav-scan">
            <span class="icon">⌖</span> New Scan
        </button>
        <button class="nav-btn" onclick="showPage('results')" id="nav-results">
            <span class="icon">◈</span> Results
        </button>
        <button class="nav-btn" onclick="showPage('history')" id="nav-history">
            <span class="icon">◷</span> Scan History
        </button>
        <button class="nav-btn" onclick="showPage('topology')" id="nav-topology">
            <span class="icon">◉</span> Topology Map
        </button>
    </div>

    <div class="sidebar-footer">
        <button class="theme-toggle" onclick="toggleTheme()">
            <div class="toggle-track"><div class="toggle-thumb"></div></div>
            <span id="theme-label">DARK MODE</span>
        </button>
        <div style="margin-top:14px; font-family:'Share Tech Mono',monospace; font-size:10px; color:var(--text-dim); line-height:1.8;">
            <div style="color:var(--accent);">// developer</div>
            <div style="color:var(--text-mid); font-weight:600; font-size:12px;">Ahmed Dahdouh</div>
        </div>
    </div>
</aside>

<!-- ── Main ── -->
<main class="main">

    <!-- Scan page -->
    <div class="page active" id="page-scan">
        <div class="page-header">
            <div class="page-title">New <span>Scan</span></div>
        </div>

        <div class="scan-card">
            <div class="form-grid">
                <div class="form-group">
                    <label class="form-label">Network Range</label>
                    <input class="form-input" id="network" placeholder="192.168.1.0/24" />
                </div>
                <div class="form-group">
                    <label class="form-label">Single Target</label>
                    <input class="form-input" id="target" placeholder="192.168.1.1" />
                </div>
                <div class="form-group">
                    <label class="form-label">Port Range</label>
                    <input class="form-input" id="ports" value="1-1000" />
                </div>
            </div>

            <div class="form-row">
                <label class="checkbox-label">
                    <input type="checkbox" id="udp">
                    <div class="checkbox-box">✓</div>
                    UDP Scan
                </label>
                <label class="checkbox-label">
                    <input type="checkbox" id="vuln">
                    <div class="checkbox-box">✓</div>
                    Vulnerability Scan
                </label>
                <label class="checkbox-label">
                    <input type="checkbox" id="no-api">
                    <div class="checkbox-box">✓</div>
                    Offline CVE only
                </label>
            </div>

            <button class="scan-btn" id="scan-btn" onclick="startScan()">▶ Start Scan</button>
        </div>

        <div class="terminal" id="terminal"></div>
    </div>

    <!-- Results page -->
    <div class="page" id="page-results">
        <div class="page-header">
            <div class="page-title">Scan <span>Results</span></div>
        </div>
        <div id="results-content">
            <div class="empty-state">
                <div class="icon">◈</div>
                No scan results yet. Run a scan first.
            </div>
        </div>
    </div>

    <!-- History page -->
    <div class="page" id="page-history">
        <div class="page-header">
            <div class="page-title">Scan <span>History</span></div>
        </div>
        <div id="history-content">
            <div class="empty-state">
                <div class="icon">◷</div>
                No scans in history yet.
            </div>
        </div>
    </div>

    <!-- Topology page -->
    <div class="page" id="page-topology">
        <div class="page-header">
            <div class="page-title">Network <span>Topology</span></div>
            <div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;">
                <div style="display:flex;gap:12px;font-family:'Share Tech Mono',monospace;font-size:11px;">
                    <span><span style="color:#ff4466">●</span> Critical CVE</span>
                    <span><span style="color:#ffcc00">●</span> Open Ports</span>
                    <span><span style="color:#00ff88">●</span> Clean</span>
                    <span><span style="color:#4a6a8a">●</span> Unknown</span>
                </div>
            </div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 300px;gap:16px;height:calc(100vh - 180px);">
            <!-- Map canvas -->
            <div style="background:var(--bg2);border:1px solid var(--border);position:relative;overflow:hidden;" id="topo-wrap">
                <svg id="topo-svg" style="width:100%;height:100%;"></svg>
                <div id="topo-empty" style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-family:'Share Tech Mono',monospace;font-size:13px;color:var(--text-dim);flex-direction:column;gap:12px;">
                    <div style="font-size:36px;">◉</div>
                    Run a scan to generate the topology map.
                </div>
            </div>
            <!-- Detail panel -->
            <div style="background:var(--bg2);border:1px solid var(--border);padding:20px;overflow-y:auto;" id="topo-panel">
                <div style="font-family:'Share Tech Mono',monospace;font-size:10px;letter-spacing:2px;color:var(--text-dim);text-transform:uppercase;margin-bottom:16px;">Device Details</div>
                <div id="topo-detail" style="font-family:'Share Tech Mono',monospace;font-size:12px;color:var(--text-dim);">
                    Click a node to see device details.
                </div>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <div style="margin-top:48px; padding-top:20px; border-top:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px;">
        <span style="font-family:'Share Tech Mono',monospace; font-size:11px; color:var(--text-dim);">
            Built by <strong style="color:var(--accent);">Ahmed Dahdouh</strong>
        </span>
        <span style="font-family:'Share Tech Mono',monospace; font-size:11px; color:var(--text-dim);">
            Network Scanner <strong style="color:var(--accent);">v1.3</strong>
        </span>
    </div>

</main>
</div>

<script>
// ── Topology Map ─────────────────────────────────────────────────
let topoData = null;

function buildTopology(results) {
    if (!results || !results.length) return;
    topoData = results;
    document.getElementById('topo-empty').style.display = 'none';
    drawTopology(results);
}

function nodeColor(host) {
    const hasCritical = host.tcp_ports?.some(p => p.cves?.some(c => c.severity === 'CRITICAL' || c.severity === 'HIGH'));
    const hasPorts    = (host.tcp_ports?.length || 0) + (host.udp_ports?.length || 0) > 0;
    if (hasCritical) return '#ff4466';
    if (hasPorts)    return '#ffcc00';
    if (host.device && host.device !== 'Unknown') return '#00ff88';
    return '#4a6a8a';
}

function nodeIcon(host) {
    const d = (host.device || '').toLowerCase();
    if (d.includes('router') || d.includes('ap')) return '⊕';
    if (d.includes('iphone') || d.includes('ipad')) return '◻';
    if (d.includes('mac') || d.includes('laptop') || d.includes('pc')) return '▣';
    if (d.includes('phone') || d.includes('android')) return '◻';
    if (d.includes('printer')) return '⊞';
    if (d.includes('tv')) return '▬';
    if (d.includes('nas')) return '▦';
    return '◈';
}

function drawTopology(results) {
    const svg = document.getElementById('topo-svg');
    const wrap = document.getElementById('topo-wrap');
    svg.innerHTML = '';

    const W = wrap.clientWidth  || 700;
    const H = wrap.clientHeight || 500;

    // Find gateway (lowest IP or router)
    const sorted = [...results].sort((a, b) => {
        const aIsRouter = a.device?.toLowerCase().includes('router');
        const bIsRouter = b.device?.toLowerCase().includes('router');
        if (aIsRouter && !bIsRouter) return -1;
        if (!aIsRouter && bIsRouter) return 1;
        return a.host.localeCompare(b.host);
    });

    const gateway = sorted[0];
    const clients = sorted.slice(1);

    // Build nodes
    const nodes = results.map((h, i) => ({
        id: h.host,
        host: h,
        x: 0, y: 0,
        r: 28 + Math.min((h.tcp_ports?.length || 0) * 3, 18),
        color: nodeColor(h),
        icon: nodeIcon(h),
        isGateway: h.host === gateway.host,
    }));

    // Build links — all clients connect to gateway
    const links = clients.map(c => ({
        source: gateway.host,
        target: c.host,
    }));

    // Position nodes in a circle around gateway
    const cx = W / 2, cy = H / 2;
    const gNode = nodes.find(n => n.isGateway);
    if (gNode) { gNode.x = cx; gNode.y = cy; }

    const cNodes = nodes.filter(n => !n.isGateway);
    const radius = Math.min(W, H) * 0.32;
    cNodes.forEach((n, i) => {
        const angle = (2 * Math.PI * i) / cNodes.length - Math.PI / 2;
        n.x = cx + radius * Math.cos(angle);
        n.y = cy + radius * Math.sin(angle);
    });

    // Draw with D3
    const d3svg = d3.select('#topo-svg')
        .attr('viewBox', `0 0 ${W} ${H}`)
        .style('background', 'transparent');

    // Defs — glow filter
    const defs = d3svg.append('defs');
    const filter = defs.append('filter').attr('id', 'glow');
    filter.append('feGaussianBlur').attr('stdDeviation', '3').attr('result', 'coloredBlur');
    const feMerge = filter.append('feMerge');
    feMerge.append('feMergeNode').attr('in', 'coloredBlur');
    feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    // Links
    const linkGroup = d3svg.append('g');
    const nodeMap = {};
    nodes.forEach(n => nodeMap[n.id] = n);

    links.forEach(l => {
        const s = nodeMap[l.source], t = nodeMap[l.target];
        if (!s || !t) return;
        linkGroup.append('line')
            .attr('x1', s.x).attr('y1', s.y)
            .attr('x2', t.x).attr('y2', t.y)
            .attr('stroke', 'rgba(0,212,255,0.15)')
            .attr('stroke-width', 1.5)
            .attr('stroke-dasharray', '4,4');
    });

    // Nodes
    const nodeGroup = d3svg.append('g');

    nodes.forEach(n => {
        const g = nodeGroup.append('g')
            .attr('transform', `translate(${n.x},${n.y})`)
            .style('cursor', 'pointer')
            .on('click', () => showNodeDetail(n.host))
            .call(d3.drag()
                .on('drag', function(event) {
                    n.x = event.x; n.y = event.y;
                    d3.select(this).attr('transform', `translate(${n.x},${n.y})`);
                    // Update links
                    linkGroup.selectAll('line').each(function() {
                        const line = d3.select(this);
                        const x1 = parseFloat(line.attr('x1'));
                        const y1 = parseFloat(line.attr('y1'));
                        // redraw topology on drag
                    });
                    drawTopology(topoData);
                })
            );

        // Outer ring
        g.append('circle')
            .attr('r', n.r + 6)
            .attr('fill', 'none')
            .attr('stroke', n.color)
            .attr('stroke-width', 1)
            .attr('opacity', 0.3);

        // Main circle
        g.append('circle')
            .attr('r', n.r)
            .attr('fill', `${n.color}18`)
            .attr('stroke', n.color)
            .attr('stroke-width', n.isGateway ? 2.5 : 1.5)
            .attr('filter', 'url(#glow)');

        // Icon
        g.append('text')
            .attr('text-anchor', 'middle')
            .attr('dominant-baseline', 'central')
            .attr('dy', '-6')
            .attr('font-size', n.isGateway ? '18' : '14')
            .attr('fill', n.color)
            .text(n.icon);

        // IP label inside
        g.append('text')
            .attr('text-anchor', 'middle')
            .attr('dominant-baseline', 'central')
            .attr('dy', '10')
            .attr('font-family', "'Share Tech Mono', monospace")
            .attr('font-size', '9')
            .attr('fill', n.color)
            .text(n.host.split('.').slice(-2).join('.'));

        // Device label below
        g.append('text')
            .attr('text-anchor', 'middle')
            .attr('y', n.r + 16)
            .attr('font-family', "'Share Tech Mono', monospace")
            .attr('font-size', '10')
            .attr('fill', 'var(--text-mid)')
            .text(n.host.vendor || (n.isGateway ? 'Gateway' : ''));
    });
}

function showNodeDetail(host) {
    const color = nodeColor(host);
    const tcpCount = host.tcp_ports?.length || 0;
    const udpCount = host.udp_ports?.length || 0;
    const cveCount = host.tcp_ports?.reduce((n, p) => n + (p.cves?.length || 0), 0) || 0;

    let portsHtml = '';
    (host.tcp_ports || []).forEach(p => {
        const worst = p.cves?.[0];
        portsHtml += `<div style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid var(--border);">
            <span style="color:var(--accent)">${p.port}</span>
            <span style="color:#00ff88">TCP</span>
            <span>${p.service}</span>
            ${worst ? `<span class="sev-${worst.severity}" style="font-size:10px;">${worst.severity}</span>` : '<span></span>'}
        </div>`;
    });
    (host.udp_ports || []).forEach(p => {
        portsHtml += `<div style="display:flex;justify-content:space-between;padding:5px 0;border-bottom:1px solid var(--border);">
            <span style="color:var(--accent)">${p.port}</span>
            <span style="color:#ffcc00">UDP</span>
            <span>${p.service}</span>
            <span></span>
        </div>`;
    });

    let cvesHtml = '';
    (host.tcp_ports || []).forEach(p => {
        (p.cves || []).forEach(c => {
            cvesHtml += `<div style="padding:5px 0;border-bottom:1px solid var(--border);">
                <div style="display:flex;gap:8px;align-items:center;">
                    <span style="color:var(--accent);font-size:11px;">${c.id}</span>
                    <span class="sev-${c.severity}" style="font-size:10px;">${c.severity}</span>
                </div>
                <div style="color:var(--text-dim);font-size:10px;margin-top:2px;">${c.desc}</div>
            </div>`;
        });
    });

    document.getElementById('topo-detail').innerHTML = `
        <div style="border-left:3px solid ${color};padding-left:12px;margin-bottom:16px;">
            <div style="font-size:16px;color:var(--text);font-weight:700;">${host.host}</div>
            <div style="color:var(--text-dim);margin-top:4px;">${host.mac || 'MAC unknown'}</div>
        </div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:16px;">
            <div style="background:var(--bg3);padding:10px;text-align:center;">
                <div style="font-size:18px;color:var(--accent);font-weight:700;">${tcpCount + udpCount}</div>
                <div style="font-size:9px;color:var(--text-dim);letter-spacing:1px;">PORTS</div>
            </div>
            <div style="background:var(--bg3);padding:10px;text-align:center;">
                <div style="font-size:18px;color:${cveCount ? '#ff4466' : 'var(--green)'};font-weight:700;">${cveCount}</div>
                <div style="font-size:9px;color:var(--text-dim);letter-spacing:1px;">CVES</div>
            </div>
        </div>
        <div style="margin-bottom:4px;color:var(--text-dim);font-size:9px;letter-spacing:2px;text-transform:uppercase;">Info</div>
        <div style="background:var(--bg3);padding:10px;margin-bottom:16px;line-height:2;">
            <div><span style="color:var(--text-dim)">OS</span> &nbsp; ${host.os || '—'}</div>
            <div><span style="color:var(--text-dim)">Device</span> &nbsp; ${host.device || '—'}</div>
            <div><span style="color:var(--text-dim)">Vendor</span> &nbsp; ${host.vendor || '—'}</div>
        </div>
        ${portsHtml ? `<div style="margin-bottom:4px;color:var(--text-dim);font-size:9px;letter-spacing:2px;text-transform:uppercase;">Ports</div><div style="margin-bottom:16px;">${portsHtml}</div>` : ''}
        ${cvesHtml ? `<div style="margin-bottom:4px;color:var(--text-dim);font-size:9px;letter-spacing:2px;text-transform:uppercase;">CVEs</div><div>${cvesHtml}</div>` : ''}
    `;
}

// ── Theme ─────────────────────────────────────────────────────────
function toggleTheme() {
    const html = document.documentElement;
    const isDark = html.getAttribute('data-theme') === 'dark';
    html.setAttribute('data-theme', isDark ? 'light' : 'dark');
    document.getElementById('theme-label').textContent = isDark ? 'LIGHT MODE' : 'DARK MODE';
    localStorage.setItem('theme', isDark ? 'light' : 'dark');
}
(function() {
    const saved = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', saved);
    document.getElementById('theme-label').textContent = saved === 'dark' ? 'DARK MODE' : 'LIGHT MODE';
})();

// ── Navigation ────────────────────────────────────────────────────
function showPage(name) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
    document.getElementById('page-' + name).classList.add('active');
    document.getElementById('nav-' + name).classList.add('active');
    if (name === 'history') loadHistory();
    if (name === 'topology' && currentResults) {
        setTimeout(() => buildTopology(currentResults), 50);
    }
}

// ── Terminal ──────────────────────────────────────────────────────
let currentResults = null;

function termLine(text) {
    const el = document.getElementById('terminal');
    const line = document.createElement('div');
    line.className = 'terminal-line';
    if (text.startsWith('[+]')) line.classList.add('ok');
    else if (text.startsWith('[-]') || text.startsWith('[!]')) line.classList.add('err');
    else if (text.startsWith('Scanning') || text.startsWith('─')) line.classList.add('info');
    else if (text.includes('CVE') || text.includes('CRITICAL')) line.classList.add('warn');
    line.textContent = text;
    el.appendChild(line);
    el.scrollTop = el.scrollHeight;
}

function clearTerminal() {
    document.getElementById('terminal').innerHTML = '';
}

// ── Scan ──────────────────────────────────────────────────────────
let scanning = false;

function startScan() {
    if (scanning) { stopScan(); return; }

    const network = document.getElementById('network').value.trim();
    const target  = document.getElementById('target').value.trim();
    const ports   = document.getElementById('ports').value.trim();
    const udp     = document.getElementById('udp').checked;
    const vuln    = document.getElementById('vuln').checked;
    const noApi   = document.getElementById('no-api').checked;

    if (!network && !target) {
        alert('Please enter a network range or single target.');
        return;
    }

    scanning = true;
    const btn = document.getElementById('scan-btn');
    btn.textContent = '■ Stop Scan';
    btn.classList.add('running');

    const term = document.getElementById('terminal');
    term.classList.add('visible');
    clearTerminal();
    termLine('// initiating scan sequence...');

    const params = new URLSearchParams({ network, target, ports, udp, vuln, noApi });

    const es = new EventSource('/scan/stream?' + params);

    es.onmessage = e => {
        const data = JSON.parse(e.data);
        if (data.type === 'line') {
            termLine(data.text);
        } else if (data.type === 'done') {
            es.close();
            scanning = false;
            btn.textContent = '▶ Start Scan';
            btn.classList.remove('running');
            termLine('// scan complete.');
            if (data.results) {
                currentResults = data.results;
                renderResults(data.results);
                buildTopology(data.results);
                showPage('results');
                saveHistory(data.results, { network, target, ports, udp, vuln });
            }
        } else if (data.type === 'error') {
            termLine('[!] ' + data.text);
            es.close();
            scanning = false;
            btn.textContent = '▶ Start Scan';
            btn.classList.remove('running');
        }
    };

    es.onerror = () => {
        es.close();
        scanning = false;
        btn.textContent = '▶ Start Scan';
        btn.classList.remove('running');
    };
}

function stopScan() {
    fetch('/scan/stop', { method: 'POST' });
    scanning = false;
    document.getElementById('scan-btn').textContent = '▶ Start Scan';
    document.getElementById('scan-btn').classList.remove('running');
}

// ── Render results ────────────────────────────────────────────────
function renderResults(results) {
    const tcpTotal  = results.reduce((n, h) => n + (h.tcp_ports?.length || 0), 0);
    const udpTotal  = results.reduce((n, h) => n + (h.udp_ports?.length || 0), 0);
    const cveTotal  = results.reduce((n, h) => n + h.tcp_ports?.reduce((m, p) => m + (p.cves?.length || 0), 0), 0);
    const vendors   = new Set(results.map(h => h.vendor).filter(v => v && !v.toLowerCase().includes('randomized') && v !== 'Unknown'));

    let html = `
    <div class="results-grid">
        <div class="stat-card"><div class="stat-label">Hosts Found</div><div class="stat-value">${results.length}</div></div>
        <div class="stat-card"><div class="stat-label">TCP Ports</div><div class="stat-value">${tcpTotal}</div></div>
        <div class="stat-card"><div class="stat-label">UDP Ports</div><div class="stat-value">${udpTotal}</div></div>
        <div class="stat-card"><div class="stat-label">CVEs Found</div><div class="stat-value">${cveTotal}</div></div>
    </div>`;

    results.forEach((host, i) => {
        const rand = host.vendor?.toLowerCase().includes('randomized');
        const vBadge = rand
            ? `<span class="badge badge-rand">Privacy MAC</span>`
            : host.vendor && host.vendor !== 'Unknown'
                ? `<span class="badge badge-vend">${host.vendor}</span>` : '';
        const osBadge  = host.os && host.os !== 'Unknown' ? `<span class="badge badge-os">${host.os}</span>` : '';
        const devBadge = host.device && host.device !== 'Unknown' ? `<span class="badge badge-dev">${host.device}</span>` : '';

        let tcpRows = '';
        (host.tcp_ports || []).forEach(p => {
            let cveHtml = '';
            (p.cves || []).forEach(c => {
                cveHtml += `<div class="cve-row"><span class="cve-id">${c.id}</span><span class="sev-${c.severity}">${c.severity}</span><span class="cve-desc">${c.desc}</span></div>`;
            });
            tcpRows += `<tr>
                <td><span class="port-num">${p.port}</span></td>
                <td><span class="proto-tcp">TCP</span></td>
                <td>${p.service}</td>
                <td>${p.banner || '—'}<div class="cve-list">${cveHtml}</div></td>
            </tr>`;
        });

        let udpRows = '';
        (host.udp_ports || []).forEach(p => {
            udpRows += `<tr>
                <td><span class="port-num">${p.port}</span></td>
                <td><span class="proto-udp">UDP</span></td>
                <td>${p.service}</td><td>—</td>
            </tr>`;
        });

        const allPorts = tcpRows + udpRows;

        html += `
        <div class="host-card" style="animation-delay:${i*0.06}s">
            <div class="host-head" onclick="toggleHost(this)">
                <div>
                    <div class="host-ip">${host.host}</div>
                    <div class="host-meta">${host.mac || ''}</div>
                </div>
                <div class="badges">${osBadge}${devBadge}${vBadge}</div>
            </div>
            <div class="host-body">
                ${allPorts ? `
                <table class="port-table">
                    <thead><tr><th>Port</th><th>Proto</th><th>Service</th><th>Info</th></tr></thead>
                    <tbody>${allPorts}</tbody>
                </table>` : '<div class="no-ports">No open ports detected.</div>'}
            </div>
        </div>`;
    });

    document.getElementById('results-content').innerHTML = html;
}

function toggleHost(el) {
    el.nextElementSibling.classList.toggle('open');
}

// ── History ───────────────────────────────────────────────────────
function saveHistory(results, params) {
    fetch('/history/save', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ results, params, ts: new Date().toISOString() })
    });
}

function loadHistory() {
    fetch('/history')
        .then(r => r.json())
        .then(data => {
            if (!data.length) {
                document.getElementById('history-content').innerHTML = `
                    <div class="empty-state"><div class="icon">◷</div>No scans in history yet.</div>`;
                return;
            }
            let html = '';
            data.forEach(entry => {
                const d = new Date(entry.ts);
                const hosts = entry.results?.length || 0;
                const ports = entry.results?.reduce((n, h) => n + (h.tcp_ports?.length || 0), 0) || 0;
                const target = entry.params?.network || entry.params?.target || '—';
                html += `
                <div class="history-item" onclick="loadHistoryEntry(${JSON.stringify(JSON.stringify(entry))})">
                    <div>
                        <div class="history-target">${target}</div>
                        <div class="history-meta">${d.toLocaleString()}</div>
                    </div>
                    <div class="history-badges">
                        <span class="pill">${hosts} hosts</span>
                        <span class="pill pill-accent">${ports} ports</span>
                    </div>
                </div>`;
            });
            document.getElementById('history-content').innerHTML = html;
        });
}

function loadHistoryEntry(entryStr) {
    const entry = JSON.parse(entryStr);
    currentResults = entry.results;
    renderResults(entry.results);
    buildTopology(entry.results);
    showPage('results');
}
</script>
</body>
</html>
"""

# ── Routes ────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/scan/stream")
def scan_stream():
    network = request.args.get("network", "").strip()
    target  = request.args.get("target", "").strip()
    ports   = request.args.get("ports", "1-1000").strip()
    udp     = request.args.get("udp") == "true"
    vuln    = request.args.get("vuln") == "true"
    no_api  = request.args.get("noApi") == "true"

    def generate():
        cmd = [sys.executable, "test.py"]
        if network: cmd += ["-n", network]
        elif target: cmd += ["-t", target]
        if ports:   cmd += ["-p", ports]
        if udp:     cmd += ["--udp"]
        if vuln:    cmd += ["--vuln"]
        if no_api:  cmd += ["--no-api"]

        def send(data):
            return f"data: {json.dumps(data)}\n\n"

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            _active_scan["running"] = True
            _active_scan["output"]  = []

            for line in proc.stdout:
                line = line.rstrip()
                if not line:
                    continue
                _active_scan["output"].append(line)
                yield send({"type": "line", "text": line})

            proc.wait()
            _active_scan["running"] = False

            # Load scan results
            results = []
            if os.path.exists("scan_results.json"):
                with open("scan_results.json") as f:
                    results = json.load(f)

            yield send({"type": "done", "results": results})

        except Exception as e:
            yield send({"type": "error", "text": str(e)})
            _active_scan["running"] = False

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )


@app.route("/scan/stop", methods=["POST"])
def scan_stop():
    _active_scan["running"] = False
    return jsonify({"ok": True})


@app.route("/history")
def get_history():
    return jsonify(load_history())


@app.route("/history/save", methods=["POST"])
def save_history_route():
    entry = request.json
    save_history(entry)
    return jsonify({"ok": True})


if __name__ == "__main__":
    print("\n" + "─" * 50)
    print("  NetScan Web Dashboard")
    print("  Open → http://localhost:8000")
    print("─" * 50 + "\n")
    app.run(host="0.0.0.0", port=8000, debug=False, threaded=True)