// NetScan dashboard
//
// Security rules for this file:
//  * Scan data is UNTRUSTED. Banners, hostnames and vendors are chosen by the
//    devices that were scanned. Every value that goes into innerHTML passes
//    through esc(); everything else uses textContent.
//  * No inline event handlers and no inline styles: the server sends a
//    Content-Security-Policy that blocks both, so injected markup can't run.
//  * Event handlers receive indexes (numbers), never scan data.

'use strict';

// ── Helpers ─────────────────────────────────────────────────────

function esc(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const SEVERITY = {          // level -> label
    4: 'Critical',
    3: 'High',
    2: 'Medium',
    1: 'Low',
    0: 'None known',
};
const LEVEL_OF = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };

function cveLevel(cve) {
    return LEVEL_OF[String(cve?.severity || '').toUpperCase()] || 0;
}

function asList(value) {
    return Array.isArray(value) ? value : [];
}

function hostLevel(host) {
    let level = 0;
    for (const port of asList(host.tcp_ports)) {
        for (const cve of asList(port.cves)) level = Math.max(level, cveLevel(cve));
    }
    return level;
}

function cveCount(host) {
    return asList(host.tcp_ports).reduce((n, p) => n + asList(p.cves).length, 0);
}

function ipKey(ip) {
    // Sort IPv4 addresses numerically (10.0.0.9 before 10.0.0.10).
    const parts = String(ip || '').split('.').map(Number);
    return parts.length === 4 && parts.every(Number.isFinite)
        ? parts.reduce((acc, n) => acc * 256 + n, 0)
        : Number.MAX_SAFE_INTEGER;
}

function sortByRisk(hosts) {
    return hosts
        .map((host, index) => ({ host, index, level: hostLevel(host) }))
        .sort((a, b) => b.level - a.level || ipKey(a.host.host) - ipKey(b.host.host));
}

function known(value) {
    return value && value !== 'Unknown' ? value : '';
}

function deviceName(host) {
    return known(String(host.device || '').replace(' (Randomized MAC (Privacy Mode))', '').trim());
}

function vendorName(host) {
    const v = known(host.vendor);
    return v && v.toLowerCase().includes('randomized') ? 'Private (randomized) MAC' : v;
}

function riskHtml(level) {
    const cls = level ? 'risk' : 'risk risk-none';
    return `<span class="${cls}"><span class="meter" data-level="${level}" aria-hidden="true"><i></i><i></i><i></i><i></i></span>`
         + `<span class="risk-label">${esc(SEVERITY[level])}</span></span>`;
}

function cveHtml(cve) {
    const id = String(cve?.id || '');
    // Only link IDs that really look like CVE IDs.
    const label = /^CVE-\d{4}-\d{4,7}$/.test(id)
        ? `<a class="cve-id" href="https://nvd.nist.gov/vuln/detail/${esc(id)}" target="_blank" rel="noopener noreferrer">${esc(id)}</a>`
        : `<span class="cve-id">${esc(id)}</span>`;
    return `<li class="cve">${riskHtml(cveLevel(cve))}${label}<span class="cve-desc">${esc(cve?.desc)}</span></li>`;
}

const dateFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
function formatDate(value) {
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? 'Unknown date' : dateFmt.format(d);
}

function plural(n, one, many) {
    return `${n} ${n === 1 ? one : many}`;
}

// ── State ───────────────────────────────────────────────────────

const DEMO = document.body.dataset.demo === 'true';
const state = {
    scan: null,          // { ts, params, results } currently shown
    history: [],         // last /history response
    stream: null,        // EventSource while a scan runs
    scanning: false,
    timer: null,
    startedAt: 0,
    selectedNode: null,
};

// ── Navigation ──────────────────────────────────────────────────

const PAGES = ['scan', 'results', 'map', 'history'];

function showPage(name, { focus = true } = {}) {
    if (!PAGES.includes(name)) name = 'scan';
    for (const page of PAGES) $(`#page-${page}`).hidden = page !== name;
    for (const btn of $$('.nav-item')) {
        if (btn.dataset.page === name) btn.setAttribute('aria-current', 'page');
        else btn.removeAttribute('aria-current');
    }
    if (name === 'map') renderMap();
    if (name === 'history') loadHistory();
    if (focus) $('#main').focus({ preventScroll: true });
    window.scrollTo(0, 0);
}

document.addEventListener('click', (e) => {
    const nav = e.target.closest('[data-page]');
    if (nav) { showPage(nav.dataset.page); return; }
    const go = e.target.closest('[data-goto]');
    if (go) showPage(go.dataset.goto);
});

// ── Theme ───────────────────────────────────────────────────────

function syncThemeLabel() {
    const dark = document.documentElement.dataset.theme !== 'light';
    $('#theme-toggle-label').textContent = dark ? 'Light theme' : 'Dark theme';
}

$('#theme-toggle').addEventListener('click', () => {
    const next = document.documentElement.dataset.theme === 'light' ? 'dark' : 'light';
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem('netscan-theme', next); } catch (e) { /* storage blocked */ }
    syncThemeLabel();
});
syncThemeLabel();

// ── Scan form ───────────────────────────────────────────────────

const form = $('#scan-form');
const scanBtn = $('#scan-btn');
const statusEl = $('#scan-status');
const optVuln = $('#opt-vuln');
const optOffline = $('#opt-offline');

optVuln.addEventListener('change', () => {
    optOffline.disabled = !optVuln.checked || DEMO;
    if (optOffline.disabled) optOffline.checked = false;
});

function setStatus(text, kind = '') {
    statusEl.textContent = text;
    statusEl.className = 'scan-status' + (kind ? ` is-${kind}` : '');
}

function logLine(text) {
    const li = document.createElement('li');
    const t = String(text);
    if (t.startsWith('[+]')) li.className = 'ok';
    else if (t.startsWith('[-]') || t.startsWith('[!]')) li.className = 'err';
    else if (t.includes('CVE') || t.includes('CRITICAL')) li.className = 'warn';
    else if (t.startsWith('//')) li.className = 'note';
    li.textContent = t;
    const log = $('#log');
    log.appendChild(li);
    log.scrollTop = log.scrollHeight;
}

function tick() {
    const s = Math.floor((Date.now() - state.startedAt) / 1000);
    $('#elapsed').textContent = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}

function setScanning(on) {
    state.scanning = on;
    scanBtn.textContent = on ? 'Stop scan' : 'Start scan';
    scanBtn.classList.toggle('btn-primary', !on);
    scanBtn.classList.toggle('btn-stop', on);
    $('#target').readOnly = on;
    $('#ports').readOnly = on;
    $('.options').disabled = on;   // checkboxes ignore readOnly
    clearInterval(state.timer);
    if (on) {
        state.startedAt = Date.now();
        tick();
        state.timer = setInterval(tick, 1000);
    } else {
        state.stream = null;
    }
}

form.addEventListener('submit', (e) => {
    e.preventDefault();
    if (DEMO) return;
    if (state.scanning) { stopScan(); return; }

    const targetInput = $('#target');
    const target = targetInput.value.trim();
    if (!target) {
        targetInput.setAttribute('aria-invalid', 'true');
        targetInput.focus();
        setStatus('Enter an IP address or a network to scan.', 'error');
        return;
    }
    targetInput.removeAttribute('aria-invalid');

    // One field in the UI; the server takes a network or a single target.
    const isNetwork = target.includes('/');
    const params = {
        network: isNetwork ? target : '',
        target: isNetwork ? '' : target,
        ports: $('#ports').value.trim(),
        udp: $('#opt-udp').checked,
        vuln: optVuln.checked,
        noApi: optOffline.checked,
    };

    $('#log').replaceChildren();
    $('#log-panel').hidden = false;
    logLine(`// Scanning ${target}, ports ${params.ports || '1-1000'}`);
    setStatus(`Scanning ${target}…`, 'running');
    setScanning(true);

    const es = new EventSource('/scan/stream?' + new URLSearchParams(params));
    state.stream = es;

    es.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'line') {
            logLine(data.text);
        } else if (data.type === 'done') {
            es.close();
            setScanning(false);
            const results = asList(data.results);
            setStatus(`Finished: ${plural(results.length, 'host', 'hosts')} found.`);
            showScan({
                ts: new Date().toISOString(),
                params: { network: params.network, target: params.target, ports: params.ports },
                results,
            });
            showPage('results');
        } else if (data.type === 'error') {
            es.close();
            setScanning(false);
            logLine('[!] ' + data.text);
            setStatus(data.text, 'error');
        }
    };

    es.onerror = () => {
        // Refused (e.g. 403) or dropped. Close it so the browser doesn't
        // silently reconnect and start a second scan.
        if (state.scanning) {
            logLine('[!] Lost connection to the scanner.');
            setStatus('Lost connection to the scanner.', 'error');
        }
        es.close();
        setScanning(false);
    };
});

function stopScan() {
    setStatus('Stopping…', 'running');
    fetch('/scan/stop', { method: 'POST' }).catch(() => {
        if (state.stream) state.stream.close();
        setScanning(false);
        setStatus('Could not reach the server to stop the scan.', 'error');
    });
}

// ── Results ─────────────────────────────────────────────────────

const CHEVRON = '<svg class="chev" viewBox="0 0 12 12" aria-hidden="true"><path d="M4 2.5 7.5 6 4 9.5"/></svg>';

function showScan(scan) {
    state.scan = scan;
    state.selectedNode = null;
    renderResults();
    const count = asList(scan.results).length;
    $('#nav-results-count').textContent = count ? String(count) : '';
}

function scanTitle(scan) {
    const p = scan.params || {};
    return p.network || p.target || 'Scan';
}

function renderResults() {
    const box = $('#results');
    const scan = state.scan;
    if (!scan) {
        $('#results-meta').textContent = 'No scan loaded yet.';
        box.innerHTML = `<div class="empty"><strong>No results yet</strong>
            <p>Run a scan, or open an earlier one from History.</p>
            <button type="button" class="btn btn-primary" data-goto="scan">Start a scan</button></div>`;
        return;
    }

    const hosts = asList(scan.results);
    const p = scan.params || {};
    $('#results-meta').textContent =
        `${scanTitle(scan)}, ports ${p.ports || '1-1000'}, scanned ${formatDate(scan.ts)}`;

    if (!hosts.length) {
        box.innerHTML = `<div class="empty"><strong>No live hosts found</strong>
            <p>Nothing answered. Check the target, or that you are on the same network.</p></div>`;
        return;
    }

    const ranked = sortByRisk(hosts);
    const byLevel = [0, 0, 0, 0, 0];
    for (const r of ranked) byLevel[r.level] += 1;
    const tcp = hosts.reduce((n, h) => n + asList(h.tcp_ports).length, 0);
    const udp = hosts.reduce((n, h) => n + asList(h.udp_ports).length, 0);
    const cves = hosts.reduce((n, h) => n + cveCount(h), 0);

    const segments = [4, 3, 2, 1, 0].filter((l) => byLevel[l])
        .map((l) => `<span class="sev-${l}" data-grow="${byLevel[l]}"></span>`).join('');
    const legend = [4, 3, 2, 1, 0].filter((l) => byLevel[l])
        .map((l) => `<li><span class="swatch sev-${l}"></span><span><b>${byLevel[l]}</b> ${esc(SEVERITY[l].toLowerCase())}</span></li>`).join('');

    let rows = '';
    for (const { host, index, level } of ranked) {
        const tcpPorts = asList(host.tcp_ports).map((x) => x.port);
        const shown = tcpPorts.slice(0, 7).map(esc).join('  ');
        const more = tcpPorts.length > 7 ? ` <span class="more">+${tcpPorts.length - 7} more</span>` : '';
        const udpNote = asList(host.udp_ports).length ? `<span class="sub">${plural(asList(host.udp_ports).length, 'UDP port', 'UDP ports')}</span>` : '';
        const name = host.hostname ? `<span class="sub">${esc(host.hostname)}</span>` : '';
        const vendor = vendorName(host);

        rows += `
        <tbody>
          <tr class="host-row" data-index="${index}">
            <td>${riskHtml(level)}</td>
            <td><button type="button" class="host-btn" aria-expanded="false" aria-controls="detail-${index}">${CHEVRON}${esc(host.host)}</button>${name}</td>
            <td class="col-device">${esc(deviceName(host) || '—')}${vendor ? `<span class="sub">${esc(vendor)}</span>` : ''}</td>
            <td class="col-os">${esc(known(host.os) || '—')}</td>
            <td class="ports-cell mono">${tcpPorts.length ? shown + more : '<span class="more">None</span>'}${udpNote}</td>
            <td class="num">${cveCount(host) || '—'}</td>
          </tr>
          <tr class="detail-row" id="detail-${index}" hidden><td colspan="6"></td></tr>
        </tbody>`;
    }

    box.innerHTML = `
      <section class="summary" aria-label="Summary">
        <div class="totals">
          <span><strong>${hosts.length}</strong>${hosts.length === 1 ? 'host' : 'hosts'}</span>
          <span><strong>${tcp}</strong>open TCP ${tcp === 1 ? 'port' : 'ports'}</span>
          <span><strong>${udp}</strong>open or filtered UDP</span>
          <span><strong>${cves}</strong>matched ${cves === 1 ? 'CVE' : 'CVEs'}</span>
        </div>
        <div class="dist" role="img" aria-label="Hosts by most severe vulnerability">${segments}</div>
        <ul class="legend">${legend}</ul>
      </section>
      <div class="table-wrap">
        <table class="findings">
          <thead><tr>
            <th scope="col">Risk</th><th scope="col">Host</th>
            <th scope="col" class="col-device">Device</th><th scope="col" class="col-os">OS guess</th>
            <th scope="col">Open ports</th><th scope="col" class="num">CVEs</th>
          </tr></thead>
          ${rows}
        </table>
      </div>
      <p class="footnote">Risk is the most severe CVE matched to a host's services. A host without a match can still be exposed. The OS guess comes from the packet TTL and is only a hint.</p>`;

    // Bar widths are set through the DOM, not inline style attributes,
    // so the strict Content-Security-Policy can stay on.
    for (const seg of $$('.dist span', box)) seg.style.flexGrow = seg.dataset.grow;
}

function portsTableHtml(host) {
    const tcp = asList(host.tcp_ports).map((p) => ({ ...p, proto: 'tcp' }));
    const udp = asList(host.udp_ports).map((p) => ({ ...p, proto: 'udp' }));
    const all = [...tcp, ...udp];
    if (!all.length) return '<p class="muted">No open ports found in the scanned range.</p>';
    const rows = all.map((p) => {
        const cves = asList(p.cves);
        return `<tr>
          <td class="port">${esc(p.port)}/${p.proto}</td>
          <td>${esc(known(p.service) || 'Unknown')}</td>
          <td class="banner">${p.banner ? esc(p.banner) : '<span class="muted">No banner</span>'}</td>
          <td>${cves.length ? `<ul class="cves">${cves.map(cveHtml).join('')}</ul>` : '<span class="muted">None matched</span>'}</td>
        </tr>`;
    }).join('');
    return `<table class="ports-table">
      <thead><tr><th scope="col">Port</th><th scope="col">Service</th><th scope="col">Banner</th><th scope="col">Vulnerabilities</th></tr></thead>
      <tbody>${rows}</tbody></table>`;
}

function factsHtml(host) {
    const facts = [
        ['MAC', host.mac && host.mac !== 'Unknown' ? `<span class="mono">${esc(host.mac)}</span>` : '—'],
        ['Vendor', esc(vendorName(host) || '—')],
        ['Device', esc(deviceName(host) || '—')],
        ['OS guess', esc(known(host.os) || '—')],
    ];
    if (host.hostname) facts.push(['mDNS name', `<span class="mono">${esc(host.hostname)}.local</span>`]);
    if (asList(host.services).length) facts.push(['Advertises', esc(asList(host.services).join(', '))]);
    return `<dl class="facts">${facts.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('')}</dl>`;
}

function toggleHost(row) {
    const index = Number(row.dataset.index);
    const host = asList(state.scan?.results)[index];
    if (!host) return;
    const detail = $(`#detail-${index}`);
    const btn = $('.host-btn', row);
    const open = detail.hidden;
    if (open && !detail.firstElementChild.innerHTML) {
        detail.firstElementChild.innerHTML = `<div class="detail">
            <div><h3>Ports</h3>${portsTableHtml(host)}</div>
            <div><h3>Host</h3>${factsHtml(host)}</div></div>`;
    }
    detail.hidden = !open;
    row.classList.toggle('is-open', open);
    btn.setAttribute('aria-expanded', String(open));
}

$('#results').addEventListener('click', (e) => {
    if (e.target.closest('a')) return;           // let CVE links work
    const row = e.target.closest('.host-row');
    if (row) toggleHost(row);
});

// ── Map (plain SVG, no chart library) ──────────────────────────

const SVG_NS = 'http://www.w3.org/2000/svg';
function svgEl(tag, attrs = {}) {
    const el = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    return el;
}

function pickGateway(hosts) {
    const byDevice = hosts.findIndex((h) => /router|gateway|\bap\b/i.test(String(h.device || '')));
    if (byDevice >= 0) return byDevice;
    const byDotOne = hosts.findIndex((h) => String(h.host || '').endsWith('.1'));
    return byDotOne >= 0 ? byDotOne : 0;
}

function renderMap() {
    const svg = $('#map-svg');
    const canvas = $('#map-canvas');
    svg.replaceChildren();
    const hosts = asList(state.scan?.results);
    if (!hosts.length) {
        $('#map-detail').innerHTML = '<p class="muted">Run a scan or open one from History to draw the map.</p>';
        return;
    }

    const W = canvas.clientWidth || 800;
    const H = canvas.clientHeight || 520;
    svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
    const cx = W / 2;
    const cy = H / 2;

    const gw = pickGateway(hosts);
    const others = hosts.map((h, i) => i).filter((i) => i !== gw);

    // Up to 12 hosts per ring; more hosts get more rings.
    const perRing = 12;
    const rings = Math.max(1, Math.ceil(others.length / perRing));
    const maxR = Math.min(W, H) / 2 - 56;
    const pos = { [gw]: { x: cx, y: cy } };
    others.forEach((hostIndex, i) => {
        const ring = Math.floor(i / perRing);
        const inRing = Math.min(perRing, others.length - ring * perRing);
        const r = maxR * (rings === 1 ? 1 : 0.55 + 0.45 * (ring / (rings - 1)));
        const angle = (2 * Math.PI * (i % perRing)) / inRing - Math.PI / 2 + ring * 0.26;
        pos[hostIndex] = { x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle) };
    });

    const links = svgEl('g');
    for (const i of others) {
        links.appendChild(svgEl('line', {
            class: 'map-link', x1: pos[gw].x, y1: pos[gw].y, x2: pos[i].x, y2: pos[i].y,
        }));
    }
    svg.appendChild(links);

    const nodes = svgEl('g');
    for (const i of [gw, ...others]) {
        const host = hosts[i];
        const { x, y } = pos[i];
        const r = i === gw ? 26 : 20;
        const level = hostLevel(host);
        const g = svgEl('g', {
            class: 'map-node' + (state.selectedNode === i ? ' is-selected' : ''),
            transform: `translate(${x.toFixed(1)},${y.toFixed(1)})`,
            tabindex: '0',
            role: 'button',
            'data-index': String(i),
        });
        const title = svgEl('title');
        title.textContent = `${host.host || ''} ${deviceName(host)} — ${SEVERITY[level]}`;
        g.appendChild(title);
        g.appendChild(svgEl('circle', { class: 'halo', r: r + 7 }));
        if (i === gw) g.appendChild(svgEl('circle', { class: 'gw-ring', r: r + 12 }));
        g.appendChild(svgEl('circle', { class: `dot sev-${level}`, r }));

        const octet = svgEl('text', { class: 'octet' });
        octet.textContent = '.' + String(host.host || '?').split('.').pop();
        g.appendChild(octet);

        const label = svgEl('text', { class: 'label', y: r + 20 });
        label.textContent = i === gw ? 'Gateway' : (deviceName(host) || vendorName(host) || String(host.host || ''));
        g.appendChild(label);
        nodes.appendChild(g);
    }
    svg.appendChild(nodes);

    if (state.selectedNode !== null && hosts[state.selectedNode]) showNodeDetail(state.selectedNode);
}

function showNodeDetail(index) {
    const host = asList(state.scan?.results)[index];
    if (!host) return;
    state.selectedNode = index;
    for (const n of $$('.map-node')) n.classList.toggle('is-selected', Number(n.dataset.index) === index);

    const ports = [
        ...asList(host.tcp_ports).map((p) => ({ ...p, proto: 'tcp' })),
        ...asList(host.udp_ports).map((p) => ({ ...p, proto: 'udp' })),
    ];
    const portItems = ports.map((p) => `<li>
        <span><span class="port">${esc(p.port)}/${p.proto}</span> ${esc(known(p.service) || 'Unknown')}</span>
        ${p.banner ? `<span class="banner">${esc(p.banner)}</span>` : ''}
        ${asList(p.cves).length ? `<ul class="cves">${asList(p.cves).map(cveHtml).join('')}</ul>` : ''}
      </li>`).join('');

    $('#map-detail').innerHTML = `
      <div class="ip">${esc(host.host)}</div>
      ${host.hostname ? `<div class="muted mono">${esc(host.hostname)}.local</div>` : ''}
      ${riskHtml(hostLevel(host))}
      ${factsHtml(host)}
      <h3>Open ports</h3>
      ${ports.length ? `<ul class="port-list">${portItems}</ul>` : '<p class="muted">No open ports found.</p>'}`;
}

$('#map-svg').addEventListener('click', (e) => {
    const node = e.target.closest('.map-node');
    if (node) showNodeDetail(Number(node.dataset.index));
});
$('#map-svg').addEventListener('keydown', (e) => {
    const node = e.target.closest('.map-node');
    if (node && (e.key === 'Enter' || e.key === ' ')) {
        e.preventDefault();
        showNodeDetail(Number(node.dataset.index));
    }
});

let resizeTimer;
window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => { if (!$('#page-map').hidden) renderMap(); }, 150);
});

// ── History ─────────────────────────────────────────────────────

function fetchHistory() {
    return fetch('/history')
        .then((r) => r.json())
        .then((data) => { state.history = asList(data); return state.history; });
}

function loadHistory() {
    const box = $('#history');
    fetchHistory().then((entries) => {
        if (!entries.length) {
            box.innerHTML = `<div class="empty"><strong>No scans yet</strong>
                <p>Finished scans are saved here automatically.</p>
                <button type="button" class="btn btn-primary" data-goto="scan">Start a scan</button></div>`;
            return;
        }
        const rows = entries.map((entry, i) => {
            const hosts = asList(entry.results);
            const ports = hosts.reduce((n, h) => n + asList(h.tcp_ports).length, 0);
            const worst = hosts.reduce((m, h) => Math.max(m, hostLevel(h)), 0);
            return `<tr class="hist-row" data-index="${i}">
              <td><button type="button" class="btn-link target">${esc(scanTitle(entry))}</button>${entry.sample ? '<span class="sub">Sample data</span>' : ''}</td>
              <td>${esc(formatDate(entry.ts))}</td>
              <td class="num">${hosts.length}</td>
              <td class="num">${ports}</td>
              <td>${riskHtml(worst)}</td>
            </tr>`;
        }).join('');
        box.innerHTML = `<div class="table-wrap"><table class="history">
          <thead><tr><th scope="col">Target</th><th scope="col">Scanned</th>
          <th scope="col" class="num">Hosts</th><th scope="col" class="num">Open TCP ports</th>
          <th scope="col">Worst risk</th></tr></thead>
          <tbody>${rows}</tbody></table></div>`;
    }).catch(() => {
        box.innerHTML = '<div class="empty"><strong>Could not load history</strong><p>The server did not respond. Reload the page to try again.</p></div>';
    });
}

$('#history').addEventListener('click', (e) => {
    const row = e.target.closest('.hist-row');
    if (!row) return;
    const entry = state.history[Number(row.dataset.index)];
    if (!entry) return;
    showScan(entry);
    showPage('results');
});

// ── Start ───────────────────────────────────────────────────────

renderResults();
if (DEMO) {
    // Visitors to the demo land on the sample scan straight away.
    fetchHistory().then((entries) => {
        if (entries.length && !state.scan) showScan(entries[0]);
        showPage('results', { focus: false });
    }).catch(() => showPage('scan', { focus: false }));
} else {
    showPage('scan', { focus: false });
}
