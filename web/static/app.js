// eFe Process Monitor — dashboard script. Served from /static/ so the page can
// run under a Content-Security-Policy of script-src 'self': nothing inline,
// no nonces. Every clickable element carries data-action (data-change /
// data-input for form controls) and the dispatcher at the bottom routes it to
// the actions table; parameters travel as data-* attributes, which the
// templates escape for the attribute context.

// Translations and the refresh interval travel on <body data-t data-refresh>:
// the page has no inline script, so the CSP can be script-src 'self'.
const T = JSON.parse(document.body.dataset.t);
let refreshSecs = parseInt(document.body.dataset.refresh, 10) || 0; // table auto-refresh seconds (server-persisted)

function loadConnections() {
    const self = document.getElementById('hide-self').checked ? '0' : '1';
    fetch('/api/connections?self=' + self)
        .then(r => r.text())
        .then(html => { document.getElementById('conn-tbody').innerHTML = html; applySort(); filterRows(); syncPinnedToggles(); })
        .catch(() => {});
}

// ── Pinned (locked) connection snapshots ──────────────────────────────────
const pinnedSigs = new Set();

function toggleLock(input, i) {
    const detail = document.getElementById('d' + i);
    const row = detail ? detail.previousElementSibling : null;
    if (!row) return;
    const sig = row.dataset.sig;
    if (input.checked) pinConnection(row, detail, sig);
    else unpin(sig);
}

function pinConnection(row, detail, sig) {
    pinnedSigs.add(sig);
    if (row) row.classList.add('pinned-row');
    if (!sig || document.querySelector('#pinned-list [data-sig="' + sig + '"]')) return; // already pinned
    const content = detail.querySelector('.details-content').cloneNode(true);
    content.querySelectorAll('.actions-block, .capture-panel').forEach(el => el.remove());
    const threat = row.querySelector('.threat');
    const badge = threat ? threat.outerHTML : '';
    const when = new Date().toLocaleTimeString();
    const card = document.createElement('div');
    card.className = 'pinned-card';
    card.setAttribute('data-sig', sig);
    card.innerHTML =
        '<div class="pinned-card-head">' +
            '<span class="pc-info">' + badge + ' <strong>' + esc(row.dataset.proc || '') + '</strong>' +
            ' <span class="t">PID ' + esc(row.dataset.pid || '—') + '</span>' +
            ' <span class="t">' + esc(row.dataset.local || '') + (row.dataset.remote ? ' → ' + esc(row.dataset.remote) : '') + '</span>' +
            ' <span class="t">· ' + esc(T.pinned_at) + ' ' + when + '</span></span>' +
            '<button class="btn btn-stop" data-action="unpinCard">✕</button>' +
        '</div>';
    card.appendChild(content);
    document.getElementById('pinned-list').appendChild(card);
    updatePinnedPanel();
}

function unpin(sig) {
    pinnedSigs.delete(sig);
    const card = document.querySelector('#pinned-list [data-sig="' + sig + '"]');
    if (card) card.remove();
    document.querySelectorAll('#conn-tbody tr.main-row').forEach(r => {
        if (r.dataset.sig === sig) {
            r.classList.remove('pinned-row');
            const cb = r.nextElementSibling && r.nextElementSibling.querySelector('.lock-switch input');
            if (cb) cb.checked = false;
        }
    });
    updatePinnedPanel();
}

function clearPinned() {
    pinnedSigs.clear();
    document.getElementById('pinned-list').innerHTML = '';
    document.querySelectorAll('.lock-switch input').forEach(cb => cb.checked = false);
    document.querySelectorAll('#conn-tbody tr.pinned-row').forEach(r => r.classList.remove('pinned-row'));
    updatePinnedPanel();
}

function updatePinnedPanel() {
    const n = document.querySelectorAll('#pinned-list .pinned-card').length;
    document.getElementById('pinned-count').textContent = n;
    document.getElementById('pinned-panel').style.display = n ? 'block' : 'none';
}
function togglePinned() { document.getElementById('pinned-panel').classList.toggle('collapsed'); }

// keep the lock toggle checked for connections still live after a refresh
function syncPinnedToggles() {
    if (!pinnedSigs.size) return;
    document.querySelectorAll('#conn-tbody tr.main-row').forEach(r => {
        if (pinnedSigs.has(r.dataset.sig)) {
            r.classList.add('pinned-row');
            const cb = r.nextElementSibling && r.nextElementSibling.querySelector('.lock-switch input');
            if (cb) cb.checked = true;
        }
    });
}

function filterRows() {
    const q = (document.getElementById('filter').value || '').toLowerCase();
    document.querySelectorAll('#conn-tbody tr.main-row').forEach(m => {
        const hay = (m.getAttribute('data-search') || '').toLowerCase();
        const show = !q || hay.includes(q);
        m.style.display = show ? '' : 'none';
        const d = m.nextElementSibling;
        if (d && d.classList.contains('details-row') && !show) d.style.display = 'none';
    });
}

function toggleDetails(i) {
    const row = document.getElementById('d' + i);
    if (!row) return;
    const show = row.style.display === 'none';
    row.style.display = show ? 'table-row' : 'none';
    const main = row.previousElementSibling;
    if (main && main.classList.contains('main-row')) main.classList.toggle('open', show);
}

function postJSON(url, body, method = 'POST') {
    return fetch(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
        .then(r => r.json());
}

function killProc(pid, name) {
    if (!confirm(`${T.kill_proc} — ${name} (${pid})?`)) return;
    postJSON('/api/kill', { PID: pid }).then(res => {
        alert(res.ok ? 'OK' : 'Error: ' + res.error);
        if (res.ok) loadConnections();
    });
}

// Suspend freezes the process without destroying it (memory, files and
// sockets stay for analysis); resume lets it go on. Resuming needs no
// confirmation: it only undoes.
function setSuspended(pid, resume) {
    postJSON('/api/suspend', { PID: pid, Resume: resume }).then(res => {
        if (!res.ok) alert('Error: ' + res.error);
        loadConnections();
    });
}
function suspendProc(pid, name) {
    if (confirm(`${T.suspend_proc} — ${name} (${pid})?`)) setSuspended(pid, false);
}
function resumeProc(pid) { setSuspended(pid, true); }

function toggleWhitelist(exe, listed) {
    postJSON('/api/whitelist', { Exe: exe }, listed ? 'DELETE' : 'POST').then(() => loadConnections());
}

function toggleIPWhitelist(ip, listed) {
    postJSON('/api/ip_whitelist', { IP: ip }, listed ? 'DELETE' : 'POST').then(() => loadConnections());
}

function blockIp(ip) {
    if (!confirm(`${T.block_ip} — ${ip}?`)) return;
    postJSON('/api/block_ip', { IP: ip }).then(res => alert(res.ok ? 'OK' : 'Error: ' + res.error));
}

function openBlock(btn) {
    const ips = (btn.dataset.ips || '').split(',').filter(Boolean);
    document.getElementById('block-ips').innerHTML = ips.map(ip =>
        `<label class="ipsel-item"><input type="checkbox" value="${esc(ip)}" checked> ${esc(ip)}</label>`).join('');
    document.getElementById('block-modal').style.display = 'flex';
}
function closeBlock() { document.getElementById('block-modal').style.display = 'none'; }
function blockModalSelected() {
    const ips = [...document.querySelectorAll('#block-ips input:checked')].map(c => c.value);
    if (!ips.length) return;
    Promise.all(ips.map(ip => postJSON('/api/block_ip', { IP: ip }))).then(rs => {
        const bad = rs.filter(r => !r.ok);
        alert(bad.length ? ('Error: ' + bad.map(b => b.error).join(' · ')) : 'OK');
        closeBlock();
    });
}

function openSettings() {
    document.getElementById('settings-modal').style.display = 'flex';
    document.getElementById('vt-key').value = '';
    document.getElementById('abuse-key').value = '';
    document.getElementById('abusech-key').value = '';
    document.getElementById('settings-msg').textContent = '';
    fetch('/api/settings').then(r => r.json()).then(s => {
        document.getElementById('refresh-interval').value = String(s.refresh_secs || 0);
        document.getElementById('audit-every').value = String(s.audit_every_hours == null ? 6 : s.audit_every_hours);
        document.getElementById('retention-days').value = String(s.event_retention_days == null ? 30 : s.event_retention_days);
        document.getElementById('webhook-url').value = '';
        document.getElementById('webhook-format').value = s.webhook_format || 'json';
        document.getElementById('webhook-status').textContent = s.webhook_configured ? `(${s.webhook_hint})` : '✗';
        document.getElementById('webhook-msg').textContent = '';
        document.getElementById('update-check').checked = !!s.update_check;
        document.getElementById('update-status').textContent = s.update_check ? '— ' + updateStatusText(s) : '';
        showUpdateNotice(s);
        document.getElementById('notify-desktop').checked = !!s.notify_desktop;
        document.getElementById('notify-sound').checked = !!s.notify_sound;
        document.getElementById('persist-whitelist').checked = !!s.persist_whitelist;
        document.getElementById('persist-blocks').checked = !!s.persist_blocks;
        document.getElementById('auth-enabled').checked = !!s.auth_enabled;
        authWasEnabled = !!s.auth_enabled;
        document.getElementById('auth-current').value = '';
        document.getElementById('auth-password').value = '';
        document.getElementById('auth-password-confirm').value = '';
        document.getElementById('auth-password').type = 'password';
        document.getElementById('auth-password-confirm').type = 'password';
        document.getElementById('logout-link').style.display = s.auth_enabled ? 'inline' : 'none';
        document.getElementById('listen-addr').value = s.listen_addr || '';
        document.getElementById('restart-msg').textContent = '';
        authToggled(); // pw fields + listen address only when login is on
        document.getElementById('vt-status').textContent =
            s.vt_configured ? `(${s.vt_hint})` : '✗';
        document.getElementById('abuse-status').textContent =
            s.abuse_configured ? `(${s.abuse_hint})` : '✗';
        document.getElementById('abusech-status').textContent =
            s.abusech_configured ? `(${s.abusech_hint})` : '✗';
    });
    loadServiceBlock();
}

// ── New-version notice (optional, off by default) ─────────────────────────
// The link target is fixed in the template; only the version text comes from
// the server, which accepts nothing but digits and dots.
function updateStatusText(s) {
    if (s.update_available) return 'v' + s.update_available + ' · ' + T.update_new;
    if (s.update_error) return '⚠ ' + T.update_failed;
    return s.update_latest ? T.update_uptodate : '…';
}
function showUpdateNotice(s) {
    const a = document.getElementById('update-link');
    a.textContent = s.update_available ? '↑ v' + s.update_available : '';
    a.style.display = s.update_available ? '' : 'none';
}
function refreshUpdateNotice() {
    fetch('/api/settings').then(r => r.json()).then(showUpdateNotice).catch(() => {});
}
refreshUpdateNotice();
setInterval(refreshUpdateNotice, 6 * 3600 * 1000); // a dashboard left open for days still finds out

// ── Alert webhook ─────────────────────────────────────────────────────────
function testWebhook() {
    const msg = document.getElementById('webhook-msg');
    msg.textContent = '…';
    // Save what is on screen first, so "Test" tests the URL just typed.
    postJSON('/api/settings', settingsPayload())
        .then(s => { if (s && s.webhook_error) throw new Error(s.webhook_error); return postJSON('/api/webhook_test', {}); })
        .then(r => { msg.textContent = r.ok ? '✓' : '⚠ ' + r.error; openSettingsKeepMsg(msg.textContent); })
        .catch(e => { msg.textContent = '⚠ ' + e.message; });
}
function clearWebhook() {
    postJSON('/api/settings', { WebhookURL: '' }).then(() => openSettings());
}
function openSettingsKeepMsg(text) {
    openSettings();
    setTimeout(() => { document.getElementById('webhook-msg').textContent = text; }, 400);
}

// ── Run at boot (systemd service; Linux) ───────────────────────────────────
let svcState = null;
function loadServiceBlock() {
    const block = document.getElementById('svc-block');
    fetch('/api/service').then(r => r.json()).then(st => {
        svcState = st;
        if (!st || !st.supported) { block.style.display = 'none'; return; }
        block.style.display = 'block';
        const pill = document.getElementById('svc-status');
        pill.textContent = st.installed ? (st.active ? T.svc_installed : T.svc_installed_inactive) : T.svc_not_installed;
        pill.className = 'status-pill ' + (st.installed && st.active ? 'status-on' : st.installed ? 'status-cap' : '');
        document.getElementById('svc-path').textContent = st.installed ? st.path : '';
        const btn = document.getElementById('svc-btn');
        btn.textContent = st.installed ? T.svc_uninstall : T.svc_install;
        btn.disabled = !st.elevated;
        document.getElementById('svc-msg').textContent = st.elevated ? '' : T.svc_needs_root;
    }).catch(() => { block.style.display = 'none'; });
}
function serviceAction() {
    if (!svcState) return;
    const install = !svcState.installed;
    if (!confirm(install ? T.svc_confirm_install : T.svc_confirm_uninstall)) return;
    const msg = document.getElementById('svc-msg');
    postJSON('/api/service', { action: install ? 'install' : 'uninstall' }).then(res => {
        if (!res.ok) { msg.textContent = '⚠ ' + (res.error || 'error'); return; }
        if (install) {
            // This instance hands the port to the service and exits; the page
            // reconnects to the service once it is up (~ port handoff time).
            msg.textContent = T.svc_installing;
            setTimeout(() => location.reload(), 6500);
        } else {
            msg.textContent = '✓';
            setTimeout(loadServiceBlock, 1500);
        }
    }).catch(() => { msg.textContent = '⚠ error'; });
}
function closeSettings() { document.getElementById('settings-modal').style.display = 'none'; }
function togglePw() {
    const a = document.getElementById('auth-password'), b = document.getElementById('auth-password-confirm');
    const t = a.type === 'password' ? 'text' : 'password';
    a.type = t; b.type = t;
}
// Whether a password is already set server-side. Changing or removing an
// existing one requires proving you know it, so the "current password" field is
// driven by this, not by the checkbox.
let authWasEnabled = false;

// pw fields + listen address (network exposure) only make sense with login on
function authToggled() {
    const on = document.getElementById('auth-enabled').checked;
    document.getElementById('auth-pw-row').style.display = on ? 'block' : 'none';
    document.getElementById('listen-row').style.display = on ? 'block' : 'none';
    document.getElementById('auth-current-row').style.display = authWasEnabled ? 'block' : 'none';
}
function clampSecs() { return Math.max(0, Math.min(3600, parseInt(document.getElementById('refresh-interval').value || '0', 10) || 0)); }
function settingsPayload() {
    return {
        VTKey: document.getElementById('vt-key').value,
        AbuseKey: document.getElementById('abuse-key').value,
        AbuseChKey: document.getElementById('abusech-key').value,
        NotifyDesktop: document.getElementById('notify-desktop').checked,
        NotifySound: document.getElementById('notify-sound').checked,
        PersistWhitelist: document.getElementById('persist-whitelist').checked,
        PersistBlocks: document.getElementById('persist-blocks').checked,
        RefreshSecs: clampSecs(),
        AuditEveryHours: Math.max(0, Math.min(168, parseInt(document.getElementById('audit-every').value || '0', 10) || 0)),
        EventRetentionDays: Math.max(0, Math.min(3650, parseInt(document.getElementById('retention-days').value || '0', 10) || 0)),
        // The URL is only sent when typed: an empty field means "leave it".
        ...(document.getElementById('webhook-url').value.trim() ? { WebhookURL: document.getElementById('webhook-url').value.trim() } : {}),
        WebhookFormat: document.getElementById('webhook-format').value,
        UpdateCheck: document.getElementById('update-check').checked,
        AuthEnabled: document.getElementById('auth-enabled').checked,
        AuthPassword: document.getElementById('auth-password').value,
        CurrentPassword: document.getElementById('auth-current').value,
        ListenAddr: document.getElementById('listen-addr').value,
    };
}
function pwMismatch() {
    const pw = document.getElementById('auth-password').value;
    return document.getElementById('auth-enabled').checked && pw !== '' &&
        pw !== document.getElementById('auth-password-confirm').value;
}
function saveSettings() {
    if (pwMismatch()) { document.getElementById('settings-msg').textContent = '⚠ ' + T.auth_mismatch; return; }
    refreshSecs = clampSecs();
    applyRefreshInterval();
    postJSON('/api/settings', settingsPayload()).then(s => {
        if (s && s.auth_error) { document.getElementById('settings-msg').textContent = '⚠ ' + s.auth_error; return; }
        if (s && s.webhook_error) { document.getElementById('settings-msg').textContent = '⚠ ' + s.webhook_error; return; }
        document.getElementById('settings-msg').textContent = '✓'; loadConnections(); openSettings();
    });
}
// derive the URL the dashboard will live at after a restart with the new address
function targetURL() {
    let addr = (document.getElementById('listen-addr').value || '').trim() || '127.0.0.1:5000';
    let host, port;
    const m6 = addr.match(/^\[(.+)\]:(\d+)$/);
    if (m6) { host = m6[1]; port = m6[2]; }
    else { const i = addr.lastIndexOf(':'); if (i >= 0) { host = addr.slice(0, i); port = addr.slice(i + 1); } else { host = addr; port = '5000'; } }
    if (!host || host === '0.0.0.0' || host === '::') host = '127.0.0.1';
    if (!port) port = '5000';
    const loopback = host === 'localhost' || host === '::1' || /^127\./.test(host);
    const h = host.includes(':') ? '[' + host + ']' : host;
    return (loopback ? 'http' : 'https') + '://' + h + ':' + port;
}
function restartNow() {
    if (pwMismatch()) { document.getElementById('restart-msg').textContent = '⚠ ' + T.auth_mismatch; return; }
    if (!confirm(T.restart_confirm)) return;
    const msg = document.getElementById('restart-msg'), target = targetURL();
    msg.textContent = T.restart_doing;
    refreshSecs = clampSecs(); applyRefreshInterval();
    const go = () => {
        msg.innerHTML = T.restart_doing + ' → <a href="' + target + '" style="color:#58a6ff">' + target + '</a>';
        setTimeout(() => { location.href = target; }, 6500); // ~ port handoff time
    };
    postJSON('/api/settings', settingsPayload())
        .then(() => postJSON('/api/restart', {}))
        .then(go).catch(go);
}

function stopService() {
    if (!confirm(T.stop_confirm)) return;
    const msg = document.getElementById('stop-msg');
    msg.textContent = T.stop_doing;
    postJSON('/api/shutdown', {}).catch(() => {});
    setTimeout(() => {
        document.body.style.cssText = 'margin:0;background:#0d1117;display:flex;align-items:center;justify-content:center;height:100vh;';
        document.body.innerHTML = '<p style="color:#8b949e;font-family:monospace;font-size:15px;">' + T.stop_done + '</p>';
    }, 800);
}

// ── Live monitor ──────────────────────────────────────────────────────────
let liveCount = 0, refreshTimer = null;

function clearFeed() {
    document.getElementById('live-feed').innerHTML = '';
    liveCount = 0;
    document.getElementById('live-count').textContent = '0';
}

function anyDetailOpen() {
    return [...document.querySelectorAll('tr.details-row')].some(r => r.style.display === 'table-row');
}
function busy() {
    return Object.keys(activeSources).length > 0 || anyDetailOpen();
}
let periodicTimer = null;
function applyRefreshInterval() {
    if (periodicTimer) { clearInterval(periodicTimer); periodicTimer = null; }
    if (refreshSecs > 0) periodicTimer = setInterval(() => { if (!busy()) loadConnections(); }, refreshSecs * 1000);
}

function scheduleRefresh() {
    if (!document.getElementById('auto-refresh').checked) return;
    if (busy()) return; // never refresh while you're inspecting a row or capturing
    if (refreshTimer) return;
    refreshTimer = setTimeout(() => {
        refreshTimer = null;
        if (!busy()) loadConnections();
    }, 1500);
}

// Escapes for HTML *and* for both quote styles. The single quote matters: some
// of the strings below land inside single-quoted attributes, and leaving ' raw
// there is an injection waiting for the first value that isn't a validated IP.
function esc(s) {
    return String(s == null ? '' : s)
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function eventLabel(ev) {
    const proc = ev.process || 'N/A', pid = ev.pid || '—';
    let tags = ev.new_process ? ` [${T.tag_newproc}]` : '';
    if (ev.changed) tags += ` [${T.tag_binchanged}]`;
    else if (ev.anomaly) tags += ` [${T.tag_newbin}]`;
    if (ev.beacon) return `⚠ ${T.ev_beacon} ~${ev.beacon}s — ${proc} (${pid}) → ${ev.remote}${tags}`;
    switch (ev.kind) {
        case 'closed':  return `✕ ${T.ev_closed} — ${proc} (${pid})${ev.remote ? ' → ' + ev.remote : ''}`;
        case 'alert':   return `⚠ ${ev.detail || T.ev_suspicious} — ${proc} (${pid})${ev.remote || ev.local ? ' → ' + (ev.remote || ev.local) : ''}${tags}`;
        case 'remote':  return `→ ${T.ev_new} — ${proc} (${pid}) → ${ev.remote}${tags}`;
        default:        return `+ ${T.ev_new} — ${proc} (${pid}) ${ev.remote ? '→ ' + ev.remote : (ev.local || '')}${tags}`;
    }
}

const monitorES = new EventSource('/events');
monitorES.onmessage = (e) => {
    const ev = JSON.parse(e.data);
    if (ev.kind === 'hello') return;
    if (ev.kind === 'refresh') { scheduleRefresh(); return; } // a background lookup landed: redraw, nothing to list
    const feed = document.getElementById('live-feed');
    const div = document.createElement('div');
    div.className = 'live-ev ev-' + ev.kind + (ev.level ? ' lvl-' + ev.level : ''); // graded reputation alerts: low / med / high
    div.innerHTML = `<span class="t">[${esc(ev.ts)}]</span> ` + esc(eventLabel(ev));
    feed.prepend(div);
    while (feed.children.length > 200) feed.removeChild(feed.lastChild);
    document.getElementById('live-count').textContent = ++liveCount;
    scheduleRefresh();
};

// ── Interface selector + capture status ───────────────────────────────────
let ifaceStatus = { text: T.detecting || '…', cls: 'status-pill', title: '' };
const activeSources = {}, packetCounts = {};

function refreshStatus() {
    const pill = document.getElementById('cap-status');
    const n = Object.keys(activeSources).length;
    if (n > 0) {
        const total = Object.values(packetCounts).reduce((a, b) => a + (b || 0), 0);
        pill.textContent = `● ${T.ev_capturing} — ${n}, ${total} pkts`;
        pill.className = 'status-pill status-cap'; pill.title = '';
    } else {
        pill.textContent = ifaceStatus.text; pill.className = ifaceStatus.cls; pill.title = ifaceStatus.title;
    }
}

fetch('/api/interfaces').then(r => r.json()).then(info => {
    const sel = document.getElementById('iface-select');
    const ifs = info.interfaces || [];
    if (!ifs.length) {
        sel.innerHTML = '<option value="1">tshark ✗</option>';
        ifaceStatus = { text: '● tshark ✗', cls: 'status-pill status-off', title: '' };
        return refreshStatus();
    }
    sel.innerHTML = '';
    ifs.forEach(i => {
        const o = document.createElement('option');
        o.value = i.index; o.textContent = `${i.index}. ${i.friendly}`;
        if (i.index === info.recommended) o.selected = true;
        sel.appendChild(o);
    });
    ifaceStatus = { text: `● ${info.adapter || 'auto'} (idx ${info.recommended})`,
        cls: 'status-pill status-on', title: info.local_ip || '' };
    refreshStatus();
}).catch(() => {});

// ── Live packet capture ───────────────────────────────────────────────────
const capState = {}; // i -> per-capture stats/buffer
const enc = encodeURIComponent;

function human(n) {
    const u = ['B','KB','MB','GB']; let f = n || 0, k = 0;
    while (f >= 1024 && k < u.length-1) { f /= 1024; k++; }
    return f.toFixed(f < 10 && k > 0 ? 1 : 0) + ' ' + u[k];
}

// While capturing the panel button is an active Stop; once stopped it becomes
// disabled (restart is done with the row's Sniff button).
function setCapBtn(i, capturing) {
    const btn = document.getElementById('cap-btn-' + i);
    if (!btn) return;
    if (capturing) {
        btn.disabled = false;
        btn.textContent = '■ Stop';
        btn.className = 'btn btn-stop';
        btn.onclick = () => stopCapture(i);
    } else {
        btn.disabled = true;          // same text, just disabled state
        btn.className = 'btn btn-stop';
        btn.onclick = null;
    }
}

function openCapture(i, localIp, remoteIp) {
    document.getElementById('d' + i).style.display = 'table-row';
    document.getElementById('cap-panel-' + i).style.display = 'block';
    document.getElementById('cap-output-' + i).innerHTML = '';
    document.getElementById('cap-doms-' + i).innerHTML = '';
    const stats = document.getElementById('cap-stats-' + i);
    stats.className = 'capture-stats cap-active'; stats.textContent = T.cap_starting;
    packetCounts[i] = 0;
    if (activeSources[i]) activeSources[i].close();
    if (capState[i] && capState[i].timer) clearInterval(capState[i].timer);
    capState[i] = { packets: [], n: 0, outB: 0, inB: 0, protos: {}, domains: new Set(),
        localIp, start: Date.now(), timer: setInterval(() => flushCapture(i), 300) };

    const iface = document.getElementById('iface-select').value;
    const count = document.getElementById('cap-count-' + i).value;
    const es = new EventSource(`/capture?local_ip=${enc(localIp)}&remote_ip=${enc(remoteIp)}&iface=${enc(iface)}&count=${enc(count)}`);
    activeSources[i] = es; setCapBtn(i, true); refreshStatus();
    es.onmessage = e => {
        const pkt = JSON.parse(e.data);
        if (pkt.done)  return endCapture(i, T.cap_done, false);
        if (pkt.error) return endCapture(i, T.cap_error + ': ' + pkt.error, true);
        ingest(i, pkt);
    };
    es.onerror = () => endCapture(i, T.cap_error, true);
}

function ingest(i, p) {
    const s = capState[i]; if (!s) return;
    s.n++; packetCounts[i] = s.n;
    const len = parseInt(p.len) || 0;
    if (p.ip_src === s.localIp) { s.outB += len; p._out = true; } else { s.inB += len; p._out = false; }
    const proto = p.proto || (p.tcp_src || p.tcp_dst ? 'TCP' : (p.udp_src || p.udp_dst ? 'UDP' : '?'));
    p._proto = proto; s.protos[proto] = (s.protos[proto] || 0) + 1;
    const dom = p.tls_sni || p.http_host || p.dns;
    if (dom) s.domains.add(dom);
    s.packets.push(p);
    if (s.packets.length > 3000) s.packets.shift();
}

function flushCapture(i) {
    const s = capState[i]; if (!s) return;
    const secs = Math.max(1, (Date.now() - s.start) / 1000);
    const protos = Object.entries(s.protos).sort((a,b)=>b[1]-a[1])
        .map(([k,v]) => `${esc(k)} ${v}`).join(' · ');
    const stats = document.getElementById('cap-stats-' + i);
    if (s.n > 0) stats.className = 'capture-stats';
    stats.innerHTML = `● ${s.n} ${T.cap_pkts} · ↑${human(s.outB)} ↓${human(s.inB)} · ${(s.n/secs).toFixed(1)}/s`
        + (protos ? ` · <span class="cap-protos">${protos}</span>` : '');
    const dl = document.getElementById('cap-doms-' + i);
    dl.innerHTML = s.domains.size
        ? '🌐 ' + [...s.domains].slice(0,40).map(d=>`<span class="cap-dom">${esc(d)}</span>`).join(' ')
        : '';
    renderPackets(i);
}

function renderPackets(i) {
    const s = capState[i]; if (!s) return;
    const q = (document.getElementById('cap-filter-' + i).value || '').toLowerCase();
    let rows = s.packets;
    if (q) rows = rows.filter(p => [p.ip_src,p.ip_dst,p._proto,p.tls_sni,p.http_host,p.dns,p.info]
        .filter(Boolean).join(' ').toLowerCase().includes(q));
    const out = document.getElementById('cap-output-' + i);
    out.innerHTML = rows.slice(-500).map(formatPacket).join('\n');
    if (document.getElementById('cap-auto-' + i).checked) out.scrollTop = out.scrollHeight;
}

function endCapture(i, msg, isErr) {
    const s = capState[i];
    if (s && s.timer) clearInterval(s.timer);
    if (activeSources[i]) { activeSources[i].close(); delete activeSources[i]; }
    if (s) flushCapture(i);
    setCapBtn(i, false);
    const stats = document.getElementById('cap-stats-' + i);
    if (stats) {
        stats.className = 'capture-stats ' + (isErr ? 'cap-err' : 'cap-stopped');
        stats.innerHTML = `${esc(msg)} — ${packetCounts[i] || 0} ${T.cap_pkts}`;
    }
    refreshStatus();
}

function stopCapture(i) {
    if (activeSources[i]) endCapture(i, T.cap_stopped, false);
}

function downloadPcap(ev, i) {
    ev.preventDefault();
    const panel = document.getElementById('cap-panel-' + i);
    const iface = document.getElementById('iface-select').value;
    let count = document.getElementById('cap-count-' + i).value;
    if (count === '0') count = '5000';
    window.location = `/capture.pcap?local_ip=${enc(panel.dataset.local)}&remote_ip=${enc(panel.dataset.remote)}&iface=${enc(iface)}&count=${count}`;
}

function formatPacket(p) {
    let o = '';
    if (p.time) { const d = new Date(parseFloat(p.time) * 1000);
        o += `<span class="pkt-time">[${d.toLocaleTimeString('es-ES', { hour12: false })}]</span> `; }
    o += `<span class="pkt-dir">${p._out ? '↑' : '↓'}</span> `;
    if (p._proto) o += `<span class="pkt-proto">${esc(p._proto)}</span> `;
    if (p.len) o += `<span class="pkt-size">${esc(p.len)}B</span> `;
    const sp = esc(p.tcp_src || p.udp_src || ''), dp = esc(p.tcp_dst || p.udp_dst || '');
    o += `<span class="pkt-flow">${esc(p.ip_src || '?')}${sp ? ':' + sp : ''} → ${esc(p.ip_dst || '?')}${dp ? ':' + dp : ''}</span>`;
    if (p.tcp_flags) { const c = p.syn === '1' ? 'pkt-syn' : p.fin === '1' ? 'pkt-fin' : 'pkt-flags';
        o += ` <span class="${c}">[${esc(p.tcp_flags)}]</span>`; }
    if (p.tls_sni)   o += ` <span class="pkt-tls">TLS ${esc(p.tls_sni)}</span>`;
    if (p.http_host) o += ` <span class="pkt-http">${esc(p.http_method || 'HTTP')} ${esc(p.http_host)}${esc(p.http_uri || '')}</span>`;
    if (p.dns)       o += ` <span class="pkt-dns">DNS ${esc(p.dns)}</span>`;
    return o;
}

// ── History ───────────────────────────────────────────────────────────────
let histEvents = [];
function openHistory() {
    const m = document.getElementById('history-modal'), b = document.getElementById('history-body');
    showingScoreHistory = false; // always open on the event list, not the risk view
    m.style.display = 'flex'; b.textContent = '…';
    fetch('/api/events?limit=500').then(r => r.json()).then(evs => {
        // refresh the kind filter with the kinds actually present
        const sel = document.getElementById('hist-kind'), cur = sel.value;
        const kinds = [...new Set((evs || []).map(e => e.kind).filter(Boolean))].sort();
        sel.innerHTML = `<option value="">${esc(T.hist_kind_all)}</option>` +
            kinds.map(k => `<option value="${esc(k)}">${esc(k)}</option>`).join('');
        sel.value = kinds.includes(cur) ? cur : '';
        histEvents = evs || [];
        renderHistory();
    }).catch(() => { b.textContent = 'error'; });
}
// The process and kind filters apply to the list as well as to deletion: the
// details block opens the history already narrowed to one process.
function renderHistory() {
    if (showingScoreHistory) return;
    const b = document.getElementById('history-body');
    const proc = document.getElementById('hist-proc').value.trim().toLowerCase();
    const kind = document.getElementById('hist-kind').value;
    const evs = histEvents.filter(e => (!proc || (e.process || '').toLowerCase().includes(proc)) && (!kind || e.kind === kind));
    if (!evs.length) { b.textContent = '—'; return; }
    b.innerHTML = evs.map(e => `<div class="hist-row"><span class="t">${esc(e.ts||'')}</span>`+
        `<span class="ev-${esc(e.kind||'')}">${esc(e.kind||'')}</span>`+
        `<span>${esc(e.process||'')} (${e.pid||'—'})</span>`+
        `<span>${esc(e.detail||e.remote||e.local||'')}</span></div>`).join('');
}
function openHistoryFor(name) {
    document.getElementById('hist-proc').value = name || '';
    openHistory();
}
function deleteHistory() {
    const kind = document.getElementById('hist-kind').value;
    const older = document.getElementById('hist-age').value;
    const proc = document.getElementById('hist-proc').value.trim();
    if (!confirm(T.hist_delete_confirm)) return;
    const qs = new URLSearchParams();
    if (kind) qs.set('kind', kind);
    if (proc) qs.set('process', proc);
    if (older && older !== '0') qs.set('older', older);
    qs.set('confirm', '1'); // the server refuses a deletion without it
    fetch('/api/events?' + qs.toString(), { method: 'DELETE' })
        .then(r => r.json()).then(res => { openHistory(); })
        .catch(() => openHistory());
}
function closeHistory() { document.getElementById('history-modal').style.display = 'none'; }

// The risk timeline: one entry per change of verdict for an (exe, IP) pair, which
// is what makes "what did this look like on Tuesday" answerable.
let showingScoreHistory = false;
function toggleScoreHistory() {
    showingScoreHistory = !showingScoreHistory;
    if (!showingScoreHistory) { openHistory(); return; }
    const b = document.getElementById('history-body');
    b.textContent = '…';
    fetch('/api/score_history?limit=500').then(r => r.json()).then(list => {
        if (!list || !list.length) { b.textContent = T.score_hist_none; return; }
        b.innerHTML = list.map(s => `<div class="hist-row">
            <span class="t">${esc(s.at)}</span>
            <span class="threat threat-${s.threat >= 70 ? 'high' : s.threat >= 40 ? 'med' : s.threat >= 15 ? 'low' : 'min'}">${s.threat}</span>
            <span>${esc(s.exe)} → ${esc(s.ip)}</span>
            <span class="t">${esc(s.breakdown)}</span></div>`).join('');
    }).catch(() => { b.textContent = 'error'; });
}

// ── Blocked IPs ───────────────────────────────────────────────────────────
function openBlocked() {
    const m = document.getElementById('blocked-modal'), b = document.getElementById('blocked-body');
    m.style.display = 'flex'; b.textContent = '…';
    fetch('/api/blocked').then(r => r.json()).then(list => {
        if (!list || !list.length) { b.textContent = T.no_blocked; return; }
        // The IP goes through data-* + dataset, never interpolated into the
        // handler string — same pattern as removeWl below.
        b.innerHTML = list.map(x => `<div class="blk-row">
            <div><strong>${esc(x.ip)}</strong> <span class="t">${esc(x.at)}</span><br>
            <span class="blk-report">${esc(x.report)}</span></div>
            <button class="btn" data-ip="${esc(x.ip)}" data-action="unblockIp">${esc(T.unblock)}</button>
        </div>`).join('');
    }).catch(() => { b.textContent = 'error'; });
}
function closeBlocked() { document.getElementById('blocked-modal').style.display = 'none'; }
function unblockIp(ip) {
    postJSON('/api/unblock', { IP: ip }).then(res => {
        if (res.warn) alert('⚠ ' + res.warn);
        else if (!res.ok) alert('Error: ' + res.error);
        openBlocked();
    });
}

// ── Machine audit ─────────────────────────────────────────────────────────
// force=true is the explicit "re-scan" button; opening the panel uses the cache.
function openAudit(force) {
    const m = document.getElementById('audit-modal'), b = document.getElementById('audit-body');
    m.style.display = 'flex'; b.textContent = T.audit_running;
    document.getElementById('audit-sum').textContent = '';
    fetch('/api/audit' + (force ? '?refresh=1' : '')).then(r => r.json()).then(res => {
        const list = res && res.checks;
        if (!list || !list.length) { b.textContent = '—'; return; }
        const icon = { ok:'✅', warn:'⚠️', risk:'🔴', info:'ℹ️' };
        const n = { ok:0, warn:0, risk:0, info:0 };
        let newTotal = 0;
        list.forEach(x => { n[x.status]++; newTotal += (x.new || []).length; });
        document.getElementById('audit-sum').innerHTML =
            `<span class="threat threat-high">🔴 ${n.risk}</span> ` +
            `<span class="threat threat-med">⚠️ ${n.warn}</span> ` +
            `<span class="threat threat-min">✅ ${n.ok}</span>` +
            (newTotal ? ` <span class="aud-newbadge">${esc(T.audit_new)} ${newTotal}</span>` : '') +
            ` <span class="aud-at">${esc(T.audit_scanned)} ${esc(res.at || '')}</span>`;
        // order: risk, warn, info, ok; anything with new items first within its level
        const ord = { risk:0, warn:1, info:2, ok:3 };
        list.sort((a,b2) => (ord[a.status] - ord[b2.status]) || ((b2.new||[]).length - (a.new||[]).length));
        b.innerHTML = `<div class="aud-note">${esc(T.audit_warn)}</div>` + list.map(x => `<div class="aud-row aud-${esc(x.status)}">
            <div class="aud-h">${icon[x.status]||''} <b>${esc(x.name)}</b> <span class="t">${esc(x.category)}</span>${(x.new||[]).length ? ` <span class="aud-newbadge">${esc(T.audit_new)} ${x.new.length}</span>` : ''}</div>
            <div class="aud-d">${esc(x.detail)}</div>
            ${(x.new||[]).length ? `<div class="aud-d aud-newlist">${esc(T.audit_new)}: ${x.new.map(esc).join(' | ')}</div>` : ''}
        </div>`).join('');
    }).catch(() => { b.textContent = 'error'; });
}
function closeAudit() { document.getElementById('audit-modal').style.display = 'none'; }

// ── Whitelist management ──────────────────────────────────────────────────
function openWhitelist() {
    const m = document.getElementById('whitelist-modal'), b = document.getElementById('whitelist-body');
    m.style.display = 'flex'; b.textContent = '…';
    Promise.all([
        fetch('/api/whitelist').then(r => r.json()).catch(() => []),
        fetch('/api/ip_whitelist').then(r => r.json()).catch(() => []),
    ]).then(([exes, ips]) => {
        const exeRows = (exes && exes.length)
            ? exes.map(x => `<div class="blk-row">
                <div><span class="badge-wl">✓</span> ${esc(x.exe)} <span class="t">${esc(x.added || '')}</span></div>
                <button class="btn" data-exe="${esc(x.exe)}" data-action="removeWl">${esc(T.wl_remove)}</button>
              </div>`).join('')
            : `<div class="t" style="padding:6px 0">${esc(T.no_whitelist)}</div>`;
        const ipRows = (ips && ips.length)
            ? ips.map(x => `<div class="blk-row">
                <div><span class="badge-wl">✓</span> ${esc(x.ip)} <span class="t">${esc(x.added || '')}</span></div>
                <button class="btn" data-ip="${esc(x.ip)}" data-action="removeIpWl">${esc(T.wl_remove)}</button>
              </div>`).join('')
            : `<div class="t" style="padding:6px 0">${esc(T.no_ip_wl)}</div>`;
        b.innerHTML = `<h4 class="wl-section">${esc(T.wl_exes)}</h4>${exeRows}`
                    + `<h4 class="wl-section">${esc(T.wl_ips)}</h4>${ipRows}`;
    }).catch(() => { b.textContent = 'error'; });
}
function closeWhitelist() { document.getElementById('whitelist-modal').style.display = 'none'; }
function openPrivacy() {
    document.getElementById('privacy-modal').style.display = 'flex';
    // The feed column is live: a withdrawn source, a missing key or a failing
    // download must not read as "no signals".
    fetch('/api/settings').then(r => r.json()).then(s => {
        document.getElementById('priv-webhook').textContent = s.webhook_configured ? s.webhook_hint : '—';
        document.getElementById('priv-update').textContent = s.update_check ? updateStatusText(s) : T.priv_update_off;
    }).catch(() => {});
    fetch('/api/feeds').then(r => r.json()).then(list => (list || []).forEach(f => {
        const cell = document.querySelector(`#privacy-modal tr[data-feed="${f.id}"] .feed-st`);
        if (!cell) return;
        cell.textContent = f.status;
        cell.className = 'feed-st ' + (f.ok ? 'feed-ok' : 'feed-bad');
    })).catch(() => {});
}
function closePrivacy() { document.getElementById('privacy-modal').style.display = 'none'; }
function removeWl(exe) {
    postJSON('/api/whitelist', { Exe: exe }, 'DELETE').then(() => { openWhitelist(); loadConnections(); });
}
function removeIpWl(ip) {
    postJSON('/api/ip_whitelist', { IP: ip }, 'DELETE').then(() => { openWhitelist(); loadConnections(); });
}

// ── Sortable columns ──────────────────────────────────────────────────────
// The table is re-rendered from the server on every refresh, which used to
// throw the chosen order away. The choice is kept here, re-applied after each
// load, shown on the header, and remembered per browser.
// col 0 / dir -1 is the server's own order (risk descending).
let sortState = { col: 0, type: 'num', dir: -1 };
try {
    const saved = JSON.parse(localStorage.getItem('sort') || 'null');
    if (saved && Number.isInteger(saved.col) && (saved.dir === 1 || saved.dir === -1)) sortState = saved;
} catch (e) {}

function sortBy(col, type) {
    sortState.dir = (sortState.col === col) ? -sortState.dir : 1;
    sortState.col = col;
    sortState.type = type;
    try { localStorage.setItem('sort', JSON.stringify(sortState)); } catch (e) {}
    applySort();
}

function applySort() {
    const tb = document.getElementById('conn-tbody');
    const { col, type, dir } = sortState;
    const mains = [...tb.querySelectorAll('tr.main-row')];
    const val = (tr) => {
        const cell = tr.children[col];
        const ds = cell && cell.getAttribute('data-sort');
        const raw = ds !== null && ds !== undefined ? ds : (cell ? cell.textContent.trim() : '');
        return type === 'num' ? (parseFloat(raw) || 0) : raw.toLowerCase();
    };
    const pairs = mains.map(m => ({ m, d: m.nextElementSibling }));
    pairs.sort((a, b) => {
        const x = val(a.m), y = val(b.m);
        return (x < y ? -1 : x > y ? 1 : 0) * dir;
    });
    pairs.forEach(p => { tb.appendChild(p.m); if (p.d) tb.appendChild(p.d); });
    document.querySelectorAll('thead th').forEach((th, i) => {
        th.classList.toggle('sort-asc', i === col && dir === 1);
        th.classList.toggle('sort-desc', i === col && dir === -1);
    });
}

loadConnections();
applyRefreshInterval();

// ── Live feed height ──────────────────────────────────────────────────────
// The block is resizable with the browser's own handle (CSS resize:vertical);
// the chosen height is remembered per browser, like the column sort.
(() => {
    const feed = document.getElementById('live-feed');
    if (!feed) return;
    try {
        const h = parseInt(localStorage.getItem('liveFeedHeight'), 10);
        if (h >= 54) feed.style.height = h + 'px';
    } catch (e) {}
    if (!window.ResizeObserver) return;
    new ResizeObserver(() => {
        try { localStorage.setItem('liveFeedHeight', String(Math.round(feed.getBoundingClientRect().height))); } catch (e) {}
    }).observe(feed);
})();

// ── Event delegation ──────────────────────────────────────────────────────
// One listener per event type at the document; the innermost element with the
// matching data-* attribute wins, so a button inside a clickable row does not
// also toggle the row. Keep every entry in `name: fn` form: a test reads this
// table and fails the build if a template references an action missing here.
const num = (el, k) => parseInt(el.dataset[k], 10);
const actions = {
    // header, panels, modals
    loadConnections: () => loadConnections(),
    openAudit: () => openAudit(),
    rescanAudit: () => openAudit(true),
    closeAudit: () => closeAudit(),
    openHistory: () => openHistory(),
    closeHistory: () => closeHistory(),
    openBlocked: () => openBlocked(),
    closeBlocked: () => closeBlocked(),
    openWhitelist: () => openWhitelist(),
    closeWhitelist: () => closeWhitelist(),
    openSettings: () => openSettings(),
    closeSettings: () => closeSettings(),
    openPrivacy: () => openPrivacy(),
    closePrivacy: () => closePrivacy(),
    closeBlock: () => closeBlock(),
    backdrop: (el, e) => { if (e.target === el) actions[el.dataset.close](el, e); },
    noop: () => {},
    stopService: () => stopService(),
    clearFeed: () => clearFeed(),
    filterRows: () => filterRows(),
    togglePinned: () => togglePinned(),
    clearPinned: () => clearPinned(),
    unpinCard: (el) => unpin(el.closest('.pinned-card').dataset.sig),
    sortBy: (el) => sortBy(num(el, 'col'), el.dataset.type),
    // history
    renderHistory: () => renderHistory(),
    toggleScoreHistory: () => toggleScoreHistory(),
    deleteHistory: () => deleteHistory(),
    // blocked / whitelist
    unblockIp: (el) => unblockIp(el.dataset.ip),
    blockModalSelected: () => blockModalSelected(),
    removeWl: (el) => removeWl(el.dataset.exe),
    removeIpWl: (el) => removeIpWl(el.dataset.ip),
    // settings
    saveSettings: () => saveSettings(),
    restartNow: () => restartNow(),
    togglePw: () => togglePw(),
    authToggled: () => authToggled(),
    serviceAction: () => serviceAction(),
    testWebhook: () => testWebhook(),
    clearWebhook: () => clearWebhook(),
    // table rows (rows.html)
    toggleDetails: (el) => toggleDetails(num(el, 'i')),
    openCapture: (el) => openCapture(num(el, 'i'), el.dataset.local, el.dataset.remote),
    openHistoryFor: (el, e) => { e.preventDefault(); openHistoryFor(el.dataset.proc); },
    toggleLock: (el) => toggleLock(el, num(el, 'i')),
    killProc: (el) => killProc(num(el, 'pid'), el.dataset.name),
    suspendProc: (el) => suspendProc(num(el, 'pid'), el.dataset.name),
    resumeProc: (el) => resumeProc(num(el, 'pid')),
    openBlock: (el) => openBlock(el),
    blockIp: (el) => blockIp(el.dataset.ip),
    toggleWhitelist: (el) => toggleWhitelist(el.dataset.exe, el.dataset.listed === 'true'),
    toggleIPWhitelist: (el) => toggleIPWhitelist(el.dataset.ip, el.dataset.listed === 'true'),
    downloadPcap: (el, e) => downloadPcap(e, num(el, 'i')),
    stopCapture: (el) => stopCapture(num(el, 'i')),
    renderPackets: (el) => renderPackets(num(el, 'i')),
};
function dispatch(attr, e) {
    const el = e.target.closest(`[data-${attr}]`);
    if (!el) return;
    const fn = actions[el.dataset[attr]];
    if (fn) fn(el, e);
}
document.addEventListener('click', e => dispatch('action', e));
document.addEventListener('change', e => dispatch('change', e));
document.addEventListener('input', e => dispatch('input', e));
