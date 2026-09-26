/* ============================================================
   TELEMETRY MODULE — self-contained, injects into Security view.
   Does not touch existing panels or JS.
   ============================================================ */
(function () {
  'use strict';

  const POLL_MS = 3000;
  const HISTORY_LEN = 30;

  // State
  
// Cache the current admin's SSH IP (from /api/session or a helper endpoint)
window.__mySSHIP = null;
(async () => {
  try {
    const r = await fetch('/api/session', { credentials: 'same-origin', cache: 'no-store' });
    const j = await r.json();
    if (j && j.clientIp) window.__mySSHIP = j.clientIp;
  } catch (e) {}
})();

const state = {
    metrics: null,
    logs: [],
    connections: [],
    banned: [],
    cpuHist: [],
    memHist: [],
    netRxHist: [],
    netTxHist: [],
    inflight: { metrics: false, logs: false, conn: false, banned: false },
    logFilterSrc: 'all',
    logFilterLvl: 'all',
    logFilterQ: '',
  };

  // ---- Utility ----
  function fmtBytes(b) {
    if (!b || b < 1024) return (b || 0) + ' B';
    if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' KB';
    if (b < 1024 * 1024 * 1024) return (b / 1048576).toFixed(1) + ' MB';
    return (b / 1073741824).toFixed(2) + ' GB';
  }
  function fmtUptime(s) {
    if (!s) return '—';
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    return d > 0 ? d + 'd ' + h + 'h' : h > 0 ? h + 'h ' + m + 'm' : m + 'm';
  }
  function esc(s) {
    return String(s || '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }
  function shortTime(iso) {
    if (!iso) return '—';
    const t = iso.replace('T', ' ').replace(/Z$/, '');
    return t.length >= 19 ? t.slice(11, 19) : t;
  }

  // ---- API ----
  async function fetchJSON(path) {
    if (typeof api === 'function') return await api(path, { csrf: false });
    const r = await fetch(path, { credentials: 'same-origin', cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return await r.json();
  }

  async function pollMetrics() {
    if (state.inflight.metrics) return;
    state.inflight.metrics = true;
    try {
      const j = await fetchJSON('/api/telemetry/metrics');
      state.metrics = j.metrics;
      state.cpuHist.push(j.metrics.cpu);
      state.memHist.push(j.metrics.mem);
      state.netRxHist.push(j.metrics.netRx);
      state.netTxHist.push(j.metrics.netTx);
      [state.cpuHist, state.memHist, state.netRxHist, state.netTxHist].forEach(a => {
        while (a.length > HISTORY_LEN) a.shift();
      });
      renderMetrics();
    } catch (e) { /* silent */ }
    finally { state.inflight.metrics = false; }
  }
  async function pollLogs() {
    if (state.inflight.logs) return;
    state.inflight.logs = true;
    try {
      const j = await fetchJSON('/api/telemetry/logs');
      state.logs = j.logs || [];
      renderLogs();
    } catch (e) {}
    finally { state.inflight.logs = false; }
  }
  async function pollConnections() {
    if (state.inflight.conn) return;
    state.inflight.conn = true;
    try {
      const j = await fetchJSON('/api/telemetry/connections');
      state.connections = j.connections || [];
      renderConnections();
    } catch (e) {}
    finally { state.inflight.conn = false; }
  }
  async function pollBanned() {
    if (state.inflight.banned) return;
    state.inflight.banned = true;
    try {
      const j = await fetchJSON('/api/telemetry/banned');
      state.banned = j.banned || [];
      renderBanned();
    } catch (e) {}
    finally { state.inflight.banned = false; }
  }

  // ---- Sparkline ----
  function sparkline(values, color, max) {
    if (!values.length) return '';
    const h = 26, w = 96;
    const m = max || Math.max(1, ...values);
    return values.map((v, i) => {
      const bh = Math.max(2, Math.round((v / m) * h));
      const x = Math.round((i / (HISTORY_LEN - 1)) * w);
      return `<span style="position:absolute;bottom:0;left:${x}px;width:3px;height:${bh}px;background:${color};border-radius:1px;opacity:.85"></span>`;
    }).join('');
  }

  function renderMetrics() {
    const el = document.getElementById('tMetrics');
    if (!el || !state.metrics) return;
    const m = state.metrics;
    const card = (label, value, unit, pct, hist, color) => `
      <div class="t-card">
        <div class="t-card-label">${label}</div>
        <div class="t-card-value">${value}<span class="t-card-unit">${unit}</span></div>
        <div class="t-spark" style="position:relative;height:26px;width:100%;border-bottom:1px solid #e6ebe8">${sparkline(hist, color, 100)}</div>
        <div class="t-card-pct">${pct}%</div>
      </div>`;
    el.innerHTML = `
      <div class="t-grid">
        ${card('CPU',   m.cpu.toFixed(1),  '%', m.cpu,   state.cpuHist,  '#0a3a2a')}
        ${card('RAM',   m.mem.toFixed(1),  '%', m.mem,   state.memHist,  '#7abeb1')}
        ${card('DISK',  m.disk.toFixed(1), '%', m.disk,  [m.disk],       '#b8d92d')}
        ${card('LOAD',  m.load1.toFixed(2), ' / 5 / 15', 0, [m.load1, m.load5, m.load15].map(x=>x*20), '#c46a2f')}
      </div>
      <div class="t-stats">
        <span><b>mem</b> ${m.memUsedMb} / ${m.memTotalMb} MB</span>
        <span><b>disk</b> ${m.diskUsedGb} / ${m.diskTotalGb} GB</span>
        <span><b>up</b> ${fmtUptime(m.uptime)}</span>
        <span><b>rx</b> ${fmtBytes(m.netRx)} · <b>tx</b> ${fmtBytes(m.netTx)}</span>
      </div>`;
  }

  function renderConnections() {
    const el = document.getElementById('tConnections');
    if (!el) return;
    if (!state.connections.length) {
      el.innerHTML = '<p class="t-empty">No active connections.</p>';
      return;
    }
    const cards = state.connections.map(c => {
      const since = c.since ? (typeof c.since === 'number' ? new Date(c.since*1000).toISOString().slice(11,19) : shortTime(c.since)) : '';
      const dot = c.active ? '<span class="t-dot t-dot-on"></span>' : '<span class="t-dot t-dot-off"></span>';
      const ipStr = String(c.ip || '');
      const isPrivate = /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.|::1|fc|fd)/i.test(ipStr);
      const isSelf = c.self === true || (window.__mySSHIPs || []).includes(String(c.ip).trim());
      const banBtn = (c.ip && !isPrivate && !isSelf)
        ? `<button class="t-btn t-btn-danger" data-ban="${esc(c.ip)}">Ban</button>`
        : (isSelf ? '<span class="t-muted" style="font-size:.625rem;">you</span>' : '');
      const traffic = (c.rx || c.tx)
        ? `<span class="t-card-traffic">${fmtBytes(c.rx)} ↓ · ${fmtBytes(c.tx)} ↑</span>`
        : '';
      return `<div class="t-conn">
        <div class="t-conn-head">
          ${dot}<span class="t-conn-proto">${esc(c.proto)}</span>
          <span class="t-conn-user">${esc(c.user)}</span>
          ${banBtn}
        </div>
        <div class="t-conn-meta">
          <code>${esc(c.ip || '—')}</code>
          ${since ? `<span class="t-muted">since ${esc(since)}</span>` : ''}
          ${traffic}
        </div>
      </div>`;
    }).join('');
    el.innerHTML = cards || '<p class="t-empty">No active connections.</p>';
  }

  function renderLogs() {
    const el = document.getElementById('tLogs');
    if (!el) return;

    // Preserve scroll position if user has scrolled up
    const wasAtTop = el.scrollTop <= 4;

    let items = state.logs.slice();

    // Filters
    const srcFilter = state.logFilterSrc || 'all';
    const lvlFilter = state.logFilterLvl || 'all';
    const q = (state.logFilterQ || '').toLowerCase();

    if (srcFilter !== 'all') items = items.filter(x => (x.src || '').toLowerCase() === srcFilter);
    if (lvlFilter === 'err')  items = items.filter(x => x.lvl === 'err');
    if (lvlFilter === 'warn') items = items.filter(x => x.lvl === 'warn' || x.lvl === 'err');
    if (q) items = items.filter(x => (x.msg || '').toLowerCase().includes(q) || (x.src || '').toLowerCase().includes(q));

    if (!items.length) {
      el.innerHTML = '<p class="t-empty" style="color:#889;padding:12px;">No log entries match the current filter.</p>';
      return;
    }

    const lines = items.map(l => {
      const cls = l.lvl === 'err' ? 't-log-err' : l.lvl === 'warn' ? 't-log-warn' : 't-log-ok';
      const full = l.ts || '';
      const timeOnly = full.includes('T') ? full.split('T')[1].slice(0, 8)
                     : full.includes(' ') ? full.split(' ')[1]?.slice(0, 8) || full.slice(-8)
                     : full.slice(-8);
      return `<div class="t-log ${cls}" title="${esc(full)}"><span class="t-log-ts">${esc(timeOnly)}</span><span class="t-log-src">${esc(l.src)}</span><span class="t-log-msg">${esc(l.msg)}</span></div>`;
    }).join('');

    el.innerHTML = lines;

    // Auto-scroll to top (newest first) unless user scrolled down
    if (wasAtTop) el.scrollTop = 0;
  }

  function renderBanned() {
    const el = document.getElementById('tBanned');
    if (!el) return;
    if (!state.banned.length) {
      el.innerHTML = '<p class="t-empty">No banned IPs.</p>';
      return;
    }
    el.innerHTML = state.banned.map(b => `
      <div class="t-ban-row">
        <code>${esc(b.ip)}</code>
        <span class="t-muted">${esc(b.reason || 'no reason')}</span>
        <span class="t-muted">${new Date(b.bannedAt * 1000).toISOString().slice(0,16).replace('T',' ')}</span>
        <button class="t-btn" data-unban="${esc(b.ip)}">Unban</button>
      </div>
    `).join('');
  }

  // ---- Ban / Unban ----
  async function banIP(ip) {
    const reason = prompt('Ban ' + ip + '? Enter reason (optional):', '');
    if (reason === null) return;
    try {
      if (typeof api === 'function') {
        await api('/api/telemetry/ban', { method: 'POST', body: { ip, reason } });
      } else {
        await fetch('/api/telemetry/ban', { method: 'POST', credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip, reason }) });
      }
      if (window.toast) window.toast('Banned ' + ip, 'success');
      await pollBanned();
    } catch (e) { if (window.toast) window.toast('Ban failed: ' + e.message, 'error'); }
  }

  async function unbanIP(ip) {
    if (!confirm('Unban ' + ip + '?')) return;
    try {
      if (typeof api === 'function') {
        await api('/api/telemetry/ban/' + encodeURIComponent(ip), { method: 'DELETE' });
      } else {
        await fetch('/api/telemetry/ban/' + encodeURIComponent(ip),
          { method: 'DELETE', credentials: 'same-origin' });
      }
      if (window.toast) window.toast('Unbanned ' + ip, 'success');
      await pollBanned();
    } catch (e) { if (window.toast) window.toast('Unban failed: ' + e.message, 'error'); }
  }

  // ---- Injection ----
  let injected = false;
  function findSecurityView() {
    // Existing security page has .security-list
    const sl = document.querySelector('.security-list');
    if (!sl) return null;
    // Make sure it's visible
    const section = sl.closest('section, .section-block, main > div, [data-view="security"]');
    return section || sl.parentElement;
  }

  function inject() {
    if (injected) return;
    const view = findSecurityView();
    if (!view) return;

    const wrap = document.createElement('div');
    wrap.id = 'telemetryWrap';
    wrap.innerHTML = `
      <section class="t-block">
        <div class="t-head"><h3>System metrics</h3><span class="t-muted" id="tMetricsUpdated"></span></div>
        <div id="tMetrics" class="t-inner"></div>
      </section>
      <section class="t-block">
        <div class="t-head"><h3>Active connections</h3><span class="t-muted" id="tConnCount"></span></div>
        <div id="tConnections" class="t-inner"></div>
      </section>
      <section class="t-block">
        <div class="t-head">
          <h3>Live logs</h3>
          <div class="t-log-controls">
            <select id="tLogSrc" class="t-mini-select" aria-label="Source">
              <option value="all">All sources</option>
              <option value="nginx">Nginx</option>
              <option value="ssh">SSH</option>
              <option value="wg">WireGuard</option>
              <option value="panel">Panel</option>
            </select>
            <select id="tLogLvl" class="t-mini-select" aria-label="Level">
              <option value="all">All levels</option>
              <option value="warn">Warn+</option>
              <option value="err">Errors only</option>
            </select>
            <input id="tLogSearch" class="t-mini-search" type="search" placeholder="search..." autocomplete="off" />
          </div>
        </div>
        <div id="tLogs" class="t-inner t-logs"></div>
      </section>
      <section class="t-block">
        <div class="t-head"><h3>Banned IPs</h3><span class="t-muted" id="tBanCount"></span></div>
        <div id="tBanned" class="t-inner"></div>
      </section>
    `;
    view.parentElement.insertBefore(wrap, view.nextSibling);
    injected = true;

    // Filter events
    const srcSel = wrap.querySelector('#tLogSrc');
    const lvlSel = wrap.querySelector('#tLogLvl');
    const qInp   = wrap.querySelector('#tLogSearch');
    if (srcSel) srcSel.addEventListener('change', () => { state.logFilterSrc = srcSel.value; renderLogs(); });
    if (lvlSel) lvlSel.addEventListener('change', () => { state.logFilterLvl = lvlSel.value; renderLogs(); });
    if (qInp)   qInp.addEventListener('input',   () => { state.logFilterQ = qInp.value; renderLogs(); });

    // Event delegation
    wrap.addEventListener('click', (e) => {
      const b = e.target.closest('[data-ban]');
      if (b) return banIP(b.dataset.ban);
      const u = e.target.closest('[data-unban]');
      if (u) return unbanIP(u.dataset.unban);
    });
  }

  // ---- Poll loop ----
  function tick() {
    if (document.hidden) return;
    if (!document.querySelector('.security-list')) {
      // Security not visible — remove our injection
      const w = document.getElementById('telemetryWrap');
      if (w) w.remove();
      injected = false;
      return;
    }
    if (!injected) inject();
    pollMetrics();
    pollConnections();
    pollLogs();
    pollBanned();
  }

  setInterval(tick, POLL_MS);
  if (document.readyState === 'complete') setTimeout(tick, 500);
  else document.addEventListener('DOMContentLoaded', () => setTimeout(tick, 500));
  window.__telemetryTick = tick;
})();

/* ==== Duration widget bootstrap ==== */
(function () {
  function boot() {
    if (typeof window.wireDurationUnit === 'function') window.wireDurationUnit();
  }
  if (document.readyState === 'complete') setTimeout(boot, 400);
  else document.addEventListener('DOMContentLoaded', () => setTimeout(boot, 400));
})();
