/* ============================================================
   CREATE ACCOUNT WIZARD
   Modal flow: Username → Password → Duration → Review → Confirm
   ============================================================ */
(function () {
  'use strict';

  const PROTOCOLS = [
    { v: 'wireguard', label: 'WireGuard' },
    { v: 'xray',      label: 'Xray (VLESS)' },
    { v: 'ssh',       label: 'SSH Tunnel' },
    { v: 'openvpn',   label: 'OpenVPN' },
    { v: 'ipsec',     label: 'IPsec / IKEv2' },
  ];

  let open = false;
  let state = { step: 1, username: '', password: '', skipPassword: false, unit: 'days', value: 30, date: '', protocol: 'wireguard' };

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function rndPassword(len) {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%';
    let out = '';
    const arr = new Uint32Array(len);
    crypto.getRandomValues(arr);
    for (let i = 0; i < len; i++) out += chars[arr[i] % chars.length];
    return out;
  }

  function durationSeconds() {
  if (state.unit === 'unlimited') return 0;
  if (state.unit === 'hours')   return Math.max(1, Math.min(8760, parseInt(state.value, 10) || 24)) * 3600;
  if (state.unit === 'days')    return Math.max(1, Math.min(365,  parseInt(state.value, 10) || 30)) * 86400;
  if (state.unit === 'weeks')   return Math.max(1, Math.min(52,   parseInt(state.value, 10) || 2))  * 7 * 86400;
  return 30 * 86400;
}

  function durationLabel() {
    if (state.unit === 'unlimited') return 'No expiry';
    if (state.unit === 'hours')   return state.value + ' hours';
    if (state.unit === 'days')    return state.date ? ('Until ' + state.date) : (state.value + ' days');
    if (state.unit === 'weeks')   return state.value + ' weeks';
    return '';
  }

  // ---------- HTML ----------
  function buildModal() {
    const root = document.createElement('div');
    root.id = 'wizRoot';
    root.className = 'wiz-root';
    root.setAttribute('aria-hidden', 'true');
    root.innerHTML = `
      <div class="wiz-backdrop" data-wiz-close></div>
      <div class="wiz-panel" role="dialog" aria-modal="true" aria-labelledby="wizTitle">
        <button class="wiz-close" type="button" data-wiz-close aria-label="Close">×</button>
        <div class="wiz-progress"><div class="wiz-progress-fill" id="wizProgress"></div></div>
        <div class="wiz-body" id="wizBody"></div>
        <div class="wiz-footer" id="wizFooter"></div>
      </div>
    `;
    document.body.appendChild(root);
    root.addEventListener('click', (e) => {
      if (e.target.closest('[data-wiz-close]')) close();
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && open) close();
    });
    return root;
  }

  // ---------- Step renderers ----------
  function step1() {
    return {
      title: 'Step 1 / 4 — Account name',
      body: `
        <p class="wiz-lede">Give this account a name. Letters, numbers, <code>._-@+</code> allowed.</p>
        <label class="wiz-label">Protocol</label>
        <select id="wizProto" class="wiz-input">
          ${PROTOCOLS.map(p => `<option value="${p.v}"${p.v === state.protocol ? ' selected' : ''}>${p.label}</option>`).join('')}
        </select>
        <label class="wiz-label">Username</label>
        <input id="wizUser" class="wiz-input" type="text" maxlength="48" placeholder="e.g. alice-laptop" value="${esc(state.username)}" autocomplete="off" />
        <p class="wiz-err" id="wizErr" hidden></p>
      `,
      next: () => {
        const u = (document.getElementById('wizUser').value || '').trim();
        const pr = (document.getElementById('wizProto').value || 'wireguard');
        if (!/^[A-Za-z0-9._@+-]{1,48}$/.test(u)) {
          const e = document.getElementById('wizErr');
          e.textContent = 'Username must be 1–48 characters (letters, digits, . _ - @ +).';
          e.hidden = false;
          return false;
        }
        state.username = u;
        state.protocol = pr;
        state.step = 2;
        render();
        return false;
      },
      back: null,
    };
  }

  function step2() {
    return {
      title: 'Step 2 / 4 — Portal password',
      body: `
        <p class="wiz-lede">Set the password for the client portal, or skip if this account won't log in.</p>
        <label class="wiz-label">Password <span class="wiz-hint">(min 4 chars, or click Random)</span></label>
        <div class="wiz-row">
          <input id="wizPass" class="wiz-input" type="text" placeholder="Password" value="${esc(state.password)}" autocomplete="off" />
          <button type="button" class="wiz-btn wiz-btn-ghost" id="wizRand">Random</button>
        </div>
        <label class="wiz-check">
          <input type="checkbox" id="wizSkip" ${state.skipPassword ? 'checked' : ''} />
          <span>Skip — no portal password (VPN-only access)</span>
        </label>
        <p class="wiz-err" id="wizErr" hidden></p>
      `,
      next: () => {
        const skip = document.getElementById('wizSkip').checked;
        const pw = (document.getElementById('wizPass').value || '');
        if (!skip && pw.length < 4) {
          const e = document.getElementById('wizErr');
          e.textContent = 'Password must be at least 4 characters, or check "Skip".';
          e.hidden = false;
          return false;
        }
        state.skipPassword = skip;
        state.password = skip ? '' : pw;
        state.step = 3;
        render();
        return false;
      },
      back: () => { state.step = 1; render(); },
      after: () => {
        const r = document.getElementById('wizRand');
        if (r) r.onclick = () => {
          const p = rndPassword(16);
          document.getElementById('wizPass').value = p;
          state.password = p;
        };
      }
    };
  }

  function step3() {
  const isUnl = state.unit === 'unlimited';
  const val = state.value || 1;
  return {
    title: 'Step 3 / 4 — Duration',
    body: `
      <p class="wiz-lede">How long should this account stay active?</p>
      <div class="wiz-dur">
        <select id="wizUnit" class="wiz-input wiz-dur-unit">
          <option value="hours"${state.unit==='hours'?' selected':''}>Hours</option>
          <option value="days"${state.unit==='days'?' selected':''}>Days</option>
          <option value="weeks"${state.unit==='weeks'?' selected':''}>Weeks</option>
          <option value="unlimited"${state.unit==='unlimited'?' selected':''}>No expiry</option>
        </select>
        <input id="wizVal" class="wiz-input" type="number" min="1" value="${val}" ${isUnl?'hidden':''} />
      </div>
      <p class="wiz-hint" id="wizDurHint"></p>
    `,
    next: () => {
      state.unit = document.getElementById('wizUnit').value;
      const v = document.getElementById('wizVal');
      if (v && !v.hidden) state.value = parseInt(v.value, 10) || 1;
      state.step = 4;
      render();
      return false;
    },
    back: () => { state.step = 2; render(); },
    after: () => {
      const u = document.getElementById('wizUnit');
      const v = document.getElementById('wizVal');
      const hint = document.getElementById('wizDurHint');
      function refresh() {
        const m = u.value;
        if (m === 'unlimited') {
          if (v) v.hidden = true;
          if (hint) hint.textContent = 'Account never expires.';
          return;
        }
        if (v) v.hidden = false;
        if (m === 'hours') { v.max = 8760; if (!v.value || v.value === '30' || v.value === '2') v.value = '24'; if (hint) hint.textContent = '1-8760 hours.'; }
        else if (m === 'days') { v.max = 365; if (!v.value || v.value === '24' || v.value === '2') v.value = '30'; if (hint) hint.textContent = '1-365 days.'; }
        else if (m === 'weeks') { v.max = 52; if (!v.value || v.value === '24' || v.value === '30') v.value = '2'; if (hint) hint.textContent = '1-52 weeks.'; }
      }
      u.onchange = refresh;
      refresh();
    }
  };
}

  function step4() {
    return {
      title: 'Step 4 / 4 — Review',
      body: `
        <dl class="wiz-review">
          <div><dt>Protocol</dt><dd>${esc((PROTOCOLS.find(p=>p.v===state.protocol)||{}).label || state.protocol)}</dd></div>
          <div><dt>Username</dt><dd>${esc(state.username)}</dd></div>
          <div><dt>Portal password</dt><dd>${state.skipPassword ? '<em class="wiz-muted">Skipped — VPN only</em>' : '<code>' + esc(state.password) + '</code>'}</dd></div>
          <div><dt>Duration</dt><dd>${esc(durationLabel())}</dd></div>
        </dl>
        <p class="wiz-hint">Creates the account immediately. You can revoke it anytime.</p>
      `,
      next: async () => {
        const btn = document.getElementById('wizConfirm');
        if (btn) { btn.disabled = true; btn.textContent = 'Creating…'; }
        try {
          const body = {
            username: state.username,
            protocol: state.protocol,
            durationHours: durationSeconds(),
          };
          if (state.skipPassword) body.skipPassword = true;
          else body.password = state.password;

          let j;
          if (typeof api === 'function') {
            // Use panel's CSRF-aware helper
            j = await api('/api/clients', { method: 'POST', body });
          } else {
            // Fallback: fetch CSRF from session then POST
            const sess = await fetch('/api/session', { credentials: 'same-origin', cache: 'no-store' }).then(r => r.json());
            const token = sess && sess.csrfToken ? sess.csrfToken : '';
            const r = await fetch('/api/clients', {
              method: 'POST',
              credentials: 'same-origin',
              headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': token,
              },
              body: JSON.stringify(body),
            });
            j = await r.json();
            if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
          }
          close();
          if (window.toast) window.toast('Account ' + state.username + ' created', 'success');
          if (typeof loadVPNClients === 'function') loadVPNClients();
          else if (typeof window.__telemetryTick === 'function') window.__telemetryTick();
        } catch (e) {
          if (btn) { btn.disabled = false; btn.textContent = 'Confirm & create'; }
          const err = document.getElementById('wizErr') || document.createElement('p');
          err.className = 'wiz-err'; err.id = 'wizErr'; err.hidden = false;
          err.textContent = e.message;
          document.getElementById('wizBody').appendChild(err);
        }
        return false;
      },
      back: () => { state.step = 3; render(); },
      confirm: true,
    };
  }

  // ---------- Render ----------
  function render() {
    const s = [null, step1, step2, step3, step4][state.step]();
    document.getElementById('wizBody').innerHTML = `<h2 id="wizTitle" class="wiz-title">${s.title}</h2>${s.body}`;
    document.getElementById('wizProgress').style.width = ((state.step - 1) / 3 * 100) + '%';

    const footer = document.getElementById('wizFooter');
    footer.innerHTML = `
      ${s.back ? '<button type="button" class="wiz-btn" id="wizBack">Back</button>' : '<span></span>'}
      <button type="button" class="wiz-btn ${s.confirm ? 'wiz-btn-primary' : 'wiz-btn-primary'}" id="${s.confirm ? 'wizConfirm' : 'wizNext'}">${s.confirm ? 'Confirm & create' : 'Next →'}</button>
    `;
    const back = document.getElementById('wizBack');
    if (back && s.back) back.onclick = s.back;
    const next = document.getElementById(s.confirm ? 'wizConfirm' : 'wizNext');
    if (next) next.onclick = s.next;
    if (s.after) s.after();

    // Autofocus first input
    const first = document.querySelector('#wizBody input:not([hidden]), #wizBody select');
    if (first) setTimeout(() => first.focus(), 50);
  }

  function openWizard() {
    state = { step: 1, username: '', password: '', skipPassword: false, unit: 'days', value: 30, date: '', protocol: 'wireguard' };
    const root = document.getElementById('wizRoot') || buildModal();
    root.setAttribute('aria-hidden', 'false');
    root.classList.add('wiz-open');
    document.body.style.overflow = 'hidden';
    open = true;
    render();
  }
  function close() {
    const root = document.getElementById('wizRoot');
    if (root) {
      root.setAttribute('aria-hidden', 'true');
      root.classList.remove('wiz-open');
    }
    document.body.style.overflow = '';
    open = false;
  }

  // ---------- Trigger ----------
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('#createClientButton, [data-open-wizard]');
    if (!btn) return;
    e.preventDefault();
    e.stopPropagation();
    openWizard();
  }, true);

  window.openCreateWizard = openWizard;
})();
