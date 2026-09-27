const byId = (id) => document.getElementById(id);
const state = {
  csrfToken: '',
  username: '',
  mustChangePassword: false,
  refreshTimer: null,
  requestPending: false,
  previousStatus: null,
};
const WELCOME_TOUR_KEY = 'vpn-client-welcome-v1:';
let welcomeTourDismissedThisPage = false;

async function request(path, { method = 'GET', body, csrf = true } = {}) {
  const headers = new Headers();
  if (body !== undefined) headers.set('Content-Type', 'application/json');
  if (csrf && method !== 'GET' && state.csrfToken) headers.set('X-CSRF-Token', state.csrfToken);
  const response = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: 'same-origin',
    cache: 'no-store',
  });
  const text = await response.text();
  let data = text;
  if (response.headers.get('Content-Type')?.startsWith('application/json')) {
    try { data = JSON.parse(text); } catch { data = {}; }
  }
  if (response.status === 401) {
    showLogin(path === '/api/portal/account' ? 'Your account session ended. Sign in again.' : 'Sign in to continue.');
  }
  if (!response.ok) {
    const error = new Error(data?.error || `Request failed (${response.status}).`);
    error.status = response.status;
    throw error;
  }
  return data;
}

function formatDuration(seconds) {
  const total = Math.max(0, Math.floor(Number(seconds) || 0));
  if (total < 60) return 'Less than a minute';
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function formatBytes(value) {
  const bytes = Math.max(0, Number(value) || 0);
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let amount = bytes / 1024;
  let index = 0;
  while (amount >= 1024 && index < units.length - 1) {
    amount /= 1024;
    index += 1;
  }
  return `${amount.toFixed(amount >= 100 ? 0 : 1)} ${units[index]}`;
}

function formatDate(timestamp) {
  if (!timestamp) return 'No expiry';
  const date = new Date(timestamp * 1000);
  return Number.isNaN(date.getTime()) ? 'Date unavailable' : new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
}

function relativeHandshake(ageSeconds) {
  if (ageSeconds === null || ageSeconds === undefined) return 'No handshake recorded';
  if (ageSeconds < 60) return 'Just now';
  return `${formatDuration(ageSeconds)} ago`;
}

function showActivity(message, error = false) {
  const notice = byId('activityPunch');
  { const __e = byId('activityPunchText'); if (__e) __e.textContent = message; }
  notice.classList.toggle('is-error', error);
  notice.hidden = false;
  clearTimeout(showActivity.timeout);
  showActivity.timeout = setTimeout(() => { notice.hidden = true; }, 4200);
}

function showLogin(message = '') {
  if (state.refreshTimer) clearInterval(state.refreshTimer);
  state.refreshTimer = null;
  state.csrfToken = '';
  state.mustChangePassword = false;
  state.previousStatus = null;
  state.username = '';
  state.account = null;
  document.getElementById('transportPanel')?.remove();
  document.getElementById('sharePanel')?.remove();
  byId('welcomeTour').hidden = true;
  { const __e = byId('portalDashboard'); if (__e) __e.hidden = true; }
  { const __e = byId('portalLogin'); if (__e) __e.hidden = false; }
  { const __e = byId('portalPasswordButton'); if (__e) __e.hidden = true; }
  { const __e = byId('portalSignOutButton'); if (__e) __e.hidden = true; }
  { const __e = byId('portalLoginError'); if (__e) __e.textContent = message; }
  { const __e = byId('portalLoginError'); if (__e) __e.hidden = !message; }
  byId('portalPassword').value = '';
  if (byId('portalPasswordDialog').open) byId('portalPasswordDialog').close();
}

function startAccountRefresh() {
  if (state.refreshTimer || state.mustChangePassword) return;
  state.refreshTimer = setInterval(() => {
    if (!document.hidden) loadAccount();
  }, 5000);
}

function openPasswordDialog(forced = false) {
  state.mustChangePassword = forced;
  byId('portalPasswordForm').reset();
  { const __e = byId('portalPasswordError'); if (__e) __e.hidden = true; }
  { const __e = byId('portalPasswordTitle'); if (__e) __e.textContent = forced ? 'Set your password' : 'Change password'; }
  { const __e = byId('portalPasswordCopy'); if (__e) __e.textContent = forced
    ? 'Replace the temporary password before viewing your account. Use at least 14 characters.'
    : 'Choose a unique password with at least 14 characters.'; }
  { const __e = byId('cancelPortalPassword'); if (__e) __e.hidden = forced; }
  byId('portalPasswordDialog').showModal();
  byId('portalCurrentPassword').focus();
}

function showDashboard(username) {
  state.username = username;
  { const __e = byId('portalLogin'); if (__e) __e.hidden = true; }
  { const __e = byId('portalDashboard'); if (__e) __e.hidden = false; }
  { const __e = byId('portalPasswordButton'); if (__e) __e.hidden = false; }
  { const __e = byId('portalSignOutButton'); if (__e) __e.hidden = false; }
  { const __e = byId('portalAccountName'); if (__e) __e.textContent = username; }
  if (!state.mustChangePassword) showWelcomeTour();
  loadAccount();
  startAccountRefresh();
}

function showWelcomeTour() {
  if (!state.username || state.mustChangePassword || welcomeTourDismissedThisPage) return;
  try {
    if (localStorage.getItem(WELCOME_TOUR_KEY + state.username.toLowerCase()) === 'dismissed') return;
  } catch {}
  byId('welcomeTour').hidden = false;
  byId('welcomeDismiss').focus();
}

function dismissWelcomeTour() {
  welcomeTourDismissedThisPage = true;
  byId('welcomeTour').hidden = true;
  try { localStorage.setItem(WELCOME_TOUR_KEY + state.username.toLowerCase(), 'dismissed'); } catch {}
}

async function restorePortalSession() {
  { const __e = byId('portalHost'); if (__e) __e.textContent = location.host; }
  try {
    const session = await request('/api/portal/session', { csrf: false });
    const maintenance = session.maintenance;
    byId('maintenanceBanner').hidden = maintenance?.enabled !== true;
    const maintenanceMessage = maintenance?.message || 'Some services may be temporarily unavailable.';
    byId('maintenanceBannerMessage').textContent = maintenance?.blockInternet
      ? `${maintenanceMessage} Internet forwarding is paused for WireGuard/OpenVPN clients; their VPN tunnels remain connected.`
      : maintenanceMessage;
    if (!session.authenticated) {
      showLogin();
      return;
    }
    state.csrfToken = session.csrfToken;
    state.mustChangePassword = session.mustChangePassword;
    showDashboard(session.username);
    if (state.mustChangePassword) openPasswordDialog(true);
  } catch (error) {
    showLogin(error.message);
  }
}

function renderAccount(account) {
  state.account = account;
  if (window.__updateDownloadLabel) window.__updateDownloadLabel(account);
  if (window.__updatePortalTransports) window.__updatePortalTransports(account.protocol);
  try {
    const lbl = document.getElementById('downloadLabel');
    if (lbl) {
      const pro = (account.protocol || '').toLowerCase();
      if (pro === 'ssh')        lbl.textContent = 'Download SSH credentials';
      else if (pro === 'xray' || pro === 'vless' || pro === 'vmess' || pro === 'trojan') lbl.textContent = 'Download Xray link';
      else if (pro === 'openvpn' || pro === 'ovpn') lbl.textContent = 'Download .ovpn';
      else if (pro === 'ipsec' || pro === 'ikev2')  lbl.textContent = 'Download IKEv2 profile';
      else if (pro === 'wireguard') lbl.textContent = 'Download .conf';
    }
  } catch (_) {}

  const previousStatus = state.previousStatus;
  state.previousStatus = account.status;
  const isWireGuard = account.protocol === 'wireguard';
  const connected = account.status === 'connected';
  const accessActive = account.active !== false && account.status !== 'expired';
  const statusText = connected ? 'Connected' : account.status === 'expired' ? 'Expired' : account.protocol === 'wireguard' ? 'Idle' : 'Active';
  { const __e = byId('accountStatus'); if (__e) __e.textContent = statusText; }
  { const __e = byId('accountStatusHint'); if (__e) __e.textContent = connected ? 'Recent WireGuard handshake' : account.status === 'expired' ? 'Access has ended' : account.protocol === 'wireguard' ? 'No recent handshake detected' : 'Account active; live connection data is unavailable for this protocol'; }
  { const __e = byId('accountAddressLabel'); if (__e) __e.textContent = isWireGuard ? 'Assigned address' : 'Account name'; }
  { const __e = byId('portalTelemetryLabel'); if (__e) __e.textContent = isWireGuard ? 'WIREGUARD / LIVE TELEMETRY' : `${(account.protocolLabel || account.protocol).toUpperCase()} / ACCOUNT`; }
  { const __e = byId('portalRefreshLabel'); if (__e) __e.textContent = isWireGuard ? 'Live updates every 5 seconds' : 'Account refresh every 5 seconds'; }
  for (const id of ['accountHandshakeRow', 'accountUploadedRow', 'accountDownloadedRow']) byId(id).hidden = !isWireGuard;
  byId('portalLiveIndicator').classList.toggle('is-offline', !accessActive);
  byId('liveDot').className = `portal-live-dot ${connected ? 'is-online' : !accessActive ? 'is-offline' : ''}`;
  { const __e = byId('liveLabel'); if (__e) __e.textContent = connected ? 'Connected now' : account.status === 'expired' ? 'Access expired' : account.protocol === 'wireguard' ? 'Not connected' : 'Access active'; }
  { const __e = byId('lastUpdated'); if (__e) __e.textContent = `Updated ${new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' }).format(new Date())}`; }
  { const __e = byId('accountAddress'); if (__e) __e.textContent = account.address; }
  { const __e = byId('accountAge'); if (__e) __e.textContent = formatDuration(account.ageSeconds); }
  { const __e = byId('accountRemaining'); if (__e) __e.textContent = account.remainingSeconds === null ? 'No expiry' : account.status === 'expired' ? 'Expired' : formatDuration(account.remainingSeconds); }
  { const __e = byId('accountExpiry'); if (__e) __e.textContent = account.expiresAt ? formatDate(account.expiresAt) : 'Access does not expire'; }
  { const __e = byId('accountEndpoint'); if (__e) __e.textContent = account.endpoint || 'No endpoint observed'; }
  { const __e = byId('accountHandshake'); if (__e) __e.textContent = relativeHandshake(account.handshakeAgeSeconds); }
  { const __e = byId('accountUploaded'); if (__e) __e.textContent = formatBytes(account.bytesReceived); }
  { const __e = byId('accountDownloaded'); if (__e) __e.textContent = formatBytes(account.bytesSent); }
  { const __e = byId('accountTerm'); if (__e) __e.textContent = account.expiresAt && account.createdAt ? formatDuration(account.expiresAt - account.createdAt) : 'No expiry'; }
  { const __e = byId('accountCreated'); if (__e) __e.textContent = formatDate(account.createdAt); }
  document.querySelector('.portal-status-metric').classList.toggle('is-offline', !accessActive);
  if (previousStatus && previousStatus !== account.status) {
    showActivity(`VPN status changed: ${previousStatus} → ${account.status}.`, !connected);
  }
  { const __e = byId('portalError'); if (__e) __e.hidden = true; }
}

async function loadAccount() {
  if (state.requestPending || state.mustChangePassword) return;
  state.requestPending = true;
  try {
    const response = await request('/api/portal/account');
    renderAccount(response.account);
  } catch (error) {
    if (error.status === 410) {
      showLogin('This account has expired or is no longer active. Contact your administrator.');
    } else if (error.status !== 401 && error.status !== 428) {
      { const __e = byId('portalError'); if (__e) __e.textContent = error.message; }
      { const __e = byId('portalError'); if (__e) __e.hidden = false; }
    }
  } finally {
    state.requestPending = false;
  }
}

async function signIn(event) {
  event.preventDefault();
  const button = byId('portalLoginSubmit');
  const error = byId('portalLoginError');
  error.hidden = true;
  button.disabled = true;
  button.querySelector('span').textContent = 'Signing in...';
  try {
    const session = await request('/api/portal/login', {
      method: 'POST',
      csrf: false,
      body: { username: byId('portalUsername').value.trim(), password: byId('portalPassword').value },
    });
    state.csrfToken = session.csrfToken;
    state.mustChangePassword = session.mustChangePassword;
    byId('portalPassword').value = '';
    showDashboard(session.username);
    if (state.mustChangePassword) openPasswordDialog(true);
    showActivity('Signed in to your SAEKA VPN account.');
  } catch (requestError) {
    error.textContent = requestError.message;
    error.hidden = false;
  } finally {
    button.disabled = false;
    button.querySelector('span').textContent = 'Sign in';
  }
}

async function changePassword(event) {
  event.preventDefault();
  const error = byId('portalPasswordError');
  const button = byId('savePortalPassword');
  error.hidden = true;
  const nextPassword = byId('portalNewPassword').value;
  if (nextPassword !== byId('portalConfirmPassword').value) {
    error.textContent = 'The new passwords do not match.';
    error.hidden = false;
    return;
  }
  button.disabled = true;
  try {
    const session = await request('/api/portal/password', {
      method: 'POST',
      body: { oldPassword: byId('portalCurrentPassword').value, newPassword: nextPassword },
    });
    state.csrfToken = session.csrfToken;
    state.mustChangePassword = false;
    byId('portalPasswordDialog').close();
    showActivity('Password updated. Other account sessions were signed out.');
    if (!state.refreshTimer) {
      loadAccount();
      state.refreshTimer = setInterval(() => { if (!document.hidden) loadAccount(); }, 5000);
    } else {
      loadAccount();
    }
    showWelcomeTour();
  } catch (requestError) {
    error.textContent = requestError.message;
    error.hidden = false;
  } finally {
    button.disabled = false;
  }
}

function downloadConfig(username, config) {
  const blobUrl = URL.createObjectURL(new Blob([config], { type: 'text/plain;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = blobUrl;
  link.download = `${username}.conf`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
}

async function downloadPortalConfig(event) {
  if (event) event.preventDefault();
  const acct = state.account || {};
  const protoLabel = acct.protocolLabel || 'VPN';
  showActivity('Preparing your ' + protoLabel + ' configuration...');
  try {
    const response = await fetch('/api/portal/config', { credentials: 'same-origin', cache: 'no-store' });
    const text = await response.text();
    if (!response.ok) {
      let msg = 'Request failed (' + response.status + ').';
      try { msg = JSON.parse(text).error || msg; } catch (_) {}
      throw new Error(msg);
    }
    const disp = response.headers.get('Content-Disposition') || '';
    const fnm = /filename="?([^"]+)"?/i.exec(disp);
    const fname = fnm ? fnm[1] : ((state.username || 'config') + '.txt');
    const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = fname;
    document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 500);
    showActivity('Downloaded ' + fname);
  } catch (err) {
    showActivity(err.message || 'Download failed.', true);
  }
}

async function signOut() {
  try {
    await request('/api/portal/logout', { method: 'POST', body: {} });
  } catch {}
  showLogin();
  showActivity('Signed out.');
}

byId('portalLoginForm').addEventListener('submit', signIn);
byId('portalPasswordButton').addEventListener('click', () => openPasswordDialog(false));
byId('portalSignOutButton').addEventListener('click', signOut);
byId('portalPasswordForm').addEventListener('submit', changePassword);
byId('welcomeDismiss').addEventListener('click', dismissWelcomeTour);
byId('welcomeSkip').addEventListener('click', dismissWelcomeTour);
byId('welcomeTour').addEventListener('keydown', (event) => {
  if (event.key === 'Escape') {
    dismissWelcomeTour();
    return;
  }
  if (event.key !== 'Tab') return;
  const controls = [byId('welcomeSkip'), byId('welcomeDismiss')];
  if (event.shiftKey && document.activeElement === controls[0]) {
    event.preventDefault();
    controls[1].focus();
  } else if (!event.shiftKey && document.activeElement === controls[1]) {
    event.preventDefault();
    controls[0].focus();
  }
});
byId('welcomeTour').addEventListener('click', (event) => {
  if (event.target === byId('welcomeTour')) dismissWelcomeTour();
});
byId('portalPasswordDialog').addEventListener('cancel', (event) => { if (state.mustChangePassword) event.preventDefault(); });
byId('cancelPortalPassword').addEventListener('click', () => byId('portalPasswordDialog').close());
byId('downloadPortalConfig').addEventListener('click', downloadPortalConfig);
restorePortalSession();
/* ==== Loader status rotator (portal) ==== */
(function () {
  const el = document.getElementById('globalLoader');
  const label = document.getElementById('globalLoaderLabel');
  if (!el || !label) return;
  let rotator = null, idx = 0;
  const filler = [
    '> contacting node...',
    '> verifying session...',
    '> tunnelling request...',
    '> reading state...',
    '> negotiating TLS...',
    '> fetching account...',
  ];
  function start() {
    if (rotator) return;
    idx = 0;
    label.textContent = filler[0];
    rotator = setInterval(() => {
      idx = (idx + 1) % filler.length;
      label.textContent = filler[idx];
    }, 900);
  }
  function stop() {
    if (rotator) { clearInterval(rotator); rotator = null; }
    label.textContent = 'working...';
  }
  new MutationObserver(() => {
    if (el.classList.contains('active')) start(); else stop();
  }).observe(el, { attributes: true, attributeFilter: ['class'] });
  if (el.classList.contains('active')) start();
})();

/* ==== Loader — definitive toggle (style.display) ==== */
(function () {
  const el = document.getElementById('globalLoader');
  if (!el) return;
  let active = 0, hideTimer = null;
  function show() { active++; clearTimeout(hideTimer); el.style.display = 'flex'; }
  function hide() { active = Math.max(0, active - 1); if (active === 0) hideTimer = setTimeout(() => el.style.display = 'none', 120); }
  if (!window.__fetchWrapped) {
    window.__fetchWrapped = true;
    const orig = window.fetch.bind(window);
    window.fetch = function (input, init) {
      const method = (init && init.method) ? init.method.toUpperCase() : 'GET';
      if (method === 'GET') return orig(input, init);
      show();
      const p = orig(input, init);
      p.then(hide, hide);
      return p;
    };
  }

/* ==== Protocol-aware config download ==== */
(function () {
  function labelFor(protoLabel) {
    switch (protoLabel) {
      case 'SSH':       return 'Download SSH credentials';
      case 'Xray':
      case 'VMess':
      case 'Trojan':    return 'Download Xray link';
      case 'OpenVPN':   return 'Download .ovpn';
      case 'IPsec':     return 'Download IKEv2 profile';
      case 'WireGuard': return 'Download .conf';
      default:          return 'Download config';
    }
  }
  window.__updateDownloadLabel = function (account) {
    const el = document.getElementById('downloadLabel');
    if (!el) return;
    const lab = (account && account.protocolLabel) || 'VPN';
    el.textContent = labelFor(lab);
    const btn = el.closest('button, a');
    if (btn) {
      btn.setAttribute('aria-label', labelFor(lab));
      btn.dataset.protocol = (account && account.protocol) || 'wireguard';
    }
  };
})();



function downloadConfigRaw(filename, text) {
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 500);
}

})();

/* ==== Xray transport chooser ==== */
(function () {
  let loadedProtocol = '';
  async function showTransports(protocol) {
    if (!['xray', 'vless', 'vmess', 'trojan'].includes((protocol || '').toLowerCase())) {
      document.getElementById('transportPanel')?.remove();
      loadedProtocol = '';
      return;
    }
    if (loadedProtocol === protocol) return;
    try {
      const r = await fetch('/api/portal/transports', { credentials: 'same-origin', cache: 'no-store' });
      if (!r.ok) throw new Error(`Request failed (${r.status}).`);
      const j = await r.json();
      if (!j.transports || !j.transports.length) throw new Error('No transports are available.');

      const host = document.querySelector('.portal-main');
      if (!host) return;
      document.getElementById('transportPanel')?.remove();

      const wrap = document.createElement('section');
      wrap.id = 'transportPanel';
      wrap.className = 'transport-panel';
      wrap.innerHTML = `
        <p class="portal-kicker">XRAY / TRANSPORTS</p>
        <h2>All available modes</h2>
        <p class="transport-lede">Same account works on every transport. Copy the one that works best for your network.</p>
        <div class="transport-grid">
          ${j.transports.map(t => `
            <div class="transport-card" data-transport="${t.id}">
              <div class="transport-head">
                <strong>${t.label}</strong>
                <span class="transport-kind">${t.kind}</span>
              </div>
              <code class="transport-url">${t.share.slice(0, 60)}…</code>
              <button class="transport-copy" type="button" data-share="${encodeURIComponent(t.share)}">Copy</button>
            </div>
          `).join('')}
        </div>
      `;
      const connectionSection = host.querySelector('[aria-labelledby="connectionHeading"]');
      if (connectionSection) connectionSection.after(wrap);
      else host.appendChild(wrap);
      loadedProtocol = protocol;

      wrap.addEventListener('click', async (e) => {
        const btn = e.target.closest('[data-share]');
        if (!btn) return;
        const txt = decodeURIComponent(btn.dataset.share);
        try {
          await navigator.clipboard.writeText(txt);
          btn.textContent = 'Copied';
          setTimeout(() => btn.textContent = 'Copy', 1500);
        } catch (_) { prompt('Copy this URL:', txt); }
      });
    } catch (error) {
      showActivity(error.message || 'Xray transports are unavailable.', true);
    }
  }
  window.__updatePortalTransports = showTransports;
})();

/* ==== Copy-share panel ==== */
(function () {
  async function injectSharePanel() {
    if (document.getElementById('sharePanel')) return;
    if (!['xray', 'vless', 'vmess', 'trojan'].includes((state.account?.protocol || '').toLowerCase())) return;
    const host = document.querySelector('.portal-main');
    if (!host) return;

    let uri = '';
    try {
      const r = await fetch('/api/portal/share', { credentials: 'same-origin', cache: 'no-store' });
      if (r.ok) {
        const j = await r.json();
        uri = j.uri || '';
      }
    } catch (e) {}

    if (!uri) return;

    const panel = document.createElement('section');
    panel.id = 'sharePanel';
    panel.className = 'share-panel';
    panel.innerHTML = `
      <p class="portal-kicker">SHARE / IMPORT</p>
      <h2>Copy connection string</h2>
      <p class="share-lede">Paste into your VPN client's import field.</p>
      <div class="share-row">
        <input id="shareUri" class="share-input" readonly value="${uri.replace(/"/g, '&quot;')}" />
        <button id="shareCopy" class="share-copy" type="button">Copy</button>
      </div>
      <p class="share-hint">Credentials shown as placeholder — replace <code>:@</code> with <code>:yourpassword@</code> if your client asks.</p>
    `;

    // Insert below the "Device configuration" block
    const cfgBlock = host.querySelector('[aria-labelledby="connectionHeading"]');
    if (cfgBlock && cfgBlock.parentNode) cfgBlock.parentNode.insertBefore(panel, cfgBlock.nextSibling);
    else host.appendChild(panel);

    document.getElementById('shareCopy').addEventListener('click', async () => {
      const input = document.getElementById('shareUri');
      input.select();
      try {
        await navigator.clipboard.writeText(input.value);
        document.getElementById('shareCopy').textContent = 'Copied';
        setTimeout(() => document.getElementById('shareCopy').textContent = 'Copy', 1500);
      } catch (_) { prompt('Copy:', input.value); }
    });
  }

  let tries = 0;
  const iv = setInterval(() => {
    if (state.account) {
      injectSharePanel();
      clearInterval(iv);
    }
    if (++tries > 60) clearInterval(iv);
  }, 500);
})();
