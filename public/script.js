'use strict';

const API = '/api';
const REFRESH_INTERVAL = 15000;

const state = {
  user: null, // { id, username, role }
  servers: [],
  statuses: {}, // serverId -> collected status (admin)
  statusErrors: {}, // serverId -> error message (admin)
  pings: {}, // serverId -> ping result
  proxies: {}, // serverId -> proxy summary (regular users)
  proxyErrors: {},
  expandedId: null,
  activeTab: 'vpn',
  autoTimer: null,
  loaded: false,
};

const el = {
  // Auth
  loginScreen: document.getElementById('loginScreen'),
  appRoot: document.getElementById('appRoot'),
  loginForm: document.getElementById('loginForm'),
  loginSub: document.getElementById('loginSub'),
  loginUsername: document.getElementById('loginUsername'),
  loginPassword: document.getElementById('loginPassword'),
  loginMessage: document.getElementById('loginMessage'),
  loginBtn: document.getElementById('loginBtn'),
  showRegister: document.getElementById('showRegister'),
  registerForm: document.getElementById('registerForm'),
  registerUsername: document.getElementById('registerUsername'),
  registerPassword: document.getElementById('registerPassword'),
  registerPassword2: document.getElementById('registerPassword2'),
  registerMessage: document.getElementById('registerMessage'),
  registerBtn: document.getElementById('registerBtn'),
  showLogin: document.getElementById('showLogin'),
  currentUser: document.getElementById('currentUser'),
  currentUserRole: document.getElementById('currentUserRole'),
  logoutBtn: document.getElementById('logoutBtn'),
  usersBtn: document.getElementById('usersBtn'),
  brandSub: document.getElementById('brandSub'),
  dashboardTitle: document.getElementById('dashboardTitle'),

  autoRefresh: document.getElementById('autoRefresh'),
  addServerBtn: document.getElementById('addServerBtn'),
  kpiRow: document.getElementById('kpiRow'),
  refreshAllBtn: document.getElementById('refreshAllBtn'),
  dashboard: document.getElementById('dashboard'),
  detail: document.getElementById('detail'),

  // Add-server modal
  serverModal: document.getElementById('serverModal'),
  serverModalTitle: document.getElementById('serverModalTitle'),
  serverModalClose: document.getElementById('serverModalClose'),
  serverModalCancel: document.getElementById('serverModalCancel'),
  serverModalSave: document.getElementById('serverModalSave'),
  serverName: document.getElementById('serverName'),
  serverAddress: document.getElementById('serverAddress'),
  pingPreviewBtn: document.getElementById('pingPreviewBtn'),
  pingPreview: document.getElementById('pingPreview'),
  serverPort: document.getElementById('serverPort'),
  serverUsername: document.getElementById('serverUsername'),
  serverAuthType: document.getElementById('serverAuthType'),
  serverPassword: document.getElementById('serverPassword'),
  serverPrivateKey: document.getElementById('serverPrivateKey'),
  serverPassphrase: document.getElementById('serverPassphrase'),
  serverVisible: document.getElementById('serverVisible'),
  passwordGroup: document.getElementById('passwordGroup'),
  keyGroup: document.getElementById('keyGroup'),
  passphraseGroup: document.getElementById('passphraseGroup'),
  formMessage: document.getElementById('formMessage'),

  // Client activity modal
  logModal: document.getElementById('logModal'),
  logModalTitle: document.getElementById('logModalTitle'),
  logModalSub: document.getElementById('logModalSub'),
  logModalBody: document.getElementById('logModalBody'),
  logModalClose: document.getElementById('logModalClose'),

  // Share / connection config modal
  configModal: document.getElementById('configModal'),
  configModalTitle: document.getElementById('configModalTitle'),
  configModalSub: document.getElementById('configModalSub'),
  configModalBody: document.getElementById('configModalBody'),
  configModalClose: document.getElementById('configModalClose'),
  configModalNew: document.getElementById('configModalNew'),
  configModalCopyLink: document.getElementById('configModalCopyLink'),

  // MTProto proxy modal
  proxyModal: document.getElementById('proxyModal'),
  proxyModalTitle: document.getElementById('proxyModalTitle'),
  proxyModalSub: document.getElementById('proxyModalSub'),
  proxyModalBody: document.getElementById('proxyModalBody'),
  proxyModalClose: document.getElementById('proxyModalClose'),
  proxyModalCopy: document.getElementById('proxyModalCopy'),

  // Install AmneziaWG modal
  installModal: document.getElementById('installModal'),
  installModalSub: document.getElementById('installModalSub'),
  installModalClose: document.getElementById('installModalClose'),
  installModalCancel: document.getElementById('installModalCancel'),
  installModalRun: document.getElementById('installModalRun'),
  installPort: document.getElementById('installPort'),
  installSubnet: document.getElementById('installSubnet'),
  installCidr: document.getElementById('installCidr'),
  installMessage: document.getElementById('installMessage'),
  installLog: document.getElementById('installLog'),

  // Users modal
  usersModal: document.getElementById('usersModal'),
  usersModalClose: document.getElementById('usersModalClose'),
  usersList: document.getElementById('usersList'),
  usersMessage: document.getElementById('usersMessage'),
  newUserName: document.getElementById('newUserName'),
  newUserPassword: document.getElementById('newUserPassword'),
  newUserRole: document.getElementById('newUserRole'),
  addUserBtn: document.getElementById('addUserBtn'),
};

function isAdmin() {
  return !!(state.user && state.user.role === 'admin');
}

async function api(path, options = {}) {
  const res = await fetch(`${API}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
    ...options,
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.error || `HTTP ${res.status}`);
    err.status = res.status;
    throw err;
  }
  return data;
}

// --- Authentication bootstrap ----------------------------------------------

async function init() {
  try {
    state.user = await api('/auth/me');
    enterApp();
  } catch (_) {
    showLogin();
  }
}

function showLogin() {
  state.user = null;
  state.servers = [];
  el.appRoot.classList.add('hidden');
  el.loginScreen.classList.remove('hidden');
  el.loginPassword.value = '';
  el.loginUsername.value = '';
  // Always return the card to the sign-in view.
  el.registerForm.classList.add('hidden');
  el.loginForm.classList.remove('hidden');
  el.loginBtn.classList.remove('hidden');
  el.loginMessage.classList.remove('hidden');
  el.loginSub.textContent = 'Войдите, чтобы продолжить';
  showLoginMessage('', '');
  el.loginUsername.focus();
}

function enterApp() {
  el.loginScreen.classList.add('hidden');
  el.appRoot.classList.remove('hidden');
  applyRole();
  loadServers();
}

/** Show/hide admin-only controls and adjust copy for the current role. */
function applyRole() {
  const admin = isAdmin();
  el.currentUser.textContent = state.user ? state.user.username : '';
  el.currentUserRole.textContent = admin ? 'администратор' : 'пользователь';
  el.currentUserRole.className = `user-chip-role ${admin ? 'role-admin' : 'role-user'}`;
  document.querySelectorAll('.admin-only').forEach((node) => node.classList.toggle('hidden', !admin));
  el.brandSub.textContent = admin
    ? 'Мониторинг VPN-контейнеров, клиентов и MTProto-прокси'
    : 'Выберите сервер и создайте подключение';
  el.dashboardTitle.textContent = admin ? 'Серверы' : 'Доступные серверы';
}

el.loginBtn.addEventListener('click', doLogin);
el.loginPassword.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') doLogin();
});
el.loginUsername.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') el.loginPassword.focus();
});

el.showRegister.addEventListener('click', (e) => {
  e.preventDefault();
  showRegisterForm();
});
el.showLogin.addEventListener('click', (e) => {
  e.preventDefault();
  showLoginForm();
});
el.registerBtn.addEventListener('click', doRegister);
el.registerPassword2.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') doRegister();
});
el.registerUsername.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') el.registerPassword.focus();
});
el.registerPassword.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') el.registerPassword2.focus();
});

async function doLogin() {
  const username = el.loginUsername.value.trim();
  const password = el.loginPassword.value;
  if (!username || !password) {
    showLoginMessage('Введите логин и пароль.', 'error');
    return;
  }
  el.loginBtn.disabled = true;
  showLoginMessage('Проверка…', '');
  try {
    state.user = await api('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    el.loginUsername.value = '';
    el.loginPassword.value = '';
    showLoginMessage('', '');
    enterApp();
  } catch (err) {
    showLoginMessage(err.message, 'error');
  } finally {
    el.loginBtn.disabled = false;
  }
}

function showLoginMessage(text, type) {
  el.loginMessage.textContent = text || '';
  el.loginMessage.className = `form-message ${type || ''}`;
}

function showRegisterMessage(text, type) {
  el.registerMessage.textContent = text || '';
  el.registerMessage.className = `form-message ${type || ''}`;
}

/** Switch the auth card to the sign-up form. */
function showRegisterForm() {
  el.loginForm.classList.add('hidden');
  el.loginBtn.classList.add('hidden');
  el.loginMessage.classList.add('hidden');
  el.loginSub.textContent = 'Создание аккаунта';
  el.registerForm.classList.remove('hidden');
  el.registerMessage.classList.remove('hidden');
  el.registerMessage.textContent = '';
  el.registerMessage.className = 'form-message';
  el.registerUsername.focus();
}

/** Switch the auth card back to the sign-in form. */
function showLoginForm() {
  el.registerForm.classList.add('hidden');
  el.loginForm.classList.remove('hidden');
  el.loginBtn.classList.remove('hidden');
  el.loginMessage.classList.remove('hidden');
  el.loginSub.textContent = 'Войдите, чтобы продолжить';
  el.registerPassword.value = '';
  el.registerPassword2.value = '';
  el.loginUsername.focus();
}

async function doRegister() {
  const username = el.registerUsername.value.trim();
  const password = el.registerPassword.value;
  const password2 = el.registerPassword2.value;

  if (!username || !password) {
    showRegisterMessage('Введите логин и пароль.', 'error');
    return;
  }
  if (password.length < 4) {
    showRegisterMessage('Пароль должен содержать минимум 4 символа.', 'error');
    return;
  }
  if (password !== password2) {
    showRegisterMessage('Пароли не совпадают.', 'error');
    return;
  }

  el.registerBtn.disabled = true;
  showRegisterMessage('Создание аккаунта…', '');
  try {
    // Successful registration also logs the user in (session cookie is set).
    state.user = await api('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
    el.registerUsername.value = '';
    el.registerPassword.value = '';
    el.registerPassword2.value = '';
    showRegisterMessage('', '');
    enterApp();
  } catch (err) {
    showRegisterMessage(err.message, 'error');
  } finally {
    el.registerBtn.disabled = false;
  }
}

async function logout() {
  try {
    await api('/auth/logout', { method: 'POST' });
  } catch (_) {
    /* ignore */
  }
  if (state.autoTimer) clearInterval(state.autoTimer);
  state.autoTimer = null;
  showLogin();
}

el.logoutBtn.addEventListener('click', logout);

// --- Loading / refreshing ---------------------------------------------------

async function loadServers() {
  try {
    state.servers = await api('/servers');
    if (state.expandedId && !state.servers.some((s) => s.id === state.expandedId)) {
      state.expandedId = null;
    }
    renderAll();
    await refreshAll();
  } catch (err) {
    if (err.status === 401) {
      showLogin();
      return;
    }
    el.dashboard.innerHTML = `<div class="error-box">Ошибка загрузки серверов: ${escapeHtml(err.message)}</div>`;
  }
}

/**
 * Refresh ping (+ status for admins) for every server. Results are painted
 * progressively as each server resolves, so a slow host never blocks others.
 */
async function refreshAll() {
  const servers = state.servers.slice();
  await mapLimit(servers, 3, (server) => refreshServer(server.id));
  state.loaded = true;
  renderAll();
}

/** Refresh ping and (for admins) status of one server, re-rendering as each part finishes. */
async function refreshServer(id, { silent = false } = {}) {
  const settle = () => {
    if (silent && id !== state.expandedId) return;
    renderAll();
  };

  const pingP = api(`/servers/${id}/ping`)
    .then((r) => {
      state.pings[id] = r;
      settle();
    })
    .catch((err) => {
      state.pings[id] = { alive: false, error: err.message };
      settle();
    });

  const statusP = isAdmin()
    ? api(`/servers/${id}/status`)
        .then((s) => {
          state.statuses[id] = s;
          delete state.statusErrors[id];
          settle();
        })
        .catch((err) => {
          state.statusErrors[id] = err.message;
          settle();
        })
    : Promise.resolve();

  await Promise.all([pingP, statusP]);
}

/** Load the list of connectable proxies for a server (regular users). */
async function loadProxies(id) {
  try {
    state.proxies[id] = await api(`/servers/${id}/proxies`);
    delete state.proxyErrors[id];
  } catch (err) {
    state.proxyErrors[id] = err.message;
  }
  if (id === state.expandedId) renderDetail();
}

/** Run async `fn` over `items` with limited concurrency. */
async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const idx = cursor;
      cursor += 1;
      results[idx] = await fn(items[idx], idx);
    }
  });
  await Promise.all(workers);
  return results;
}

function renderAll() {
  renderKpi();
  renderDashboard();
  renderDetail();
}

// --- KPI row ----------------------------------------------------------------

function renderKpi() {
  const servers = state.servers;
  const reachable = servers.filter((s) => {
    const ping = state.pings[s.id];
    return ping && ping.alive;
  }).length;

  if (!isAdmin()) {
    el.kpiRow.innerHTML = [
      kpi(servers.length, 'Доступных серверов'),
      kpi(reachable, 'Доступно (ping)', reachable < servers.length ? 'accent-warn' : ''),
    ].join('');
    return;
  }

  let runningTotal = 0;
  let containersTotal = 0;
  let clientsOnline = 0;
  let keysTotal = 0;

  for (const s of servers) {
    const st = state.statuses[s.id];
    if (!st) continue;
    runningTotal += st.summary.containersRunning;
    containersTotal += st.summary.containersTotal;
    clientsOnline += st.summary.clientsOnline;
    keysTotal += st.summary.mtprotoKeysTotal || 0;
  }

  el.kpiRow.innerHTML = [
    kpi(servers.length, 'Серверов'),
    kpi(reachable, 'Доступно (ping)', reachable < servers.length ? 'accent-warn' : ''),
    kpi(`${runningTotal}/${containersTotal}`, 'Amnezia-контейнеры'),
    kpi(clientsOnline, 'Клиентов онлайн', 'accent-blue'),
    kpi(keysTotal, 'MTProto ключей'),
  ].join('');
}

function kpi(value, label, accent) {
  return `<div class="kpi${accent ? ' ' + accent : ''}">
    <div class="kpi-value">${escapeHtml(String(value))}</div>
    <div class="kpi-label">${escapeHtml(label)}</div>
  </div>`;
}

// --- Dashboard cards --------------------------------------------------------

function renderDashboard() {
  if (state.servers.length === 0) {
    const hint = isAdmin()
      ? 'Серверов пока нет. Добавьте первый через «➕ Добавить сервер».'
      : 'Для вас пока нет доступных серверов. Обратитесь к администратору.';
    el.dashboard.innerHTML = `<div class="muted" style="grid-column:1/-1">${hint}</div>`;
    return;
  }

  el.dashboard.innerHTML = state.servers.map((s) => (isAdmin() ? adminServerCard(s) : userServerCard(s))).join('');
}

function adminServerCard(server) {
  const id = server.id;
  const active = id === state.expandedId ? ' active' : '';
  const st = state.statuses[id];
  const ping = state.pings[id];
  const online = serverState(server);
  const auth = server.hasKey ? 'ключ' : 'пароль';

  const metrics = st
    ? `<div class="server-card-metrics">
         ${metric(`${st.summary.containersRunning}/${st.summary.containersTotal}`, 'Контейнеры')}
         ${metric(st.summary.clientsOnline, 'Онлайн')}
         ${metric(st.summary.mtprotoKeysTotal || 0, 'Ключи TG')}
       </div>`
    : `<div class="server-card-metrics">
         ${metric('—', 'Контейнеры')}
         ${metric('—', 'Онлайн')}
         ${metric('—', 'Ключи TG')}
       </div>`;

  const visibleBadge = server.visible
    ? '<span class="pill pill-online">👁 виден пользователям</span>'
    : '<span class="pill pill-mute">🚫 скрыт</span>';

  return `
    <div class="server-card${active}" data-id="${escapeHtml(id)}">
      <div class="server-card-head">
        <div>
          <div class="server-card-title">${escapeHtml(server.name)}</div>
          <div class="server-card-host">${escapeHtml(server.host)}:${server.port} · ${escapeHtml(server.username)} · ${auth}</div>
        </div>
        <span class="pill pill-${online.key}">${online.label}</span>
      </div>
      ${metrics}
      <div class="server-card-foot">
        ${pingBadge(ping)}
        ${visibleBadge}
      </div>
      <div class="server-card-foot">
        <button class="btn btn-ghost" data-action="toggle-visible" data-id="${escapeHtml(id)}">
          ${server.visible ? '🚫 Скрыть от пользователей' : '👁 Показать пользователям'}
        </button>
        <button class="btn btn-danger" data-action="remove" data-id="${escapeHtml(id)}">Удалить</button>
      </div>
    </div>`;
}

function userServerCard(server) {
  const id = server.id;
  const active = id === state.expandedId ? ' active' : '';
  const ping = state.pings[id];

  return `
    <div class="server-card${active}" data-id="${escapeHtml(id)}">
      <div class="server-card-head">
        <div>
          <div class="server-card-title">${escapeHtml(server.name)}</div>
          <div class="server-card-host">${escapeHtml(server.host)}</div>
        </div>
        ${pingBadge(ping)}
      </div>
      <div class="server-card-actions">
        <button class="btn btn-primary btn-sm" data-action="new-awg" data-id="${escapeHtml(id)}">➕ AmneziaWG</button>
        <button class="btn btn-sm" data-action="new-proxy" data-id="${escapeHtml(id)}">🔗 Прокси</button>
      </div>
    </div>`;
}

function metric(value, label) {
  return `<div class="metric">
    <div class="metric-value">${escapeHtml(String(value))}</div>
    <div class="metric-label">${escapeHtml(label)}</div>
  </div>`;
}

/** Classify a server by the last collected status / error (admins only). */
function serverState(server) {
  const id = server.id;
  if (state.statusErrors[id]) return { key: 'offline', label: 'ошибка' };
  const st = state.statuses[id];
  if (!st) return { key: 'unknown', label: '—' };
  if (st.summary.containersRunning > 0) return { key: 'online', label: 'онлайн' };
  return { key: 'offline', label: 'офлайн' };
}

function pingBadge(ping) {
  if (!ping) return `<span class="pill pill-unknown">пинг: …</span>`;
  if (ping.error || ping.alive === false) {
    return `<span class="pill pill-offline ping-bad">недоступен</span>`;
  }
  const ms = Number(ping.rttMs);
  const cls = pingClass(ms);
  const loss = Number(ping.lossPercent) || 0;
  return `<span class="pill pill-mute"><span class="ping-value ${cls}">${ms} мс</span>${loss ? ` · ${loss}%` : ''}</span>`;
}

function pingClass(ms) {
  if (!Number.isFinite(ms)) return 'ping-mid';
  if (ms <= 60) return 'ping-good';
  if (ms <= 150) return 'ping-mid';
  return 'ping-bad';
}

// --- Detail panel -----------------------------------------------------------

function renderDetail() {
  const id = state.expandedId;
  const server = id ? state.servers.find((s) => s.id === id) : null;
  if (!server) {
    el.detail.hidden = true;
    el.detail.innerHTML = '';
    return;
  }
  if (!isAdmin()) {
    renderUserDetail(server);
    return;
  }

  const st = state.statuses[id];
  const error = state.statusErrors[id];
  const ping = state.pings[id];
  const auth = server.hasKey ? 'SSH-ключ' : 'пароль';

  let body;
  if (error) {
    body = `<div class="error-box">Не удалось получить статус: ${escapeHtml(error)}</div>`;
  } else if (!st) {
    body = '<div class="muted"><span class="spinner">Сбор данных…</span></div>';
  } else {
    body = `
      <div class="summary">
        ${summaryItem(`${st.summary.containersRunning}/${st.summary.containersTotal}`, 'VPN-контейнеры')}
        ${summaryItem(`${st.summary.clientsOnline}/${st.summary.clientsTotal}`, 'Клиентов онлайн')}
        ${summaryItem(`${st.summary.mtprotoRunning}/${st.summary.mtprotoTotal}`, 'MTProto-прокси')}
        ${summaryItem(st.summary.mtprotoKeysTotal || 0, 'Ключей Telegram')}
        ${summaryItem(`${st.durationMs} мс`, 'Время сбора')}
      </div>
      <div class="tabs">
        <button class="tab${state.activeTab === 'vpn' ? ' active' : ''}" data-tab="vpn">VPN-контейнеры (Amnezia)</button>
        <button class="tab${state.activeTab === 'mtproto' ? ' active' : ''}" data-tab="mtproto">MTProto-прокси (Telegram)</button>
      </div>
      <div class="tab-body">${state.activeTab === 'vpn' ? renderVpn(st) : renderMtproto(st)}</div>`;
  }

  el.detail.hidden = false;
  el.detail.innerHTML = `
    <div class="detail-head">
      <div>
        <h2>${escapeHtml(server.name)}</h2>
        <div class="muted">${escapeHtml(server.host)}:${server.port} · ${escapeHtml(server.username)} · ${auth}${
          st ? ` · собрано ${escapeHtml(formatDate(st.collectedAt))}` : ''
        }</div>
      </div>
      <div class="detail-actions">
        ${pingBadge(ping)}
        <button class="btn" data-action="refresh-detail">↻ Обновить</button>
        <button class="btn btn-ghost" data-action="ping-detail">Пинг</button>
        <button class="btn btn-danger" data-action="remove">Удалить</button>
      </div>
    </div>
    ${body}`;
}

/** Detail panel for regular users: the list of connectable proxies. */
function renderUserDetail(server) {
  const id = server.id;
  const ping = state.pings[id];
  const proxyData = state.proxies[id];
  const error = state.proxyErrors[id];

  let body;
  if (error) {
    body = `<div class="error-box">Не удалось получить список подключений: ${escapeHtml(error)}</div>`;
  } else if (!proxyData) {
    body = '<div class="muted"><span class="spinner">Загрузка доступных подключений…</span></div>';
  } else if (!proxyData.proxies.length) {
    body =
      '<div class="proxy-empty">На этом сервере пока нет доступных подключений.<br>Создайте подключение AmneziaWG, если контейнер уже развёрнут администратором.</div>';
  } else {
    body = `<div class="proxy-list">${proxyData.proxies.map((p) => renderProxyItem(p)).join('')}</div>`;
  }

  el.detail.hidden = false;
  el.detail.innerHTML = `
    <div class="detail-head">
      <div>
        <h2>${escapeHtml(server.name)}</h2>
        <div class="muted">${escapeHtml(server.host)}</div>
      </div>
      <div class="detail-actions">
        ${pingBadge(ping)}
        <button class="btn" data-action="refresh-detail">↻ Обновить</button>
        <button class="btn btn-primary" data-action="new-awg" data-id="${escapeHtml(id)}">➕ Создать подключение AmneziaWG</button>
        <button class="btn" data-action="new-proxy" data-id="${escapeHtml(id)}">🔗 Подключение к прокси</button>
      </div>
    </div>
    ${body}`;
}

function renderProxyItem(p) {
  const isAwg = p.kind === 'awg';
  const typeLabel = isAwg ? 'AmneziaWG' : 'MTProto';
  const stateClass = p.running ? ' running' : '';
  const action = isAwg
    ? `<button class="btn btn-primary btn-sm" data-action="new-awg" data-container="${escapeHtml(p.name)}">➕ Создать подключение</button>`
    : `<button class="btn btn-primary btn-sm" data-action="new-proxy" data-name="${escapeHtml(p.name)}">🔗 Подключение к прокси</button>`;

  return `
    <div class="container-card">
      <div class="container-head">
        <h3>${escapeHtml(p.name)}</h3>
        <span class="badge badge-state${stateClass}">${escapeHtml(p.state)}</span>
        <span class="badge badge-type">${typeLabel}</span>
        ${p.port ? `<span class="badge badge-count">порт: ${p.port}</span>` : ''}
        <span class="container-image">${escapeHtml(p.image)}</span>
      </div>
      <div class="server-card-actions">${action}</div>
    </div>`;
}

function summaryItem(value, label) {
  return `<div class="summary-item"><span class="value">${escapeHtml(String(value))}</span><span class="label">${escapeHtml(label)}</span></div>`;
}

// --- VPN containers (admin) -------------------------------------------------

function renderVpn(st) {
  const hasAwg = !!(st.summary && st.summary.hasAwgContainer);
  if (!st.containers.length) {
    return `
      <div class="install-empty">
        <div class="muted">AmneziaWG-контейнер не найден на этом сервере.</div>
        <button class="btn btn-primary" data-action="install-awg">⬇ Установить AmneziaWG</button>
      </div>`;
  }
  const body = st.containers.map((c) => renderContainer(c)).join('');
  // Offer the install action even when other Amnezia protocols exist but AWG is absent.
  const installBanner = hasAwg
    ? ''
    : `<div class="install-banner">
         <span>Контейнер AmneziaWG (amnezia-awg) не найден — протокол AmneziaWG не развёрнут.</span>
         <button class="btn btn-primary" data-action="install-awg">⬇ Установить AmneziaWG</button>
       </div>`;
  return installBanner + body;
}

function renderContainer(c) {
  const stateClass = c.running ? ' running' : '';
  const clients = c.clients.length
    ? c.clients
        .map(
          (cl) => `
        <tr class="client-row"
            data-id="${escapeHtml(cl.id || cl.publicKeyFull || '')}"
            data-client="${escapeHtml(cl.name)}"
            data-endpoint="${escapeHtml(cl.endpoint || '')}"
            data-container="${escapeHtml(c.name)}"
            title="Клик — показать активность; кнопка «Поделиться» — данные для подключения">
          <td><span class="dot${cl.online ? ' online' : ''}"></span>${escapeHtml(cl.name)}</td>
          <td>${escapeHtml(cl.endpoint || '—')}</td>
          <td>${escapeHtml((cl.allowedIps || []).join(', ') || '—')}</td>
          <td>${cl.online ? 'онлайн' : 'офлайн'}</td>
          <td>${escapeHtml(formatDate(cl.lastSeen))}</td>
          <td>${formatBytes(cl.rx)} / ${formatBytes(cl.tx)}</td>
          <td class="row-actions">
            <button class="btn-copy"
                    data-share="1"
                    data-id="${escapeHtml(cl.id || cl.publicKeyFull || '')}"
                    data-client="${escapeHtml(cl.name)}"
                    data-container="${escapeHtml(c.name)}"
                    title="Показать данные для подключения (как «Поделиться» в приложении Amnezia)">
              🔗 Поделиться
            </button>
          </td>
        </tr>`,
        )
        .join('')
    : `<tr class="empty-row"><td colspan="7">Нет подключённых клиентов</td></tr>`;

  return `
    <div class="container-card">
      <div class="container-head">
        <h3>${escapeHtml(c.name)}</h3>
        <span class="badge badge-state${stateClass}">${escapeHtml(c.state)}</span>
        <span class="badge badge-type">${escapeHtml(c.type)}</span>
        <span class="badge badge-online">онлайн: ${c.onlineCount}</span>
        <span class="badge badge-count">клиентов: ${c.clientCount}</span>
        <span class="container-image">${escapeHtml(c.image)}</span>
        <button class="btn btn-primary btn-sm" data-action="new-awg-client" data-container="${escapeHtml(c.name)}">➕ Создать подключение</button>
      </div>
      <table>
        <thead>
          <tr>
            <th>Пользователь</th>
            <th>Endpoint</th>
            <th>IP</th>
            <th>Статус</th>
            <th>Последний хендшейк</th>
            <th>RX / TX</th>
            <th></th>
          </tr>
        </thead>
        <tbody>${clients}</tbody>
      </table>
    </div>`;
}

// --- MTProto proxies (admin) ------------------------------------------------

function renderMtproto(st) {
  const proxies = st.mtprotoContainers || [];
  if (!proxies.length) {
    return '<div class="muted mtproto-empty">MTProto-прокси (Telegram) не найдены на этом сервере.</div>';
  }

  return proxies
    .map((p) => {
      const stateClass = p.running ? ' running' : '';
      const keys = p.keys.length
        ? p.keys.map((k) => renderKey(k)).join('')
        : '<div class="muted" style="padding:8px 0">Ключи не найдены (нет SECRET и записей в логах).</div>';

      return `
      <div class="container-card">
        <div class="container-head">
          <h3>${escapeHtml(p.name)}</h3>
          <span class="badge badge-state${stateClass}">${escapeHtml(p.state)}</span>
          <span class="badge badge-type">MTProto</span>
          ${p.port ? `<span class="badge badge-count">порт: ${p.port}</span>` : ''}
          ${p.domain ? `<span class="badge badge-count">домен: ${escapeHtml(p.domain)}</span>` : ''}
          <span class="badge badge-online">ключей: ${p.keys.length}</span>
          <span class="container-image">${escapeHtml(p.image)}</span>
        </div>
        ${keys}
      </div>`;
    })
    .join('');
}

function renderKey(key) {
  const link = key.link || '';
  return `
    <div class="key-card">
      <div class="key-row">
        <span class="key-secret">${escapeHtml(key.secret)}</span>
        <span class="key-source">${escapeHtml(key.source)}</span>
        ${link ? `<button class="btn-copy" data-copy="${escapeHtml(link)}">Копировать ссылку</button>` : ''}
      </div>
      ${link ? `<div class="key-meta">${escapeHtml(link)}</div>` : ''}
    </div>`;
}

// --- Dashboard / detail interactions ---------------------------------------

el.dashboard.addEventListener('click', (e) => {
  const actionBtn = e.target.closest('button[data-action]');
  if (actionBtn) {
    e.stopPropagation();
    const action = actionBtn.dataset.action;
    if (action === 'remove') removeServer(actionBtn.dataset.id);
    else if (action === 'toggle-visible') toggleVisible(actionBtn.dataset.id);
    else if (action === 'new-awg') openClientConfig({ serverId: actionBtn.dataset.id, container: 'amnezia-awg', mode: 'new' });
    else if (action === 'new-proxy') openProxyConfig({ serverId: actionBtn.dataset.id });
    return;
  }
  const card = e.target.closest('.server-card');
  if (!card) return;
  toggleServer(card.dataset.id);
});

function toggleServer(id) {
  if (state.expandedId === id) {
    state.expandedId = null;
    state.activeTab = 'vpn';
  } else {
    state.expandedId = id;
    if (isAdmin()) {
      // Fetch immediately if we have never seen this server's status.
      if (!state.statuses[id] && !state.statusErrors[id]) {
        refreshServer(id);
      }
    } else if (!state.proxies[id] && !state.proxyErrors[id]) {
      loadProxies(id);
    }
  }
  renderAll();
  if (state.expandedId) {
    el.detail.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
}

async function toggleVisible(id) {
  const server = state.servers.find((s) => s.id === id);
  if (!server) return;
  try {
    const updated = await api(`/servers/${id}`, {
      method: 'PUT',
      body: JSON.stringify({ visible: !server.visible }),
    });
    server.visible = updated.visible;
    renderAll();
  } catch (err) {
    window.alert(`Не удалось изменить видимость: ${err.message}`);
  }
}

el.detail.addEventListener('click', async (e) => {
  const tab = e.target.closest('.tab');
  if (tab) {
    state.activeTab = tab.dataset.tab;
    renderDetail();
    return;
  }

  const copyBtn = e.target.closest('button[data-copy]');
  if (copyBtn) {
    copyLink(copyBtn);
    return;
  }

  // "Поделиться" — must be handled before the generic client-row handler.
  const shareBtn = e.target.closest('button[data-share]');
  if (shareBtn) {
    e.stopPropagation();
    openClientConfig({
      id: shareBtn.dataset.id,
      client: shareBtn.dataset.client,
      container: shareBtn.dataset.container,
      mode: 'existing',
    });
    return;
  }

  const row = e.target.closest('tr.client-row');
  if (row) {
    openClientLogs({
      id: row.dataset.id,
      container: row.dataset.container,
      client: row.dataset.client,
      endpoint: row.dataset.endpoint,
    });
    return;
  }

  const actionBtn = e.target.closest('button[data-action]');
  if (!actionBtn) return;
  const id = state.expandedId;
  const action = actionBtn.dataset.action;

  if (action === 'install-awg') {
    openInstallModal();
    return;
  }

  if (action === 'new-awg-client') {
    openClientConfig({ container: actionBtn.dataset.container, mode: 'new' });
    return;
  }

  if (action === 'new-awg') {
    openClientConfig({ serverId: actionBtn.dataset.id, container: actionBtn.dataset.container || 'amnezia-awg', mode: 'new' });
    return;
  }

  if (action === 'new-proxy') {
    openProxyConfig({ serverId: actionBtn.dataset.id, name: actionBtn.dataset.name });
    return;
  }

  if (action === 'refresh-detail') {
    actionBtn.disabled = true;
    if (isAdmin()) {
      await refreshServer(id);
    } else {
      await Promise.all([refreshServer(id), loadProxies(id)]);
    }
    renderAll();
  } else if (action === 'ping-detail') {
    actionBtn.disabled = true;
    try {
      state.pings[id] = await api(`/servers/${id}/ping`);
    } catch (err) {
      state.pings[id] = { alive: false, error: err.message };
    }
    renderAll();
  } else if (action === 'remove') {
    removeServer(id);
  }
});

async function copyLink(btn) {
  await copyText(btn.dataset.copy, btn, btn.textContent);
}

/** Copy `value` to the clipboard, briefly relabelling `btn` on success. */
async function copyText(value, btn, restoreLabel) {
  const original = restoreLabel !== undefined ? restoreLabel : btn.textContent;
  try {
    await navigator.clipboard.writeText(value);
    if (btn) {
      btn.textContent = 'Скопировано!';
      setTimeout(() => {
        btn.textContent = original;
      }, 1500);
    }
  } catch (_) {
    window.prompt('Скопируйте значение:', value);
  }
}

async function removeServer(id) {
  const server = state.servers.find((s) => s.id === id);
  if (!window.confirm(`Удалить сервер «${server ? server.name : id}»?`)) return;
  try {
    await api(`/servers/${id}`, { method: 'DELETE' });
    delete state.statuses[id];
    delete state.statusErrors[id];
    delete state.pings[id];
    delete state.proxies[id];
    delete state.proxyErrors[id];
    if (state.expandedId === id) state.expandedId = null;
    await loadServers();
  } catch (err) {
    window.alert(`Не удалось удалить сервер: ${err.message}`);
  }
}

el.refreshAllBtn.addEventListener('click', async () => {
  el.refreshAllBtn.disabled = true;
  await refreshAll();
  el.refreshAllBtn.disabled = false;
});

// --- Add-server modal -------------------------------------------------------

function openServerModal() {
  resetForm();
  showFormMessage('');
  el.pingPreview.textContent = '';
  el.serverModal.classList.remove('hidden');
  el.serverAddress.focus();
}

function closeServerModal() {
  el.serverModal.classList.add('hidden');
}

el.addServerBtn.addEventListener('click', openServerModal);
el.serverModalClose.addEventListener('click', closeServerModal);
el.serverModalCancel.addEventListener('click', closeServerModal);
el.serverModal.querySelector('[data-close-server]').addEventListener('click', closeServerModal);

el.serverAuthType.addEventListener('change', syncAuthFields);

function syncAuthFields() {
  const isKey = el.serverAuthType.value === 'key';
  el.passwordGroup.classList.toggle('hidden', isKey);
  el.keyGroup.classList.toggle('hidden', !isKey);
  el.passphraseGroup.classList.toggle('hidden', !isKey);
}

function showFormMessage(text, type) {
  el.formMessage.textContent = text || '';
  el.formMessage.className = `form-message ${type || ''}`;
}

function resetForm() {
  el.serverName.value = '';
  el.serverAddress.value = '';
  el.serverPort.value = '22';
  el.serverUsername.value = '';
  el.serverPassword.value = '';
  el.serverPrivateKey.value = '';
  el.serverPassphrase.value = '';
  el.serverAuthType.value = 'password';
  el.serverVisible.checked = false;
  syncAuthFields();
}

async function pingPreview() {
  const host = el.serverAddress.value.trim();
  if (!host) {
    el.pingPreview.innerHTML = '<span class="ping-bad">Укажите адрес сервера.</span>';
    return;
  }
  el.pingPreview.innerHTML = '<span class="spinner">Проверка пинга…</span>';
  try {
    const r = await api(`/servers/ping?host=${encodeURIComponent(host)}`);
    el.pingPreview.innerHTML = r.alive
      ? `<span class="ping-value ${pingClass(Number(r.rttMs))}">✅ Доступен, ${r.rttMs} мс</span> <span class="muted">(потери ${r.lossPercent}%)</span>`
      : '<span class="ping-bad ping-value">❌ Хост не отвечает на ping</span>';
  } catch (err) {
    el.pingPreview.innerHTML = `<span class="ping-bad">Ошибка: ${escapeHtml(err.message)}</span>`;
  }
}

el.pingPreviewBtn.addEventListener('click', pingPreview);

async function saveServer() {
  const payload = {
    name: el.serverName.value.trim(),
    host: el.serverAddress.value.trim(),
    port: Number(el.serverPort.value) || 22,
    username: el.serverUsername.value.trim(),
    authType: el.serverAuthType.value,
    visible: el.serverVisible.checked,
  };

  if (!payload.host || !payload.username) {
    showFormMessage('Укажите адрес сервера и пользователя.', 'error');
    return;
  }
  if (payload.authType === 'password') {
    payload.password = el.serverPassword.value;
    if (!payload.password) {
      showFormMessage('Введите пароль.', 'error');
      return;
    }
  } else {
    payload.privateKey = el.serverPrivateKey.value.trim();
    payload.passphrase = el.serverPassphrase.value;
    if (!payload.privateKey) {
      showFormMessage('Вставьте приватный ключ.', 'error');
      return;
    }
  }

  el.serverModalSave.disabled = true;
  showFormMessage('Проверка подключения…', '');
  try {
    const created = await api('/servers', { method: 'POST', body: JSON.stringify(payload) });
    closeServerModal();
    await loadServers();
    if (created && created.id) toggleServer(created.id);
  } catch (err) {
    showFormMessage(err.message, 'error');
  } finally {
    el.serverModalSave.disabled = false;
  }
}

el.serverModalSave.addEventListener('click', saveServer);

// --- Client activity modal (admin) ------------------------------------------

async function openClientLogs({ id, container, client, endpoint }) {
  const serverId = state.expandedId;
  el.logModal.classList.remove('hidden');
  el.logModalTitle.textContent = `Активность клиента: ${client || '—'}`;
  el.logModalSub.textContent = `${container}${endpoint ? ` · ${endpoint}` : ''} · последние 10 записей`;
  el.logModalBody.innerHTML = '<div class="muted"><span class="spinner">Загрузка…</span></div>';

  try {
    const params = new URLSearchParams({ container });
    if (id) params.set('id', id);
    if (client) params.set('client', client);
    if (endpoint) params.set('endpoint', endpoint);
    const data = await api(`/servers/${serverId}/logs?${params.toString()}`);
    renderLogs(data);
  } catch (err) {
    el.logModalBody.innerHTML = `<div class="error-box">Не удалось получить данные: ${escapeHtml(err.message)}</div>`;
  }
}

const EVENT_LABELS = {
  online: 'подключение',
  offline: 'отключение',
  endpoint: 'смена endpoint',
  handshake: 'хендшейк',
  snapshot: 'первое наблюдение',
};

function renderLogs(data) {
  const entries = (data && data.entries) || [];
  if (entries.length === 0) {
    el.logModalBody.innerHTML =
      '<div class="muted">Для этого клиента пока нет записей. История накапливается при обновлении статуса сервера.</div>';
    return;
  }
  el.logModalBody.innerHTML = entries
    .map((entry) => {
      // History entries are objects; raw container log lines are plain strings.
      if (entry && typeof entry === 'object') {
        const label = EVENT_LABELS[entry.event] || entry.event || 'событие';
        const when = `[${formatDate(entry.time)}]`;
        const dot = `<span class="dot${entry.online ? ' online' : ''}"></span>`;
        const detail = `${escapeHtml(label)}${entry.endpoint ? ` · ${escapeHtml(entry.endpoint)}` : ''}`;
        const traffic = `RX ${formatBytes(entry.rx)} / TX ${formatBytes(entry.tx)}`;
        return `<div class="log-line">${dot}${escapeHtml(when)} ${detail} <span class="log-traffic">${traffic}</span></div>`;
      }
      return `<div class="log-line">${escapeHtml(entry)}</div>`;
    })
    .join('');
}

function closeLogModal() {
  el.logModal.classList.add('hidden');
  el.logModalBody.innerHTML = '';
}

el.logModalClose.addEventListener('click', closeLogModal);
el.logModal.querySelector('[data-close]').addEventListener('click', closeLogModal);

// --- Share / connection config modal ----------------------------------------

let currentConfig = null;
let currentConfigServerId = null;

/**
 * Show the connection data for one AmneziaWG client, exactly like the Amnezia
 * app's "Share" button: the native `.conf` file plus the importable `vpn://`
 * link. With { mode: 'new' } a brand-new client connection is generated.
 */
async function openClientConfig({ serverId, id, client, container, mode }) {
  const sid = serverId || state.expandedId;
  currentConfigServerId = sid;
  el.configModal.classList.remove('hidden');
  el.configModalTitle.textContent = 'Данные для подключения';
  el.configModalSub.textContent =
    `${container || 'amnezia-awg'}${client ? ` · ${client}` : ''}` + (mode === 'new' ? ' · новое подключение' : '');
  el.configModalBody.innerHTML =
    mode === 'new'
      ? '<div class="muted"><span class="spinner">Генерация ключей и добавление пира…</span></div>'
      : '<div class="muted"><span class="spinner">Загрузка конфигурации…</span></div>';
  // Regular users may only generate their own connection.
  el.configModalNew.classList.toggle('hidden', mode === 'new' || !isAdmin());
  el.configModalCopyLink.disabled = true;
  currentConfig = null;

  try {
    const params = new URLSearchParams();
    if (container) params.set('container', container);
    if (id) params.set('id', id);
    if (client) params.set('client', client);
    if (mode === 'new') params.set('mode', 'new');
    const data = await api(`/servers/${sid}/awg/config?${params.toString()}`);
    currentConfig = data;
    renderConfig(data);
  } catch (err) {
    el.configModalBody.innerHTML = `<div class="error-box">Не удалось получить данные: ${escapeHtml(err.message)}</div>`;
    // Offer to create a new connection when the stored config is unavailable.
    el.configModalNew.classList.toggle('hidden', mode === 'new' || !isAdmin());
  }
}

function renderConfig(data) {
  const rows = [
    ['Сервер', `${data.host}:${data.port}`],
    ['Клиент', data.clientName || '—'],
    ['IP клиента', data.clientIp || '—'],
    ['DNS', `${data.dns1 || ''}${data.dns2 ? ', ' + data.dns2 : ''}` || '—'],
    ['Публичный ключ сервера', data.serverPublicKey || '—'],
  ]
    .map(
      ([label, value]) =>
        `<div class="config-row"><span class="config-label">${escapeHtml(label)}</span><span class="config-value">${escapeHtml(String(value))}</span></div>`,
    )
    .join('');

  const source = data.reused
    ? 'Сохранённая конфигурация клиента'
    : 'Создано новое подключение (ключи сгенерированы на сервере)';

  el.configModalBody.innerHTML = `
    <div class="config-meta">${escapeHtml(source)}</div>
    <div class="config-grid">${rows}</div>
    <label class="config-block-label">Ссылка для импорта в приложение Amnezia (vpn://)</label>
    <div class="config-code">
      <button class="btn-copy" data-copy="${escapeHtml(data.vpnLink || '')}">Копировать</button>
      <code>${escapeHtml(data.vpnLink || '')}</code>
    </div>
    <label class="config-block-label">Конфигурация WireGuard (.conf)</label>
    <div class="config-code">
      <button class="btn-copy" data-copy="${escapeHtml(data.config || '')}">Копировать</button>
      <pre>${escapeHtml(data.config || '')}</pre>
    </div>`;

  el.configModalCopyLink.disabled = !data.vpnLink;
}

function closeConfigModal() {
  el.configModal.classList.add('hidden');
  el.configModalBody.innerHTML = '';
  currentConfig = null;
}

el.configModalClose.addEventListener('click', closeConfigModal);
el.configModal.querySelector('[data-close-config]').addEventListener('click', closeConfigModal);

el.configModalCopyLink.addEventListener('click', () => {
  if (currentConfig && currentConfig.vpnLink) copyText(currentConfig.vpnLink, el.configModalCopyLink, '🔗 Копировать vpn:// ссылку');
});

el.configModalNew.addEventListener('click', () => {
  const sub = el.configModalSub.textContent.split(' · ')[0];
  openClientConfig({ serverId: currentConfigServerId || state.expandedId, container: sub, mode: 'new' });
});

// --- MTProto proxy connection modal (regular users) -------------------------

let currentProxy = null;

async function openProxyConfig({ serverId, name }) {
  const sid = serverId || state.expandedId;
  el.proxyModal.classList.remove('hidden');
  el.proxyModalTitle.textContent = 'Подключение к прокси';
  el.proxyModalSub.textContent = name ? name : 'MTProto (Telegram)';
  el.proxyModalBody.innerHTML = '<div class="muted"><span class="spinner">Загрузка данных прокси…</span></div>';
  el.proxyModalCopy.disabled = true;
  currentProxy = null;

  try {
    const params = new URLSearchParams();
    if (name) params.set('name', name);
    const data = await api(`/servers/${sid}/mtproto/config?${params.toString()}`);
    currentProxy = data;
    renderProxyConfig(data);
  } catch (err) {
    el.proxyModalBody.innerHTML = `<div class="error-box">Не удалось получить данные прокси: ${escapeHtml(err.message)}</div>`;
  }
}

function renderProxyConfig(data) {
  const rows = [
    ['Прокси', data.name || '—'],
    ['Сервер', data.host],
    ['Порт', data.port != null ? String(data.port) : '—'],
    ['Домен', data.domain || '—'],
    ['Secret', data.secret || '—'],
  ]
    .map(
      ([label, value]) =>
        `<div class="config-row"><span class="config-label">${escapeHtml(label)}</span><span class="config-value">${escapeHtml(String(value))}</span></div>`,
    )
    .join('');

  const link = data.tgLink || data.link || '';
  const linkBlock = link
    ? `<label class="config-block-label">Ссылка для подключения (Telegram)</label>
       <div class="config-code">
         <button class="btn-copy" data-copy="${escapeHtml(link)}">Копировать</button>
         <code>${escapeHtml(link)}</code>
       </div>`
    : '<div class="muted">Секрет прокси не найден — обратитесь к администратору.</div>';

  el.proxyModalBody.innerHTML = `
    <div class="config-grid">${rows}</div>
    ${linkBlock}`;

  el.proxyModalCopy.disabled = !link;
}

function closeProxyModal() {
  el.proxyModal.classList.add('hidden');
  el.proxyModalBody.innerHTML = '';
  currentProxy = null;
}

el.proxyModalClose.addEventListener('click', closeProxyModal);
el.proxyModal.querySelector('[data-close-proxy]').addEventListener('click', closeProxyModal);
el.proxyModalCopy.addEventListener('click', () => {
  const link = currentProxy && (currentProxy.tgLink || currentProxy.link);
  if (link) copyText(link, el.proxyModalCopy, '🔗 Копировать ссылку');
});

// --- Install AmneziaWG modal ------------------------------------------------

function openInstallModal() {
  const serverId = state.expandedId;
  const server = state.servers.find((s) => s.id === serverId);
  el.installModalSub.textContent = server ? `${server.name} · ${server.host}` : '';
  el.installMessage.textContent = '';
  el.installMessage.className = 'form-message';
  el.installLog.classList.add('hidden');
  el.installLog.textContent = '';
  el.installModalRun.disabled = false;
  el.installModal.classList.remove('hidden');
}

function closeInstallModal() {
  el.installModal.classList.add('hidden');
}

el.installModalClose.addEventListener('click', closeInstallModal);
el.installModalCancel.addEventListener('click', closeInstallModal);
el.installModal.querySelector('[data-close-install]').addEventListener('click', closeInstallModal);

el.installModalRun.addEventListener('click', async () => {
  const serverId = state.expandedId;
  const port = el.installPort.value.trim();
  const payload = {
    subnet: el.installSubnet.value.trim() || undefined,
    cidr: el.installCidr.value.trim() || undefined,
  };
  if (port) payload.port = Number(port);

  el.installModalRun.disabled = true;
  el.installMessage.textContent = 'Установка запущена. Это может занять до нескольких минут (загрузка образа)…';
  el.installMessage.className = 'form-message';
  el.installLog.classList.remove('hidden');
  el.installLog.textContent = 'docker pull amneziavpn/amnezia-wg:latest …\n';

  try {
    const result = await api(`/servers/${serverId}/install-awg`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    el.installMessage.textContent = `Готово: контейнер ${result.container} запущен на порту ${result.port} UDP. Публичный ключ: ${result.serverPublicKey || '—'}`;
    el.installMessage.className = 'form-message success';
    el.installLog.textContent += `\n✔ ${result.container} → ${result.subnet}, порт ${result.port}/udp`;
    await refreshServer(serverId);
    renderAll();
    setTimeout(closeInstallModal, 1500);
  } catch (err) {
    el.installMessage.textContent = `Ошибка установки: ${err.message}`;
    el.installMessage.className = 'form-message error';
    el.installLog.textContent += `\n✖ ${err.message}`;
    el.installModalRun.disabled = false;
  }
});

// --- Users management modal (admin) -----------------------------------------

function openUsersModal() {
  el.usersMessage.textContent = '';
  el.usersMessage.className = 'form-message';
  el.newUserName.value = '';
  el.newUserPassword.value = '';
  el.newUserRole.value = 'user';
  el.usersModal.classList.remove('hidden');
  loadUsers();
}

function closeUsersModal() {
  el.usersModal.classList.add('hidden');
}

el.usersBtn.addEventListener('click', openUsersModal);
el.usersModalClose.addEventListener('click', closeUsersModal);
el.usersModal.querySelector('[data-close-users]').addEventListener('click', closeUsersModal);

async function loadUsers() {
  el.usersList.innerHTML = '<div class="muted"><span class="spinner">Загрузка…</span></div>';
  try {
    const list = await api('/users');
    renderUsers(list);
  } catch (err) {
    el.usersList.innerHTML = `<div class="error-box">Не удалось загрузить пользователей: ${escapeHtml(err.message)}</div>`;
  }
}

function renderUsers(list) {
  if (!list.length) {
    el.usersList.innerHTML = '<div class="muted">Пользователей нет.</div>';
    return;
  }
  el.usersList.innerHTML = list
    .map((u) => {
      const isSelf = state.user && u.id === state.user.id;
      return `
      <div class="user-row" data-id="${escapeHtml(u.id)}">
        <div class="user-row-main">
          <span class="user-row-name">${escapeHtml(u.username)}${isSelf ? ' <span class="user-self">(вы)</span>' : ''}</span>
        </div>
        <select class="user-role-select" data-id="${escapeHtml(u.id)}">
          <option value="user"${u.role === 'user' ? ' selected' : ''}>Пользователь</option>
          <option value="admin"${u.role === 'admin' ? ' selected' : ''}>Администратор</option>
        </select>
        <button class="btn-copy" data-action="user-password" data-id="${escapeHtml(u.id)}">Пароль</button>
        <button class="btn btn-danger btn-sm" data-action="user-delete" data-id="${escapeHtml(u.id)}">Удалить</button>
      </div>`;
    })
    .join('');
}

el.usersList.addEventListener('change', async (e) => {
  const select = e.target.closest('.user-role-select');
  if (!select) return;
  try {
    await api(`/users/${select.dataset.id}`, {
      method: 'PUT',
      body: JSON.stringify({ role: select.value }),
    });
    showUsersMessage('Роль обновлена.', 'success');
  } catch (err) {
    showUsersMessage(err.message, 'error');
    loadUsers();
  }
});

el.usersList.addEventListener('click', async (e) => {
  const btn = e.target.closest('button[data-action]');
  if (!btn) return;
  const id = btn.dataset.id;

  if (btn.dataset.action === 'user-delete') {
    if (!window.confirm('Удалить пользователя?')) return;
    try {
      await api(`/users/${id}`, { method: 'DELETE' });
      showUsersMessage('Пользователь удалён.', 'success');
      loadUsers();
    } catch (err) {
      showUsersMessage(err.message, 'error');
    }
    return;
  }

  if (btn.dataset.action === 'user-password') {
    const password = window.prompt('Новый пароль (минимум 4 символа):');
    if (!password) return;
    try {
      await api(`/users/${id}`, { method: 'PUT', body: JSON.stringify({ password }) });
      showUsersMessage('Пароль обновлён.', 'success');
    } catch (err) {
      showUsersMessage(err.message, 'error');
    }
  }
});

function showUsersMessage(text, type) {
  el.usersMessage.textContent = text || '';
  el.usersMessage.className = `form-message ${type || ''}`;
}

el.addUserBtn.addEventListener('click', async () => {
  const username = el.newUserName.value.trim();
  const password = el.newUserPassword.value;
  const role = el.newUserRole.value;
  if (!username || !password) {
    showUsersMessage('Укажите логин и пароль.', 'error');
    return;
  }
  el.addUserBtn.disabled = true;
  try {
    await api('/users', { method: 'POST', body: JSON.stringify({ username, password, role }) });
    el.newUserName.value = '';
    el.newUserPassword.value = '';
    el.newUserRole.value = 'user';
    showUsersMessage('Пользователь добавлен.', 'success');
    loadUsers();
  } catch (err) {
    showUsersMessage(err.message, 'error');
  } finally {
    el.addUserBtn.disabled = false;
  }
});

// --- Global keyboard --------------------------------------------------------

document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  if (!el.logModal.classList.contains('hidden')) closeLogModal();
  else if (!el.configModal.classList.contains('hidden')) closeConfigModal();
  else if (!el.proxyModal.classList.contains('hidden')) closeProxyModal();
  else if (!el.installModal.classList.contains('hidden')) closeInstallModal();
  else if (!el.usersModal.classList.contains('hidden')) closeUsersModal();
  else if (!el.serverModal.classList.contains('hidden')) closeServerModal();
});

// --- Auto refresh -----------------------------------------------------------

function setAutoRefresh(on) {
  if (state.autoTimer) clearInterval(state.autoTimer);
  state.autoTimer = null;
  if (on) {
    state.autoTimer = setInterval(() => {
      if (state.user && state.servers.length) refreshAll();
    }, REFRESH_INTERVAL);
  }
}

el.autoRefresh.addEventListener('change', () => setAutoRefresh(el.autoRefresh.checked));

// --- Helpers ----------------------------------------------------------------

function formatDate(iso) {
  if (!iso) return 'никогда';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString('ru-RU');
}

function formatBytes(n) {
  const v = Number(n) || 0;
  if (v < 1024) return `${v} B`;
  const units = ['KB', 'MB', 'GB', 'TB'];
  let value = v / 1024;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${value.toFixed(1)} ${units[i]}`;
}

function escapeHtml(str) {
  const entities = {
    '&': '&' + 'amp;',
    '<': '&' + 'lt;',
    '>': '&' + 'gt;',
    '"': '&' + 'quot;',
    "'": '&' + '#39;',
  };
  return String(str).replace(/[&<>"']/g, (ch) => entities[ch]);
}

// --- Init -------------------------------------------------------------------

syncAuthFields();
setAutoRefresh(el.autoRefresh.checked);
init();
