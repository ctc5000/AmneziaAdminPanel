'use strict';

const API = '/api';
const REFRESH_INTERVAL = 15000;

const state = {
  servers: [],
  statuses: {}, // serverId -> collected status
  statusErrors: {}, // serverId -> error message
  pings: {}, // serverId -> ping result
  expandedId: null,
  activeTab: 'vpn',
  autoTimer: null,
  loaded: false,
};

const el = {
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
};

async function api(path, options = {}) {
  const res = await fetch(`${API}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

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
    el.dashboard.innerHTML = `<div class="error-box">Ошибка загрузки серверов: ${escapeHtml(err.message)}</div>`;
  }
}

/**
 * Refresh ping + status for every server. Results are painted progressively as
 * each server resolves, so a slow/unreachable host never blocks the others.
 */
async function refreshAll() {
  const servers = state.servers.slice();
  await mapLimit(servers, 3, (server) => refreshServer(server.id));
  state.loaded = true;
  renderAll();
}

/**
 * Refresh ping and status of one server independently, re-rendering as soon as
 * each part finishes. When `silent` is set (auto-refresh) the render is skipped
 * if this server is not expanded, to avoid needless DOM work.
 */
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

  const statusP = api(`/servers/${id}/status`)
    .then((s) => {
      state.statuses[id] = s;
      delete state.statusErrors[id];
      settle();
    })
    .catch((err) => {
      state.statusErrors[id] = err.message;
      settle();
    });

  await Promise.all([pingP, statusP]);
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
    el.dashboard.innerHTML =
      '<div class="muted" style="grid-column:1/-1">Серверов пока нет. Добавьте первый через «➕ Добавить сервер».</div>';
    return;
  }

  el.dashboard.innerHTML = state.servers.map((s) => serverCard(s)).join('');
}

function serverCard(server) {
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
        <button class="btn btn-danger" data-action="remove" data-id="${escapeHtml(id)}">Удалить</button>
      </div>
    </div>`;
}

function metric(value, label) {
  return `<div class="metric">
    <div class="metric-value">${escapeHtml(String(value))}</div>
    <div class="metric-label">${escapeHtml(label)}</div>
  </div>`;
}

/** Classify a server by the last collected status / error. */
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

function summaryItem(value, label) {
  return `<div class="summary-item"><span class="value">${escapeHtml(String(value))}</span><span class="label">${escapeHtml(label)}</span></div>`;
}

// --- VPN containers ---------------------------------------------------------

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

// --- MTProto proxies --------------------------------------------------------

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
  const removeBtn = e.target.closest('button[data-action="remove"]');
  if (removeBtn) {
    e.stopPropagation();
    removeServer(removeBtn.dataset.id);
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
    // Fetch immediately if we have never seen this server's status.
    if (!state.statuses[id] && !state.statusErrors[id]) {
      refreshServer(id);
    }
  }
  renderAll();
  if (state.expandedId) {
    el.detail.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
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

  if (actionBtn.dataset.action === 'install-awg') {
    openInstallModal();
    return;
  }

  if (actionBtn.dataset.action === 'new-awg-client') {
    openClientConfig({ container: actionBtn.dataset.container, mode: 'new' });
    return;
  }

  if (actionBtn.dataset.action === 'refresh-detail') {
    actionBtn.disabled = true;
    await refreshServer(id);
    renderAll();
  } else if (actionBtn.dataset.action === 'ping-detail') {
    actionBtn.disabled = true;
    try {
      state.pings[id] = await api(`/servers/${id}/ping`);
    } catch (err) {
      state.pings[id] = { alive: false, error: err.message };
    }
    renderAll();
  } else if (actionBtn.dataset.action === 'remove') {
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

// --- Client activity modal --------------------------------------------------

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

/**
 * Show the connection data for one AmneziaWG client, exactly like the Amnezia
 * app's "Share" button: the native `.conf` file plus the importable `vpn://`
 * link. With { mode: 'new' } a brand-new client connection is generated.
 */
async function openClientConfig({ id, client, container, mode }) {
  const serverId = state.expandedId;
  el.configModal.classList.remove('hidden');
  el.configModalTitle.textContent = 'Данные для подключения';
  el.configModalSub.textContent =
    `${container || 'amnezia-awg'}${client ? ` · ${client}` : ''}` +
    (mode === 'new' ? ' · новое подключение' : '');
  el.configModalBody.innerHTML =
    mode === 'new'
      ? '<div class="muted"><span class="spinner">Генерация ключей и добавление пира…</span></div>'
      : '<div class="muted"><span class="spinner">Загрузка конфигурации…</span></div>';
  el.configModalNew.classList.toggle('hidden', mode === 'new');
  el.configModalCopyLink.disabled = true;
  currentConfig = null;

  try {
    const params = new URLSearchParams();
    if (container) params.set('container', container);
    if (id) params.set('id', id);
    if (client) params.set('client', client);
    if (mode === 'new') params.set('mode', 'new');
    const data = await api(`/servers/${serverId}/awg/config?${params.toString()}`);
    currentConfig = data;
    renderConfig(data);
  } catch (err) {
    el.configModalBody.innerHTML = `<div class="error-box">Не удалось получить данные: ${escapeHtml(err.message)}</div>`;
    // Offer to create a new connection when the stored config is unavailable.
    el.configModalNew.classList.toggle('hidden', mode === 'new');
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
  openClientConfig({ container: sub, mode: 'new' });
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

document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  if (!el.logModal.classList.contains('hidden')) closeLogModal();
  else if (!el.configModal.classList.contains('hidden')) closeConfigModal();
  else if (!el.installModal.classList.contains('hidden')) closeInstallModal();
  else if (!el.serverModal.classList.contains('hidden')) closeServerModal();
});

// --- Auto refresh -----------------------------------------------------------

function setAutoRefresh(on) {
  if (state.autoTimer) clearInterval(state.autoTimer);
  state.autoTimer = null;
  if (on) {
    state.autoTimer = setInterval(() => {
      if (state.servers.length) refreshAll();
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
loadServers();
