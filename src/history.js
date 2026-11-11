'use strict';

const fs = require('fs');
const path = require('path');

// Client connection history. Amnezia VPN containers ship with the `none`
// logging driver, so `docker logs` is empty for them; instead the panel keeps
// its own per-client event log and updates it on every status refresh.
const DATA_DIR = path.join(__dirname, '..', 'data');
const FILE = path.join(DATA_DIR, 'history.json');
const MAX_PER_CLIENT = 100;
const SAVE_DEBOUNCE_MS = 2000;

let cache = null;
let saveTimer = null;

function load() {
  if (cache) return cache;
  try {
    cache = JSON.parse(fs.readFileSync(FILE, 'utf8'));
    if (!cache || typeof cache !== 'object') cache = {};
  } catch (_) {
    cache = {};
  }
  return cache;
}

function scheduleSave() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    try {
      if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
      fs.writeFileSync(FILE, JSON.stringify(cache), { mode: 0o600 });
    } catch (_) {
      /* best-effort persistence */
    }
  }, SAVE_DEBOUNCE_MS);
  if (saveTimer.unref) saveTimer.unref();
}

function clientKey(serverId, container, client) {
  const id = client.id || client.publicKeyFull || client.endpoint || client.name || 'unknown';
  return `${serverId}|${container}|${id}`;
}

function signature(client) {
  return [client.online ? '1' : '0', client.endpoint || '', client.lastSeen || '', client.rx || 0, client.tx || 0].join('|');
}

/**
 * Record one observation of a client. An event is stored only when something
 * changed (online state, endpoint, handshake) or on first sight.
 */
function recordClient(serverId, container, client, at) {
  const store = load();
  const key = clientKey(serverId, container, client);
  const list = store[key] || (store[key] = []);

  const sig = signature(client);
  const last = list[list.length - 1];
  if (last && last.sig === sig) return;

  const prevOnline = last ? last.online : null;
  let event = 'snapshot';
  if (prevOnline === false && client.online) event = 'online';
  else if (prevOnline === true && !client.online) event = 'offline';
  else if (last && last.endpoint && client.endpoint && last.endpoint !== client.endpoint) event = 'endpoint';
  else if (last && last.lastSeen && client.lastSeen && last.lastSeen !== client.lastSeen) event = 'handshake';

  list.push({
    time: at || new Date().toISOString(),
    sig,
    event,
    online: Boolean(client.online),
    endpoint: client.endpoint || null,
    lastSeen: client.lastSeen || null,
    rx: client.rx || 0,
    tx: client.tx || 0,
  });

  if (list.length > MAX_PER_CLIENT) list.splice(0, list.length - MAX_PER_CLIENT);
}

/** Record every client of a collected status snapshot. */
function recordStatus(status) {
  if (!status || !Array.isArray(status.containers)) return;
  const at = status.collectedAt || new Date().toISOString();
  for (const container of status.containers) {
    for (const client of container.clients || []) {
      recordClient(status.serverId, container.name, client, at);
    }
  }
  scheduleSave();
}

/** Return the most recent events for a client, newest first. */
function getHistory(serverId, container, client, limit = 10) {
  const store = load();
  const list = store[clientKey(serverId, container, client)] || [];
  return list.slice(-limit).reverse();
}

/** Forget all history for a server (used when the server is removed). */
function clearServer(serverId) {
  const store = load();
  let changed = false;
  for (const key of Object.keys(store)) {
    if (key.startsWith(`${serverId}|`)) {
      delete store[key];
      changed = true;
    }
  }
  if (changed) scheduleSave();
}

module.exports = { recordClient, recordStatus, getHistory, clearServer };
