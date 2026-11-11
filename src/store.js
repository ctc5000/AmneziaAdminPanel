'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = path.join(__dirname, '..', 'data');
const DATA_FILE = path.join(DATA_DIR, 'servers.json');

let cache = null;

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

function load() {
  if (cache) return cache;
  ensureDataDir();
  if (fs.existsSync(DATA_FILE)) {
    try {
      cache = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      if (!Array.isArray(cache)) cache = [];
    } catch (_) {
      cache = [];
    }
  } else {
    cache = [];
  }
  return cache;
}

function save() {
  ensureDataDir();
  fs.writeFileSync(DATA_FILE, JSON.stringify(cache, null, 2), { mode: 0o600 });
}

function listServers() {
  return load();
}

function getServer(id) {
  return load().find((s) => s.id === id) || null;
}

function addServer(input) {
  const server = {
    id: crypto.randomUUID(),
    name: input.name || `${input.username}@${input.host}`,
    host: input.host,
    port: Number(input.port) || 22,
    username: input.username,
    authType: input.authType === 'key' ? 'key' : 'password',
    password: input.authType === 'key' ? null : input.password || null,
    privateKey: input.authType === 'key' ? input.privateKey || null : null,
    passphrase: input.authType === 'key' ? input.passphrase || null : null,
    createdAt: new Date().toISOString(),
  };
  load().push(server);
  save();
  return server;
}

function updateServer(id, patch) {
  const server = getServer(id);
  if (!server) return null;
  const allowed = ['name', 'host', 'port', 'username', 'authType', 'password', 'privateKey', 'passphrase'];
  for (const key of allowed) {
    if (patch[key] !== undefined) server[key] = patch[key];
  }
  if (server.authType === 'password') {
    server.privateKey = null;
    server.passphrase = null;
  } else {
    server.password = null;
  }
  save();
  return server;
}

function removeServer(id) {
  const servers = load();
  const idx = servers.findIndex((s) => s.id === id);
  if (idx === -1) return false;
  servers.splice(idx, 1);
  save();
  return true;
}

/** Public view of a server: never leaks credentials. */
function toPublic(server) {
  const { password, privateKey, passphrase, ...rest } = server;
  return {
    ...rest,
    hasPassword: Boolean(password),
    hasKey: Boolean(privateKey),
  };
}

module.exports = {
  listServers,
  getServer,
  addServer,
  updateServer,
  removeServer,
  toPublic,
};
