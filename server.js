'use strict';

const path = require('path');

// Load variables from a local .env file (PORT, etc.) if present.
// The path is resolved against the project root (not the current working
// directory) so it also works when started via systemd/pm2/docker.
// Must run before any other module reads process.env.
require('dotenv').config({ path: path.join(__dirname, '.env') });
const express = require('express');

const store = require('./src/store');
const users = require('./src/users');
const auth = require('./src/auth');
const { collectServerStatus, collectClientLogs, collectProxyStatus, getMtprotoConfig } = require('./src/collect');
const history = require('./src/history');
const { pingHost } = require('./src/ping');
const { installAwgContainer, getAwgShare, getAwgState } = require('./src/awg');

const app = express();
const PORT = process.env.PORT || 3000;

// Ensure at least one admin exists before serving any request.
users.ensureAdmin();

app.use(express.json({ limit: '256kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Resolve the current user from the session cookie (never rejects).
app.use(auth.attachUser(users));

// --- Helpers ----------------------------------------------------------------

/**
 * Whether `user` is allowed to reach the given server. Admins see everything;
 * regular users only see servers an admin marked as visible.
 */
function canAccessServer(user, server) {
  if (!user || !server) return false;
  if (user.role === 'admin') return true;
  return Boolean(server.visible);
}

/** Load a server by id only when the current user may access it. */
function loadAccessibleServer(req, res) {
  const server = store.getServer(req.params.id);
  if (!server) {
    res.status(404).json({ error: 'server not found' });
    return null;
  }
  if (!canAccessServer(req.user, server)) {
    res.status(403).json({ error: 'access to this server is not allowed' });
    return null;
  }
  return server;
}

// --- Auth -------------------------------------------------------------------

app.get('/api/auth/me', (req, res) => {
  if (!req.user) return res.status(401).json({ error: 'authentication required' });
  res.json(users.toPublicUser(req.user));
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = users.getUserByUsername(username);
  if (!user || !users.verifyPassword(password, user.passwordHash)) {
    return res.status(401).json({ error: 'invalid username or password' });
  }
  const sid = auth.createSession(user.id);
  auth.setSessionCookie(res, sid);
  res.json(users.toPublicUser(user));
});

// Self-service registration. The role is ALWAYS 'user' — privileges are granted
// by an administrator afterwards (Users dialog, or by editing data/users.json).
app.post('/api/auth/register', (req, res) => {
  const { username, password } = req.body || {};
  try {
    const user = users.registerUser({ username, password });
    const sid = auth.createSession(user.id);
    auth.setSessionCookie(res, sid);
    res.status(201).json(users.toPublicUser(user));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/auth/logout', (req, res) => {
  auth.destroySession(req.sessionId);
  auth.clearSessionCookie(res);
  res.status(204).end();
});

// Everything below this line requires an authenticated user.
app.use('/api', (req, res, next) => {
  // `/api/health` is intentionally left public.
  if (req.path === '/health') return next();
  return auth.requireAuth(req, res, next);
});

// --- Users (admin only) -----------------------------------------------------

app.get('/api/users', auth.requireAdmin, (req, res) => {
  res.json(users.listUsers().map(users.toPublicUser));
});

app.post('/api/users', auth.requireAdmin, (req, res) => {
  const { username, password, role } = req.body || {};
  try {
    const user = users.addUser({ username, password, role });
    res.status(201).json(users.toPublicUser(user));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.put('/api/users/:id', auth.requireAdmin, (req, res) => {
  const target = users.getUser(req.params.id);
  if (!target) return res.status(404).json({ error: 'user not found' });

  const patch = req.body || {};
  // Protect against self-lockout: an admin cannot demote the last admin.
  if (patch.role && patch.role !== 'admin' && target.role === 'admin' && users.countAdmins() <= 1) {
    return res.status(400).json({ error: 'cannot demote the last admin' });
  }
  try {
    const updated = users.updateUser(req.params.id, patch);
    res.json(users.toPublicUser(updated));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete('/api/users/:id', auth.requireAdmin, (req, res) => {
  const target = users.getUser(req.params.id);
  if (!target) return res.status(404).json({ error: 'user not found' });
  if (target.role === 'admin' && users.countAdmins() <= 1) {
    return res.status(400).json({ error: 'cannot remove the last admin' });
  }
  users.removeUser(req.params.id);
  res.status(204).end();
});

// --- Servers CRUD (admin only) ----------------------------------------------

app.get('/api/servers', (req, res) => {
  const all = store.listServers();
  const visible = req.user.role === 'admin' ? all : all.filter((s) => s.visible);
  res.json(visible.map(store.toPublic));
});

// Ping an arbitrary host (used to preview latency before a server is added).
// Registered before `/api/servers/:id/...` so "ping" is not read as an id.
app.get('/api/servers/ping', auth.requireAdmin, async (req, res) => {
  const host = (req.query && req.query.host) || '';
  if (!host) return res.status(400).json({ error: 'host is required' });
  try {
    const result = await pingHost(String(host), { count: Number(req.query.count) || 4 });
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: err.message || 'ping failed' });
  }
});

app.post('/api/servers', auth.requireAdmin, (req, res) => {
  const { name, host, port, username, authType, password, privateKey, passphrase, visible } = req.body || {};

  if (!host || !username) {
    return res.status(400).json({ error: 'host and username are required' });
  }
  const type = authType === 'key' ? 'key' : 'password';
  if (type === 'password' && !password) {
    return res.status(400).json({ error: 'password is required for password auth' });
  }
  if (type === 'key' && !privateKey) {
    return res.status(400).json({ error: 'privateKey is required for key auth' });
  }

  const server = store.addServer({
    name,
    host,
    port: Number(port) || 22,
    username,
    authType: type,
    password,
    privateKey,
    passphrase,
    visible,
  });
  res.status(201).json(store.toPublic(server));
});

app.put('/api/servers/:id', auth.requireAdmin, (req, res) => {
  const updated = store.updateServer(req.params.id, req.body || {});
  if (!updated) return res.status(404).json({ error: 'server not found' });
  res.json(store.toPublic(updated));
});

app.delete('/api/servers/:id', auth.requireAdmin, (req, res) => {
  const ok = store.removeServer(req.params.id);
  if (!ok) return res.status(404).json({ error: 'server not found' });
  history.clearServer(req.params.id);
  res.status(204).end();
});

// --- Ping (any authenticated user with access) ------------------------------

app.get('/api/servers/:id/ping', async (req, res) => {
  const server = loadAccessibleServer(req, res);
  if (!server) return;

  try {
    const result = await pingHost(server.host, { count: Number(req.query.count) || 4 });
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: err.message || 'ping failed' });
  }
});

// --- Status (admin only — full monitoring details) --------------------------

app.get('/api/servers/:id/status', auth.requireAdmin, async (req, res) => {
  const server = store.getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'server not found' });

  try {
    const status = await collectServerStatus(server);
    history.recordStatus(status);
    res.json(status);
  } catch (err) {
    res.status(502).json({ error: err.message || 'failed to collect status' });
  }
});

// --- Proxy summary (regular users: what they can connect to) ----------------

app.get('/api/servers/:id/proxies', async (req, res) => {
  const server = loadAccessibleServer(req, res);
  if (!server) return;

  try {
    const result = await collectProxyStatus(server);
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: err.message || 'failed to collect proxy status' });
  }
});

// --- Client activity (admin only) -------------------------------------------

app.get('/api/servers/:id/logs', auth.requireAdmin, async (req, res) => {
  const server = store.getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'server not found' });

  const { container, client, endpoint, id } = req.query || {};
  if (!container) return res.status(400).json({ error: 'container is required' });

  // Prefer the panel-side history (works even when the container has no logs).
  const entries = history.getHistory(req.params.id, container, { id, endpoint, name: client }, 10);
  if (entries.length > 0) {
    return res.json({
      container,
      name: client || null,
      endpoint: endpoint || null,
      source: 'history',
      count: entries.length,
      entries,
    });
  }

  // Fall back to container logs where the driver supports reading them.
  try {
    const logs = await collectClientLogs(server, { container, name: client, endpoint });
    res.json(logs);
  } catch (err) {
    res.json({ container, name: client || null, endpoint: endpoint || null, source: 'history', count: 0, entries: [] });
  }
});

// --- AmneziaWG --------------------------------------------------------------

// Install the AmneziaWG container on a server that does not have one yet.
app.post('/api/servers/:id/install-awg', auth.requireAdmin, async (req, res) => {
  const server = store.getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'server not found' });

  const { port, subnet, cidr } = req.body || {};
  try {
    const result = await installAwgContainer(server, {
      port: port === undefined || port === null || port === '' ? undefined : Number(port),
      subnet,
      cidr,
    });
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: err.message || 'failed to install AmneziaWG' });
  }
});

// Connection data for the Amnezia VPN app (native .conf + vpn:// share link),
// mirroring the app's "Share" action. Available to admins and to regular users
// (who may create their own connection) for servers they can access.
app.get('/api/servers/:id/awg/config', async (req, res) => {
  const server = loadAccessibleServer(req, res);
  if (!server) return;

  const { container, id, client, clientName, clientIp, mode, dns1, dns2 } = req.query || {};
  try {
    const result = await getAwgShare(server, {
      container,
      clientId: id,
      client: client,
      clientName: clientName || client,
      clientIp,
      mode,
      dns1,
      dns2,
    });
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: err.message || 'failed to build connection config' });
  }
});

// MTProto proxy connection link (Telegram). Regular users use this to "create a
// connection" to a proxy that is already deployed on the server.
app.get('/api/servers/:id/mtproto/config', async (req, res) => {
  const server = loadAccessibleServer(req, res);
  if (!server) return;

  try {
    const result = await getMtprotoConfig(server, { name: (req.query && req.query.name) || '' });
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: err.message || 'failed to read MTProto proxy config' });
  }
});

// Lightweight AWG state (obfuscation params + server public key), used to
// populate the install dialog defaults.
app.get('/api/servers/:id/awg/state', auth.requireAdmin, async (req, res) => {
  const server = store.getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'server not found' });

  try {
    const state = await getAwgState(server, (req.query && req.query.container) || 'amnezia-awg');
    res.json({
      container: state.container,
      listenPort: state.listenPort,
      subnet: state.subnetAddress ? `${state.subnetAddress}/${state.subnetCidr}` : null,
      serverPublicKey: state.serverPublicKey || null,
      clientsCount: state.clients.length,
    });
  } catch (err) {
    res.status(502).json({ error: err.message || 'failed to read AmneziaWG state' });
  }
});

// --- Meta -------------------------------------------------------------------

app.get('/api/health', (req, res) => {
  res.json({ ok: true, time: new Date().toISOString() });
});

app.use((err, req, res, next) => {
  // eslint-disable-next-line no-unused-vars
  console.error(err);
  res.status(500).json({ error: 'internal error' });
});

app.listen(PORT, () => {
  console.log(`Amnezia Control Panel running on http://localhost:${PORT}`);
});
