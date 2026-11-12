'use strict';

const path = require('path');

// Load variables from a local .env file (PORT, etc.) if present.
// The path is resolved against the project root (not the current working
// directory) so it also works when started via systemd/pm2/docker.
// Must run before any other module reads process.env.
require('dotenv').config({ path: path.join(__dirname, '.env') });
const express = require('express');

const store = require('./src/store');
const { collectServerStatus, collectClientLogs } = require('./src/collect');
const history = require('./src/history');
const { pingHost } = require('./src/ping');
const { installAwgContainer, getAwgShare, getAwgState } = require('./src/awg');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '256kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// --- Servers CRUD -----------------------------------------------------------

app.get('/api/servers', (req, res) => {
  res.json(store.listServers().map(store.toPublic));
});

// Ping an arbitrary host (used to preview latency before a server is added).
// Registered before `/api/servers/:id/...` so "ping" is not read as an id.
app.get('/api/servers/ping', async (req, res) => {
  const host = (req.query && req.query.host) || '';
  if (!host) return res.status(400).json({ error: 'host is required' });
  try {
    const result = await pingHost(String(host), { count: Number(req.query.count) || 4 });
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: err.message || 'ping failed' });
  }
});

app.post('/api/servers', (req, res) => {
  const { name, host, port, username, authType, password, privateKey, passphrase } = req.body || {};

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
  });
  res.status(201).json(store.toPublic(server));
});

app.put('/api/servers/:id', (req, res) => {
  const updated = store.updateServer(req.params.id, req.body || {});
  if (!updated) return res.status(404).json({ error: 'server not found' });
  res.json(store.toPublic(updated));
});

app.delete('/api/servers/:id', (req, res) => {
  const ok = store.removeServer(req.params.id);
  if (!ok) return res.status(404).json({ error: 'server not found' });
  history.clearServer(req.params.id);
  res.status(204).end();
});

// --- Ping -------------------------------------------------------------------

app.get('/api/servers/:id/ping', async (req, res) => {
  const server = store.getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'server not found' });

  try {
    const result = await pingHost(server.host, { count: Number(req.query.count) || 4 });
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: err.message || 'ping failed' });
  }
});

// --- Status -----------------------------------------------------------------

app.get('/api/servers/:id/status', async (req, res) => {
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

// --- Client activity --------------------------------------------------------

app.get('/api/servers/:id/logs', async (req, res) => {
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
app.post('/api/servers/:id/install-awg', async (req, res) => {
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
// mirroring the app's "Share" action. Fetched on demand so credentials are not
// returned by the periodic status refresh.
app.get('/api/servers/:id/awg/config', async (req, res) => {
  const server = store.getServer(req.params.id);
  if (!server) return res.status(404).json({ error: 'server not found' });

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

// Lightweight AWG state (obfuscation params + server public key), used to
// populate the install dialog defaults.
app.get('/api/servers/:id/awg/state', async (req, res) => {
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
