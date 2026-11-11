'use strict';

const { runCommand } = require('./ssh');
const {
  parseDockerPs,
  isWgLike,
  isAmneziaContainer,
  isMtprotoContainer,
  parseTgProxyLinks,
  parseSecretTokens,
  extractMtprotoPort,
  buildTgLinks,
  parseWgDump,
  isPeerOnline,
  parseWgConfigNames,
  parseClientsTable,
  parseOpenVpnStatus,
  normalizeIp,
} = require('./parsers');

const CONTAINER_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/;
// How many log lines/entries to show per client.
const CLIENT_LOG_LIMIT = 10;
// Max raw log lines to fetch from a container (keeps the tail bounded).
const DOCKER_LOG_TAIL = 2000;

/**
 * Collect the full status of one VPN server: containers and their clients.
 */
async function collectServerStatus(server) {
  const startedAt = Date.now();

  const ps = await runCommand(server, "docker ps -a --format '{{json .}}'");
  if (ps.code !== 0 && !ps.stdout.trim()) {
    throw new Error(ps.stderr.trim() || `docker ps failed with code ${ps.code}`);
  }
  const allContainers = parseDockerPs(ps.stdout);
  // Two independent groups are monitored: Amnezia VPN containers and Telegram
  // MTProto proxies. Foreign VPN stacks and unrelated images are ignored.
  const containers = allContainers.filter(isAmneziaContainer);
  const mtprotoContainers = allContainers.filter(isMtprotoContainer);

  const vpnContainers = containers.filter((c) => isWgLike(c.type) || c.type === 'OpenVPN' || c.type === 'OpenVPN Cloak');

  let execOutput = '';
  if (vpnContainers.length > 0) {
    const script = buildCollectScript(vpnContainers);
    const res = await runCommand(server, script);
    execOutput = res.stdout;
  }

  const sections = splitSections(execOutput);
  const clientsByContainer = {};

  for (const container of containers) {
    let clients = [];

    if (isWgLike(container.type)) {
      const dump = sections.peers[container.name] || '';
      const conf = sections.conf[container.name] || '';
      const table = sections.clients[container.name] || '';
      clients = buildWgClients(dump, conf, table);
    } else if (container.type === 'OpenVPN' || container.type === 'OpenVPN Cloak') {
      const status = sections.ovpn[container.name] || '';
      clients = buildOpenVpnClients(status);
    }

    clientsByContainer[container.name] = clients;
  }

  const withClients = containers.map((c) => {
    const clients = clientsByContainer[c.name] || [];
    return {
      ...c,
      clients,
      clientCount: clients.length,
      onlineCount: clients.filter((cl) => cl.online).length,
    };
  });

  const allClients = withClients.flatMap((c) =>
    c.clients.map((cl) => ({ ...cl, container: c.name, vpnType: c.type })),
  );

  let mtproto = [];
  if (mtprotoContainers.length > 0) {
    mtproto = await collectMtprotoProxies(server, mtprotoContainers);
  }

  // AmneziaWG containers only — used by the UI to offer the "install" action
  // when the protocol is missing on the server.
  const awgContainers = containers.filter(isAwgContainer);

  return {
    serverId: server.id,
    serverName: server.name,
    host: `${server.host}:${server.port}`,
    collectedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    summary: {
      containersTotal: withClients.length,
      containersRunning: withClients.filter((c) => c.running).length,
      clientsTotal: allClients.length,
      clientsOnline: allClients.filter((c) => c.online).length,
      mtprotoTotal: mtproto.length,
      mtprotoRunning: mtproto.filter((m) => m.running).length,
      mtprotoKeysTotal: mtproto.reduce((sum, m) => sum + m.keys.length, 0),
      awgTotal: awgContainers.length,
      hasAwgContainer: awgContainers.length > 0,
    },
    containers: withClients,
    mtprotoContainers: mtproto,
  };
}

/**
 * Whether a container belongs to the AmneziaWG protocol (the container the
 * panel can install/manage). Plain WireGuard is deliberately excluded.
 */
function isAwgContainer(container) {
  const haystack = `${(container && container.name) || ''} ${(container && container.image) || ''}`.toLowerCase();
  if (/amneziawg/.test(haystack)) return true;
  if (/(^|[^a-z])awg([^a-z]|$)/.test(haystack)) return true;
  return container && container.type === 'AmneziaWG';
}

/**
 * Collect Telegram MTProto proxies and their generated keys. Keys come from
 * the container's `SECRET` env var, from `t.me/proxy` links / `secret:` lines
 * printed in the logs, and from a `telemt.toml` `[access.users]` section.
 */
async function collectMtprotoProxies(server, containers) {
  const script = buildMtprotoScript(containers);
  const res = await runCommand(server, script, { timeout: 40000 });
  const sections = splitSections(res.stdout, { ENV: 'env', PORTS: 'ports', LOGS: 'logs', TELEMT: 'telemt' });

  const telemtUsers = parseTelemtUsers((sections.telemt && sections.telemt.toml) || '');

  return containers.map((c) => {
    const env = parseEnvJson(sections.env[c.name] || '');
    const logs = sections.logs[c.name] || '';
    const portsRaw = sections.ports[c.name] || '';

    const secrets = new Map();
    if (env.SECRET) {
      for (const s of env.SECRET.split(',').map((t) => t.trim()).filter(Boolean)) {
        secrets.set(s, 'env');
      }
    }
    const links = parseTgProxyLinks(logs);
    for (const l of links) if (!secrets.has(l.secret)) secrets.set(l.secret, 'log');
    for (const s of parseSecretTokens(logs)) if (!secrets.has(s)) secrets.set(s, 'log');

    // Attach keys from a telemt.toml only to the matching container.
    if (/telemt/i.test(`${c.name} ${c.image}`)) {
      for (const u of telemtUsers) {
        if (!secrets.has(u.secret)) secrets.set(u.secret, `telemt:${u.name}`);
      }
    }

    // Prefer the port the proxy advertises in its own t.me links, since the
    // container env `PORT` may be an external/mapped value.
    const port =
      (links[0] && links[0].port) ||
      extractMtprotoPort(logs) ||
      Number(env.PORT) ||
      portFromPortsJson(portsRaw) ||
      null;

    const keys = [...secrets.entries()].map(([secret, source]) => {
      const built = port ? buildTgLinks(server.host, port, secret) : { link: null, tgLink: null };
      return { secret, source, link: built.link, tgLink: built.tgLink };
    });

    return {
      name: c.name,
      image: c.image,
      state: c.state,
      status: c.status,
      running: c.running,
      domain: env.DOMAIN || null,
      port,
      keys,
    };
  });
}

function buildMtprotoScript(containers) {
  const lines = ['set +e'];
  for (const c of containers) {
    if (!CONTAINER_NAME_RE.test(c.name)) continue;
    const name = c.name;
    lines.push(`echo "###ENV ${name}"`);
    lines.push(`docker inspect ${name} --format '{{json .Config.Env}}' 2>/dev/null`);
    lines.push(`echo "###PORTS ${name}"`);
    lines.push(`docker inspect ${name} --format '{{json .NetworkSettings.Ports}}' 2>/dev/null`);
    lines.push(`echo "###LOGS ${name}"`);
    lines.push(`docker logs --tail 300 ${name} 2>&1`);
  }
  lines.push('echo "###TELEMT toml"');
  lines.push('cat /root/mtproxy-data/*.toml 2>/dev/null');
  return lines.join('\n');
}

function parseEnvJson(text) {
  const out = {};
  let arr;
  try {
    arr = JSON.parse(String(text).trim());
  } catch (_) {
    return out;
  }
  if (!Array.isArray(arr)) return out;
  for (const item of arr) {
    const str = String(item);
    const i = str.indexOf('=');
    if (i === -1) continue;
    out[str.slice(0, i).toUpperCase()] = str.slice(i + 1);
  }
  return out;
}

function parseTelemtUsers(text) {
  const users = [];
  let inUsers = false;
  for (const line of String(text).split(/\r?\n/)) {
    const t = line.trim();
    if (t.startsWith('[')) {
      inUsers = t.toLowerCase() === '[access.users]';
      continue;
    }
    if (!inUsers || !t || t.startsWith('#')) continue;
    const eq = t.indexOf('=');
    if (eq === -1) continue;
    const name = t.slice(0, eq).trim();
    const secret = t.slice(eq + 1).trim().replace(/^["']|["']$/g, '');
    if (name && secret) users.push({ name, secret });
  }
  return users;
}

function portFromPortsJson(text) {
  let obj;
  try {
    obj = JSON.parse(String(text).trim());
  } catch (_) {
    return null;
  }
  for (const key of Object.keys(obj || {})) {
    const m = key.match(/^(\d+)\//);
    if (m) return Number(m[1]);
  }
  return null;
}

function buildCollectScript(containers) {
  const lines = ['set +e'];
  for (const c of containers) {
    if (!CONTAINER_NAME_RE.test(c.name)) continue;
    const name = c.name;
    if (isWgLike(c.type)) {
      lines.push(`echo "###PEERS ${name}"`);
      lines.push(`docker exec ${name} sh -c 'awg show all dump 2>/dev/null || wg show all dump 2>/dev/null' 2>/dev/null`);
      lines.push(`echo "###CONF ${name}"`);
      lines.push(`docker exec ${name} sh -c 'cat /opt/amnezia/awg/wg0.conf /etc/wireguard/*.conf 2>/dev/null' 2>/dev/null`);
      lines.push(`echo "###CLIENTS ${name}"`);
      lines.push(`docker exec ${name} sh -c 'cat /opt/amnezia/awg/clientsTable 2>/dev/null' 2>/dev/null`);
    } else if (c.type === 'OpenVPN' || c.type === 'OpenVPN Cloak') {
      lines.push(`echo "###OVPN ${name}"`);
      lines.push(`docker exec ${name} sh -c 'cat /etc/openvpn/openvpn-status.log /etc/openvpn/log/openvpn-status.log 2>/dev/null' 2>/dev/null`);
    }
  }
  return lines.join('\n');
}

function splitSections(text, keyMap) {
  const map = keyMap || { PEERS: 'peers', CONF: 'conf', CLIENTS: 'clients', OVPN: 'ovpn' };
  const result = {};
  for (const key of Object.values(map)) result[key] = {};

  let currentKey = null;
  let currentName = null;
  const buffers = {};

  for (const line of String(text).split(/\r?\n/)) {
    const m = line.match(/^###([A-Z]+)\s+(\S+)\s*$/);
    if (m) {
      const key = map[m[1]];
      if (key) {
        currentKey = key;
        currentName = m[2];
        buffers[`${key}:${currentName}`] = [];
      } else {
        currentKey = null;
      }
      continue;
    }
    if (currentKey && currentName) {
      buffers[`${currentKey}:${currentName}`].push(line);
    }
  }

  for (const [compound, lines] of Object.entries(buffers)) {
    const idx = compound.indexOf(':');
    const key = compound.slice(0, idx);
    const name = compound.slice(idx + 1);
    result[key][name] = lines.join('\n');
  }

  return result;
}

function buildWgClients(dumpText, confText, tableText) {
  const { peers } = parseWgDump(dumpText);
  const namesFromConf = parseWgConfigNames(confText);
  const namesFromTable = parseClientsTable(tableText);

  const now = Date.now();
  return peers.map((peer, i) => {
    const name =
      namesFromConf.byPubkey[peer.publicKey] ||
      namesFromTable.byPubkey[peer.publicKey] ||
      matchByIp(peer.allowedIps, namesFromConf.byIp, namesFromTable.byIp) ||
      `peer-${i + 1}`;

    return {
      // Stable identifier: the full public key is unique per client and never
      // changes, unlike the display name or the client's current endpoint.
      id: peer.publicKey || `peer-${i + 1}`,
      name,
      publicKey: shortKey(peer.publicKey),
      publicKeyFull: peer.publicKey || null,
      endpoint: peer.endpoint,
      allowedIps: peer.allowedIps,
      latestHandshake: peer.latestHandshake,
      lastSeen: peer.latestHandshake ? new Date(peer.latestHandshake * 1000).toISOString() : null,
      rx: peer.rx,
      tx: peer.tx,
      online: isPeerOnline(peer, now),
    };
  });
}

function matchByIp(allowedIps, ...maps) {
  for (const ip of allowedIps) {
    const key = normalizeIp(ip);
    for (const map of maps) {
      if (map[key]) return map[key];
    }
  }
  return null;
}

function buildOpenVpnClients(statusText) {
  return parseOpenVpnStatus(statusText).map((c) => ({
    // OpenVPN clients have no public key; the common name is their stable id.
    id: c.name,
    name: c.name,
    publicKey: null,
    publicKeyFull: null,
    endpoint: c.realAddress,
    allowedIps: [],
    latestHandshake: 0,
    lastSeen: c.connectedSince || null,
    rx: c.bytesReceived,
    tx: c.bytesSent,
    online: true,
  }));
}

function shortKey(key) {
  if (!key) return null;
  return key.length > 16 ? `${key.slice(0, 8)}…${key.slice(-6)}` : key;
}

/**
 * Fetch the last log entries of one client from its container.
 *
 * AmneziaWG / WireGuard containers log handshakes and packet traffic with the
 * peer endpoint (IP:port) in each line, so we tail the container logs and keep
 * only the lines that mention this client — matched by endpoint and/or name.
 */
async function collectClientLogs(server, { container, endpoint, name } = {}) {
  if (!container || !CONTAINER_NAME_RE.test(container)) {
    throw new Error('valid container name is required');
  }

  const terms = [endpoint, name]
    .filter((t) => typeof t === 'string' && t.trim())
    .map((t) => t.trim());

  const baseCmd = `docker logs --tail ${DOCKER_LOG_TAIL} ${container} 2>&1`;
  const cmd = terms.length
    ? `${baseCmd} | grep -F ${terms.map((t) => `-e '${escapeSingleQuotes(t)}'`).join(' ')} | tail -n ${CLIENT_LOG_LIMIT * 3}`
    : baseCmd;

  const res = await runCommand(server, cmd);
  // A non-zero exit code from grep just means "no matches".
  if (res.code !== 0 && !res.stdout.trim() && res.stderr.trim() && res.code !== 1) {
    throw new Error(res.stderr.trim());
  }

  const lines = res.stdout.split(/\r?\n/).filter((l) => l.trim());

  return {
    container,
    endpoint: endpoint || null,
    name: name || null,
    count: Math.min(lines.length, CLIENT_LOG_LIMIT),
    entries: lines.slice(-CLIENT_LOG_LIMIT),
  };
}

function escapeSingleQuotes(value) {
  return String(value).replace(/'/g, "'\\''");
}

module.exports = { collectServerStatus, collectClientLogs };
