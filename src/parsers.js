'use strict';

// A peer is considered online if its latest handshake happened within this window.
const ONLINE_WINDOW_MS = 180 * 1000;

/**
 * Parse `docker ps -a --format '{{json .}}'` output (one JSON object per line).
 */
function parseDockerPs(text) {
  const containers = [];
  for (const line of String(text).split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed[0] !== '{') continue;
    try {
      const c = JSON.parse(trimmed);
      containers.push({
        id: (c.ID || '').slice(0, 12),
        name: c.Names || '',
        image: c.Image || '',
        state: c.State || '',
        status: c.Status || '',
        ports: c.Ports || '',
        type: classifyVpnType(`${c.Names || ''} ${c.Image || ''}`),
        running: (c.State || '').toLowerCase() === 'running',
      });
    } catch (_) {
      /* skip malformed line */
    }
  }
  return containers;
}

function classifyVpnType(haystack) {
  const s = haystack.toLowerCase();
  if (s.includes('amneziawg') || /(^|[^a-z])awg([^a-z]|$)/.test(s)) return 'AmneziaWG';
  if (s.includes('wireguard')) return 'WireGuard';
  if (s.includes('cloak')) return 'OpenVPN Cloak';
  if (s.includes('openvpn')) return 'OpenVPN';
  if (s.includes('shadowsocks')) return 'Shadowsocks';
  if (s.includes('xray')) return 'Xray';
  if (s.includes('amnezia')) return 'Amnezia';
  return 'other';
}

function isWgLike(type) {
  return type === 'AmneziaWG' || type === 'WireGuard';
}

// Non-Amnezia VPN stacks that may be installed on the same server.
const FOREIGN_VPN_RE = /wireguard|openvpn|shadowsocks|xray|v2ray|outline|openconnect|ipsec|strongswan|softether|sing-box|singbox|tor|socks|trojan|ocserv|pptp|l2tp|hysteria|naive|warp|zerotier|tailscale|clash|v2raya/;
// Amnezia fingerprints: container/image names or the AmneziaWG protocol.
const AMNEZIA_RE = /(^|[^a-z])amnezia|amneziawg|(^|[^a-z])awg([^a-z]|$)/;

/**
 * Decide whether a `docker ps` entry belongs to Amnezia. Only such containers
 * are interesting for monitoring; foreign VPN stacks and unrelated images
 * (nginx, databases, ...) are ignored.
 */
function isAmneziaContainer(container) {
  const name = (container && container.name) || '';
  const image = (container && container.image) || '';
  const haystack = `${name} ${image}`.toLowerCase();

  if (AMNEZIA_RE.test(haystack)) return true;
  // AmneziaWG protocol in the name/image, even without the "amnezia" prefix.
  if (isWgLike(classifyVpnType(haystack)) && !FOREIGN_VPN_RE.test(haystack)) return true;
  return false;
}

// --- MTProto (Telegram) proxies ---------------------------------------------

// Container/image fingerprints for Telegram MTProto proxies:
//   telegrammessenger/proxy (official), seriyps/mtproto-proxy (Erlang), mtg, telemt...
const MT_PROTO_RE = /mtproto|mtproxy|(^|[^a-z])mtg([^a-z]|$)|telegrammessenger|telemt/;

function isMtprotoContainer(container) {
  const name = (container && container.name) || '';
  const image = (container && container.image) || '';
  return MT_PROTO_RE.test(`${name} ${image}`.toLowerCase());
}

/**
 * Extract `https://t.me/proxy?...` links that MTProto proxies print on start.
 * Returns an array of { server, port, secret, url }.
 */
function parseTgProxyLinks(text) {
  const links = [];
  const re = /https?:\/\/t\.me\/proxy\?([^\s"'<>]+)/gi;
  let m;
  while ((m = re.exec(String(text)))) {
    const params = {};
    for (const pair of m[1].split('&')) {
      const i = pair.indexOf('=');
      if (i === -1) continue;
      params[pair.slice(0, i).toLowerCase()] = decodeURIComponent(pair.slice(i + 1));
    }
    if (params.secret) {
      links.push({
        server: params.server || null,
        port: Number(params.port) || null,
        secret: params.secret,
        url: m[0],
      });
    }
  }
  return links;
}

/**
 * Extract MTProto secret tokens from arbitrary text. Matches `secret=...` /
 * `SECRET=...` env lines and `with secret: ...` log lines.
 */
function parseSecretTokens(text) {
  const secrets = new Set();
  const re = /secret["']?\s*[=:]\s*["']?([A-Za-z0-9+/=_-]{16,})/gi;
  let m;
  while ((m = re.exec(String(text)))) secrets.add(m[1]);
  return [...secrets];
}

/** Try to read the listening port from env (`PORT=`) or a log line. */
function extractMtprotoPort(text) {
  const s = String(text);
  let m = s.match(/started on [0-9a-fA-F.:[\]]*?:(\d{2,5})/i);
  if (m) return Number(m[1]);
  m = s.match(/port["']?\s*[=:]\s*["']?(\d{2,5})/i);
  if (m) return Number(m[1]);
  return null;
}

/** Build `t.me` / `tg://` links for one secret. */
function buildTgLinks(host, port, secret) {
  const q = `server=${encodeURIComponent(host)}&port=${port}&secret=${encodeURIComponent(secret)}`;
  return { link: `https://t.me/proxy?${q}`, tgLink: `tg://proxy?${q}` };
}

/**
 * Parse `wg show all dump` / `awg show all dump`.
 * With `all`, every line is prefixed with the interface name:
 *   interface: name privkey pubkey port fwmark                       (5 fields)
 *   peer:      name pubkey psk endpoint allowedips handshake rx tx ka (9 fields)
 */
function parseWgDump(text) {
  const interfaces = [];
  const peers = [];

  for (const line of String(text).split(/\r?\n/)) {
    const raw = line.trim();
    if (!raw) continue;
    const parts = raw.split('\t');
    if (parts.length === 0) continue;

    // Peer rows are exactly 9 fields (with interface prefix) or 8 (without).
    // AmneziaWG appends extra obfuscation fields, so the interface row is much
    // longer (>= 10 fields) and must NOT be mistaken for a peer.
    if (parts.length === 9) {
      peers.push(buildPeer(parts[0], parts.slice(1)));
    } else if (parts.length === 8) {
      peers.push(buildPeer('wg0', parts));
    } else if (parts.length === 5) {
      interfaces.push(buildInterface(parts));
    } else if (parts.length === 4) {
      interfaces.push(buildInterface(['wg0', ...parts]));
    } else if (parts.length >= 10) {
      // AmneziaWG interface line: name privkey pubkey port fwmark <obfuscation...>
      interfaces.push(buildInterface([parts[0], parts[1], parts[2], parts[3]]));
    }
  }

  return { interfaces, peers };
}

function buildPeer(iface, f) {
  const [publicKey, psk, endpoint, allowedIps, handshake, rx, tx, keepalive] = f;
  return {
    interface: iface,
    publicKey: publicKey || '',
    endpoint: !endpoint || endpoint === '(none)' ? null : endpoint,
    allowedIps: (allowedIps || '').split(',').map((s) => s.trim()).filter(Boolean),
    latestHandshake: Number(handshake) || 0,
    rx: Number(rx) || 0,
    tx: Number(tx) || 0,
    keepalive: Number(keepalive) || 0,
  };
}

function buildInterface(f) {
  const [name, , publicKey, port] = f;
  return { name, publicKey: publicKey || '', port: Number(port) || 0 };
}

function isPeerOnline(peer, now = Date.now()) {
  if (!peer.latestHandshake) return false;
  return now - peer.latestHandshake * 1000 < ONLINE_WINDOW_MS;
}

/**
 * Parse a wg/awg `.conf` file: map peer PublicKey -> name (from `#` comments)
 * and peer AllowedIPs -> name.
 */
function parseWgConfigNames(text) {
  const byPubkey = {};
  const byIp = {};

  let block = null;
  const blocks = [];
  for (const line of String(text).split(/\r?\n/)) {
    const t = line.trim();
    if (!t) continue;
    if (t.startsWith('[') && t.endsWith(']')) {
      if (block) blocks.push(block);
      block = { type: t.slice(1, -1).toLowerCase(), comments: [], fields: {} };
      continue;
    }
    if (!block) continue;
    if (t.startsWith('#')) {
      block.comments.push(t.replace(/^#+\s*/, '').trim());
      continue;
    }
    const eq = t.indexOf('=');
    if (eq === -1) continue;
    const key = t.slice(0, eq).trim().toLowerCase();
    const val = t.slice(eq + 1).trim();
    if (!block.fields[key]) block.fields[key] = val;
  }
  if (block) blocks.push(block);

  for (const b of blocks) {
    if (b.type !== 'peer') continue;
    const name = b.comments.join(' ').trim() || null;
    const pubkey = b.fields.publickey;
    if (name && pubkey) byPubkey[pubkey] = name;
    if (name && b.fields.allowedips) {
      for (const ip of b.fields.allowedips.split(',')) {
        const key = normalizeIp(ip);
        if (key) byIp[key] = name;
      }
    }
  }

  return { byPubkey, byIp };
}

/**
 * Parse an Amnezia `clientsTable` JSON file. The exact shape varies between
 * protocol versions, so this is intentionally tolerant. Returns maps that
 * allow matching dump peers to human client names.
 */
function parseClientsTable(text) {
  const byIp = {};
  const byPubkey = {};
  const names = [];

  let data;
  try {
    data = JSON.parse(String(text).trim());
  } catch (_) {
    return { byIp, byPubkey, names };
  }

  let entries = [];
  if (Array.isArray(data)) entries = data;
  else if (data && typeof data === 'object') entries = Object.values(data);
  else return { byIp, byPubkey, names };

  for (const entry of entries) {
    if (!entry || typeof entry !== 'object') continue;
    const name =
      (entry.userData && entry.userData.clientName) ||
      entry.clientName ||
      entry.name ||
      entry.comment ||
      null;

    const configPart = typeof entry.configPart === 'string' ? entry.configPart : '';
    const addressMatch = configPart.match(/Address\s*=\s*([0-9a-fA-F.:]+\/\d+)/);
    const pubkeyMatch = configPart.match(/PublicKey\s*=\s*([A-Za-z0-9+/=]+)/);

    if (name) names.push(name);
    if (name && addressMatch) {
      const key = normalizeIp(addressMatch[1]);
      if (key) byIp[key] = name;
    }
    if (name && pubkeyMatch) byPubkey[pubkeyMatch[1]] = name;
  }

  return { byIp, byPubkey, names };
}

function normalizeIp(value) {
  if (!value) return '';
  return value.split('/')[0].trim();
}

/**
 * Parse an OpenVPN status log (v1) CLIENT_LIST section.
 */
function parseOpenVpnStatus(text) {
  const clients = [];
  const lines = String(text).split(/\r?\n/);
  let inList = false;

  for (const line of lines) {
    if (/^Common Name,/.test(line)) {
      inList = true;
      continue;
    }
    if (inList && !line.trim()) break;
    if (inList && /^ROUTING TABLE|^GLOBAL STATS|^END/.test(line)) {
      inList = false;
      continue;
    }
    if (!inList) continue;

    const cols = line.split(',');
    if (cols.length < 6) continue;
    clients.push({
      name: cols[0],
      realAddress: cols[1],
      bytesReceived: Number(cols[2]) || 0,
      bytesSent: Number(cols[3]) || 0,
      connectedSince: cols[4] || '',
    });
  }

  return clients;
}

module.exports = {
  ONLINE_WINDOW_MS,
  parseDockerPs,
  classifyVpnType,
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
};
