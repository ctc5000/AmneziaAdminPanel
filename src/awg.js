'use strict';

/**
 * AmneziaWG support: install the `amnezia-awg` container on a remote server and
 * build the same connection payloads the official Amnezia client produces when
 * the "Share" button is pressed.
 *
 * The share format was reverse-engineered from amnezia-client:
 *   vpn://<base64url(qCompress(utf8(JSON), level=8))>   (trailing '=' omitted)
 * where `qCompress` prepends a 4-byte big-endian uncompressed length to a zlib
 * (deflate) stream. The JSON mirrors SelfHostedAdminServerConfig::toJson():
 *
 *   {
 *     "format_version": 1,
 *     "hostName": "<server ip>",
 *     "containers": [ { "container": "amnezia-awg",
 *                       "awg": { ...server obfuscation params...,
 *                                "last_config": "<compact client config json>" } } ],
 *     "defaultContainer": "amnezia-awg",
 *     "dns1": "1.1.1.1", "dns2": "1.0.0.1"
 *   }
 *
 * All remote commands are constant strings built here from validated inputs
 * (container name and numeric port) — never raw user input.
 */

const zlib = require('zlib');
const { runCommand } = require('./ssh');

// --- Constants (mirror client/core/utils/constants/protocolConstants.h) -----

const AWG_IMAGE = 'amneziavpn/amnezia-wg:latest';
const AWG_CONTAINER = 'amnezia-awg';
const AWG_VOLUME = 'amnezia-awg-data';
const AWG_CONFIG_DIR = '/opt/amnezia/awg';
const AWG_CONF_PATH = `${AWG_CONFIG_DIR}/awg0.conf`;
const AWG_SERVER_PUBKEY_PATH = `${AWG_CONFIG_DIR}/wireguard_server_public_key.key`;
const AWG_PSK_PATH = `${AWG_CONFIG_DIR}/wireguard_psk.key`;
const AWG_CLIENTS_TABLE_PATH = `${AWG_CONFIG_DIR}/clientsTable`;

const AWG_DEFAULT_PORT = 55424;
const DEFAULT_SUBNET = '10.8.1.0';
const DEFAULT_CIDR = '24';
const DEFAULT_DNS1 = '1.1.1.1';
const DEFAULT_DNS2 = '1.0.0.1';
// Amnezia desktop defaults (see protocols::awg / wireguard constants).
const DESKTOP_MTU = '1376';
const DEFAULT_KEEPALIVE = '25';
const AWG3_KEEPALIVE = '25-35';

// Ordered obfuscation keys as they appear in the `.conf` template / JSON.
const OBFUSCATION_KEYS = [
  'Jc', 'Jmin', 'Jmax',
  'S1', 'S2', 'S3', 'S4',
  'H1', 'H2', 'H3', 'H4',
  'I1', 'I2', 'I3', 'I4', 'I5',
  'HeaderProtectionKey', 'ContentPaddingAddition',
  'RekeyAfterTime', 'RekeyTimeout', 'RejectAfterTime',
  'KeepaliveTimeout', 'MaxHandshakeAttempts',
  'RandomTrailers', 'DisableCookies',
];

// AWG v3 markers (see AwgProtocolConfig::hasAwg3Markers).
const AWG3_KEYS = [
  'HeaderProtectionKey', 'ContentPaddingAddition',
  'RekeyAfterTime', 'RekeyTimeout', 'RejectAfterTime',
  'KeepaliveTimeout', 'MaxHandshakeAttempts',
];

const CONTAINER_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/;

// --- Encoding helpers -------------------------------------------------------

/** Reproduce Qt's qCompress(level 8): 4-byte BE size header + zlib deflate. */
function qCompress(buf, level = 8) {
  const deflated = zlib.deflateSync(buf, { level });
  const header = Buffer.alloc(4);
  header.writeUInt32BE(buf.length >>> 0, 0);
  return Buffer.concat([header, deflated]);
}

function base64Url(buffer) {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/** Build the `vpn://` share link that the Amnezia app can import. */
function buildVpnLink(serverJson) {
  const json = Buffer.from(JSON.stringify(serverJson), 'utf8');
  return `vpn://${base64Url(qCompress(json, 8))}`;
}

// --- Native config assembly -------------------------------------------------

/**
 * Build the client `.conf` file (same layout as server_scripts/awg/template.conf)
 * from the collected Interface obfuscation params and per-client values.
 */
function buildNativeClientConfig({ obf, clientIp, clientPrivKey, serverPubKey, psk, host, port, dns1, dns2, keepalive }) {
  const lines = ['[Interface]'];
  lines.push(`Address = ${clientIp}/32`);
  if (dns1 || dns2) {
    lines.push(`DNS = ${[dns1, dns2].filter(Boolean).join(', ')}`);
  }
  lines.push(`PrivateKey = ${clientPrivKey}`);
  for (const key of OBFUSCATION_KEYS) {
    const value = obf[key];
    if (value !== undefined && value !== null && String(value).trim() !== '') {
      lines.push(`${key} = ${value}`);
    }
  }
  lines.push('');
  lines.push('[Peer]');
  lines.push(`PublicKey = ${serverPubKey}`);
  if (psk) lines.push(`PresharedKey = ${psk}`);
  lines.push('AllowedIPs = 0.0.0.0/0, ::/0');
  lines.push(`Endpoint = ${host}:${port}`);
  if (keepalive) lines.push(`PersistentKeepalive = ${keepalive}`);
  return `${lines.join('\n')}\n`;
}

/** Build the AwgClientConfig JSON embedded as `last_config`. */
function buildClientJson({ nativeConfig, host, port, clientIp, clientPrivKey, clientPubKey, serverPubKey, psk, mtu, keepalive, obf }) {
  const obj = {
    config: nativeConfig,
    hostName: host,
    port: Number(port) || 0,
    client_ip: clientIp,
    client_priv_key: clientPrivKey,
    client_pub_key: clientPubKey,
    server_pub_key: serverPubKey,
  };
  if (psk) obj.psk_key = psk;
  if (clientPubKey) obj.clientId = clientPubKey;
  obj.allowed_ips = ['0.0.0.0/0', '::/0'];
  if (keepalive) obj.persistent_keep_alive = keepalive;
  if (mtu) obj.mtu = String(mtu);
  for (const key of OBFUSCATION_KEYS) {
    const value = obf[key];
    if (value !== undefined && value !== null && String(value).trim() !== '') {
      obj[key] = String(value);
    }
  }
  return obj;
}

/** Build the AwgServerConfig JSON for the `awg` container node. */
function buildServerConfigJson({ port, obf, subnetAddress, subnetCidr, isThirdPartyConfig }) {
  const obj = {
    port: String(port),
    transport_proto: 'udp',
  };
  if (subnetAddress) obj.subnet_address = subnetAddress;
  if (subnetCidr) obj.subnet_cidr = String(subnetCidr);
  for (const key of OBFUSCATION_KEYS) {
    const value = obf[key];
    // Server serialization always emits the special-junk keys (I1..I5).
    if (value !== undefined && value !== null && String(value).trim() !== '') {
      obj[key] = String(value);
    } else if (/^I[1-5]$/.test(key)) {
      obj[key] = '';
    }
  }
  if (isThirdPartyConfig) obj.isThirdPartyConfig = true;
  return obj;
}

/** Assemble the full SelfHostedAdminServerConfig JSON for the share link. */
function buildServerJson({ host, port, obf, subnetAddress, subnetCidr, clientJson, dns1, dns2 }) {
  const serverCfg = buildServerConfigJson({ port, obf, subnetAddress, subnetCidr });
  serverCfg.last_config = JSON.stringify(clientJson);
  const obj = {
    format_version: 1,
    hostName: host,
    containers: [
      {
        container: AWG_CONTAINER,
        awg: serverCfg,
      },
    ],
    defaultContainer: AWG_CONTAINER,
  };
  if (dns1) obj.dns1 = dns1;
  if (dns2) obj.dns2 = dns2;
  return obj;
}

// --- Parsers ----------------------------------------------------------------

/** Parse an `awg0.conf`-style file into ordered sections of key/value maps. */
function parseConfSections(text) {
  const sections = {};
  let current = null;
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const sec = line.match(/^\[(.+)]$/);
    if (sec) {
      current = sec[1].trim().toLowerCase();
      if (!sections[current]) sections[current] = [];
      continue;
    }
    if (!current) continue;
    const eq = line.indexOf('=');
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    const value = line.slice(eq + 1).trim();
    sections[current].push({ key, value });
  }
  return sections;
}

/** Extract the obfuscation params from an `[Interface]` section. */
function parseInterfaceObf(text) {
  const sections = parseConfSections(text);
  const iface = sections.interface || [];
  const byKey = {};
  for (const { key, value } of iface) byKey[key] = value;

  const obf = {};
  for (const key of OBFUSCATION_KEYS) {
    if (byKey[key] !== undefined) obf[key] = byKey[key];
  }
  return {
    obf,
    privateKey: byKey.PrivateKey || '',
    address: byKey.Address || '',
    listenPort: byKey.ListenPort || '',
  };
}

/** Parse `Address = 10.8.1.0/24` into { subnetAddress, subnetCidr }. */
function splitAddress(address) {
  const [addr, cidr] = String(address || '').split('/');
  return { subnetAddress: (addr || '').trim(), subnetCidr: (cidr || '').trim() };
}

/**
 * Parse the Amnezia `clientsTable` file. It stores one entry per generated
 * client with the full client `.conf` in `configPart`, which is exactly what
 * the Share feature needs (it contains the client's private key).
 */
function parseClientsTableEntries(text) {
  let data;
  try {
    data = JSON.parse(String(text).trim());
  } catch (_) {
    return [];
  }
  let entries = [];
  if (Array.isArray(data)) entries = data;
  else if (data && typeof data === 'object') {
    entries = Object.values(data);
  } else {
    return [];
  }

  return entries
    .filter((e) => e && typeof e === 'object')
    .map((e) => {
      const configPart = typeof e.configPart === 'string' ? e.configPart : (typeof e.config === 'string' ? e.config : '');
      const parsed = parseClientConf(configPart);
      const clientName =
        (e.userData && e.userData.clientName) ||
        e.clientName ||
        e.name ||
        e.comment ||
        null;
      return {
        clientId: e.clientId || e.id || parsed.publicKey || null,
        clientName,
        publicKey: parsed.publicKey,
        privateKey: parsed.privateKey,
        address: parsed.address,
        psk: parsed.psk,
        configPart,
      };
    });
}

/** Extract per-client values from a client `.conf` text. */
function parseClientConf(text) {
  const sections = parseConfSections(text);
  const iface = sections.interface || [];
  const peer = sections.peer || [];
  const iByKey = {};
  for (const { key, value } of iface) iByKey[key] = value;
  const pByKey = {};
  for (const { key, value } of peer) pByKey[key] = value;
  return {
    address: iByKey.Address || '',
    privateKey: iByKey.PrivateKey || '',
    psk: pByKey.PresharedKey || pByKey.PreSharedKey || '',
    publicKey: pByKey.PublicKey || '',
    serverPublicKey: pByKey.PublicKey || '',
  };
}

// --- Remote command builders ------------------------------------------------

function assertContainer(name) {
  if (!CONTAINER_NAME_RE.test(name)) {
    throw new Error('invalid container name');
  }
  return name;
}

function assertPort(port) {
  const n = Number(port);
  if (!Number.isInteger(n) || n < 1 || n > 65535) {
    throw new Error('invalid port');
  }
  return n;
}

function randomPort() {
  return 30000 + Math.floor(Math.random() * 20000);
}

/**
 * Read the server-side AWG wiring: Interface obfuscation params, server public
 * key, PSK and the clients table. Runs as one sectioned command.
 */
function buildReadStateScript(container) {
  const c = assertContainer(container);
  return [
    'set +e',
    `echo "###CONF"`,
    `docker exec ${c} cat ${AWG_CONF_PATH} 2>/dev/null`,
    `echo "###PUB"`,
    `docker exec ${c} cat ${AWG_SERVER_PUBKEY_PATH} 2>/dev/null`,
    `echo "###PSK"`,
    `docker exec ${c} cat ${AWG_PSK_PATH} 2>/dev/null`,
    `echo "###TABLE"`,
    `docker exec ${c} cat ${AWG_CLIENTS_TABLE_PATH} 2>/dev/null`,
  ].join('\n');
}

/**
 * Generate a fresh key pair and compute the next free client IP from the peer
 * AllowedIPs currently present in the config.
 */
function buildGenerateKeysScript(container) {
  const c = assertContainer(container);
  return [
    'set +e',
    `echo "###GENKEY"`,
    `docker exec ${c} sh -c 'P=$(awg genkey); echo $P; echo $P | awg pubkey' 2>/dev/null`,
    `echo "###CONF"`,
    `docker exec ${c} cat ${AWG_CONF_PATH} 2>/dev/null`,
  ].join('\n');
}

/** Append a new `[Peer]` block to `awg0.conf` and hot-reload the interface. */
function buildAddPeerScript(container, { publicKey, psk, clientIp, name }) {
  const c = assertContainer(container);
  if (!/^[A-Za-z0-9+/=]{40,45}$/.test(publicKey)) throw new Error('invalid client public key');
  if (psk && !/^[A-Za-z0-9+/=]{40,45}$/.test(psk)) throw new Error('invalid psk');
  if (!/^[0-9a-fA-F.:]+$/.test(clientIp)) throw new Error('invalid client ip');
  const safeName = String(name || 'client').replace(/[^A-Za-z0-9 _.-]/g, '').slice(0, 64) || 'client';

  const peer = [
    '[Peer]',
    `# ${safeName}`,
    `PublicKey = ${publicKey}`,
    ...(psk ? [`PresharedKey = ${psk}`] : []),
    `AllowedIPs = ${clientIp}/32`,
    '',
  ].join('\n');

  // Write the peer block to the config, then re-apply the whole config.
  return [
    'set +e',
    `docker exec -i ${c} sh -c 'cat >> ${AWG_CONF_PATH}' <<'AWGPEEREOF'`,
    peer,
    'AWGPEEREOF',
    `docker exec ${c} bash -c 'awg syncconf awg0 <(awg-quick strip ${AWG_CONF_PATH})' 2>&1`,
    'echo "###DONE"',
  ].join('\n');
}

// --- Public API -------------------------------------------------------------

/**
 * Install the AmneziaWG container on a server.
 *
 * Creates a named volume holding the generated config, writes the awg0.conf and
 * the container start script, then launches the container with the same flags
 * as the official `server_scripts/awg/run_container.sh`.
 */
async function installAwgContainer(server, options = {}) {
  const container = assertContainer(options.container || AWG_CONTAINER);
  const port = options.port ? assertPort(options.port) : (options.port === 0 ? 0 : randomPort());
  const listenPort = port || AWG_DEFAULT_PORT;
  const subnet = String(options.subnet || DEFAULT_SUBNET).replace(/[^0-9.]/g, '');
  const cidr = String(options.cidr || DEFAULT_CIDR).replace(/[^0-9]/g, '') || DEFAULT_CIDR;

  const script = buildInstallScript({ container, listenPort, subnet, cidr });
  const res = await runCommand(server, script, { timeout: 300000 });

  if (!/###INSTALL_OK/.test(res.stdout)) {
    const detail = res.stderr.trim() || res.stdout.trim() || `exit code ${res.code}`;
    throw new Error(`installation failed: ${tail(detail, 800)}`);
  }

  // Read back the generated public key/port so the caller can show a summary.
  const state = await getAwgState(server, container).catch(() => null);

  return {
    container,
    image: AWG_IMAGE,
    port: listenPort,
    subnet: `${subnet}/${cidr}`,
    serverPublicKey: state ? state.serverPublicKey : null,
  };
}

function buildInstallScript({ container, listenPort, subnet, cidr }) {
  const c = assertContainer(container);
  const p = assertPort(listenPort);

  // The start script lives inside the same volume that holds the config, so the
  // published image's placeholder entrypoint can be replaced safely.
  const startScript = [
    '#!/bin/bash',
    `awg-quick down ${AWG_CONF_PATH} 2>/dev/null`,
    `awg-quick up ${AWG_CONF_PATH}`,
    'iptables -A INPUT -i awg0 -j ACCEPT',
    'iptables -A FORWARD -i awg0 -j ACCEPT',
    'iptables -A OUTPUT -o awg0 -j ACCEPT',
    'iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT',
    `iptables -t nat -A POSTROUTING -s ${subnet}/${cidr} -o eth0 -j MASQUERADE`,
    `iptables -t nat -A POSTROUTING -s ${subnet}/${cidr} -o eth1 -j MASQUERADE`,
    'tail -f /dev/null',
    '',
  ].join('\n');

  return [
    'set +e',
    'echo "###STEP pull"',
    `docker pull ${AWG_IMAGE}`,
    `if [ $? -ne 0 ]; then echo "###INSTALL_FAIL pull"; exit 1; fi`,

    'echo "###STEP configure"',
    `docker volume create ${AWG_VOLUME} >/dev/null`,
    `docker run --rm -v ${AWG_VOLUME}:${AWG_CONFIG_DIR} --entrypoint sh ${AWG_IMAGE} -c '`,
    '  set -e',
    `  mkdir -p ${AWG_CONFIG_DIR}`,
    `  PRIV=$(awg genkey)`,
    `  echo "$PRIV" > ${AWG_CONFIG_DIR}/wireguard_server_private_key.key`,
    `  echo "$PRIV" | awg pubkey > ${AWG_CONFIG_DIR}/wireguard_server_public_key.key`,
    `  PSK=$(awg genpsk)`,
    `  echo "$PSK" > ${AWG_CONFIG_DIR}/wireguard_psk.key`,
    `  cat > ${AWG_CONF_PATH} <<EOF`,
    '[Interface]',
    'PrivateKey = $PRIV',
    `Address = ${subnet}/${cidr}`,
    `ListenPort = ${p}`,
    'Jc = 3',
    'Jmin = 10',
    'Jmax = 30',
    'S1 = 0',
    'S2 = 0',
    'H1 = 1',
    'H2 = 2',
    'H3 = 3',
    'H4 = 4',
    'EOF',
    `  printf '%s' "${startScript.replace(/\n/g, '\\n')}" > ${AWG_CONFIG_DIR}/start.sh`,
    `  chmod a+x ${AWG_CONFIG_DIR}/start.sh`,
    `  chmod -R a+r ${AWG_CONFIG_DIR}`,
    `'`,
    `if [ $? -ne 0 ]; then echo "###INSTALL_FAIL configure"; exit 1; fi`,

    'echo "###STEP run"',
    `docker rm -f ${c} 2>/dev/null`,
    'docker run -d \\',
    '  --log-driver none \\',
    '  --restart always \\',
    '  --privileged \\',
    '  --cap-add=NET_ADMIN \\',
    '  --cap-add=SYS_MODULE \\',
    `  -p ${p}:${p}/udp \\`,
    '  -v /lib/modules:/lib/modules \\',
    '  --sysctl="net.ipv4.conf.all.src_valid_mark=1" \\',
    `  -v ${AWG_VOLUME}:${AWG_CONFIG_DIR} \\`,
    `  --entrypoint ${AWG_CONFIG_DIR}/start.sh \\`,
    `  --name ${c} ${AWG_IMAGE}`,
    `if [ $? -ne 0 ]; then echo "###INSTALL_FAIL run"; exit 1; fi`,

    'echo "###INSTALL_OK"',
  ].join('\n');
}

/**
 * Read the current AWG state (Interface params, server keys, clients table).
 */
async function getAwgState(server, container = AWG_CONTAINER) {
  const res = await runCommand(server, buildReadStateScript(container), { timeout: 30000 });
  const sections = splitSections(res.stdout, ['CONF', 'PUB', 'PSK', 'TABLE']);
  const conf = sections.conf || '';
  const { obf, address, listenPort } = parseInterfaceObf(conf);
  const { subnetAddress, subnetCidr } = splitAddress(address);
  return {
    container,
    obf,
    address,
    subnetAddress,
    subnetCidr,
    listenPort: Number(listenPort) || AWG_DEFAULT_PORT,
    serverPublicKey: (sections.pub || '').trim(),
    psk: (sections.psk || '').trim(),
    clients: parseClientsTableEntries(sections.table || ''),
  };
}

/**
 * Build the full connection data (native `.conf` + `vpn://` link) for either an
 * existing client (when its config is stored in `clientsTable`) or a freshly
 * generated one — the same thing the Amnezia app does on "Share".
 *
 * `mode`:
 *   - 'existing' (default): reuse `clientsTable` config for the requested client
 *   - 'new':                generate a brand-new key pair and add it as a peer
 *
 * `client` may be a client id (public key), a client name, or nothing.
 */
async function getAwgShare(server, options = {}) {
  const container = assertContainer(options.container || AWG_CONTAINER);
  const mode = options.mode === 'new' ? 'new' : 'existing';
  const dns1 = options.dns1 || DEFAULT_DNS1;
  const dns2 = options.dns2 || DEFAULT_DNS2;
  const host = server.host;
  const requestedName = (options.clientName || options.client || '').trim();

  if (mode === 'existing') {
    const state = await getAwgState(server, container);
    if (!state.serverPublicKey) {
      throw new Error('AmneziaWG is not configured on this server');
    }
    const entry = pickClient(state.clients, options.clientId || options.id, requestedName, options.clientIp);
    if (!entry || !entry.configPart) {
      throw new Error(
        'config for this client is not stored on the server; use «Создать подключение» to generate a shareable link',
      );
    }
    const parsed = parseClientConf(entry.configPart);
    const clientIp = String(parsed.address || '').split('/')[0];
    return buildSharePayload({
      host,
      port: state.listenPort,
      obf: state.obf,
      subnetAddress: state.subnetAddress,
      subnetCidr: state.subnetCidr,
      dns1,
      dns2,
      clientName: entry.clientName || requestedName || null,
      clientIp,
      clientPrivKey: parsed.privateKey,
      clientPubKey: entry.publicKey || parsed.publicKey,
      serverPubKey: state.serverPublicKey,
      psk: entry.psk || parsed.psk,
      nativeConfig: entry.configPart,
      reused: true,
    });
  }

  // mode === 'new' — mirror the Amnezia "Share" flow.
  const gen = await runCommand(server, buildGenerateKeysScript(container), { timeout: 30000 });
  const genSections = splitSections(gen.stdout, ['GENKEY', 'CONF']);
  const keyLines = (genSections.genkey || '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const clientPrivKey = keyLines[0];
  const clientPubKey = keyLines[1];
  if (!clientPrivKey || !clientPubKey) {
    throw new Error('failed to generate client keys');
  }

  const conf = genSections.conf || '';
  const { obf, address, listenPort } = parseInterfaceObf(conf);
  const { subnetAddress, subnetCidr } = splitAddress(address);
  const clientIp = nextClientIp(conf, subnetAddress);
  const psk = (await runCommand(server, buildReadPskScript(container), { timeout: 20000 })).stdout.trim();

  const addScript = buildAddPeerScript(container, {
    publicKey: clientPubKey,
    psk,
    clientIp,
    name: requestedName || `client-${clientIp.split('.').pop()}`,
  });
  const added = await runCommand(server, addScript, { timeout: 30000 });
  if (!/###DONE/.test(added.stdout)) {
    throw new Error(`failed to add peer: ${tail((added.stderr || added.stdout).trim(), 400)}`);
  }

  const serverPubKey = (await runCommand(server, buildReadPubScript(container), { timeout: 20000 })).stdout.trim();

  return buildSharePayload({
    host,
    port: Number(listenPort) || AWG_DEFAULT_PORT,
    obf,
    subnetAddress,
    subnetCidr,
    dns1,
    dns2,
    clientName: requestedName || null,
    clientIp,
    clientPrivKey,
    clientPubKey,
    serverPubKey,
    psk,
    nativeConfig: null,
    reused: false,
  });
}

function buildSharePayload(ctx) {
  const {
    host, port, obf, subnetAddress, subnetCidr, dns1, dns2,
    clientName, clientIp, clientPrivKey, clientPubKey, serverPubKey, psk,
  } = ctx;

  const hasAwg3 = AWG3_KEYS.some((k) => String(obf[k] || '').trim() !== '')
    || /^(on|true|yes)$/i.test(String(obf.RandomTrailers || ''))
    || /^(on|true|yes)$/i.test(String(obf.DisableCookies || ''));
  const keepalive = hasAwg3 ? AWG3_KEEPALIVE : DEFAULT_KEEPALIVE;

  const nativeConfig = ctx.nativeConfig || buildNativeClientConfig({
    obf, clientIp, clientPrivKey, serverPubKey, psk, host, port, dns1, dns2, keepalive,
  });

  const clientJson = buildClientJson({
    nativeConfig, host, port, clientIp, clientPrivKey, clientPubKey, serverPubKey, psk,
    mtu: DESKTOP_MTU, keepalive, obf,
  });

  const serverJson = buildServerJson({
    host, port, obf, subnetAddress, subnetCidr, clientJson, dns1, dns2,
  });

  return {
    container: AWG_CONTAINER,
    clientName: clientName || null,
    clientIp,
    host,
    port,
    dns1,
    dns2,
    serverPublicKey: serverPubKey,
    reused: !!ctx.reused,
    config: nativeConfig,
    vpnLink: buildVpnLink(serverJson),
    serverJson,
  };
}

function buildReadPskScript(container) {
  const c = assertContainer(container);
  return `docker exec ${c} cat ${AWG_PSK_PATH} 2>/dev/null`;
}

function buildReadPubScript(container) {
  const c = assertContainer(container);
  return `docker exec ${c} cat ${AWG_SERVER_PUBKEY_PATH} 2>/dev/null`;
}

/** Find a stored client by id, name or IP. */
function pickClient(clients, id, name, ip) {
  if (!clients.length) return null;
  const wanted = [id, name, ip].filter(Boolean).map((v) => String(v));
  for (const c of clients) {
    const candidates = [c.clientId, c.publicKey, c.clientName, c.address]
      .filter(Boolean)
      .map((v) => String(v));
    for (const w of wanted) {
      if (candidates.some((v) => v === w || v.split('/')[0] === w.split('/')[0])) {
        return c;
      }
    }
  }
  return null;
}

/**
 * Compute the next free client IP from existing peer AllowedIPs, mirroring the
 * app's rule: start from the subnet address, then increment.
 */
function nextClientIp(conf, subnetAddress) {
  const used = [];
  for (const raw of String(conf).split(/\r?\n/)) {
    const line = raw.trim();
    if (!/^AllowedIPs\s*=/i.test(line)) continue;
    const value = line.slice(line.indexOf('=') + 1);
    for (const part of value.split(',')) {
      const ip = part.trim().split('/')[0];
      if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) used.push(ip);
    }
  }
  const base = used.length ? used[used.length - 1] : (subnetAddress || DEFAULT_SUBNET);
  const octets = base.split('.').map((n) => parseInt(n, 10));
  if (octets.length !== 4 || octets.some((n) => Number.isNaN(n))) {
    return `${DEFAULT_SUBNET.slice(0, DEFAULT_SUBNET.lastIndexOf('.'))}.2`;
  }
  let last = octets[3];
  if (last === 254) last += 3;
  else if (last === 255) last += 2;
  else last += 1;
  if (last > 254) last = 2; // wrap back into the usable range
  octets[3] = last;
  return octets.join('.');
}

// --- Small helpers ----------------------------------------------------------

function splitSections(text, keys) {
  const result = {};
  for (const k of keys) result[k.toLowerCase()] = '';
  let current = null;
  const buffers = {};
  for (const line of String(text).split(/\r?\n/)) {
    const m = line.match(/^###([A-Z_]+)\s*$/);
    if (m && keys.includes(m[1])) {
      current = m[1].toLowerCase();
      buffers[current] = [];
      continue;
    }
    if (current) buffers[current].push(line);
  }
  for (const [key, lines] of Object.entries(buffers)) {
    result[key] = lines.join('\n');
  }
  return result;
}

function tail(text, n) {
  const s = String(text || '');
  return s.length > n ? s.slice(-n) : s;
}

module.exports = {
  AWG_IMAGE,
  AWG_CONTAINER,
  AWG_DEFAULT_PORT,
  installAwgContainer,
  getAwgState,
  getAwgShare,
  // exported for tests / reuse
  buildVpnLink,
  qCompress,
  base64Url,
  parseInterfaceObf,
  parseClientsTableEntries,
  parseClientConf,
  buildNativeClientConfig,
  buildClientJson,
  buildServerJson,
  nextClientIp,
};
