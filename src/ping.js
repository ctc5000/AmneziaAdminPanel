'use strict';

const { spawn } = require('child_process');
const os = require('os');

const IS_WIN = os.platform() === 'win32';

// Only hostnames, IPv4 or IPv6 literals are allowed. Arguments are passed to
// spawn as an array (never a shell string), so this is a defence-in-depth check.
const HOST_RE = /^[a-zA-Z0-9._:-]{1,255}$/;

/**
 * Ping a host and return latency statistics.
 *
 * Works on Windows (`ping -n`), Linux and macOS (`ping -c`). The command is
 * spawned directly with an argument array (no shell), so the host value cannot
 * be used to inject extra commands.
 *
 * @returns {Promise<{host:string, alive:boolean, rttMs:number|null,
 *   minMs:number|null, maxMs:number|null, lossPercent:number|null,
 *   packetsSent:number, packetsReceived:number, error:string|null}>}
 */
function pingHost(host, options = {}) {
  const count = options.count || 4;
  const perTryMs = options.perTryMs || 1500;
  const overallMs = options.overallMs || count * perTryMs + 4000;

  return new Promise((resolve) => {
    if (!host || !HOST_RE.test(String(host))) {
      resolve(failure(host, 'invalid host'));
      return;
    }

    const args = IS_WIN
      ? ['-n', String(count), '-w', String(perTryMs), host]
      : ['-c', String(count), '-W', String(Math.max(1, Math.round(perTryMs / 1000))), host];

    let stdout = '';
    let stderr = '';
    let settled = false;

    const child = spawn('ping', args, { windowsHide: true });

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try {
        child.kill();
      } catch (_) {
        /* ignore */
      }
      resolve(failure(host, 'ping timed out'));
    }, overallMs);
    if (timer.unref) timer.unref();

    child.stdout.on('data', (d) => {
      stdout += d.toString('utf8');
    });
    child.stderr.on('data', (d) => {
      stderr += d.toString('utf8');
    });

    child.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(failure(host, err.message || 'ping failed to start'));
    });

    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(parsePing(host, stdout, stderr, code, count));
    });
  });
}

function parsePing(host, stdout, stderr, code, count) {
  const text = `${stdout}\n${stderr}`;
  const replies = parseReplyTimes(text);
  const packets = parsePackets(text, count, replies.length);

  // A successful exit code (0) means at least one reply was received on all
  // platforms; a parsed reply / "TTL=" is a locale-independent fallback.
  const alive = code === 0 || replies.length > 0 || /TTL[=:]/i.test(text);

  // Prefer measured per-reply values; fall back to the summary line.
  let rtt;
  if (replies.length > 0) {
    const sum = replies.reduce((a, b) => a + b, 0);
    rtt = { min: Math.min(...replies), avg: sum / replies.length, max: Math.max(...replies) };
  } else {
    rtt = parseSummaryRtt(text);
  }

  const lost = Math.max(0, packets.sent - packets.received);
  const lossPercent =
    packets.sent > 0 ? Math.round((lost / packets.sent) * 1000) / 10 : alive ? 0 : 100;

  return {
    host,
    alive,
    rttMs: rtt.avg === null ? null : round(rtt.avg),
    minMs: rtt.min === null ? null : round(rtt.min),
    maxMs: rtt.max === null ? null : round(rtt.max),
    lossPercent,
    packetsSent: packets.sent,
    packetsReceived: packets.received,
    error: alive ? null : stderr.trim() || 'no reply',
  };
}

function round(n) {
  return Math.round(n * 100) / 100;
}

/**
 * Collect the per-reply latency values. Latency digits are always ASCII, so we
 * anchor on ASCII markers to stay independent of the system language:
 *   - Unix / English Windows: "... time=1.2ms" / "... time<1ms"
 *   - localized Windows: only "TTL=" and the digits survive, e.g.
 *     "...=32 <garbled><1<garbled> TTL=128" (the "time" word is garbled).
 */
function parseReplyTimes(text) {
  const times = [];

  // Unix / English: "time=1.2ms" or "time<1ms".
  let re = /time\s*([<=])\s*(\d+(?:[.,]\d+)?)\s*ms/gi;
  let m;
  while ((m = re.exec(text))) {
    const value = Number(String(m[2]).replace(',', '.'));
    if (!Number.isNaN(value)) times.push(m[1] === '<' ? 0.5 : value);
  }

  // Localized Windows: anchor on the ASCII "TTL=" and take the number right
  // before it. The bytes count ("=32") is skipped because it is separated from
  // TTL by a space, which the pattern does not cross.
  if (times.length === 0) {
    re = /([<=])([\d.]+)[^\d\s]{0,6}\s*TTL[=:]/gi;
    while ((m = re.exec(text))) {
      const value = Number(m[2]);
      if (!Number.isNaN(value)) times.push(m[1] === '<' ? 0.5 : value);
    }
  }

  return times;
}

function parsePackets(text, count, received) {
  // Linux: "4 packets transmitted, 4 received, 0% packet loss"
  let m = text.match(/(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets )?received/i);
  if (m) return { sent: Number(m[1]), received: Number(m[2]) };
  // English Windows: "Sent = 4, Received = 4, Lost = 0 (0% loss)"
  m = text.match(/Sent\s*=\s*(\d+),\s*Received\s*=\s*(\d+)/i);
  if (m) return { sent: Number(m[1]), received: Number(m[2]) };
  // Localized Windows: numbers are ASCII, the surrounding words are not.
  m = text.match(/=\s*(\d+)\s*,\s*\D*?=\s*(\d+)\s*,/);
  if (m) return { sent: Number(m[1]), received: Number(m[2]) };
  // Fallbacks based on the requested count and the replies we observed.
  return { sent: count || received, received };
}

function parseSummaryRtt(text) {
  // Linux/macOS: "rtt min/avg/max/mdev = 0.045/0.052/0.060/0.005 ms"
  let m = text.match(/=\s*([\d.]+)\/([\d.]+)\/([\d.]+)\/[\d.]+\s*ms/);
  if (m) return { min: Number(m[1]), avg: Number(m[2]), max: Number(m[3]) };

  // English Windows: "Minimum = 1ms, Maximum = 3ms, Average = 2ms"
  m = text.match(/Minimum\s*=\s*(\d+)ms,\s*Maximum\s*=\s*(\d+)ms,\s*Average\s*=\s*(\d+)ms/i);
  if (m) return { min: Number(m[1]), max: Number(m[2]), avg: Number(m[3]) };

  return { min: null, avg: null, max: null };
}

function failure(host, error) {
  return {
    host,
    alive: false,
    rttMs: null,
    minMs: null,
    maxMs: null,
    lossPercent: null,
    packetsSent: 0,
    packetsReceived: 0,
    error: error || 'ping failed',
  };
}

module.exports = { pingHost };
