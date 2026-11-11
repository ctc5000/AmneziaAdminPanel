'use strict';

const { Client } = require('ssh2');

const DEFAULT_TIMEOUT = 20000;

/**
 * Run a single shell command over SSH and resolve with { code, stdout, stderr }.
 * The connection is opened, the command is executed, then the connection is closed.
 *
 * NOTE: command input must be a trusted, constant string built by the application.
 * It is never taken from raw user input.
 */
function runCommand(server, command, options = {}) {
  const timeout = options.timeout || DEFAULT_TIMEOUT;

  return new Promise((resolve, reject) => {
    const conn = new Client();
    let stdout = '';
    let stderr = '';
    let exitCode = null;
    let settled = false;

    const finish = (fn, payload) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        conn.end();
      } catch (_) {
        /* ignore */
      }
      fn(payload);
    };

    const timer = setTimeout(() => {
      finish(reject, new Error(`SSH command timed out after ${timeout}ms`));
    }, timeout);

    conn
      .on('ready', () => {
        conn.exec(command, (err, stream) => {
          if (err) {
            finish(reject, err);
            return;
          }
          stream
            .on('close', (code) => {
              exitCode = typeof code === 'number' ? code : exitCode;
              finish(resolve, {
                code: exitCode === null ? 0 : exitCode,
                stdout,
                stderr,
              });
            })
            .on('data', (data) => {
              stdout += data.toString('utf8');
            })
            .stderr.on('data', (data) => {
              stderr += data.toString('utf8');
            });
        });
      })
      .on('error', (err) => {
        finish(reject, err);
      })
      .connect(buildConnectConfig(server, timeout));
  });
}

function buildConnectConfig(server, timeout) {
  const config = {
    host: server.host,
    port: Number(server.port) || 22,
    username: server.username,
    readyTimeout: timeout,
    keepaliveInterval: 5000,
  };

  if (server.authType === 'key' && server.privateKey) {
    config.privateKey = server.privateKey;
    if (server.passphrase) config.passphrase = server.passphrase;
  } else {
    config.password = server.password;
    // Amnezia default root password auth also needs these in some setups.
    config.tryKeyboard = true;
  }

  return config;
}

module.exports = { runCommand };
