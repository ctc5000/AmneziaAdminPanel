'use strict';

/**
 * User store with a simple role model.
 *
 * Roles:
 *   - 'admin' — full access: sees every server (including hidden ones), can add
 *     /edit/remove servers, install AmneziaWG, and manage users.
 *   - 'user'  — limited access: sees only the servers an admin marked visible and
 *     can create a connection (AmneziaWG config / MTProto proxy link) for them.
 *
 * Passwords are stored as `scrypt` hashes (salt + derived key) and are compared
 * with a constant-time check. The very first admin is bootstrapped from the
 * ADMIN_USERNAME / ADMIN_PASSWORD environment variables (or from
 * data/users.json if it already exists).
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DATA_DIR = path.join(__dirname, '..', 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');

const SCRYPT_KEYLEN = 64;
const USERNAME_RE = /^[a-zA-Z0-9._-]{3,32}$/;

let cache = null;

function load() {
  if (cache) return cache;
  try {
    cache = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
    if (!Array.isArray(cache)) cache = [];
  } catch (_) {
    cache = [];
  }
  return cache;
}

function save() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(USERS_FILE, JSON.stringify(cache, null, 2), { mode: 0o600 });
}

// --- Password hashing -------------------------------------------------------

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(String(password), salt, SCRYPT_KEYLEN);
  return `scrypt:${salt.toString('hex')}:${key.toString('hex')}`;
}

function verifyPassword(password, stored) {
  if (!stored || typeof stored !== 'string') return false;
  const [scheme, saltHex, keyHex] = stored.split(':');
  if (scheme !== 'scrypt' || !saltHex || !keyHex) return false;
  let derived;
  try {
    derived = crypto.scryptSync(String(password), Buffer.from(saltHex, 'hex'), SCRYPT_KEYLEN);
  } catch (_) {
    return false;
  }
  const expected = Buffer.from(keyHex, 'hex');
  if (expected.length !== derived.length) return false;
  return crypto.timingSafeEqual(expected, derived);
}

// --- CRUD -------------------------------------------------------------------

function listUsers() {
  return load();
}

function getUser(id) {
  return load().find((u) => u.id === id) || null;
}

function getUserByUsername(username) {
  const wanted = String(username || '').trim().toLowerCase();
  if (!wanted) return null;
  return load().find((u) => u.username.toLowerCase() === wanted) || null;
}

function addUser(input) {
  const username = String((input && input.username) || '').trim();
  if (!USERNAME_RE.test(username)) {
    throw new Error('invalid username (3-32 chars: letters, digits, . _ -)');
  }
  if (getUserByUsername(username)) {
    throw new Error('username already exists');
  }
  if (!input.password) {
    throw new Error('password is required');
  }
  const user = {
    id: crypto.randomUUID(),
    username,
    passwordHash: hashPassword(input.password),
    role: input.role === 'admin' ? 'admin' : 'user',
    createdAt: new Date().toISOString(),
  };
  load().push(user);
  save();
  return user;
}

function updateUser(id, patch) {
  const user = getUser(id);
  if (!user) return null;

  if (patch.username !== undefined) {
    const username = String(patch.username).trim();
    if (!USERNAME_RE.test(username)) throw new Error('invalid username');
    const existing = getUserByUsername(username);
    if (existing && existing.id !== id) throw new Error('username already exists');
    user.username = username;
  }
  if (patch.role !== undefined) {
    user.role = patch.role === 'admin' ? 'admin' : 'user';
  }
  if (patch.password) {
    user.passwordHash = hashPassword(patch.password);
  }
  save();
  return user;
}

function removeUser(id) {
  const users = load();
  const idx = users.findIndex((u) => u.id === id);
  if (idx === -1) return false;
  users.splice(idx, 1);
  save();
  return true;
}

/** Number of admins currently registered (used to protect the last admin). */
function countAdmins() {
  return load().filter((u) => u.role === 'admin').length;
}

/** Public view of a user: never leaks the password hash. */
function toPublicUser(user) {
  const { passwordHash, ...rest } = user;
  return rest;
}

/**
 * Create the bootstrap admin from the environment if no admin exists yet.
 * Idempotent: safe to call on every start.
 */
function ensureAdmin() {
  const users = load();
  const hasAdmin = users.some((u) => u.role === 'admin');
  if (hasAdmin) return null;

  const username = String(process.env.ADMIN_USERNAME || 'admin').trim();
  const password = String(process.env.ADMIN_PASSWORD || 'admin');
  // Reuse an existing account with the same name if present.
  let user = users.find((u) => u.username.toLowerCase() === username.toLowerCase());
  if (user) {
    user.role = 'admin';
    if (!user.passwordHash) user.passwordHash = hashPassword(password);
  } else {
    user = {
      id: crypto.randomUUID(),
      username,
      passwordHash: hashPassword(password),
      role: 'admin',
      createdAt: new Date().toISOString(),
    };
    users.push(user);
  }
  save();
  console.log(
    `[users] bootstrap admin "${username}" created${process.env.ADMIN_PASSWORD ? '' : ' (default password "admin" — change it!)'}`,
  );
  return user;
}

module.exports = {
  verifyPassword,
  hashPassword,
  listUsers,
  getUser,
  getUserByUsername,
  addUser,
  updateUser,
  removeUser,
  countAdmins,
  toPublicUser,
  ensureAdmin,
};
