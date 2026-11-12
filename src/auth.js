'use strict';

/**
 * Session-based authentication and role guards.
 *
 * A successful login exchanges credentials for a random session id stored in an
 * HttpOnly cookie; the session map lives in memory (sessions are dropped on
 * restart, which is acceptable for this control panel). Sessions carry only the
 * user id so role/name changes are picked up on the next request.
 */

const crypto = require('crypto');

const COOKIE_NAME = 'amp_session';
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7 days

const sessions = new Map(); // sid -> { userId, expires }

// --- Cookie helpers ---------------------------------------------------------

function parseCookies(req) {
  const header = req.headers && req.headers.cookie;
  const out = {};
  if (!header) return out;
  for (const part of String(header).split(';')) {
    const i = part.indexOf('=');
    if (i === -1) continue;
    const key = part.slice(0, i).trim();
    const value = part.slice(i + 1).trim();
    if (key) out[key] = decodeURIComponent(value);
  }
  return out;
}

function setSessionCookie(res, sid) {
  const attrs = [`${COOKIE_NAME}=${sid}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`];
  res.setHeader('Set-Cookie', attrs.join('; '));
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`);
}

// --- Session lifecycle ------------------------------------------------------

function createSession(userId) {
  const sid = crypto.randomBytes(24).toString('hex');
  sessions.set(sid, { userId, expires: Date.now() + SESSION_TTL_MS });
  return sid;
}

function getSession(sid) {
  if (!sid) return null;
  const session = sessions.get(sid);
  if (!session) return null;
  if (session.expires < Date.now()) {
    sessions.delete(sid);
    return null;
  }
  return session;
}

function destroySession(sid) {
  if (sid) sessions.delete(sid);
}

// --- Express middleware -----------------------------------------------------

/**
 * `attachUser(users)` mounts `req.user` / `req.sessionId` from the session
 * cookie. It never rejects — it only annotates the request.
 */
function attachUser(users) {
  return (req, res, next) => {
    const cookies = parseCookies(req);
    const session = getSession(cookies[COOKIE_NAME]);
    req.sessionId = session ? cookies[COOKIE_NAME] : null;
    req.user = session ? users.getUser(session.userId) : null;
    // A user may have been deleted while their session is still alive.
    if (session && !req.user) {
      destroySession(cookies[COOKIE_NAME]);
      req.sessionId = null;
    }
    next();
  };
}

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'authentication required' });
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'authentication required' });
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'admin access required' });
  next();
}

module.exports = {
  COOKIE_NAME,
  attachUser,
  requireAuth,
  requireAdmin,
  createSession,
  getSession,
  destroySession,
  setSessionCookie,
  clearSessionCookie,
  parseCookies,
};
