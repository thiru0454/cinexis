import { createServer } from 'node:http';
import { createReadStream } from 'node:fs';
import { access } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import {
  createHash,
  randomBytes,
  scrypt as scryptCallback,
  timingSafeEqual
} from 'node:crypto';
import { neon } from '@neondatabase/serverless';

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT) || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const SESSION_DAYS = 30;
const COOKIE_DAYS = 60;
const MAX_HISTORY = 30;
const MAX_FAVORITES = 500;
const BODY_LIMIT = 2 * 1024 * 1024;
const scrypt = promisify(scryptCallback);
const rateLimits = new Map();

let neonClient;
function getNeonClient() {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) throw new Error('DATABASE_URL is not configured.');
  if (!neonClient) neonClient = neon(databaseUrl);
  return neonClient;
}

const sql = (strings, ...values) => getNeonClient()(strings, ...values);
let databaseReady;

export function ensureDatabase() {
  if (!databaseReady) {
    databaseReady = initializeDatabase().catch(error => {
      databaseReady = null;
      throw error;
    });
  }
  return databaseReady;
}

async function initializeDatabase() {
  await sql`
    CREATE TABLE IF NOT EXISTS cinexis_users (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      email text NOT NULL,
      password_hash text NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now()
    )`;
  await sql`CREATE UNIQUE INDEX IF NOT EXISTS cinexis_users_email_unique ON cinexis_users (lower(email))`;
  await sql`
    CREATE TABLE IF NOT EXISTS cinexis_sessions (
      token_hash text PRIMARY KEY,
      user_id uuid NOT NULL REFERENCES cinexis_users(id) ON DELETE CASCADE,
      expires_at timestamptz NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now()
    )`;
  await sql`CREATE INDEX IF NOT EXISTS cinexis_sessions_expiry_idx ON cinexis_sessions (expires_at)`;
  await sql`
    CREATE TABLE IF NOT EXISTS cinexis_account_data (
      user_id uuid PRIMARY KEY REFERENCES cinexis_users(id) ON DELETE CASCADE,
      watch_history jsonb NOT NULL DEFAULT '[]'::jsonb,
      favorites jsonb NOT NULL DEFAULT '[]'::jsonb,
      updated_at timestamptz NOT NULL DEFAULT now()
    )`;
  await sql`
    CREATE TABLE IF NOT EXISTS cinexis_site_viewers (
      viewer_key text PRIMARY KEY,
      first_seen timestamptz NOT NULL DEFAULT now(),
      last_seen timestamptz NOT NULL DEFAULT now(),
      total_visits integer NOT NULL DEFAULT 1
    )`;
  await sql`CREATE INDEX IF NOT EXISTS cinexis_site_viewers_last_seen_idx ON cinexis_site_viewers (last_seen DESC)`;
  await sql`DELETE FROM cinexis_sessions WHERE expires_at < now() - interval '60 days'`;
}

function sendJson(response, status, data, extraHeaders = {}) {
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'same-origin',
    ...extraHeaders
  });
  response.end(JSON.stringify(data));
}

function cookieValue(request, name) {
  const cookies = String(request.headers.cookie || '').split(';');
  for (const entry of cookies) {
    const separator = entry.indexOf('=');
    if (separator < 0) continue;
    if (entry.slice(0, separator).trim() === name) return entry.slice(separator + 1).trim();
  }
  return '';
}

function sessionCookie(token, maxAge = COOKIE_DAYS * 86400) {
  return `cinexis_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${IS_PRODUCTION ? '; Secure' : ''}`;
}

function viewerCookie(token, maxAge = 365 * 86400) {
  return `cinexis_viewer=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${IS_PRODUCTION ? '; Secure' : ''}`;
}

function hashToken(token) {
  return createHash('sha256').update(token).digest('hex');
}

function getClientKey(request) {
  return request.ip || request.socket?.remoteAddress || 'unknown';
}

function enforceRateLimit(request, action, limit, windowMs) {
  const key = `${action}:${getClientKey(request)}`;
  const now = Date.now();
  const entry = rateLimits.get(key);
  if (!entry || entry.resetAt <= now) {
    rateLimits.set(key, { count: 1, resetAt: now + windowMs });
    return;
  }
  entry.count += 1;
  if (entry.count > limit) {
    const error = new Error('Too many attempts. Wait a few minutes and try again.');
    error.status = 429;
    throw error;
  }
}

async function readJson(request) {
  if (request.body !== undefined && request.body !== null) {
    if (typeof request.body === 'object' && !Buffer.isBuffer(request.body)) return request.body;
    const rawBody = Buffer.isBuffer(request.body) ? request.body.toString('utf8') : String(request.body);
    try { return JSON.parse(rawBody || '{}'); }
    catch (_) {
      const error = new Error('Request must contain valid JSON.');
      error.status = 400;
      throw error;
    }
  }
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > BODY_LIMIT) {
      const error = new Error('Request is too large.');
      error.status = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); }
  catch (_) {
    const error = new Error('Request must contain valid JSON.');
    error.status = 400;
    throw error;
  }
}

function checkSameOrigin(request) {
  const origin = request.headers.origin;
  if (!origin) return;
  try {
    if (new URL(origin).host !== request.headers.host) throw new Error('Origin mismatch.');
  } catch (_) {
    const error = new Error('Request origin is not allowed.');
    error.status = 403;
    throw error;
  }
}

function authError(message = 'Please sign in to continue.', code = 'NO_SESSION') {
  const error = new Error(message);
  error.status = 401;
  error.code = code;
  return error;
}

async function getSession(request) {
  const token = cookieValue(request, 'cinexis_session');
  if (!token) throw authError();
  const digest = hashToken(token);
  const rows = await sql`
    SELECT s.user_id, s.expires_at, u.email
    FROM cinexis_sessions s JOIN cinexis_users u ON u.id = s.user_id
    WHERE s.token_hash = ${digest}
    LIMIT 1`;
  if (!rows.length) throw authError();
  if (new Date(rows[0].expires_at).getTime() <= Date.now()) {
    throw authError('Your session expired. Sign in again to sync your favorites and watch history.', 'SESSION_EXPIRED');
  }
  return { id: rows[0].user_id, email: rows[0].email };
}

async function createSession(user, response) {
  const token = randomBytes(32).toString('base64url');
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 86400000);
  await sql`
    INSERT INTO cinexis_sessions (token_hash, user_id, expires_at)
    VALUES (${hashToken(token)}, ${user.id}, ${expiresAt.toISOString()})`;
  response.setHeader('Set-Cookie', sessionCookie(token));
  return { id: user.id, email: user.email };
}

async function makePasswordHash(password) {
  const salt = randomBytes(16);
  const derived = await scrypt(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
  return `scrypt$16384$8$1$${salt.toString('base64url')}$${Buffer.from(derived).toString('base64url')}`;
}

async function verifyPassword(password, stored) {
  const [algorithm, n, r, p, saltText, hashText] = String(stored).split('$');
  if (algorithm !== 'scrypt' || !saltText || !hashText) return false;
  const expected = Buffer.from(hashText, 'base64url');
  const actual = Buffer.from(await scrypt(password, Buffer.from(saltText, 'base64url'), expected.length, {
    N: Number(n), r: Number(r), p: Number(p), maxmem: 64 * 1024 * 1024
  }));
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

function cleanText(value, maxLength) {
  return String(value ?? '').trim().slice(0, maxLength);
}

function sanitizeAccountData(data) {
  const rawHistory = Array.isArray(data?.watchHistory) ? data.watchHistory : [];
  const rawFavorites = Array.isArray(data?.favorites) ? data.favorites : [];
  const watchHistory = rawHistory.slice(0, MAX_HISTORY).flatMap(item => {
    const title = cleanText(item?.title, 250);
    if (!title) return [];
    const year = Number(item.year) || null;
    const movieLink = cleanText(item.movieLink, 2000);
    const position = Number(item.position);
    const duration = Number(item.duration);
    const progress = Number(item.progress);
    return [{
      id: movieIdentity(title, movieLink, year), title, year, movieLink,
      position: Number.isFinite(position) ? Math.max(0, position) : 0,
      duration: Number.isFinite(duration) ? Math.max(0, duration) : 0,
      progress: Number.isFinite(progress) ? Math.max(0, Math.min(100, progress)) : 0,
      updatedAt: Number(item.updatedAt) || Date.now()
    }];
  });
  const favorites = rawFavorites.slice(0, MAX_FAVORITES).flatMap(movie => {
    const title = cleanText(movie?.title, 250);
    const link = cleanText(movie?.link || movie?.url, 2000);
    if (!title && !link) return [];
    return [{
      title: title || link,
      rawTitle: cleanText(movie?.rawTitle, 300),
      year: Number(movie?.year) || null,
      link,
      url: cleanText(movie?.url, 2000),
      poster: cleanText(movie?.poster, 2000)
    }];
  });
  return { watchHistory, favorites };
}

async function handleApi(request, response, url) {
  const route = `${request.method} ${url.pathname}`;

  if (route === 'GET /api/health') {
    const rows = await sql`SELECT 1 AS connected`;
    return sendJson(response, 200, { ok: true, database: rows[0]?.connected === 1 });
  }

  if (route === 'POST /api/auth/register' || route === 'POST /api/auth/login') {
    checkSameOrigin(request);
    const isRegister = request.method === 'POST' && url.pathname.endsWith('/register');
    enforceRateLimit(request, isRegister ? 'register' : 'login', isRegister ? 5 : 12, 15 * 60 * 1000);
    const body = await readJson(request);
    const email = cleanText(body.email, 254).toLowerCase();
    const password = String(body.password || '');
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      const error = new Error('Enter a valid email address.'); error.status = 400; throw error;
    }
    if (password.length < 6 || password.length > 128) {
      const error = new Error('Password must be between 6 and 128 characters.'); error.status = 400; throw error;
    }

    let user;
    if (isRegister) {
      const passwordHash = await makePasswordHash(password);
      try {
        const rows = await sql`
          INSERT INTO cinexis_users (email, password_hash)
          VALUES (${email}, ${passwordHash})
          RETURNING id, email`;
        user = rows[0];
      } catch (error) {
        if (error.code === '23505') {
          const duplicate = new Error('An account with that email already exists. Sign in instead.'); duplicate.status = 409; throw duplicate;
        }
        throw error;
      }
    } else {
      const rows = await sql`SELECT id, email, password_hash FROM cinexis_users WHERE lower(email) = ${email} LIMIT 1`;
      if (!rows.length || !await verifyPassword(password, rows[0].password_hash)) {
        const error = new Error('Email or password is incorrect.'); error.status = 401; throw error;
      }
      user = rows[0];
    }

    const safeUser = await createSession(user, response);
    return sendJson(response, 200, { user: safeUser }, { 'Set-Cookie': response.getHeader('Set-Cookie') });
  }

  if (route === 'GET /api/auth/session') {
    try {
      const user = await getSession(request);
      return sendJson(response, 200, { user });
    } catch (error) {
      if (error.status === 401) {
        return sendJson(response, 401, { code: error.code, error: error.message }, {
          'Set-Cookie': sessionCookie('', 0)
        });
      }
      throw error;
    }
  }

  if (route === 'POST /api/auth/logout') {
    checkSameOrigin(request);
    const token = cookieValue(request, 'cinexis_session');
    if (token) await sql`DELETE FROM cinexis_sessions WHERE token_hash = ${hashToken(token)}`;
    return sendJson(response, 200, { ok: true }, { 'Set-Cookie': sessionCookie('', 0) });
  }

  if (route === 'GET /api/account/data') {
    const user = await getSession(request);
    const rows = await sql`SELECT watch_history, favorites FROM cinexis_account_data WHERE user_id = ${user.id} LIMIT 1`;
    return sendJson(response, 200, sanitizeAccountData(rows[0] || {}));
  }

  if (route === 'PUT /api/account/data') {
    checkSameOrigin(request);
    const user = await getSession(request);
    const data = sanitizeAccountData(await readJson(request));
    await sql`
      INSERT INTO cinexis_account_data (user_id, watch_history, favorites, updated_at)
      VALUES (${user.id}, ${JSON.stringify(data.watchHistory)}::jsonb, ${JSON.stringify(data.favorites)}::jsonb, now())
      ON CONFLICT (user_id) DO UPDATE SET
        watch_history = EXCLUDED.watch_history,
        favorites = EXCLUDED.favorites,
        updated_at = now()`;
    return sendJson(response, 200, { ok: true });
  }

  if (route === 'POST /api/site-visit') {
    checkSameOrigin(request);
    await readJson(request);
    let viewerToken = cookieValue(request, 'cinexis_viewer');
    let setCookie;
    if (!/^[A-Za-z0-9_-]{40,60}$/.test(viewerToken)) {
      viewerToken = randomBytes(32).toString('base64url');
      setCookie = viewerCookie(viewerToken);
    }
    await sql`
      INSERT INTO cinexis_site_viewers (viewer_key, first_seen, last_seen, total_visits)
      VALUES (${hashToken(viewerToken)}, now(), now(), 1)
      ON CONFLICT (viewer_key) DO UPDATE SET
        last_seen = now(),
        total_visits = cinexis_site_viewers.total_visits + CASE
          WHEN cinexis_site_viewers.last_seen < now() - interval '30 minutes' THEN 1
          ELSE 0
        END`;
    return sendJson(response, 201, { ok: true }, setCookie ? { 'Set-Cookie': setCookie } : {});
  }

  if (route === 'GET /api/site-stats') {
    const rows = await sql`
      SELECT count(*)::int AS total_visitors,
        count(*) FILTER (WHERE last_seen >= now() - interval '5 minutes')::int AS active_visitors,
        coalesce(sum(total_visits), 0)::int AS total_visits
      FROM cinexis_site_viewers`;
    return sendJson(response, 200, {
      totalVisitors: rows[0]?.total_visitors || 0,
      activeVisitors: rows[0]?.active_visitors || 0,
      totalVisits: rows[0]?.total_visits || 0
    }, { 'Cache-Control': 'no-store' });
  }

  return sendJson(response, 404, { error: 'Not found.' });
}

const mimeTypes = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon'
};

async function serveStatic(request, response, url) {
  let requestedPath;
  try { requestedPath = decodeURIComponent(url.pathname); }
  catch (_) { return sendJson(response, 400, { error: 'Invalid path.' }); }
  if (requestedPath === '/') requestedPath = '/index.html';
  const target = path.resolve(ROOT, `.${requestedPath}`);
  if (!target.startsWith(`${ROOT}${path.sep}`) || path.basename(target).startsWith('.')) {
    return sendJson(response, 404, { error: 'Not found.' });
  }
  try { await access(target); }
  catch (_) { return sendJson(response, 404, { error: 'Not found.' }); }
  response.writeHead(200, {
    'Content-Type': mimeTypes[path.extname(target).toLowerCase()] || 'application/octet-stream',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': target.endsWith('index.html') ? 'no-cache' : 'public, max-age=300'
  });
  if (request.method === 'HEAD') return response.end();
  createReadStream(target).pipe(response);
}

const server = createServer(async (request, response) => {
  try {
    const url = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`);
    if (url.pathname.startsWith('/api/')) await dispatchApi(request, response, url);
    else if (request.method === 'GET' || request.method === 'HEAD') await serveStatic(request, response, url);
    else sendJson(response, 405, { error: 'Method not allowed.' });
  } catch (error) {
    if (response.headersSent) { response.destroy(); return; }
    const status = Number(error.status) || 500;
    if (status >= 500) console.error('Cinexis request failed:', error.message);
    const headers = error.status === 401 && error.code === 'SESSION_EXPIRED'
      ? { 'Set-Cookie': sessionCookie('', 0) }
      : {};
    sendJson(response, status, { code: error.code || 'REQUEST_FAILED', error: status >= 500 ? 'The account service is temporarily unavailable.' : error.message }, headers);
  }
});

export async function dispatchApi(request, response, url) {
  try {
    await ensureDatabase();
    await handleApi(request, response, url);
  } catch (error) {
    if (response.headersSent) { response.destroy(); return; }
    const status = Number(error.status) || 500;
    if (status >= 500) console.error('Cinexis request failed:', error.message);
    const headers = error.status === 401 && error.code === 'SESSION_EXPIRED'
      ? { 'Set-Cookie': sessionCookie('', 0) }
      : {};
    sendJson(response, status, {
      code: error.code || 'REQUEST_FAILED',
      error: status >= 500 ? 'The account service is temporarily unavailable.' : error.message
    }, headers);
  }
}

if (!process.env.VERCEL && !process.env.VERCEL_ENV) {
  await ensureDatabase();
  server.listen(PORT, () => console.log(`Cinexis listening on port ${PORT}`));
}
