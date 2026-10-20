// OrbitHost control plane - Cloudflare Pages Functions port.
// Worker-mode API backed by D1, drop-in replacement for the Express server.
// Matches upstream OrbitHost v2: demo mode removed, all runtime ops go to a real worker.

const PYTHON_VERSIONS = ['3.10', '3.11', '3.12', '3.13'];
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const NAME_RE = /^[\p{L}\p{N}][\p{L}\p{N} ._-]{0,59}$/u;
const ENV_KEY_RE = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const COOKIE_NAME = 'orb.sid';
const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const AUTH_WINDOW_MS = 15 * 60 * 1000;
const AUTH_LIMIT = 25;
const BUNDLE_CHUNK = 512 * 1024;
const projectOperations = new Set();

class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const fail = (status, message) => { throw new ApiError(status, message); };

const enc = new TextEncoder();
const dec = new TextDecoder();
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json; charset=utf-8', ...headers } });
const nowISO = () => new Date().toISOString();

function bytesToB64url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlToBytes(str) {
  const norm = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = norm + '='.repeat((4 - (norm.length % 4)) % 4);
  const raw = atob(pad);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}
function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
const bytesToHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');

async function hmac(secret, payload) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(payload)));
}

// --- sessions (signed cookies) ---

function parseCookies(request) {
  const out = {};
  const header = request.headers.get('cookie') || '';
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx > 0) out[part.slice(0, idx).trim()] = part.slice(idx + 1).trim();
  }
  return out;
}

async function sessionCookie(value, maxAge) {
  return `${COOKIE_NAME}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}

async function readSession(request, env) {
  const raw = parseCookies(request)[COOKIE_NAME];
  if (!raw) return null;
  const dot = raw.lastIndexOf('.');
  if (dot < 1) return null;
  const payload = raw.slice(0, dot);
  const sig = raw.slice(dot + 1);
  const expected = bytesToB64url(await hmac(env.SESSION_SECRET, payload));
  if (sig !== expected) return null;
  let data;
  try { data = JSON.parse(dec.decode(b64urlToBytes(payload))); } catch { return null; }
  if (!data || data.e < Date.now()) return null;
  return data;
}

async function writeSession(env, data, existingHeaders = {}) {
  const payload = bytesToB64url(enc.encode(JSON.stringify(data)));
  const sig = bytesToB64url(await hmac(env.SESSION_SECRET, payload));
  return sessionCookie(`${payload}.${sig}`, Math.floor(SESSION_TTL_MS / 1000));
}
const clearSessionCookie = () => sessionCookie('', 0);

// --- passwords (PBKDF2, native WebCrypto; Workers CPU limits rule out bcrypt) ---

async function pbkdf2Bits(password, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256));
}
async function hashPassword(password, env) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iterations = Math.min(100000, Math.max(1000, Number(env.PBKDF2_ITERATIONS || 25000)));
  const bits = await pbkdf2Bits(password, salt, iterations);
  return `pbkdf2$${iterations}$${bytesToB64url(salt)}$${bytesToB64url(bits)}`;
}
async function verifyPassword(password, stored) {
  const parts = String(stored).split('$');
  if (parts.length !== 4 || parts[0] !== 'pbkdf2') return false;
  const bits = await pbkdf2Bits(password, b64urlToBytes(parts[2]), Number(parts[1]));
  const expect = b64urlToBytes(parts[3]);
  if (bits.length !== expect.length) return false;
  let diff = 0;
  for (let i = 0; i < bits.length; i++) diff |= bits[i] ^ expect[i];
  return diff === 0;
}

// --- AES-256-GCM secrets, same v1.iv.tag.ciphertext format as the original ---

async function aesKey(env) {
  const raw = env.ENV_ENCRYPTION_KEY || '';
  if (!/^[a-f0-9]{64}$/i.test(raw)) return null;
  return crypto.subtle.importKey('raw', hexToBytes(raw), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
async function encryptText(plain, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(String(plain))));
  const tag = ct.slice(ct.length - 16);
  const body = ct.slice(0, ct.length - 16);
  return `v1.${bytesToB64url(iv)}.${bytesToB64url(tag)}.${bytesToB64url(body)}`;
}
async function decryptText(payload, key) {
  const parts = String(payload).split('.');
  if (parts.length !== 4 || parts[0] !== 'v1') fail(500, 'Unsupported encrypted secret format.');
  const params = { name: 'AES-GCM', iv: b64urlToBytes(parts[1]) };
  const joined = new Uint8Array(b64urlToBytes(parts[3]).length + 16);
  joined.set(b64urlToBytes(parts[3]));
  joined.set(b64urlToBytes(parts[2]), b64urlToBytes(parts[3]).length);
  const plain = await crypto.subtle.decrypt(params, key, joined);
  return dec.decode(plain);
}

// --- text helpers ---

const safeText = (value, max = 200) => (typeof value === 'string' ? value.trim().slice(0, max) : '');
const isValidEnvKey = (key) => ENV_KEY_RE.test(key);
const isValidPythonVersion = (v) => PYTHON_VERSIONS.includes(v);

function isIpLiteral(host) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return true;
  if (host.includes(':') && /^[0-9a-fA-F:]+$/.test(host)) return true;
  return false;
}
function safeHttpsRepository(input) {
  try {
    const u = new URL(input);
    if (u.protocol !== 'https:' || u.username || u.password || u.port || u.search || u.hash) return false;
    const host = u.hostname.toLowerCase();
    if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) return false;
    if (isIpLiteral(host) || /^[\d.]+$/.test(host)) return false;
    if (!/^[a-z0-9.-]+$/.test(host) || host.includes('..')) return false;
    return true;
  } catch { return false; }
}

function maskSecrets(text, secrets = []) {
  let out = String(text ?? '');
  for (const secret of secrets) {
    if (typeof secret === 'string' && secret.length >= 4) out = out.split(secret).join('[REDACTED]');
  }
  return out.replace(/(token|password|secret|api[_-]?key)\s*([=:])\s*([^\s,;]+)/gi, '$1$2[REDACTED]')
    .replace(/(Bot\s+)[A-Za-z0-9._-]{20,}/g, '$1[REDACTED]');
}

// --- ZIP central-directory validation ---

function validateZip(buffer, limits) {
  const u8 = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const view = new DataView(u8.buffer, u8.byteOffset, u8.byteLength);
  if (u8.length < 22 || view.getUint32(0, true) !== 0x04034b50) fail(400, 'The ZIP archive is damaged or invalid.');
  let eocd = -1;
  const floor = Math.max(0, u8.length - 22 - 65535);
  for (let i = u8.length - 22; i >= floor; i--) {
    if (view.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) fail(400, 'The ZIP archive is damaged or invalid.');
  const count = view.getUint16(eocd + 10, true);
  const cdOffset = view.getUint32(eocd + 16, true);
  let p = cdOffset, files = 0, expanded = 0;
  for (let i = 0; i < count; i++) {
    if (p + 46 > u8.length || view.getUint32(p, true) !== 0x02014b50) fail(400, 'The ZIP archive is damaged or invalid.');
    const nameLen = view.getUint16(p + 28, true);
    const extraLen = view.getUint16(p + 30, true);
    const commentLen = view.getUint16(p + 32, true);
    const usize = view.getUint32(p + 24, true);
    const mode = (view.getUint32(p + 38, true) >>> 16) & 0o170000;
    const name = dec.decode(u8.subarray(p + 46, p + 46 + nameLen));
    if (!name || name.includes('\0') || name.includes('\\') || name.startsWith('/') || /^[a-zA-Z]:/.test(name)
      || name.split('/').includes('..') || name.split('/').join('/') !== name) fail(400, 'ZIP contains an unsafe file path.');
    if (name.startsWith('../')) fail(400, 'ZIP contains an unsafe file path.');
    if (mode === 0o120000) fail(400, 'ZIP symbolic links are not allowed.');
    files += 1; expanded += Number(usize || 0);
    if (files > limits.entries) fail(400, 'ZIP contains too many files for the configured extraction safety limit.');
    if (expanded > limits.expandedMb * 1024 * 1024) fail(400, 'ZIP expands beyond the configured extraction safety limit.');
    if (Number(usize || 0) > limits.entryMb * 1024 * 1024) fail(400, 'A single ZIP entry exceeds the configured extraction safety limit.');
    p += 46 + nameLen + extraLen + commentLen;
  }
  if (!files) fail(400, 'ZIP archive is empty.');
  return { files, expandedBytes: expanded };
}


// --- worker integration (upstream v2 behavior) ---

function zipLimits(env) {
  return {
    entries: Math.max(1, Number(env.MAX_ZIP_ENTRIES || 2000)),
    expandedMb: Math.max(1, Number(env.MAX_ZIP_EXPANDED_MB || 200)),
    entryMb: Math.max(1, Number(env.MAX_ZIP_ENTRY_MB || 80))
  };
}

async function workerRequest(env, route, options = {}, timeoutMs = Number(env.WORKER_TIMEOUT_MS || 3600000)) {
  const base = String(env.WORKER_URL || '').replace(/\/$/, '');
  if (!base || !env.WORKER_TOKEN) throw new ApiError(503, 'Container worker is not configured.');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(`${base}${route}`, { ...options, signal: controller.signal, headers: { authorization: `Bearer ${env.WORKER_TOKEN}`, ...(options.headers || {}) } });
    const raw = await response.text();
    let data; try { data = raw ? JSON.parse(raw) : {}; } catch { data = {}; }
    if (!response.ok) throw new ApiError(502, data.error || `Worker returned ${response.status}.`);
    return data;
  } finally { clearTimeout(timer); }
}

async function liveProjectView(env, p) {
  try {
    const measured = await workerRequest(env, `/v1/projects/${p.id}/status`, {}, 15000);
    if (p.status === 'deploying') return projectView(env, p);
    const measuredStatus = ['online', 'stopped', 'failed', 'unknown'].includes(measured.status) ? measured.status : 'unknown';
    await env.DB.prepare("UPDATE projects SET status=? WHERE id=? AND status <> 'deploying'").bind(measuredStatus, p.id).run();
    const current = await first(env.DB.prepare('SELECT status FROM projects WHERE id=?').bind(p.id));
    return projectView(env, { ...p, status: current?.status || measuredStatus });
  } catch {
    const current = await first(env.DB.prepare('SELECT status FROM projects WHERE id=?').bind(p.id));
    return projectView(env, { ...p, status: current?.status === 'deploying' ? 'deploying' : 'unknown' });
  }
}

async function loadBundle(env, bundleId) {
  if (!bundleId) return null;
  const parts = await rows(env.DB.prepare('SELECT seq, data FROM bundles WHERE bundle_id = ? ORDER BY seq').bind(bundleId));
  let length = 0;
  for (const part of parts) length += part.data.byteLength;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) { out.set(new Uint8Array(part.data), offset); offset += part.data.byteLength; }
  return out;
}

async function deployWithWorker(env, p, deploymentId) {
  const aes = await aesKey(env);
  const envPairs = aes ? await readEnv(env, p.id, aes) : [];
  const form = new FormData();
  form.set('projectId', p.id);
  form.set('pythonVersion', p.python_version);
  form.set('buildCommand', p.build_command || '');
  form.set('startCommand', p.start_command || 'python main.py');
  form.set('envJson', JSON.stringify(Object.fromEntries(envPairs.map((item) => [item.key, item.value]))));
  form.set('deploymentId', deploymentId);
  if (p.source_type === 'git') {
    form.set('repositoryUrl', p.repository_url || '');
  } else if (p.source_type === 'zip' && p.source_bundle) {
    const bundle = await loadBundle(env, p.source_bundle);
    if (!bundle) throw new ApiError(400, 'The uploaded source archive is missing. Re-upload the project.');
    form.set('bundle', new Blob([bundle], { type: 'application/zip' }), `${p.id}.zip`);
  }
  return workerRequest(env, `/v1/projects/${p.id}/deploy`, { method: 'POST', body: form });
}

// --- schema ---

const DDL = `
CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS projects (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, name TEXT NOT NULL, source_type TEXT NOT NULL CHECK(source_type IN ('zip','git','demo')), source_bundle TEXT, repository_url TEXT, python_version TEXT NOT NULL DEFAULT '3.12', build_command TEXT NOT NULL DEFAULT '', start_command TEXT NOT NULL DEFAULT 'python main.py', status TEXT NOT NULL DEFAULT 'stopped', is_sample INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_deployed_at TEXT);
CREATE INDEX IF NOT EXISTS projects_by_user ON projects(user_id, updated_at DESC);
CREATE TABLE IF NOT EXISTS env_vars (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, key TEXT NOT NULL, encrypted_value TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(project_id, key));
CREATE TABLE IF NOT EXISTS deployments (id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, sequence INTEGER NOT NULL, status TEXT NOT NULL, trigger TEXT NOT NULL DEFAULT 'manual', summary TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, finished_at TEXT, duration_ms INTEGER, UNIQUE(project_id, sequence));
CREATE INDEX IF NOT EXISTS deployments_by_project ON deployments(project_id, sequence DESC);
CREATE TABLE IF NOT EXISTS project_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE, stream TEXT NOT NULL, level TEXT NOT NULL DEFAULT 'info', message TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS logs_by_project ON project_logs(project_id, id DESC);
CREATE TABLE IF NOT EXISTS activities (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE, project_id TEXT REFERENCES projects(id) ON DELETE SET NULL, action TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS activity_by_user ON activities(user_id, id DESC);
CREATE TABLE IF NOT EXISTS bundles (bundle_id TEXT NOT NULL, seq INTEGER NOT NULL, data BLOB NOT NULL, PRIMARY KEY(bundle_id, seq));
CREATE TABLE IF NOT EXISTS rate_limits (ip TEXT NOT NULL, route TEXT NOT NULL, window_start INTEGER NOT NULL, count INTEGER NOT NULL, PRIMARY KEY(ip, route));
`;

let schemaPromise = null;
function ensureSchema(env) {
  if (!schemaPromise) {
    schemaPromise = env.DB.exec(DDL).catch((error) => { schemaPromise = null; throw error; });
  }
  return schemaPromise;
}

// --- row helpers ---

const first = async (q) => await q.first();
const rows = async (q) => (await q.all()).results || [];

function publicUser(row) { return { id: row.id, email: row.email, createdAt: row.created_at }; }

async function ownerProject(env, userId, projectId) {
  return first(env.DB.prepare('SELECT * FROM projects WHERE id = ? AND user_id = ?').bind(projectId, userId));
}

async function projectView(env, p) {
  const envCount = (await first(env.DB.prepare('SELECT count(*) AS count FROM env_vars WHERE project_id = ?').bind(p.id))).count;
  const deployCount = (await first(env.DB.prepare('SELECT count(*) AS count FROM deployments WHERE project_id = ?').bind(p.id))).count;
  return {
    id: p.id, name: p.name, sourceType: p.source_type, repositoryUrl: p.repository_url,
    pythonVersion: p.python_version, buildCommand: p.build_command, startCommand: p.start_command,
    status: p.status, isSample: false, createdAt: p.created_at, updatedAt: p.updated_at,
    lastDeployedAt: p.last_deployed_at, environmentCount: envCount, deploymentCount: deployCount,
    runtimeMode: 'container'
  };
}

async function readEnv(env, projectId, aes) {
  const list = await rows(env.DB.prepare('SELECT key, encrypted_value FROM env_vars WHERE project_id = ? ORDER BY key').bind(projectId));
  const out = [];
  for (const row of list) {
    try { out.push({ key: row.key, value: await decryptText(row.encrypted_value, aes) }); }
    catch { out.push({ key: row.key, value: '' }); }
  }
  return out;
}

async function envView(env, projectId) {
  return (await rows(env.DB.prepare('SELECT key, created_at, updated_at FROM env_vars WHERE project_id = ? ORDER BY key').bind(projectId)))
    .map((row) => ({ key: row.key, isSet: true, maskedValue: '••••••••', createdAt: row.created_at, updatedAt: row.updated_at }));
}

async function addDeploy(env, projectId, status, summary, trigger = 'manual', duration = null) {
  const seq = (await first(env.DB.prepare('SELECT COALESCE(MAX(sequence),0)+1 AS n FROM deployments WHERE project_id = ?').bind(projectId))).n;
  const timestamp = nowISO();
  const id = crypto.randomUUID();
  await env.DB.prepare('INSERT INTO deployments(id,project_id,sequence,status,trigger,summary,created_at,finished_at,duration_ms) VALUES(?,?,?,?,?,?,?,?,?)')
    .bind(id, projectId, seq, status, trigger, summary, timestamp, status === 'building' ? null : timestamp, duration).run();
  return first(env.DB.prepare('SELECT * FROM deployments WHERE id = ?').bind(id));
}
function deploymentView(d) {
  return { id: d.id, sequence: d.sequence, status: d.status, trigger: d.trigger, summary: d.summary, createdAt: d.created_at, finishedAt: d.finished_at, durationMs: d.duration_ms };
}

async function addActivity(env, userId, projectId, action, message) {
  await env.DB.prepare('INSERT INTO activities(user_id, project_id, action, message, created_at) VALUES(?,?,?,?,?)')
    .bind(userId, projectId || null, action, message, nowISO()).run();
}
async function addLog(env, projectId, stream, level, message) {
  await env.DB.prepare('INSERT INTO project_logs(project_id, stream, level, message, created_at) VALUES(?,?,?,?,?)')
    .bind(projectId, stream, level, String(message).slice(0, 4000), nowISO()).run();
}

// --- bundle storage (chunked BLOBs in D1) ---

async function storeBundle(env, bytes) {
  const id = crypto.randomUUID();
  const statements = [];
  for (let i = 0; i < bytes.length; i += BUNDLE_CHUNK) {
    statements.push(env.DB.prepare('INSERT INTO bundles(bundle_id, seq, data) VALUES(?,?,?)').bind(id, i / BUNDLE_CHUNK, bytes.slice(i, i + BUNDLE_CHUNK)));
  }
  if (statements.length) await env.DB.batch(statements);
  return id;
}
async function deleteBundle(env, bundleId) {
  if (!bundleId) return;
  await env.DB.prepare('DELETE FROM bundles WHERE bundle_id = ?').bind(bundleId).run();
}

// --- auth rate limit (D1-backed, /api/auth writes) ---

async function authRateLimit(env, ip) {
  const nowMs = Date.now();
  const row = await first(env.DB.prepare('SELECT window_start, count FROM rate_limits WHERE ip = ? AND route = ?').bind(ip, 'auth'));
  const windowStart = row && nowMs - row.window_start < AUTH_WINDOW_MS ? row.window_start : nowMs;
  const count = row && windowStart === row.window_start ? row.count : 0;
  if (count >= AUTH_LIMIT) fail(429, 'Too many authentication attempts. Try again later.');
  await env.DB.prepare(`INSERT INTO rate_limits(ip, route, window_start, count) VALUES(?,?,?,1)
    ON CONFLICT(ip, route) DO UPDATE SET window_start = excluded.window_start,
    count = CASE WHEN excluded.window_start <> rate_limits.window_start THEN 1 ELSE rate_limits.count + 1 END`)
    .bind(ip, 'auth', windowStart).run();
  if (Math.random() < 0.05) {
    await env.DB.prepare('DELETE FROM rate_limits WHERE window_start < ?').bind(nowMs - 3600 * 1000).run();
  }
}

// --- request body helpers ---

async function readJson(request) {
  try {
    const body = await request.json();
    return body && typeof body === 'object' ? body : {};
  } catch { return {}; }
}

// --- main handler ---

export async function onRequest({ request, env }) {
  const url = new URL(request.url);
  const path = url.pathname.replace(/^\/api/, '') || '/';
  const method = request.method.toUpperCase();
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  try {
    await ensureSchema(env);
    return await handle(request, env, method, path, url, ip);
  } catch (error) {
    if (error instanceof ApiError) return json({ error: error.message }, error.status);
    console.error(`[orbithost] ${method} ${path}:`, error && error.message ? error.message : error);
    return json({ error: 'Something went wrong while processing that request. Check the project logs and server configuration.' }, 500);
  }
}

async function handle(request, env, method, path, url, ip) {
  const MAX_UPLOAD_MB = Math.min(100, Math.max(1, Number(env.MAX_UPLOAD_MB || 8)));
  const segments = path.split('/').filter(Boolean);

  // ---- public endpoints ----

  if (method === 'GET' && path === '/health') {
    return json({ ok: true, service: 'orbithost-control-plane', mode: 'worker', time: nowISO() });
  }
  if (method === 'GET' && path === '/config') {
    let workerReady = false;
    const workerBase = String(env.WORKER_URL || '').replace(/\/$/, '');
    if (workerBase && env.WORKER_TOKEN) {
      try {
        const probe = await fetch(`${workerBase}/v1/healthz`, { signal: AbortSignal.timeout(2500), headers: { authorization: `Bearer ${env.WORKER_TOKEN}` } });
        workerReady = probe.ok;
      } catch {}
    }
    return json({ hostingMode: 'worker', isPrototype: false, workerReady, maxUploadMb: MAX_UPLOAD_MB, pythonVersions: PYTHON_VERSIONS });
  }

  // ---- session plumbing ----

  const session = await readSession(request, env);
  const requireAuth = () => {
    if (!session?.u) fail(401, 'Please sign in to continue.');
    return session.u;
  };
  const checkCsrf = () => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(method)) return;
    const header = request.headers.get('x-csrf-token');
    if (!session?.c || !header || header !== session.c) fail(403, 'Your session token expired. Refresh the page and try again.');
  };

  if (method === 'GET' && path === '/auth/csrf') {
    const headers = {};
    if (!session?.c) {
      const data = { c: bytesToB64url(crypto.getRandomValues(new Uint8Array(32))), e: Date.now() + SESSION_TTL_MS };
      headers['set-cookie'] = await writeSession(env, data);
      return json({ csrfToken: data.c }, 200, headers);
    }
    return json({ csrfToken: session.c });
  }
  if (method === 'GET' && path === '/auth/me') {
    if (!session?.u) return json({ user: null });
    const user = await first(env.DB.prepare('SELECT id,email,created_at FROM users WHERE id = ?').bind(session.u));
    if (!user) return json({ user: null }, 200, { 'set-cookie': await clearSessionCookie() });
    return json({ user: publicUser(user) });
  }

  if (path === '/auth/register' && method === 'POST') {
    await authRateLimit(env, ip);
    checkCsrf();
    const body = await readJson(request);
    const email = safeText(body.email, 254).toLowerCase();
    const password = typeof body.password === 'string' ? body.password : '';
    if (!EMAIL_RE.test(email)) return json({ error: 'Enter a valid email address.' }, 400);
    if (password.length < 10 || password.length > 128 || new Blob([password]).size > 72) return json({ error: 'Use a password with at least 10 characters and no more than 72 UTF-8 bytes.' }, 400);
    if (await first(env.DB.prepare('SELECT 1 FROM users WHERE email = ?').bind(email))) return json({ error: 'An account with that email already exists.' }, 409);
    const user = { id: crypto.randomUUID(), email, created_at: nowISO() };
    await env.DB.prepare('INSERT INTO users(id,email,password_hash,created_at) VALUES(?,?,?,?)')
      .bind(user.id, email, await hashPassword(password, env), user.created_at).run();
    const sessionData = { u: user.id, c: bytesToB64url(crypto.getRandomValues(new Uint8Array(32))), e: Date.now() + SESSION_TTL_MS };
    return json({ user: publicUser(user), csrfToken: sessionData.c }, 201, { 'set-cookie': await writeSession(env, sessionData) });
  }

  if (path === '/auth/login' && method === 'POST') {
    await authRateLimit(env, ip);
    checkCsrf();
    const body = await readJson(request);
    const email = safeText(body.email, 254).toLowerCase();
    const password = typeof body.password === 'string' ? body.password : '';
    const user = await first(env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email));
    if (new Blob([password]).size > 72 || !user || !(await verifyPassword(password, user.password_hash))) {
      return json({ error: 'Email or password is incorrect.' }, 401);
    }
    const sessionData = { u: user.id, c: bytesToB64url(crypto.getRandomValues(new Uint8Array(32))), e: Date.now() + SESSION_TTL_MS };
    return json({ user: publicUser(user), csrfToken: sessionData.c }, 200, { 'set-cookie': await writeSession(env, sessionData) });
  }

  if (path === '/auth/logout' && method === 'POST') {
    requireAuth();
    checkCsrf();
    return json({ ok: true }, 200, { 'set-cookie': await clearSessionCookie() });
  }

  // ---- authenticated endpoints ----

  if (path === '/dashboard' && method === 'GET') {
    const userId = requireAuth();
    const projectRows = await rows(env.DB.prepare('SELECT * FROM projects WHERE user_id = ? ORDER BY updated_at DESC').bind(userId));
    const projects = [];
    for (const p of projectRows) projects.push(await liveProjectView(env, p));
    const count = (status) => projects.filter((p) => p.status === status).length;
    const activity = (await rows(env.DB.prepare('SELECT a.id,a.action,a.message,a.created_at,p.name AS project_name FROM activities a LEFT JOIN projects p ON p.id=a.project_id WHERE a.user_id=? ORDER BY a.id DESC LIMIT 8').bind(userId)))
      .map((a) => ({ id: a.id, action: a.action, message: a.message, createdAt: a.created_at, projectName: a.project_name }));
    const deploys = await rows(env.DB.prepare('SELECT d.*,p.name AS project_name FROM deployments d JOIN projects p ON p.id=d.project_id WHERE p.user_id=? ORDER BY d.created_at DESC LIMIT 6').bind(userId));
    return json({
      projects, activity,
      recentDeployments: deploys.map((d) => ({ ...deploymentView(d), projectName: d.project_name })),
      stats: { total: projects.length, online: count('online'), stopped: count('stopped'), deploying: count('deploying'), uptime: null },
      hostingMode: 'worker'
    });
  }

  if (path === '/projects' && method === 'GET') {
    const userId = requireAuth();
    const list = await rows(env.DB.prepare('SELECT * FROM projects WHERE user_id = ? ORDER BY updated_at DESC').bind(userId));
    const projects = [];
    for (const p of list) projects.push(await liveProjectView(env, p));
    return json({ projects });
  }

  if (path === '/projects' && method === 'POST') {
    const userId = requireAuth();
    checkCsrf();
    let form;
    try { form = await request.formData(); } catch { fail(400, 'Upload request could not be processed.'); }
    const name = safeText(form.get('name'), 60);
    const sourceType = form.get('sourceType');
    const pythonVersion = form.get('pythonVersion') || '3.12';
    const buildCommand = safeText(form.get('buildCommand') || '', 500);
    const startCommand = safeText(form.get('startCommand') || 'python main.py', 500);
    if (!name || !NAME_RE.test(name)) return json({ error: 'Project name may use letters, numbers, spaces, dots, underscores, and hyphens.' }, 400);
    if (!isValidPythonVersion(String(pythonVersion))) return json({ error: 'Choose a supported Python version.' }, 400);
    if (!startCommand) return json({ error: 'A start command is required.' }, 400);

    if (sourceType === 'git') {
      const repositoryUrl = safeText(form.get('repositoryUrl'), 1000);
      if (!safeHttpsRepository(repositoryUrl)) return json({ error: 'Use a public HTTPS Git URL without embedded credentials, query parameters, ports, or IP addresses.' }, 400);
      const id = crypto.randomUUID();
      const ts = nowISO();
      await env.DB.prepare('INSERT INTO projects(id,user_id,name,source_type,repository_url,python_version,build_command,start_command,status,is_sample,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')
        .bind(id, userId, name, 'git', repositoryUrl, String(pythonVersion), buildCommand, startCommand, 'stopped', 0, ts, ts).run();
      await addActivity(env, userId, id, 'project_created', `${name} was connected to Git.`);
      return json({ project: await projectView(env, await ownerProject(env, userId, id)) }, 201);
    }

    if (sourceType !== 'zip') return json({ error: 'Upload a ZIP archive or choose a Git repository.' }, 400);
    const file = form.get('bundle');
    if (!file || typeof file === 'string') return json({ error: 'Upload a ZIP archive or choose a Git repository.' }, 400);
    if (!file.name || !file.name.toLowerCase().endsWith('.zip') || file.size < 4) return json({ error: 'Upload a valid .zip archive.' }, 400);
    if (file.size > MAX_UPLOAD_MB * 1024 * 1024) return json({ error: `ZIP file exceeds the ${MAX_UPLOAD_MB} MB upload limit.` }, 413);
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (bytes[0] !== 0x50 || bytes[1] !== 0x4b) return json({ error: 'Upload a valid .zip archive.' }, 400);
    validateZip(bytes, zipLimits(env));
    const id = crypto.randomUUID();
    const ts = nowISO();
    const bundleId = await storeBundle(env, bytes);
    await env.DB.prepare('INSERT INTO projects(id,user_id,name,source_type,source_bundle,python_version,build_command,start_command,status,is_sample,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')
      .bind(id, userId, name, 'zip', bundleId, String(pythonVersion), buildCommand, startCommand, 'stopped', 0, ts, ts).run();
    await addActivity(env, userId, id, 'project_created', `${name} was created from a ZIP upload.`);
    return json({ project: await projectView(env, await ownerProject(env, userId, id)) }, 201);
  }

  if (segments[0] === 'projects' && segments.length === 2) {
    const userId = requireAuth();
    const p = await ownerProject(env, userId, segments[1]);
    if (!p) return json({ error: 'Project not found.' }, 404);

    if (method === 'GET') {
      let view = p;
      try {
        const measured = await workerRequest(env, `/v1/projects/${p.id}/status`, {}, 15000);
        if (p.status !== 'deploying' && measured.status && ['online', 'stopped', 'failed', 'unknown'].includes(measured.status)) {
          await env.DB.prepare("UPDATE projects SET status=? WHERE id=? AND status <> 'deploying'").bind(measured.status, p.id).run();
          const current = await first(env.DB.prepare('SELECT status FROM projects WHERE id=?').bind(p.id));
          if (current) view = { ...p, status: current.status };
        } else if (p.status === 'deploying') view = { ...p, status: 'deploying' };
      } catch {
        const current = await first(env.DB.prepare('SELECT status FROM projects WHERE id=?').bind(p.id));
        if (p.status !== 'deploying') view = { ...p, status: current?.status === 'deploying' ? 'deploying' : 'unknown' };
      }
      const latest = await first(env.DB.prepare('SELECT * FROM deployments WHERE project_id=? ORDER BY sequence DESC LIMIT 1').bind(p.id));
      const deployments = await rows(env.DB.prepare('SELECT * FROM deployments WHERE project_id=? ORDER BY sequence DESC').bind(p.id));
      return json({ project: await projectView(env, view), environment: await envView(env, p.id), latestDeployment: latest ? deploymentView(latest) : null, deployments: deployments.map(deploymentView), runtimeMode: 'worker' });
    }

    if (method === 'PATCH') {
      checkCsrf();
      const body = await readJson(request);
      if (p.status === 'deploying' || projectOperations.has(p.id)) return json({ error: 'Project settings cannot change while an operation is running.' }, 409);
      const name = body.name === undefined ? p.name : safeText(body.name, 60);
      const pythonVersion = body.pythonVersion === undefined ? p.python_version : body.pythonVersion;
      const buildCommand = body.buildCommand === undefined ? p.build_command : safeText(body.buildCommand, 500);
      const startCommand = body.startCommand === undefined ? p.start_command : safeText(body.startCommand, 500);
      if (!name || !NAME_RE.test(name)) return json({ error: 'Enter a valid project name.' }, 400);
      if (!isValidPythonVersion(String(pythonVersion))) return json({ error: 'Choose a supported Python version.' }, 400);
      if (!startCommand) return json({ error: 'A start command is required.' }, 400);
      await env.DB.prepare('UPDATE projects SET name=?,python_version=?,build_command=?,start_command=?,updated_at=? WHERE id=?')
        .bind(name, String(pythonVersion), buildCommand, startCommand, nowISO(), p.id).run();
      await addActivity(env, userId, p.id, 'settings_updated', `${name} settings were updated.`);
      return json({ project: await projectView(env, await ownerProject(env, userId, p.id)) });
    }

    if (method === 'DELETE') {
      checkCsrf();
      if (p.status === 'deploying' || projectOperations.has(p.id)) return json({ error: 'A project cannot be deleted while an operation is running.' }, 409);
      projectOperations.add(p.id);
      try {
        await workerRequest(env, `/v1/projects/${p.id}/action`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action: 'delete' }) });
        await addActivity(env, userId, null, 'project_deleted', `${p.name} was deleted.`);
        await deleteBundle(env, p.source_bundle);
        await env.DB.prepare('DELETE FROM projects WHERE id=?').bind(p.id).run();
        return json({ ok: true });
      } catch (error) {
        if (error instanceof ApiError) return json({ error: error.message }, error.status);
        throw error;
      } finally { projectOperations.delete(p.id); }
    }
  }

  if (segments[0] === 'projects' && segments[2] === 'env' && segments.length === 3) {
    const userId = requireAuth();
    const p = await ownerProject(env, userId, segments[1]);
    if (!p) return json({ error: 'Project not found.' }, 404);
    if (method === 'GET') return json({ variables: await envView(env, p.id) });
    if (method === 'PUT') {
      checkCsrf();
      if (p.status === 'deploying' || projectOperations.has(p.id)) return json({ error: 'Environment variables cannot change while an operation is running.' }, 409);
      const body = await readJson(request);
      const key = safeText(body.key, 128);
      const value = typeof body.value === 'string' ? body.value : '';
      if (!isValidEnvKey(key)) return json({ error: 'Variable names must start with a letter or underscore and contain only letters, numbers, and underscores.' }, 400);
      if (value.length > 8192 || /[\r\n\0]/.test(value)) return json({ error: 'Secret values must be 8 KB or less and cannot contain line breaks.' }, 400);
      const current = await first(env.DB.prepare('SELECT * FROM env_vars WHERE project_id=? AND key=?').bind(p.id, key));
      if (!value && !current) return json({ error: 'Enter a value for this new variable.' }, 400);
      if (value) {
        const aes = await aesKey(env);
        if (!aes) fail(500, 'Secret storage is not configured. Set ENV_ENCRYPTION_KEY to a 64 hex character key.');
        const encrypted = await encryptText(value, aes);
        const timestamp = nowISO();
        await env.DB.prepare('INSERT INTO env_vars(id,project_id,key,encrypted_value,created_at,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(project_id,key) DO UPDATE SET encrypted_value=excluded.encrypted_value,updated_at=excluded.updated_at')
          .bind(crypto.randomUUID(), p.id, key, encrypted, timestamp, timestamp).run();
      }
      await addActivity(env, userId, p.id, 'secret_updated', `${key} ${value ? 'was saved' : 'was left unchanged'}.`);
      return json({ variables: await envView(env, p.id), message: value ? 'Secret saved securely.' : 'No secret value changed.' });
    }
  }

  if (segments[0] === 'projects' && segments[2] === 'env' && segments.length === 4 && method === 'DELETE') {
    const userId = requireAuth();
    const p = await ownerProject(env, userId, segments[1]);
    if (!p) return json({ error: 'Project not found.' }, 404);
    checkCsrf();
    if (p.status === 'deploying' || projectOperations.has(p.id)) return json({ error: 'Environment variables cannot change while an operation is running.' }, 409);
    const key = decodeURIComponent(segments[3]);
    const result = await env.DB.prepare('DELETE FROM env_vars WHERE project_id=? AND key=?').bind(p.id, key).run();
    if (!result.meta || !result.meta.changes) return json({ error: 'Variable not found.' }, 404);
    await addActivity(env, userId, p.id, 'secret_deleted', `${key} was removed.`);
    return json({ variables: await envView(env, p.id) });
  }

  if (segments[0] === 'projects' && segments[2] === 'deployments' && method === 'GET') {
    const userId = requireAuth();
    const p = await ownerProject(env, userId, segments[1]);
    if (!p) return json({ error: 'Project not found.' }, 404);
    const deployments = await rows(env.DB.prepare('SELECT * FROM deployments WHERE project_id=? ORDER BY sequence DESC').bind(p.id));
    return json({ deployments: deployments.map(deploymentView) });
  }

  if (segments[0] === 'projects' && segments[2] === 'deploy' && method === 'POST') {
    const userId = requireAuth();
    checkCsrf();
    const p = await ownerProject(env, userId, segments[1]);
    if (!p) return json({ error: 'Project not found.' }, 404);
    if (p.status === 'deploying' || projectOperations.has(p.id)) return json({ error: 'Another operation is already in progress for this project.' }, 409);
    const started = Date.now();
    const deployment = await addDeploy(env, p.id, 'building', 'Deployment is being prepared.');
    await env.DB.prepare('UPDATE projects SET status=?,updated_at=? WHERE id=?').bind('deploying', nowISO(), p.id).run();
    await addActivity(env, userId, p.id, 'deployment_started', `${p.name} deployment started.`);
    projectOperations.add(p.id);
    try {
      const result = await deployWithWorker(env, p, deployment.id);
      let runtimeStatus = 'unknown';
      try {
        const measured = await workerRequest(env, `/v1/projects/${p.id}/status`, {}, 15000);
        if (['online', 'stopped', 'failed', 'unknown'].includes(measured.status)) runtimeStatus = measured.status;
      } catch {}
      const duration = Date.now() - started;
      const summary = runtimeStatus === 'online' ? 'Container deployed and process is running.'
        : runtimeStatus === 'stopped' ? 'Container was created, but its process is not running. Inspect runtime logs.'
        : 'Container deployment completed; runtime status could not be confirmed.';
      await env.DB.prepare('UPDATE deployments SET status=?,summary=?,finished_at=?,duration_ms=? WHERE id=?')
        .bind('success', summary, nowISO(), duration, deployment.id).run();
      await env.DB.prepare('UPDATE projects SET status=?,updated_at=?,last_deployed_at=? WHERE id=?').bind(runtimeStatus, nowISO(), nowISO(), p.id).run();
      await addActivity(env, userId, p.id, 'deployment_succeeded', `${p.name} deployment completed; runtime status is ${runtimeStatus}.`);
      const message = runtimeStatus === 'online' ? 'Deployment completed and the process is running.'
        : runtimeStatus === 'stopped' ? 'The image was deployed, but the process is stopped. Inspect runtime logs for the startup error.'
        : 'Deployment completed, but the worker could not confirm runtime status.';
      return json({
        project: await projectView(env, await ownerProject(env, userId, p.id)),
        deployment: deploymentView(await first(env.DB.prepare('SELECT * FROM deployments WHERE id=?').bind(deployment.id))),
        message: result?.message || message
      });
    } catch (error) {
      const duration = Date.now() - started;
      const aes = await aesKey(env);
      const secrets = aes ? (await readEnv(env, p.id, aes)).map((x) => x.value) : [];
      await env.DB.prepare('UPDATE deployments SET status=?,summary=?,finished_at=?,duration_ms=? WHERE id=?')
        .bind('failed', maskSecrets(error && error.message ? error.message : 'Deployment failed.', secrets), nowISO(), duration, deployment.id).run();
      await env.DB.prepare('UPDATE projects SET status=?,updated_at=? WHERE id=?').bind('failed', nowISO(), p.id).run();
      await addActivity(env, userId, p.id, 'deployment_failed', `${p.name} deployment failed.`);
      if (error instanceof ApiError) return json({ error: error.message }, error.status);
      throw error;
    } finally { projectOperations.delete(p.id); }
  }

  if (segments[0] === 'projects' && segments[2] === 'action' && method === 'POST') {
    const userId = requireAuth();
    checkCsrf();
    const p = await ownerProject(env, userId, segments[1]);
    if (!p) return json({ error: 'Project not found.' }, 404);
    if (p.status === 'deploying' || projectOperations.has(p.id)) return json({ error: 'Project actions are unavailable while another operation is running.' }, 409);
    const body = await readJson(request);
    const action = body.action;
    if (!['start', 'stop', 'restart', 'redeploy'].includes(action)) return json({ error: 'Unsupported project action.' }, 400);
    if (action === 'redeploy') {
      return new Response(null, { status: 307, headers: { location: `/api/projects/${p.id}/deploy` } });
    }
    projectOperations.add(p.id);
    try {
      await workerRequest(env, `/v1/projects/${p.id}/action`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action }) });
      const measured = await workerRequest(env, `/v1/projects/${p.id}/status`, {}, 15000);
      const status = ['online', 'stopped', 'failed', 'unknown'].includes(measured.status) ? measured.status : 'unknown';
      await env.DB.prepare("UPDATE projects SET status=?,updated_at=? WHERE id=? AND status <> 'deploying'").bind(status, nowISO(), p.id).run();
      await addActivity(env, userId, p.id, `project_${action}`, `${p.name} ${action} action completed; runtime status is ${status}.`);
      return json({ project: await projectView(env, await ownerProject(env, userId, p.id)), message: `Bot ${action} completed; runtime status is ${status}.` });
    } catch (error) {
      if (error instanceof ApiError) return json({ error: error.message }, error.status);
      throw error;
    } finally { projectOperations.delete(p.id); }
  }

  if (segments[0] === 'projects' && segments[2] === 'logs' && method === 'GET') {
    const userId = requireAuth();
    const p = await ownerProject(env, userId, segments[1]);
    if (!p) return json({ error: 'Project not found.' }, 404);
    const streamParam = url.searchParams.get('stream');
    const stream = ['build', 'runtime'].includes(streamParam) ? streamParam : 'runtime';
    const search = safeText(String(url.searchParams.get('search') || ''), 120).toLowerCase();
    try {
      const data = await workerRequest(env, `/v1/projects/${p.id}/logs?stream=${encodeURIComponent(stream)}`);
      let entries = data.entries || [];
      const aes = await aesKey(env);
      const secrets = aes ? (await readEnv(env, p.id, aes)).map((x) => x.value) : [];
      entries = entries.map((line) => ({ ...line, message: maskSecrets(line.message, secrets) }));
      if (search) entries = entries.filter((line) => line.message.toLowerCase().includes(search) || line.level.toLowerCase().includes(search));
      return json({ entries, stream, mode: 'container', cursor: data.cursor ?? null });
    } catch (error) {
      if (error instanceof ApiError) return json({ error: error.message }, error.status);
      throw error;
    }
  }

  if (segments[0] === 'projects' && segments[2] === 'logs' && segments[3] === 'stream' && method === 'GET') {
    const userId = requireAuth();
    const p = await ownerProject(env, userId, segments[1]);
    if (!p) return json({ error: 'Project not found.' }, 404);
    const streamParam = url.searchParams.get('stream');
    const stream = ['build', 'runtime'].includes(streamParam) ? streamParam : 'runtime';
    const workerBase = String(env.WORKER_URL || '').replace(/\/$/, '');
    if (!workerBase || !env.WORKER_TOKEN) return json({ error: 'A real container worker is not configured.' }, 503);
    const qs = new URLSearchParams({ stream });
    const offset = url.searchParams.get('offset');
    if (stream === 'build' && offset != null && /^\d+$/.test(String(offset))) qs.set('offset', String(offset));
    const since = url.searchParams.get('since');
    if (stream === 'runtime' && since && !Number.isNaN(Date.parse(String(since)))) qs.set('since', String(since));
    let upstream;
    try {
      upstream = await fetch(`${workerBase}/v1/projects/${encodeURIComponent(p.id)}/logs/stream?${qs}`, { headers: { authorization: `Bearer ${env.WORKER_TOKEN}`, accept: 'text/event-stream' } });
    } catch { return json({ error: 'Could not connect to the live log stream.' }, 502); }
    if (!upstream.ok) {
      const raw = await upstream.text();
      let detail = 'Could not connect to the live log stream.';
      try { detail = JSON.parse(raw).error || detail; } catch {}
      return json({ error: detail }, upstream.status);
    }
    return new Response(upstream.body, { status: 200, headers: { 'content-type': 'text/event-stream; charset=utf-8', 'cache-control': 'no-cache, no-transform', 'x-accel-buffering': 'no' } });
  }

  if (segments[0] === 'projects' && segments[2] === 'metrics' && method === 'GET') {
    const userId = requireAuth();
    const p = await ownerProject(env, userId, segments[1]);
    if (!p) return json({ error: 'Project not found.' }, 404);
    try {
      const measured = await workerRequest(env, `/v1/projects/${p.id}/status`);
      if (p.status !== 'deploying' && measured.status && ['online', 'stopped', 'failed', 'unknown'].includes(measured.status))
        await env.DB.prepare("UPDATE projects SET status=?,updated_at=? WHERE id=? AND status <> 'deploying'").bind(measured.status, nowISO(), p.id).run();
      const current = await first(env.DB.prepare('SELECT status FROM projects WHERE id=?').bind(p.id));
      return json(current?.status === 'deploying' ? { ...measured, status: 'deploying' } : measured);
    } catch (error) {
      if (error instanceof ApiError) return json({ error: error.message }, error.status);
      throw error;
    }
  }

  return json({ error: 'API endpoint not found.' }, 404);
}
