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

const STALE_DEPLOY_MS = 45 * 60 * 1000;
async function sweepStaleDeploy(env, p) {
  if (!p || p.status !== 'deploying') return p;
  const now = nowISO();
  const latest = await first(env.DB.prepare('SELECT * FROM deployments WHERE project_id=? ORDER BY sequence DESC LIMIT 1').bind(p.id));
  if (!latest || latest.status !== 'building') return p;
  let deployState = null;
  try { deployState = await workerRequest(env, `/v1/projects/${p.id}/deploy-state`, {}, 8000); } catch {}
  const finished = deployState && deployState.state ? deployState.state : null;
  const duration = Math.max(0, Date.now() - Date.parse(latest.created_at));
  const successSummary = 'Build and runtime logs scanned; no fatal errors. Process is running.';
  if (finished === 'deployed') {
    let runtimeStatus = 'online';
    try { const m = await workerRequest(env, `/v1/projects/${p.id}/status`, {}, 10000); if (['online', 'stopped', 'failed'].includes(m.status)) runtimeStatus = m.status; } catch {}
    await env.DB.prepare("UPDATE deployments SET status='success',summary=?,finished_at=?,duration_ms=? WHERE id=? AND status='building'")
      .bind(successSummary, now, duration, latest.id).run();
    await env.DB.prepare("UPDATE projects SET status=?,updated_at=?,last_deployed_at=? WHERE id=? AND status='deploying'").bind(runtimeStatus, now, now, p.id).run();
    await addActivity(env, p.user_id, p.id, 'deployment_succeeded', `${p.name} deployment completed.`);
    return { ...p, status: runtimeStatus };
  }
  if (finished === 'failed' || finished === 'canceled') {
    await env.DB.prepare("UPDATE deployments SET status='failed',summary=?,finished_at=?,duration_ms=? WHERE id=? AND status='building'")
      .bind(finished === 'canceled' ? 'Deployment canceled: the project was deleted.' : 'Deployment failed on the worker. Check the build logs and try again.', now, duration, latest.id).run();
    await env.DB.prepare("UPDATE projects SET status=?,updated_at=? WHERE id=? AND status='deploying'").bind(finished === 'canceled' ? 'stopped' : 'failed', now, p.id).run();
    if (finished !== 'canceled') await addActivity(env, p.user_id, p.id, 'deployment_failed', `${p.name} deployment failed.`);
    return { ...p, status: finished === 'canceled' ? 'stopped' : 'failed' };
  }
  const started = Date.parse(p.updated_at || p.created_at || '');
  const age = Number.isFinite(started) ? Date.now() - started : 0;
  if (age < STALE_DEPLOY_MS) return p;
  if (deployState && deployState.active) return p;
  let runtimeStatus = null;
  try { const m = await workerRequest(env, `/v1/projects/${p.id}/status`, {}, 10000); if (['online', 'stopped', 'failed', 'unknown'].includes(m.status)) runtimeStatus = m.status; } catch {}
  if (runtimeStatus === 'online') {
    await env.DB.prepare("UPDATE deployments SET status='success',summary=?,finished_at=?,duration_ms=? WHERE id=? AND status='building'")
      .bind(successSummary, now, duration, latest.id).run();
    await env.DB.prepare("UPDATE projects SET status='online',updated_at=?,last_deployed_at=? WHERE id=? AND status='deploying'").bind(now, now, p.id).run();
    await addActivity(env, p.user_id, p.id, 'deployment_succeeded', `${p.name} deployment completed.`);
    return { ...p, status: 'online' };
  }
  await env.DB.prepare("UPDATE deployments SET status='failed',summary=?,finished_at=?,duration_ms=? WHERE id=? AND status='building'")
    .bind('Deployment timed out: the worker stopped reporting progress. Check the build logs and try again.', now, duration, latest.id).run();
  await env.DB.prepare("UPDATE projects SET status='failed',updated_at=? WHERE id=? AND status='deploying'").bind(now, p.id).run();
  await addActivity(env, p.user_id, p.id, 'deployment_failed', `${p.name} deployment timed out and was marked failed.`);
  return { ...p, status: 'failed' };
}

async function liveProjectView(env, p, collect) {
  p = await sweepStaleDeploy(env, p);
  try {
    const measured = await workerRequest(env, `/v1/projects/${p.id}/status`, {}, 15000);
    if (collect && measured && measured.status === 'online' && Number.isFinite(Number(measured.uptime))) collect.push(Math.max(0, Number(measured.uptime)));
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

function toBytes(v) {
  if (v instanceof Uint8Array) return v;
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (ArrayBuffer.isView(v)) return new Uint8Array(v.buffer, v.byteOffset || 0, v.byteLength || 0);
  if (typeof v === 'string') return enc.encode(v);
  if (Array.isArray(v)) return new Uint8Array(v);
  return null;
}

async function loadBundle(env, bundleId) {
  if (!bundleId) return null;
  const parts = await rows(env.DB.prepare('SELECT seq, data FROM bundles WHERE bundle_id = ? ORDER BY seq').bind(bundleId));
  const chunks = [];
  let length = 0;
  for (const part of parts) {
    const c = toBytes(part.data);
    if (c === null) throw new ApiError(500, `Stored source archive could not be read (chunk type ${part.data === null ? 'null' : typeof part.data}${Array.isArray(part.data) ? ' array' : ''}). Re-upload the project.`);
    chunks.push(c); length += c.length;
  }
  const out = new Uint8Array(length);
  let offset = 0;
  for (const c of chunks) { out.set(c, offset); offset += c.length; }
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
    if (!bundle || !bundle.length) throw new ApiError(400, 'The uploaded source archive is missing. Re-upload the project.');
    const magic = Array.from(bundle.slice(0, 4)).map((b) => b.toString(16).padStart(2, '0')).join('');
    if (magic !== '504b0304') throw new ApiError(500, `Stored source archive failed its integrity check (${magic || 'empty'}). Re-upload the project.`);
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
CREATE TABLE IF NOT EXISTS email_verifications (email TEXT PRIMARY KEY, code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, last_sent_at INTEGER NOT NULL);
`;

let schemaPromise = null;
function ensureSchema(env) {
  if (!schemaPromise) {
    schemaPromise = env.DB.exec(DDL).then(async () => {
      for (const statement of ['ALTER TABLE users ADD COLUMN username TEXT', 'ALTER TABLE users ADD COLUMN username_lower TEXT', 'ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0', 'ALTER TABLE users ADD COLUMN github_id INTEGER', "ALTER TABLE users ADD COLUMN provider TEXT NOT NULL DEFAULT 'password'", 'ALTER TABLE users ADD COLUMN github_token TEXT']) {
        try { await env.DB.prepare(statement).run(); } catch (migrationError) { if (!/duplicate column name|already exists/i.test(String(migrationError && migrationError.message || ''))) throw migrationError; }
      }
      await env.DB.prepare('CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower ON users(username_lower)').run();
      await env.DB.prepare('CREATE UNIQUE INDEX IF NOT EXISTS users_github_id ON users(github_id)').run();
      await env.DB.prepare('CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)').run();
    }).catch((error) => { schemaPromise = null; throw error; });
  }
  return schemaPromise;
}

// --- GitHub sign-in credentials: env vars first, then the app_settings table filled by the one-click setup page ---

async function githubCreds(env) {
  if (env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET) return { clientId: env.GITHUB_CLIENT_ID, clientSecret: env.GITHUB_CLIENT_SECRET };
  try {
    await ensureSchema(env);
    const idRow = await first(env.DB.prepare('SELECT value FROM app_settings WHERE key = ?').bind('github_client_id'));
    const secRow = await first(env.DB.prepare('SELECT value FROM app_settings WHERE key = ?').bind('github_client_secret'));
    if (!idRow || !secRow) return null;
    const key = await aesKey(env);
    if (!key) return null;
    return { clientId: String(idRow.value), clientSecret: await decryptText(String(secRow.value), key) };
  } catch { return null; }
}

// --- row helpers ---

const first = async (q) => await q.first();
const rows = async (q) => (await q.all()).results || [];

const GMAIL_RE = /^[a-z0-9](?:[a-z0-9._%+-]{0,62}[a-z0-9])?@gmail\.com$/;
const USERNAME_RE = /^[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*$/;
function validateGmail(email) {
  if (!email || !GMAIL_RE.test(email)) return 'Enter a valid Gmail address ending in @gmail.com.';
  const local = email.slice(0, email.indexOf('@'));
  if (local.includes('+')) return 'Gmail aliases with a plus sign are not allowed. Use your plain Gmail address, like name@gmail.com.';
  return null;
}
function gmailCanonicalLocal(email) {
  const at = email.indexOf('@');
  if (at < 0 || !/@gmail\.com$/.test(email)) return null;
  return email.slice(0, at).replace(/\./g, '');
}
function validateUsername(username) {
  if (!username || username.length < 3 || username.length > 20) return 'Use between 3 and 20 characters for your username.';
  if (!USERNAME_RE.test(username)) return 'Usernames can only contain letters, numbers, and dots: no spaces, and a dot cannot start, end, or repeat.';
  return null;
}
function validatePassword(password) {
  if (!password || password.length < 10 || password.length > 128 || new Blob([password]).size > 72) return 'Use a password with at least 10 characters and no more than 72 UTF-8 bytes.';
  if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) return 'Include at least one letter and one number in your password.';
  return null;
}
// --- email verification (real 6-digit codes, hashed at rest; delivery over HTTPS because Render blocks SMTP) ---

const CODE_TTL_MS = 10 * 60 * 1000;
const CODE_RESEND_MS = 60 * 1000;
const CODE_MAX_ATTEMPTS = 5;
async function hashCodeValue(code, email, env) {
  const pepper = String(env.SESSION_SECRET || 'orbithost');
  const digest = await crypto.subtle.digest('SHA-256', enc.encode(`${pepper}|${email.toLowerCase()}|${code}`));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
const escapeHtmlEmail = (t) => String(t).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
async function sendVerificationEmail(env, to, code, username) {
  if (!env.BREVO_API_KEY || !env.SENDER_EMAIL) return { ok: false, error: 'Email delivery is not configured yet.' };
  const name = escapeHtmlEmail(username || 'there');
  const html = `<div style="font-family:Arial,Helvetica,sans-serif;background:#f4f5f7;padding:30px 12px"><div style="max-width:460px;margin:0 auto;background:#ffffff;border:1px solid #e2e5ea;border-radius:12px;padding:30px"><div style="font-size:12px;letter-spacing:2px;color:#8a8f98;font-weight:bold">ORBITHOST</div><h1 style="font-size:20px;color:#1a1d23;margin:14px 0 8px">Verify your email</h1><p style="font-size:14px;color:#3c4048;line-height:1.6;margin:0 0 18px">Hi ${name}, use this 6-digit code to finish creating your OrbitHost account. It expires in 10 minutes.</p><div style="font-size:32px;font-weight:bold;letter-spacing:10px;color:#1a1d23;background:#f2f3f5;border:1px solid #e2e5ea;border-radius:10px;padding:16px 0;text-align:center">${code}</div><p style="font-size:12px;color:#8a8f98;line-height:1.6;margin:18px 0 0">If you didn't create an OrbitHost account, you can ignore this email and the address will not be registered.</p></div></div>`;
  const text = `Your OrbitHost verification code is ${code}. It expires in 10 minutes. If you didn't create an account, ignore this email.`;
  let res;
  try {
    res = await fetch('https://api.brevo.com/v3/smtp/email', {
      method: 'POST',
      headers: { 'api-key': env.BREVO_API_KEY, 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify({ sender: { email: env.SENDER_EMAIL, name: env.SENDER_NAME || 'OrbitHost' }, to: [{ email: to }], subject: `Your OrbitHost verification code: ${code}`, htmlContent: html, textContent: text })
    });
  } catch (sendError) {
    return { ok: false, error: 'Could not reach the email service. Please try again.' };
  }
  if (!res.ok) return { ok: false, error: `The email service rejected the request (${res.status}). Please try again shortly.` };
  return { ok: true };
}
async function issueVerificationCode(env, email, username) {
  const code = String(crypto.getRandomValues(new Uint32Array(1))[0] % 1000000).padStart(6, '0');
  const now = Date.now();
  await env.DB.prepare('INSERT INTO email_verifications(email,code_hash,expires_at,attempts,last_sent_at) VALUES(?,?,?,?,?) ON CONFLICT(email) DO UPDATE SET code_hash=excluded.code_hash, expires_at=excluded.expires_at, attempts=0, last_sent_at=excluded.last_sent_at')
    .bind(email, await hashCodeValue(code, email, env), now + CODE_TTL_MS, 0, now).run();
  const sent = await sendVerificationEmail(env, email, code, username);
  return { sent: sent.ok, error: sent.error };
}
function publicUser(row) { return { id: row.id, email: row.email, username: row.username || null, createdAt: row.created_at, provider: row.provider || 'password', github: row.github_id != null }; }

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
    const gh = await githubCreds(env);
    return json({ hostingMode: 'worker', isPrototype: false, workerReady, maxUploadMb: MAX_UPLOAD_MB, pythonVersions: PYTHON_VERSIONS, githubEnabled: Boolean(gh) });
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
    const user = await first(env.DB.prepare('SELECT id,email,created_at,provider,github_id FROM users WHERE id = ?').bind(session.u));
    if (!user) return json({ user: null }, 200, { 'set-cookie': await clearSessionCookie() });
    return json({ user: publicUser(user) });
  }

  if (path === '/internal/worker/exit' && method === 'POST') {
    const auth = request.headers.get('authorization') || '';
    if (!env.WORKER_TOKEN || auth !== `Bearer ${env.WORKER_TOKEN}`) return json({ error: 'Unauthorized.' }, 401);
    const body = await readJson(request);
    const projectId = String(body.projectId || '');
    if (!/^[a-f0-9-]{36}$/i.test(projectId)) return json({ error: 'Invalid project ID.' }, 400);
    const p = await first(env.DB.prepare('SELECT * FROM projects WHERE id=?').bind(projectId));
    if (!p) return json({ ok: true, note: 'Project no longer exists.' });
    const codeRaw = Number(body.exitCode);
    const code = body.exitCode === null || body.exitCode === undefined || !Number.isFinite(codeRaw) ? null : codeRaw;
    const signal = safeText(String(body.signal || ''), 24);
    const uptimeSec = Math.max(0, Math.floor(Number(body.uptimeSec) || 0));
    const fatalLine = safeText(String(body.fatalLine || ''), 240);
    const reasonCode = safeText(String(body.reasonCode || ''), 40);
    const memoryKilledMb = Math.max(0, Math.floor(Number(body.memoryKilledMb) || 0));
    const memoryLimitMb = Math.max(0, Math.floor(Number(body.memoryLimitMb) || 0));
    const deploymentId = String(body.deploymentId || '');
    const crashed = code === null ? Boolean(signal) : code !== 0;
    if (!crashed) return json({ ok: true });
    const exitText = `Process exited ${code === null ? `on signal ${signal}` : `with exit code ${code}`}${uptimeSec ? ` after ${uptimeSec}s` : ''}.`;
    const reason = reasonCode === 'memory_limit'
      ? `Process exceeded the Free plan's memory budget${memoryKilledMb ? ` (was using about ${memoryKilledMb} MB)` : ''} and was stopped.`
      : `${exitText}${fatalLine ? ` Last fatal output: ${fatalLine}` : ''}`;
    const finalStatus = reasonCode === 'memory_limit' ? 'stopped' : 'failed';
    const aes = await aesKey(env);
    const secrets = aes ? (await readEnv(env, p.id, aes)).map((x) => x.value) : [];
    let deployment = null;
    if (/^[a-f0-9-]{36}$/i.test(deploymentId)) deployment = await first(env.DB.prepare('SELECT * FROM deployments WHERE id=? AND project_id=?').bind(deploymentId, projectId));
    if (!deployment) deployment = await first(env.DB.prepare('SELECT * FROM deployments WHERE project_id=? ORDER BY sequence DESC LIMIT 1').bind(projectId));
    const now = nowISO();
    if (p.status === 'deploying') {
      if (deployment && deployment.status === 'building') {
        await env.DB.prepare("UPDATE deployments SET status='failed',summary=?,finished_at=?,duration_ms=? WHERE id=? AND status='building'")
          .bind(maskSecrets(`Deployment failed: ${reason}`, secrets), now, Math.max(0, Date.now() - Date.parse(deployment.created_at)), deployment.id).run();
      }
      await env.DB.prepare("UPDATE projects SET status=?,updated_at=? WHERE id=? AND status='deploying'").bind(finalStatus, now, projectId).run();
      await addActivity(env, p.user_id, projectId, 'deployment_failed', `${p.name} deployment failed: ${exitText}`);
    } else if (deployment && deployment.status === 'success' && deployment.finished_at && Date.now() - Date.parse(deployment.finished_at) < 5 * 60 * 1000) {
      await env.DB.prepare("UPDATE deployments SET status='failed',summary=? WHERE id=?").bind(maskSecrets(`Runtime crash: ${reason}`, secrets), deployment.id).run();
      await env.DB.prepare("UPDATE projects SET status=?,updated_at=? WHERE id=? AND status <> 'deploying'").bind(finalStatus, now, projectId).run();
      await addActivity(env, p.user_id, projectId, 'deployment_failed', `${p.name} crashed after deployment: ${exitText}`);
    } else {
      await addActivity(env, p.user_id, projectId, 'deployment_failed', `${p.name} process exited unexpectedly: ${exitText}`);
      await env.DB.prepare("UPDATE projects SET status=?,updated_at=? WHERE id=? AND status='online'").bind(finalStatus, now, projectId).run();
    }
    return json({ ok: true });
  }

  // ---- worker-only internal endpoints (Bearer WORKER_TOKEN) ----

  if (path === '/internal/worker/running' && method === 'POST') {
    const auth = request.headers.get('authorization') || '';
    if (!env.WORKER_TOKEN || auth !== `Bearer ${env.WORKER_TOKEN}`) return json({ error: 'Unauthorized.' }, 401);
    const body = await readJson(request);
    const projectId = String(body.projectId || '');
    if (!/^[a-f0-9-]{36}$/i.test(projectId)) return json({ error: 'Invalid project ID.' }, 400);
    const p = await first(env.DB.prepare('SELECT id,status FROM projects WHERE id=?').bind(projectId));
    if (!p) return json({ ok: true, note: 'Project no longer exists.' });
    if (p.status === 'deploying') return json({ ok: true, note: 'Deploying.' });
    await env.DB.prepare("UPDATE projects SET status='online',updated_at=? WHERE id=?").bind(nowISO(), projectId).run();
    return json({ ok: true });
  }

  if (path === '/internal/worker/db' && method === 'POST') {
    const auth = request.headers.get('authorization') || '';
    if (!env.WORKER_TOKEN || auth !== `Bearer ${env.WORKER_TOKEN}`) return json({ error: 'Unauthorized.' }, 401);
    const body = await readJson(request);
    const sql = String(body.sql || '');
    if (!sql || sql.length > 8000 || /;\s*(attach|pragma)/i.test(sql)) return json({ error: 'Unsupported SQL.' }, 400);
    const params = Array.isArray(body.params) ? body.params : [];
    try {
      const bound = env.DB.prepare(sql).bind(...params);
      const result = /^\s*select/i.test(sql) ? await bound.all() : await bound.run();
      return json({ ok: true, rows: result.results === undefined ? [] : result.results });
    } catch (e) {
      return json({ error: safeText(String((e && e.message) || e), 300) }, 400);
    }
  }

  if (path === '/internal/worker/deploy-complete' && method === 'POST') {
    const auth = request.headers.get('authorization') || '';
    if (!env.WORKER_TOKEN || auth !== `Bearer ${env.WORKER_TOKEN}`) return json({ error: 'Unauthorized.' }, 401);
    const body = await readJson(request);
    const projectId = String(body.projectId || '');
    if (!/^[a-f0-9-]{36}$/i.test(projectId)) return json({ error: 'Invalid project ID.' }, 400);
    const p = await first(env.DB.prepare('SELECT * FROM projects WHERE id=?').bind(projectId));
    if (!p) return json({ ok: true, note: 'Project no longer exists.' });
    const outcome = String(body.outcome || '');
    const deploymentId = String(body.deploymentId || '');
    const summary = safeText(String(body.summary || ''), 500);
    const runtimeStatus = ['online', 'stopped', 'failed', 'unknown'].includes(String(body.runtimeStatus)) ? String(body.runtimeStatus) : null;
    if (!['deployed', 'failed', 'canceled'].includes(outcome)) return json({ error: 'Invalid outcome.' }, 400);
    let deployment = null;
    if (/^[a-f0-9-]{36}$/i.test(deploymentId)) deployment = await first(env.DB.prepare('SELECT * FROM deployments WHERE id=? AND project_id=?').bind(deploymentId, projectId));
    if (!deployment) deployment = await first(env.DB.prepare('SELECT * FROM deployments WHERE project_id=? ORDER BY sequence DESC LIMIT 1').bind(projectId));
    if (!deployment || deployment.status !== 'building') return json({ ok: true, note: 'Deployment already finalized.' });
    const now = nowISO();
    const aes = await aesKey(env);
    const secrets = aes ? (await readEnv(env, projectId, aes)).map((x) => x.value) : [];
    if (outcome === 'deployed') {
      await env.DB.prepare("UPDATE deployments SET status='success',summary=?,finished_at=?,duration_ms=? WHERE id=? AND status='building'")
        .bind(maskSecrets(summary || 'Deployment completed; build and runtime logs scanned.', secrets), now, Math.max(0, Date.now() - Date.parse(deployment.created_at)), deployment.id).run();
      await env.DB.prepare("UPDATE projects SET status=?,updated_at=?,last_deployed_at=? WHERE id=? AND status='deploying'")
        .bind(runtimeStatus || 'online', now, now, projectId).run();
      await addActivity(env, p.user_id, projectId, 'deployment_succeeded', `${p.name} deployment completed.`);
    } else {
      await env.DB.prepare("UPDATE deployments SET status='failed',summary=?,finished_at=?,duration_ms=? WHERE id=? AND status='building'")
        .bind(maskSecrets(summary || 'Deployment failed.', secrets), now, Math.max(0, Date.now() - Date.parse(deployment.created_at)), deployment.id).run();
      await env.DB.prepare("UPDATE projects SET status=?,updated_at=? WHERE id=? AND status='deploying'")
        .bind(outcome === 'canceled' ? 'stopped' : 'failed', now, projectId).run();
      if (outcome !== 'canceled') await addActivity(env, p.user_id, projectId, 'deployment_failed', `${p.name} deployment failed.`);
    }
    return json({ ok: true });
  }

  if (path.startsWith('/internal/worker/') && method === 'GET') {
    const auth = request.headers.get('authorization') || '';
    if (!env.WORKER_TOKEN || auth !== `Bearer ${env.WORKER_TOKEN}`) return json({ error: 'Unauthorized.' }, 401);
    if (path.startsWith('/internal/worker/exists/')) {
      const id = path.slice('/internal/worker/exists/'.length);
      if (!/^[a-f0-9-]{36}$/i.test(id)) return json({ error: 'Invalid project ID.' }, 400);
      const row = await first(env.DB.prepare('SELECT id FROM projects WHERE id=?').bind(id));
      return json({ exists: Boolean(row) });
    }
    if (path === '/internal/worker/restore') {
      const list = await rows(env.DB.prepare("SELECT id, source_type, repository_url, python_version, build_command, start_command, status FROM projects WHERE is_sample = 0 ORDER BY created_at ASC"));
      const aes = await aesKey(env);
      const out = [];
      for (const p of list) {
        const envPairs = aes ? await readEnv(env, p.id, aes) : [];
        out.push({ id: p.id, sourceType: p.source_type, repositoryUrl: p.repository_url || '', pythonVersion: p.python_version, buildCommand: p.build_command || '', startCommand: p.start_command || 'python main.py', status: p.status, env: Object.fromEntries(envPairs.map((x) => [x.key, x.value])) });
      }
      return json({ projects: out });
    }
    const bundleMatch = path.match(/^\/internal\/worker\/bundle\/([a-f0-9-]{36})$/i);
    if (bundleMatch) {
      const p = await first(env.DB.prepare('SELECT source_bundle, source_type FROM projects WHERE id = ?').bind(bundleMatch[1]));
      if (!p || p.source_type !== 'zip' || !p.source_bundle) return json({ error: 'No stored source archive for this project.' }, 404);
      const bundle = await loadBundle(env, p.source_bundle);
      if (!bundle || !bundle.length) return json({ error: 'Stored source archive is missing. Re-upload the project.' }, 404);
      return new Response(bundle, { status: 200, headers: { 'content-type': 'application/zip' } });
    }
    return json({ error: 'Not found.' }, 404);
  }

  if (path === '/auth/register/check-email' && method === 'POST') {
    await authRateLimit(env, ip);
    checkCsrf();
    const body = await readJson(request);
    const email = safeText(body.email, 254).toLowerCase();
    const gmailError = validateGmail(email);
    if (gmailError) return json({ error: gmailError }, 400);
    const dup = await first(env.DB.prepare('SELECT email_verified FROM users WHERE email = ?').bind(email));
    if (dup) return json({ error: dup.email_verified ? 'An account with that Gmail address is already registered.' : 'An account with that Gmail address is already registered. Sign in to finish verifying it.' }, 409);
    const gmailCanon = gmailCanonicalLocal(email);
    if (gmailCanon && gmailCanon !== email.slice(0, email.indexOf('@')) && await first(env.DB.prepare("SELECT 1 FROM users WHERE email LIKE '%@gmail.com' AND LOWER(REPLACE(SUBSTR(email,1,INSTR(email,'@')-1),'.','')) = ?").bind(gmailCanon))) return json({ error: 'An account with that Gmail address is already registered.' }, 409);
    return json({ ok: true });
  }

  if (path === '/auth/register/check-username' && method === 'POST') {
    await authRateLimit(env, ip);
    checkCsrf();
    const body = await readJson(request);
    const username = safeText(body.username, 32).trim();
    const usernameError = validateUsername(username);
    if (usernameError) return json({ error: usernameError }, 400);
    if (await first(env.DB.prepare('SELECT 1 FROM users WHERE username_lower = ?').bind(username.toLowerCase()))) return json({ error: 'That username is already taken.' }, 409);
    return json({ ok: true });
  }

  // ---- GitHub sign-in (OAuth user flow; auto-creates the account on first sign-in) ----

  if (path === '/auth/github/start' && method === 'GET') {
    const gh = await githubCreds(env);
    const params = new URL(request.url).searchParams;
    const mode = params.get('connect') === '1' && session?.u ? 'connect' : 'login';
    if (!gh) return new Response(null, { status: 302, headers: { location: '/?authError=github_unavailable' } });
    const origin = new URL(request.url).origin;
    const authorize = new URL('https://github.com/login/oauth/authorize');
    authorize.searchParams.set('client_id', gh.clientId);
    authorize.searchParams.set('redirect_uri', `${origin}/api/auth/github/callback`);
    authorize.searchParams.set('scope', 'read:user user:email');
    authorize.searchParams.set('state', `${bytesToB64url(crypto.getRandomValues(new Uint8Array(24)))}.${mode}`);
    return new Response(null, { status: 302, headers: { location: authorize.toString(), 'set-cookie': `gh_oauth_state=${authorize.searchParams.get('state')}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600` } });
  }

  if (path === '/auth/github/callback' && method === 'GET') {
    const land = (reason) => { const h = new Headers({ location: `/?authError=${reason}` }); h.append('set-cookie', 'gh_oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0'); return new Response(null, { status: 302, headers: h }); };
    const url = new URL(request.url);
    const code = url.searchParams.get('code') || '';
    const state = url.searchParams.get('state') || '';
    const cookieState = parseCookies(request).gh_oauth_state || '';
    if (url.searchParams.get('error')) return land('github_denied');
    const gh = await githubCreds(env);
    if (!gh) return land('github_unavailable');
    if (!code || !state || state !== cookieState) return land('github_expired');
    const mode = state.endsWith('.connect') && session?.u ? 'connect' : 'login';
    const ip = request.headers.get('cf-connecting-ip') || 'unknown';
    await authRateLimit(env, ip);
    let accessToken = '';
    try {
      const tokenRes = await fetch('https://github.com/login/oauth/access_token', { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify({ client_id: gh.clientId, client_secret: gh.clientSecret, code, redirect_uri: `${url.origin}/api/auth/github/callback` }) });
      const tokenJson = await tokenRes.json();
      if (tokenRes.ok && tokenJson && tokenJson.access_token) accessToken = String(tokenJson.access_token);
    } catch {}
    if (!accessToken) return land('github_failed');
    const ghHeaders = { authorization: `Bearer ${accessToken}`, accept: 'application/vnd.github+json', 'user-agent': 'OrbitHost' };
    let ghUser = null; let ghEmails = [];
    try { ghUser = await (await fetch('https://api.github.com/user', { headers: ghHeaders })).json(); } catch {}
    try { const eRes = await fetch('https://api.github.com/user/emails', { headers: ghHeaders }); if (eRes.ok) ghEmails = await eRes.json(); } catch {}
    if (!ghUser || !ghUser.id) return land('github_failed');
    const ghId = Number(ghUser.id);
    const verifiedEmails = (Array.isArray(ghEmails) ? ghEmails : []).filter((e) => e && e.verified && e.email);
    const chosen = verifiedEmails.find((e) => e.primary) || verifiedEmails[0] || null;
    if (!chosen) return land('github_no_email');
    const email = String(chosen.email).toLowerCase();
    let tokenCell = null;
    try { const key = await aesKey(env); if (key) tokenCell = await encryptText(accessToken, key); } catch {}
    if (mode === 'connect') {
      const conflict = await first(env.DB.prepare('SELECT id FROM users WHERE github_id = ? AND id != ?').bind(ghId, session.u));
      if (conflict) return land('github_conflict');
      await env.DB.prepare('UPDATE users SET github_id = ?, github_token = ? WHERE id = ?').bind(ghId, tokenCell, session.u).run();
      const h = new Headers({ location: '/?ghConnected=1' });
      h.append('set-cookie', 'gh_oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
      return new Response(null, { status: 302, headers: h });
    }
    let user = await first(env.DB.prepare('SELECT * FROM users WHERE github_id = ?').bind(ghId));
    if (!user) user = await first(env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email));
    if (user) {
      await env.DB.prepare('UPDATE users SET github_id = ?, github_token = ?, email_verified = CASE WHEN ? THEN 1 ELSE email_verified END WHERE id = ?').bind(ghId, tokenCell, chosen.verified ? 1 : 0, user.id).run();
      user = await first(env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(user.id));
    } else {
      let base = String(ghUser.login || '').toLowerCase().replace(/-/g, '.').replace(/[^a-z0-9.]/g, '').replace(/\.{2,}/g, '.').replace(/^\.+|\.+$/g, '').slice(0, 18);
      if (!/^[a-z0-9]/.test(base)) base = `u${base}`;
      let username = base.length >= 3 ? base : 'ghuser';
      for (let n = 1; n <= 60; n += 1) {
        const taken = await first(env.DB.prepare('SELECT 1 FROM users WHERE username_lower = ?').bind(username.toLowerCase()));
        if (!taken) break;
        username = `${base || 'ghuser'}${n + 1}`.slice(0, 20);
      }
      const usernameError = validateUsername(username);
      if (usernameError) return land('github_username');
      user = { id: crypto.randomUUID(), created_at: nowISO() };
      await env.DB.prepare('INSERT INTO users(id,email,username,username_lower,password_hash,email_verified,github_id,provider,created_at) VALUES(?,?,?,?,?,?,?,\'github\',?)')
        .bind(user.id, email, username, username.toLowerCase(), `oauth-${bytesToB64url(crypto.getRandomValues(new Uint8Array(24)))}`, chosen.verified ? 1 : 0, ghId, user.created_at).run();
      user = await first(env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(user.id));
    }
    if (!user) return land('github_failed');
    if (!user.email_verified && !chosen.verified) return land('github_unverified');
    const sessionData = { u: user.id, c: bytesToB64url(crypto.getRandomValues(new Uint8Array(32))), e: Date.now() + SESSION_TTL_MS };
    const headers = new Headers({ location: '/' });
    headers.append('set-cookie', await writeSession(env, sessionData));
    headers.append('set-cookie', 'gh_oauth_state=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0');
    return new Response(null, { status: 302, headers });
  }

  if (path === '/auth/github/repos' && method === 'GET') {
    const userId = requireAuth();
    const row = await first(env.DB.prepare('SELECT github_token, github_id FROM users WHERE id = ?').bind(userId));
    if (!row || row.github_id == null) return json({ connected: false, repos: [] });
    let token = '';
    try { const key = await aesKey(env); if (key && row.github_token) token = await decryptText(String(row.github_token), key); } catch {}
    if (!token) return json({ connected: true, repos: [] });
    try {
      const res = await fetch('https://api.github.com/user/repos?per_page=100&sort=updated&affiliation=owner,collaborator,organization_member', { headers: { authorization: `Bearer ${token}`, accept: 'application/vnd.github+json', 'user-agent': 'OrbitHost' }, signal: AbortSignal.timeout(8000) });
      if (!res.ok) return json({ connected: true, repos: [] });
      const list = await res.json();
      const repos = (Array.isArray(list) ? list : []).map((r) => ({ name: r.full_name || r.name, cloneUrl: r.clone_url || '', private: Boolean(r.private), updatedAt: r.updated_at || '', description: r.description || '' }));
      return json({ connected: true, repos });
    } catch { return json({ connected: true, repos: [] }); }
  }

  if (path === '/auth/github/disconnect' && method === 'POST') {
    const userId = requireAuth();
    checkCsrf();
    const row = await first(env.DB.prepare('SELECT provider, password_hash FROM users WHERE id = ?').bind(userId));
    if (!row) fail(404, 'Account not found.');
    if (row.provider === 'github' && !String(row.password_hash || '').startsWith('pbkdf2$')) fail(409, 'This account signs in with GitHub only, so GitHub cannot be disconnected. Add a password sign-in first.');
    await env.DB.prepare('UPDATE users SET github_id = NULL, github_token = NULL WHERE id = ?').bind(userId).run();
    return json({ ok: true });
  }

  if (path === '/auth/register' && method === 'POST') {
    await authRateLimit(env, ip);
    checkCsrf();
    const body = await readJson(request);
    const email = safeText(body.email, 254).toLowerCase();
    const username = safeText(body.username, 32).trim();
    const password = typeof body.password === 'string' ? body.password : '';
    const gmailError = validateGmail(email);
    if (gmailError) return json({ error: gmailError }, 400);
    const dup = await first(env.DB.prepare('SELECT email_verified FROM users WHERE email = ?').bind(email));
    if (dup) return json({ error: dup.email_verified ? 'An account with that Gmail address is already registered.' : 'An account with that Gmail address is already registered. Sign in to finish verifying it.' }, 409);
    const gmailCanon = gmailCanonicalLocal(email);
    if (gmailCanon && gmailCanon !== email.slice(0, email.indexOf('@')) && await first(env.DB.prepare("SELECT 1 FROM users WHERE email LIKE '%@gmail.com' AND LOWER(REPLACE(SUBSTR(email,1,INSTR(email,'@')-1),'.','')) = ?").bind(gmailCanon))) return json({ error: 'An account with that Gmail address is already registered.' }, 409);
    const usernameError = validateUsername(username);
    if (usernameError) return json({ error: usernameError }, 400);
    if (await first(env.DB.prepare('SELECT 1 FROM users WHERE username_lower = ?').bind(username.toLowerCase()))) return json({ error: 'That username is already taken.' }, 409);
    const passwordError = validatePassword(password);
    if (passwordError) return json({ error: passwordError }, 400);
    const user = { id: crypto.randomUUID(), email, username, created_at: nowISO() };
    await env.DB.prepare('INSERT INTO users(id,email,username,username_lower,password_hash,email_verified,created_at) VALUES(?,?,?,?,?,0,?)')
      .bind(user.id, email, username, username.toLowerCase(), await hashPassword(password, env), user.created_at).run();
    const mailed = await issueVerificationCode(env, user.email, username);
    if (!mailed.sent) {
      await env.DB.prepare('DELETE FROM email_verifications WHERE email = ?').bind(user.email).run();
      await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(user.id).run();
      return json({ error: mailed.error || 'We could not send the verification email. Please try again.' }, 502);
    }
    return json({ needsVerification: true, email: user.email }, 201);
  }

  if (path === '/auth/verify' && method === 'POST') {
    await authRateLimit(env, ip);
    checkCsrf();
    const body = await readJson(request);
    const email = safeText(body.email, 254).toLowerCase();
    const code = String(body.code || '').replace(/\D/g, '');
    if (!GMAIL_RE.test(email)) return json({ error: 'Enter a valid Gmail address.' }, 400);
    if (code.length !== 6) return json({ error: 'Enter the 6-digit code from your email.' }, 400);
    let user = await first(env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email));
    if (!user) {
      const gmailCanon = gmailCanonicalLocal(email);
      if (gmailCanon) user = await first(env.DB.prepare("SELECT * FROM users WHERE email LIKE '%@gmail.com' AND LOWER(REPLACE(SUBSTR(email,1,INSTR(email,'@')-1),'.','')) = ?").bind(gmailCanon));
    }
    if (!user) return json({ error: 'No account is waiting for verification at that address.' }, 404);
    if (user.email_verified) return json({ error: 'That account is already verified. Sign in instead.' }, 400);
    const row = await first(env.DB.prepare('SELECT * FROM email_verifications WHERE email = ?').bind(user.email));
    const now = Date.now();
    if (!row) return json({ error: 'No active code for that address. Request a new one below.' }, 400);
    if (row.expires_at < now) return json({ error: 'That code has expired. Request a new one below.' }, 410);
    if (row.attempts >= CODE_MAX_ATTEMPTS) {
      await env.DB.prepare('DELETE FROM email_verifications WHERE email = ?').bind(user.email).run();
      return json({ error: 'Too many wrong attempts. Request a new code.' }, 429);
    }
    if ((await hashCodeValue(code, user.email, env)) !== row.code_hash) {
      const attempts = (row.attempts || 0) + 1;
      if (attempts >= CODE_MAX_ATTEMPTS) await env.DB.prepare('DELETE FROM email_verifications WHERE email = ?').bind(user.email).run();
      else await env.DB.prepare('UPDATE email_verifications SET attempts = ? WHERE email = ?').bind(attempts, user.email).run();
      return json({ error: attempts >= CODE_MAX_ATTEMPTS ? 'Too many wrong attempts. Request a new code.' : "That code isn't right. Check the latest email and try again." }, 400);
    }
    await env.DB.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').bind(user.id).run();
    await env.DB.prepare('DELETE FROM email_verifications WHERE email = ?').bind(user.email).run();
    const sessionData = { u: user.id, c: bytesToB64url(crypto.getRandomValues(new Uint8Array(32))), e: Date.now() + SESSION_TTL_MS };
    return json({ user: publicUser(user), csrfToken: sessionData.c }, 200, { 'set-cookie': await writeSession(env, sessionData) });
  }

  if (path === '/auth/verify/resend' && method === 'POST') {
    await authRateLimit(env, ip);
    checkCsrf();
    const body = await readJson(request);
    const email = safeText(body.email, 254).toLowerCase();
    if (!GMAIL_RE.test(email)) return json({ error: 'Enter a valid Gmail address.' }, 400);
    let user = await first(env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email));
    if (!user) {
      const gmailCanon = gmailCanonicalLocal(email);
      if (gmailCanon) user = await first(env.DB.prepare("SELECT * FROM users WHERE email LIKE '%@gmail.com' AND LOWER(REPLACE(SUBSTR(email,1,INSTR(email,'@')-1),'.','')) = ?").bind(gmailCanon));
    }
    if (!user) return json({ error: 'No account is waiting for verification at that address.' }, 404);
    if (user.email_verified) return json({ error: 'That account is already verified. Sign in instead.' }, 400);
    const row = await first(env.DB.prepare('SELECT last_sent_at FROM email_verifications WHERE email = ?').bind(user.email));
    if (row && Date.now() - row.last_sent_at < CODE_RESEND_MS) return json({ error: 'A code was just sent. Please wait a minute before asking for another.' }, 429);
    const mailed = await issueVerificationCode(env, user.email, user.username);
    if (!mailed.sent) return json({ error: mailed.error || 'We could not send the verification email. Please try again.' }, 502);
    return json({ ok: true });
  }

  if (path === '/auth/login' && method === 'POST') {
    await authRateLimit(env, ip);
    checkCsrf();
    const body = await readJson(request);
    const email = safeText(body.email, 254).toLowerCase();
    const password = typeof body.password === 'string' ? body.password : '';
    let user = await first(env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email));
    if (!user) {
      const gmailCanon = gmailCanonicalLocal(email);
      if (gmailCanon) user = await first(env.DB.prepare("SELECT * FROM users WHERE email LIKE '%@gmail.com' AND LOWER(REPLACE(SUBSTR(email,1,INSTR(email,'@')-1),'.','')) = ?").bind(gmailCanon));
    }
    if (new Blob([password]).size > 72 || !user || !(await verifyPassword(password, user.password_hash))) {
      return json({ error: 'Email or password is incorrect.' }, 401);
    }
    if (!user.email_verified) return json({ needsVerification: true, email: user.email }, 403);
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
    const onlineUptimes = [];
    for (const p of projectRows) projects.push(await liveProjectView(env, p, onlineUptimes));
    const count = (status) => projects.filter((p) => p.status === status).length;
    const activity = (await rows(env.DB.prepare('SELECT a.id,a.action,a.message,a.created_at,p.name AS project_name FROM activities a LEFT JOIN projects p ON p.id=a.project_id WHERE a.user_id=? ORDER BY a.id DESC LIMIT 8').bind(userId)))
      .map((a) => ({ id: a.id, action: a.action, message: a.message, createdAt: a.created_at, projectName: a.project_name }));
    const deploys = await rows(env.DB.prepare('SELECT d.*,p.name AS project_name FROM deployments d JOIN projects p ON p.id=d.project_id WHERE p.user_id=? ORDER BY d.created_at DESC LIMIT 6').bind(userId));
    return json({
      projects, activity,
      recentDeployments: deploys.map((d) => ({ ...deploymentView(d), projectName: d.project_name })),
      stats: { total: projects.length, online: count('online'), stopped: count('stopped'), deploying: count('deploying'), uptime: onlineUptimes.reduce((a, b) => a + b, 0) },
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
    let p = await ownerProject(env, userId, segments[1]);
    if (!p) return json({ error: 'Project not found.' }, 404);

    if (method === 'GET') {
      p = await sweepStaleDeploy(env, p);
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
      projectOperations.add(p.id);
      try {
        const deleteResult = await workerRequest(env, `/v1/projects/${p.id}/action`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action: 'delete' }) });
        await env.DB.prepare("UPDATE deployments SET status='failed',summary='Deployment canceled: the project was deleted.',finished_at=?,duration_ms=0 WHERE project_id=? AND status='building'").bind(nowISO(), p.id).run();
        await addActivity(env, userId, null, 'project_deleted', `${p.name} was deleted.${deleteResult && deleteResult.wasRunning ? ' Its running bot process was stopped.' : ''}`);
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
    let p = await ownerProject(env, userId, segments[1]);
    if (!p) return json({ error: 'Project not found.' }, 404);
    p = await sweepStaleDeploy(env, p);
    if (p.status === 'deploying' || projectOperations.has(p.id)) return json({ error: 'Another operation is already in progress for this project.' }, 409);
    const started = Date.now();
    const deployment = await addDeploy(env, p.id, 'building', 'Deployment is being prepared.');
    await env.DB.prepare('UPDATE projects SET status=?,updated_at=? WHERE id=?').bind('deploying', nowISO(), p.id).run();
    await addActivity(env, userId, p.id, 'deployment_started', `${p.name} deployment started.`);
    projectOperations.add(p.id);
    const deployTimeoutMs = Math.max(60000, Number(env.DEPLOY_TIMEOUT_MS || 30 * 60 * 1000));
    let deployTimer;
    try {
      const result = await Promise.race([
        deployWithWorker(env, p, deployment.id),
        new Promise((_, reject) => { deployTimer = setTimeout(() => reject(new ApiError(504, 'Deployment timed out: the worker stopped responding. Check the build logs and try again.')), deployTimeoutMs); })
      ]);
      if (deployTimer) clearTimeout(deployTimer);
      const still = await first(env.DB.prepare('SELECT id FROM projects WHERE id=?').bind(p.id));
      if (!still) return json({ error: 'Project was deleted during its deployment.' }, 409);
      let runtimeStatus = 'unknown';
      try {
        const measured = await workerRequest(env, `/v1/projects/${p.id}/status`, {}, 15000);
        if (['online', 'stopped', 'failed', 'unknown'].includes(measured.status)) runtimeStatus = measured.status;
      } catch {}
      const duration = Date.now() - started;
      const summary = runtimeStatus === 'online' ? 'Build and runtime logs scanned; no fatal errors. Process is running.'
        : runtimeStatus === 'stopped' ? 'Container was created, but its process is not running. Inspect runtime logs.'
        : 'Container deployment completed; runtime status could not be confirmed.';
      await env.DB.prepare("UPDATE deployments SET status='success',summary=?,finished_at=?,duration_ms=? WHERE id=? AND status='building'")
        .bind(summary, nowISO(), duration, deployment.id).run();
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
      const gone = await first(env.DB.prepare('SELECT id FROM projects WHERE id=?').bind(p.id));
      if (!gone) return json({ error: 'Project was deleted during its deployment.' }, 409);
      const duration = Date.now() - started;
      const aes = await aesKey(env);
      const secrets = aes ? (await readEnv(env, p.id, aes)).map((x) => x.value) : [];
      await env.DB.prepare("UPDATE deployments SET status='failed',summary=?,finished_at=?,duration_ms=? WHERE id=? AND status='building'")
        .bind(maskSecrets(error && error.message ? error.message : 'Deployment failed.', secrets), nowISO(), duration, deployment.id).run();
      await env.DB.prepare('UPDATE projects SET status=?,updated_at=? WHERE id=?').bind('failed', nowISO(), p.id).run();
      await addActivity(env, userId, p.id, 'deployment_failed', `${p.name} deployment failed.`);
      if (error instanceof ApiError) return json({ error: error.message }, error.status);
      return json({ error: (error && error.message) || 'Deployment failed.' }, 500);
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
    await sweepStaleDeploy(env, p);
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
