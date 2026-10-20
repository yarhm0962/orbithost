import 'dotenv/config';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import express from 'express';
import session from 'express-session';
import helmet from 'helmet';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import { rateLimit } from 'express-rate-limit';
import yauzl from 'yauzl';
import { db, SQLiteSessionStore, now, uuid, addActivity, addLog } from './db.js';
import { encryptText, decryptText, safeText, isValidEnvKey, isValidPythonVersion, safeHttpsRepository, maskSecrets } from './security.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const app = express();
const PORT = Number(process.env.PORT || 8080);
const MODE = process.env.HOSTING_MODE || 'demo';
const UPLOAD_DIR = path.resolve(process.env.UPLOAD_DIR || './.data/uploads');
const MAX_UPLOAD_MB = Math.min(100, Math.max(1, Number(process.env.MAX_UPLOAD_MB || 25)));
const allowedPythonVersions = ['3.10', '3.11', '3.12', '3.13'];
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const appSecret = process.env.SESSION_SECRET || '';
const production = process.env.NODE_ENV === 'production';

if (!['demo','worker'].includes(MODE)) throw new Error('HOSTING_MODE must be either demo or worker.');
if (production && (appSecret.length < 32 || /replace-with|development-only/i.test(appSecret))) throw new Error('SESSION_SECRET must be a unique high-entropy value of at least 32 characters in production.');
if (MODE === 'worker' && (!process.env.WORKER_URL || !process.env.WORKER_TOKEN || process.env.WORKER_TOKEN.length < 32 || /replace-with/i.test(process.env.WORKER_TOKEN))) throw new Error('HOSTING_MODE=worker requires WORKER_URL and a unique WORKER_TOKEN of at least 32 characters.');
if (!process.env.ENV_ENCRYPTION_KEY || !/^[a-f0-9]{64}$/i.test(process.env.ENV_ENCRYPTION_KEY)) {
  if (production) throw new Error('ENV_ENCRYPTION_KEY must be 64 hex characters in production. Generate one with: openssl rand -hex 32');
  console.warn('WARNING: ENV_ENCRYPTION_KEY is missing or invalid. Secret-setting endpoints will be unavailable until configured.');
}
fs.mkdirSync(UPLOAD_DIR, { recursive: true, mode: 0o700 });
app.disable('x-powered-by');
if (process.env.TRUST_PROXY === '1') app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"], baseUri: ["'self'"], objectSrc: ["'none'"], frameAncestors: ["'none'"],
      scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"],
      formAction: ["'self'"], upgradeInsecureRequests: production ? [] : null
    }
  }, crossOriginEmbedderPolicy: false
}));
app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: false, limit: '32kb' }));
app.use(session({
  name: 'orb.sid', secret: appSecret || 'development-only-change-this-session-secret',
  store: new SQLiteSessionStore(), resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'strict', secure: production, maxAge: 1000 * 60 * 60 * 24 * 7, path: '/' }
}));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60 * 1000, limit: 25, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Too many authentication attempts. Try again later.' } }));
app.use('/api', rateLimit({ windowMs: 60 * 1000, limit: 300, standardHeaders: 'draft-7', legacyHeaders: false, message: { error: 'Request rate limit reached. Try again shortly.' } }));

const upload = multer({ storage: multer.diskStorage({ destination: (_req, _file, cb) => cb(null, UPLOAD_DIR), filename: (_req, _file, cb) => cb(null, `.incoming-${uuid()}.upload`) }), limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024, files: 1, fields: 12, fieldSize: 20000 } });
const apiError = (res, status, error) => res.status(status).json({ error });
const requireAuth = (req, res, next) => req.session?.userId ? next() : apiError(res, 401, 'Please sign in to continue.');
function csrf(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const header = req.get('x-csrf-token');
  if (!req.session?.csrfToken || !header || header !== req.session.csrfToken) return apiError(res, 403, 'Your session token expired. Refresh the page and try again.');
  next();
}
app.use('/api', csrf);
function publicUser(row) { return { id: row.id, email: row.email, createdAt: row.created_at }; }
function ownerProject(userId, projectId) {
  return db.prepare('SELECT * FROM projects WHERE id = ? AND user_id = ?').get(projectId, userId);
}
function projectView(p) {
  const envCount = db.prepare('SELECT count(*) AS count FROM env_vars WHERE project_id = ?').get(p.id).count;
  const deployCount = db.prepare('SELECT count(*) AS count FROM deployments WHERE project_id = ?').get(p.id).count;
  return {
    id: p.id, name: p.name, sourceType: p.source_type, repositoryUrl: p.repository_url,
    pythonVersion: p.python_version, buildCommand: p.build_command, startCommand: p.start_command,
    status: p.status, isSample: Boolean(p.is_sample), createdAt: p.created_at, updatedAt: p.updated_at,
    lastDeployedAt: p.last_deployed_at, environmentCount: envCount, deploymentCount: deployCount,
    runtimeMode: MODE === 'demo' ? 'simulated' : 'container'
  };
}
function readEnv(projectId) {
  return db.prepare('SELECT key, encrypted_value FROM env_vars WHERE project_id = ? ORDER BY key').all(projectId)
    .map((row) => ({ key: row.key, value: decryptText(row.encrypted_value) }));
}
function envView(projectId) {
  return db.prepare('SELECT key, created_at, updated_at FROM env_vars WHERE project_id = ? ORDER BY key').all(projectId)
    .map((row) => ({ key: row.key, isSet: true, maskedValue: '••••••••', createdAt: row.created_at, updatedAt: row.updated_at }));
}
function addDeploy(projectId, status, summary, trigger = 'manual', duration = null) {
  const seq = db.prepare('SELECT COALESCE(MAX(sequence),0)+1 AS n FROM deployments WHERE project_id = ?').get(projectId).n;
  const timestamp = now();
  const id = uuid();
  db.prepare('INSERT INTO deployments(id,project_id,sequence,status,trigger,summary,created_at,finished_at,duration_ms) VALUES(?,?,?,?,?,?,?,?,?)')
    .run(id, projectId, seq, status, trigger, summary, timestamp, status === 'building' ? null : timestamp, duration);
  return db.prepare('SELECT * FROM deployments WHERE id = ?').get(id);
}
function deploymentView(d) {
  return { id: d.id, sequence: d.sequence, status: d.status, trigger: d.trigger, summary: d.summary, createdAt: d.created_at, finishedAt: d.finished_at, durationMs: d.duration_ms };
}
function createDemoSeeds(userId) {
  if (MODE !== 'demo') return;
  const existing = db.prepare('SELECT count(*) AS n FROM projects WHERE user_id = ?').get(userId).n;
  if (existing) return;
  const seeds = [
    { name: 'lunar-moderator', status: 'online', python: '3.12', start: 'python main.py', kind: 'success', summary: 'Sample deployment completed' },
    { name: 'welcome-engine', status: 'stopped', python: '3.11', start: 'python bot.py', kind: 'stopped', summary: 'Sample service is stopped' }
  ];
  for (const s of seeds) {
    const id = uuid(); const ts = now();
    db.prepare('INSERT INTO projects(id,user_id,name,source_type,python_version,build_command,start_command,status,is_sample,created_at,updated_at,last_deployed_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')
      .run(id,userId,s.name,'demo',s.python,'',s.start,s.status,1,ts,ts,s.status === 'online' ? ts : null);
    const dep = addDeploy(id, s.kind, s.summary, 'sample', 1840);
    addLog(id, 'runtime', 'info', `[${ts}] ${s.name} — sample runtime initialized`);
    addLog(id, 'runtime', 'info', s.status === 'online' ? 'Connected to Discord gateway (sample data only).' : 'Service stopped by user (sample data only).');
    addLog(id, 'build', 'info', `Python ${s.python} environment prepared (sample data).`);
  }
  addActivity(userId, null, 'workspace_created', 'Your workspace is ready with sample projects.');
}

function inspectZip(filePath) {
  return new Promise((resolve, reject) => {
    yauzl.open(filePath, { lazyEntries: true, decodeStrings: true, validateEntrySizes: true, strictFileNames: true }, (err, zip) => {
      if (err) return reject(new Error('The ZIP file could not be opened.'));
      let count = 0, expanded = 0;
      let failed = false;
      const fail = (message) => { if (failed) return; failed = true; try { zip.close(); } catch {} reject(new Error(message)); };
      zip.on('error', () => fail('The ZIP archive is damaged or invalid.'));
      zip.on('entry', (entry) => {
        if (failed) return;
        const name = entry.fileName;
        const normalized = path.posix.normalize(name);
        const mode = (entry.externalFileAttributes >>> 16) & 0o170000;
        if (!name || name.includes('\0') || name.includes('\\') || name.startsWith('/') || /^[a-zA-Z]:/.test(name) || name.split('/').includes('..') || normalized === '..' || normalized.startsWith('../')) return fail('ZIP contains an unsafe file path.');
        if (mode === 0o120000) return fail('ZIP symbolic links are not allowed.');
        count++; expanded += Number(entry.uncompressedSize || 0);
        if (count > 2000) return fail('ZIP contains too many files (maximum 2,000).');
        if (expanded > 200 * 1024 * 1024) return fail('ZIP expands beyond the 200 MB limit.');
        if (Number(entry.uncompressedSize || 0) > 80 * 1024 * 1024) return fail('A single ZIP entry is too large.');
        zip.readEntry();
      });
      zip.on('end', () => { if (!failed) { if (!count) return reject(new Error('ZIP archive is empty.')); resolve({ files: count, expandedBytes: expanded }); } });
      zip.readEntry();
    });
  });
}

async function workerRequest(route, options = {}) {
  const base = (process.env.WORKER_URL || '').replace(/\/$/, '');
  if (!base || !process.env.WORKER_TOKEN) throw new Error('Container worker is not configured.');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Number(process.env.WORKER_TIMEOUT_MS || 180000));
  try {
    const response = await fetch(`${base}${route}`, { ...options, signal: controller.signal, headers: { authorization: `Bearer ${process.env.WORKER_TOKEN}`, ...(options.headers || {}) } });
    const raw = await response.text();
    let data; try { data = raw ? JSON.parse(raw) : {}; } catch { data = {}; }
    if (!response.ok) throw new Error(data.error || `Worker returned ${response.status}.`);
    return data;
  } finally { clearTimeout(timer); }
}
async function deployWithWorker(p, deploymentId) {
  const env = Object.fromEntries(readEnv(p.id).map((item) => [item.key, item.value]));
  const form = new FormData();
  form.set('projectId', p.id);
  form.set('pythonVersion', p.python_version);
  form.set('buildCommand', p.build_command || '');
  form.set('startCommand', p.start_command || 'python main.py');
  form.set('envJson', JSON.stringify(env));
  form.set('deploymentId', deploymentId);
  if (p.source_type === 'git') form.set('repositoryUrl', p.repository_url || '');
  else if (p.source_type === 'zip' && p.source_path && fs.existsSync(p.source_path)) {
    const bundle = await fs.openAsBlob(p.source_path, { type: 'application/zip' });
    form.set('bundle', bundle, `${p.id}.zip`);
  } else throw new Error('This project has no deployable source. Upload a ZIP or connect a Git repository first.');
  return workerRequest('/v1/deploy', { method: 'POST', body: form });
}

app.get('/api/health', (req, res) => res.json({ ok: true, service: 'orbithost-control-plane', mode: MODE, time: now() }));
app.get('/api/config', (req, res) => res.json({ hostingMode: MODE, isPrototype: MODE === 'demo', maxUploadMb: MAX_UPLOAD_MB, pythonVersions: allowedPythonVersions }));
app.get('/api/auth/csrf', (req, res) => {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(32).toString('base64url');
  res.json({ csrfToken: req.session.csrfToken });
});
app.get('/api/auth/me', (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  const user = db.prepare('SELECT id,email,created_at FROM users WHERE id = ?').get(req.session.userId);
  if (!user) { req.session.destroy(() => {}); return res.json({ user: null }); }
  res.json({ user: publicUser(user) });
});
app.post('/api/auth/register', async (req, res, next) => {
  try {
    const email = safeText(req.body?.email, 254).toLowerCase();
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    if (!emailPattern.test(email)) return apiError(res, 400, 'Enter a valid email address.');
    if (password.length < 10 || password.length > 128 || Buffer.byteLength(password, 'utf8') > 72) return apiError(res, 400, 'Use a password with at least 10 characters and no more than 72 UTF-8 bytes.');
    if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) return apiError(res, 409, 'An account with that email already exists.');
    const user = { id: uuid(), email, created_at: now() };
    db.prepare('INSERT INTO users(id,email,password_hash,created_at) VALUES(?,?,?,?)').run(user.id, email, await bcrypt.hash(password, 12), user.created_at);
    createDemoSeeds(user.id);
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId = user.id; req.session.csrfToken = crypto.randomBytes(32).toString('base64url');
      req.session.save((saveErr) => saveErr ? next(saveErr) : res.status(201).json({ user: publicUser(user), csrfToken: req.session.csrfToken }));
    });
  } catch (error) { next(error); }
});
app.post('/api/auth/login', async (req, res, next) => {
  try {
    const email = safeText(req.body?.email, 254).toLowerCase();
    const password = typeof req.body?.password === 'string' ? req.body.password : '';
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (Buffer.byteLength(password, 'utf8') > 72 || !user || !(await bcrypt.compare(password, user.password_hash))) return apiError(res, 401, 'Email or password is incorrect.');
    req.session.regenerate((err) => {
      if (err) return next(err);
      req.session.userId = user.id; req.session.csrfToken = crypto.randomBytes(32).toString('base64url');
      req.session.save((saveErr) => saveErr ? next(saveErr) : res.json({ user: publicUser(user), csrfToken: req.session.csrfToken }));
    });
  } catch (error) { next(error); }
});
app.post('/api/auth/logout', requireAuth, (req, res, next) => req.session.destroy((err) => {
  if (err) return next(err); res.clearCookie('orb.sid', { httpOnly: true, sameSite: 'strict', secure: production, path: '/' }); res.json({ ok: true });
}));

app.get('/api/dashboard', requireAuth, (req, res) => {
  const projects = db.prepare('SELECT * FROM projects WHERE user_id = ? ORDER BY updated_at DESC').all(req.session.userId).map(projectView);
  const count = (status) => projects.filter((p) => p.status === status).length;
  const activity = db.prepare('SELECT a.id,a.action,a.message,a.created_at,p.name AS project_name FROM activities a LEFT JOIN projects p ON p.id=a.project_id WHERE a.user_id=? ORDER BY a.id DESC LIMIT 8').all(req.session.userId)
    .map((a) => ({ id:a.id, action:a.action, message:a.message, createdAt:a.created_at, projectName:a.project_name }));
  const deploys = db.prepare('SELECT d.*,p.name AS project_name FROM deployments d JOIN projects p ON p.id=d.project_id WHERE p.user_id=? ORDER BY d.created_at DESC LIMIT 6').all(req.session.userId);
  res.json({ projects, activity, recentDeployments: deploys.map((d) => ({ ...deploymentView(d), projectName:d.project_name })), stats: { total:projects.length, online:count('online'), stopped:count('stopped'), deploying:count('deploying'), uptime: MODE === 'demo' ? '99.9%' : null }, hostingMode:MODE });
});
app.get('/api/projects', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM projects WHERE user_id = ? ORDER BY updated_at DESC').all(req.session.userId);
  res.json({ projects: rows.map(projectView) });
});
app.post('/api/projects', requireAuth, upload.single('bundle'), async (req, res, next) => {
  let storedPath = null;
  let uploadedTemp = req.file?.path || null;
  try {
    const name = safeText(req.body?.name, 60);
    const sourceType = req.body?.sourceType;
    const pythonVersion = req.body?.pythonVersion || '3.12';
    const buildCommand = safeText(req.body?.buildCommand || '', 500);
    const startCommand = safeText(req.body?.startCommand || 'python main.py', 500);
    if (!name || !/^[\p{L}\p{N}][\p{L}\p{N} ._-]{0,59}$/u.test(name)) return apiError(res, 400, 'Project name may use letters, numbers, spaces, dots, underscores, and hyphens.');
    if (!isValidPythonVersion(pythonVersion)) return apiError(res, 400, 'Choose a supported Python version.');
    if (!startCommand) return apiError(res, 400, 'A start command is required.');
    if (sourceType === 'git') {
      const repositoryUrl = safeText(req.body?.repositoryUrl, 1000);
      if (!safeHttpsRepository(repositoryUrl)) return apiError(res, 400, 'Use a public HTTPS Git URL without embedded credentials, query parameters, ports, or IP addresses.');
      const id = uuid(), ts = now();
      db.prepare('INSERT INTO projects(id,user_id,name,source_type,repository_url,python_version,build_command,start_command,status,is_sample,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')
        .run(id,req.session.userId,name,'git',repositoryUrl,pythonVersion,buildCommand,startCommand,'stopped',0,ts,ts);
      addActivity(req.session.userId,id,'project_created',`${name} was connected to Git.`);
      addLog(id,'build','info',`Repository connected: ${new URL(repositoryUrl).host}`);
      return res.status(201).json({ project:projectView(ownerProject(req.session.userId,id)) });
    }
    if (sourceType !== 'zip' || !req.file) return apiError(res, 400, 'Upload a ZIP archive or choose a Git repository.');
    await fs.promises.chmod(uploadedTemp, 0o600);
    if (!req.file.originalname.toLowerCase().endsWith('.zip') || req.file.size < 4) return apiError(res, 400, 'Upload a valid .zip archive.');
    const header = Buffer.alloc(4);
    const archiveHandle = await fs.promises.open(uploadedTemp, 'r');
    try { await archiveHandle.read(header, 0, 4, 0); } finally { await archiveHandle.close(); }
    if (header[0] !== 0x50 || header[1] !== 0x4b) return apiError(res, 400, 'Upload a valid .zip archive.');
    try {
      await inspectZip(uploadedTemp);
      const id = uuid(), ts = now();
      storedPath = path.join(UPLOAD_DIR, `${id}.zip`);
      await fs.promises.rename(uploadedTemp, storedPath);
      uploadedTemp = null;
      db.prepare('INSERT INTO projects(id,user_id,name,source_type,source_path,python_version,build_command,start_command,status,is_sample,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)')
        .run(id,req.session.userId,name,'zip',storedPath,pythonVersion,buildCommand,startCommand,'stopped',0,ts,ts);
      addActivity(req.session.userId,id,'project_created',`${name} was created from a ZIP upload.`);
      addLog(id,'build','info',`Source archive received (${Math.round(req.file.size/1024)} KB).`);
      res.status(201).json({ project:projectView(ownerProject(req.session.userId,id)) });
    } catch (e) { if (uploadedTemp) await fs.promises.rm(uploadedTemp,{force:true}); if (storedPath) await fs.promises.rm(storedPath,{force:true}); throw e; }
  } catch (error) { next(error); }
  finally { if (uploadedTemp) await fs.promises.rm(uploadedTemp,{force:true}).catch(()=>{}); }
});
app.get('/api/projects/:id', requireAuth, (req, res) => {
  const p = ownerProject(req.session.userId, req.params.id);
  if (!p) return apiError(res,404,'Project not found.');
  const latest = db.prepare('SELECT * FROM deployments WHERE project_id=? ORDER BY sequence DESC LIMIT 1').get(p.id);
  const deployments = db.prepare('SELECT * FROM deployments WHERE project_id=? ORDER BY sequence DESC LIMIT 20').all(p.id);
  res.json({ project:projectView(p), environment:envView(p.id), latestDeployment:latest?deploymentView(latest):null, deployments:deployments.map(deploymentView), runtimeMode:MODE });
});
app.patch('/api/projects/:id', requireAuth, (req, res) => {
  const p = ownerProject(req.session.userId,req.params.id);
  if (!p) return apiError(res,404,'Project not found.');
  const name = req.body?.name === undefined ? p.name : safeText(req.body.name,60);
  const pythonVersion = req.body?.pythonVersion === undefined ? p.python_version : req.body.pythonVersion;
  const buildCommand = req.body?.buildCommand === undefined ? p.build_command : safeText(req.body.buildCommand,500);
  const startCommand = req.body?.startCommand === undefined ? p.start_command : safeText(req.body.startCommand,500);
  if (!name || !/^[\p{L}\p{N}][\p{L}\p{N} ._-]{0,59}$/u.test(name)) return apiError(res,400,'Enter a valid project name.');
  if (!allowedPythonVersions.includes(pythonVersion)) return apiError(res,400,'Choose a supported Python version.');
  if (!startCommand) return apiError(res,400,'A start command is required.');
  db.prepare('UPDATE projects SET name=?,python_version=?,build_command=?,start_command=?,updated_at=? WHERE id=?')
    .run(name,pythonVersion,buildCommand,startCommand,now(),p.id);
  addActivity(req.session.userId,p.id,'settings_updated',`${name} settings were updated.`);
  res.json({ project:projectView(ownerProject(req.session.userId,p.id)) });
});
app.get('/api/projects/:id/env', requireAuth, (req,res) => {
  const p=ownerProject(req.session.userId,req.params.id); if(!p) return apiError(res,404,'Project not found.');
  res.json({ variables:envView(p.id) });
});
app.put('/api/projects/:id/env', requireAuth, (req,res,next) => {
  try {
    const p=ownerProject(req.session.userId,req.params.id); if(!p) return apiError(res,404,'Project not found.');
    const key=safeText(req.body?.key,128); const value=typeof req.body?.value==='string'?req.body.value:'';
    if(!isValidEnvKey(key)) return apiError(res,400,'Variable names must start with a letter or underscore and contain only letters, numbers, and underscores.');
    if(value.length>8192 || /[\r\n\0]/.test(value)) return apiError(res,400,'Secret values must be 8 KB or less and cannot contain line breaks.');
    const current=db.prepare('SELECT * FROM env_vars WHERE project_id=? AND key=?').get(p.id,key);
    if(!value && !current) return apiError(res,400,'Enter a value for this new variable.');
    if(value) {
      const encrypted=encryptText(value);
      const timestamp=now();
      db.prepare('INSERT INTO env_vars(id,project_id,key,encrypted_value,created_at,updated_at) VALUES(?,?,?,?,?,?) ON CONFLICT(project_id,key) DO UPDATE SET encrypted_value=excluded.encrypted_value,updated_at=excluded.updated_at')
        .run(uuid(),p.id,key,encrypted,timestamp,timestamp);
    }
    addActivity(req.session.userId,p.id,'secret_updated',`${key} ${value?'was saved':'was left unchanged'}.`);
    res.json({ variables:envView(p.id), message:value?'Secret saved securely.':'No secret value changed.' });
  } catch(error) { next(error); }
});
app.delete('/api/projects/:id/env/:key', requireAuth, (req,res) => {
  const p=ownerProject(req.session.userId,req.params.id); if(!p) return apiError(res,404,'Project not found.');
  const key=req.params.key;
  const result=db.prepare('DELETE FROM env_vars WHERE project_id=? AND key=?').run(p.id,key);
  if(!result.changes) return apiError(res,404,'Variable not found.');
  addActivity(req.session.userId,p.id,'secret_deleted',`${key} was removed.`);
  res.json({ variables:envView(p.id) });
});
app.get('/api/projects/:id/deployments', requireAuth, (req,res) => {
  const p=ownerProject(req.session.userId,req.params.id); if(!p) return apiError(res,404,'Project not found.');
  res.json({ deployments:db.prepare('SELECT * FROM deployments WHERE project_id=? ORDER BY sequence DESC LIMIT 50').all(p.id).map(deploymentView) });
});
app.post('/api/projects/:id/deploy', requireAuth, async (req,res,next) => {
  const p=ownerProject(req.session.userId,req.params.id); if(!p) return apiError(res,404,'Project not found.');
  if(p.status==='deploying') return apiError(res,409,'A deployment is already in progress for this project.');
  const started=Date.now();
  const deployment=addDeploy(p.id,'building','Deployment is being prepared.');
  db.prepare('UPDATE projects SET status=?,updated_at=? WHERE id=?').run('deploying',now(),p.id);
  addActivity(req.session.userId,p.id,'deployment_started',`${p.name} deployment started.`);
  addLog(p.id,'build','info',`Starting deployment #${deployment.sequence}…`);
  try {
    let result;
    if(MODE==='worker') result=await deployWithWorker(p,deployment.id);
    else {
      addLog(p.id,'build','info','Checking source bundle and runtime settings…');
      addLog(p.id,'build','info',`Preparing Python ${p.python_version} runtime (simulated).`);
      addLog(p.id,'runtime','info','DEMO MODE: no bot process or Discord connection has been started.');
      result={ status:'online', containerId:null };
    }
    const duration=Date.now()-started;
    db.prepare('UPDATE deployments SET status=?,summary=?,finished_at=?,duration_ms=? WHERE id=?')
      .run('success',MODE==='demo'?'Simulated deployment completed — demo mode.':'Container deployed successfully.',now(),duration,deployment.id);
    db.prepare('UPDATE projects SET status=?,updated_at=?,last_deployed_at=? WHERE id=?').run('online',now(),now(),p.id);
    addLog(p.id,'build','info',MODE==='demo'?'Demo deployment finished; no code was executed.':'Build succeeded and container started.');
    addActivity(req.session.userId,p.id,'deployment_succeeded',`${p.name} deployment ${MODE==='demo'?'was simulated':'succeeded'}.`);
    res.json({ project:projectView(ownerProject(req.session.userId,p.id)), deployment:deploymentView(db.prepare('SELECT * FROM deployments WHERE id=?').get(deployment.id)), message:MODE==='demo'?'Simulated deployment complete. Configure the isolated worker to run a real bot.':'Deployment completed.' });
  } catch(error) {
    const duration=Date.now()-started;
    db.prepare('UPDATE deployments SET status=?,summary=?,finished_at=?,duration_ms=? WHERE id=?').run('failed',maskSecrets(error.message,readEnv(p.id).map(x=>x.value)),now(),duration,deployment.id);
    db.prepare('UPDATE projects SET status=?,updated_at=? WHERE id=?').run('failed',now(),p.id);
    addLog(p.id,'build','error',maskSecrets(error.message,readEnv(p.id).map(x=>x.value)));
    addActivity(req.session.userId,p.id,'deployment_failed',`${p.name} deployment failed.`);
    next(error);
  }
});
app.post('/api/projects/:id/action', requireAuth, async (req,res,next) => {
  const p=ownerProject(req.session.userId,req.params.id); if(!p) return apiError(res,404,'Project not found.');
  const action=req.body?.action;
  if(!['start','stop','restart','redeploy'].includes(action)) return apiError(res,400,'Unsupported project action.');
  if(action==='redeploy') {
    // Keep the action endpoint idempotent by sharing the regular deployment path.
    req.url=`/api/projects/${p.id}/deploy`;
    return res.status(307).set('Location',req.url).end();
  }
  try {
    if(MODE==='worker') await workerRequest(`/v1/projects/${p.id}/action`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action})});
    const status=action==='stop'?'stopped':'online';
    db.prepare('UPDATE projects SET status=?,updated_at=? WHERE id=?').run(status,now(),p.id);
    addLog(p.id,'runtime','info',MODE==='demo'?`${action} action simulated; no process was started.`:`Container ${action} requested.`);
    addActivity(req.session.userId,p.id,`project_${action}`,`${p.name} ${action} action completed${MODE==='demo'?' (demo mode)':''}.`);
    res.json({project:projectView(ownerProject(req.session.userId,p.id)),message:MODE==='demo'?`${action[0].toUpperCase()+action.slice(1)} simulated in demo mode.`:`Bot ${action} completed.`});
  } catch(error) { next(error); }
});
app.delete('/api/projects/:id', requireAuth, async (req,res,next) => {
  const p=ownerProject(req.session.userId,req.params.id); if(!p) return apiError(res,404,'Project not found.');
  try {
    if(MODE==='worker') await workerRequest(`/v1/projects/${p.id}/action`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action:'delete'})});
    addActivity(req.session.userId,null,'project_deleted',`${p.name} was deleted.`);
    if(p.source_path) await fs.promises.rm(p.source_path,{force:true}).catch(()=>{});
    db.prepare('DELETE FROM projects WHERE id=?').run(p.id);
    res.json({ok:true});
  } catch(error) { next(error); }
});
app.get('/api/projects/:id/logs', requireAuth, async (req,res,next) => {
  const p=ownerProject(req.session.userId,req.params.id); if(!p) return apiError(res,404,'Project not found.');
  const stream=['build','runtime'].includes(req.query.stream)?req.query.stream:'runtime';
  const search=safeText(String(req.query.search||''),120).toLowerCase();
  try {
    let entries;
    if(MODE==='worker' && p.source_type!=='demo') {
      const data=await workerRequest(`/v1/projects/${p.id}/logs?stream=${encodeURIComponent(stream)}`);
      entries=data.entries||[];
    } else {
      entries=db.prepare('SELECT id,stream,level,message,created_at AS createdAt FROM project_logs WHERE project_id=? AND stream=? ORDER BY id DESC LIMIT 500').all(p.id,stream).reverse();
    }
    const secrets=readEnv(p.id).map((x)=>x.value);
    entries=entries.map((line)=>({...line,message:maskSecrets(line.message,secrets)}));
    if(search) entries=entries.filter((line)=>line.message.toLowerCase().includes(search)||line.level.toLowerCase().includes(search));
    res.json({entries,stream,mode:MODE==='demo'?'simulated':'container'});
  } catch(error) { next(error); }
});
app.get('/api/projects/:id/metrics', requireAuth, async (req,res,next) => {
  const p=ownerProject(req.session.userId,req.params.id); if(!p) return apiError(res,404,'Project not found.');
  if(MODE==='worker' && p.source_type!=='demo') {
    try { return res.json(await workerRequest(`/v1/projects/${p.id}/status`)); } catch(error) { return next(error); }
  }
  const online=p.status==='online';
  res.json({status:p.status,cpuPercent:online?Number((3+Math.random()*8).toFixed(1)):0,memoryMb:online?Math.round(62+Math.random()*45):0,memoryLimitMb:256,uptime:p.last_deployed_at?Math.max(1,Math.floor((Date.now()-new Date(p.last_deployed_at).getTime())/1000)):0,mode:'simulated'});
});

app.use('/api', (req,res) => apiError(res,404,'API endpoint not found.'));
app.use(express.static(path.join(root,'public'), { etag:true, maxAge:production?'1h':0, extensions:['html'] }));
app.get('*', (req,res) => res.sendFile(path.join(root,'public','index.html')));
app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  if (error instanceof multer.MulterError) return apiError(res,error.code==='LIMIT_FILE_SIZE'?413:400,error.code==='LIMIT_FILE_SIZE'?`ZIP file exceeds the ${MAX_UPLOAD_MB} MB upload limit.`:'Upload request could not be processed.');
  const status=Number(error.status)||500;
  if(status>=500) console.error(`[${now()}] ${req.method} ${req.path}: ${maskSecrets(error.message||'Unexpected error')}`);
  apiError(res,status,status>=500?'Something went wrong while processing that request. Check the project logs and server configuration.':error.message||'Request failed.');
});

app.listen(PORT, '0.0.0.0', () => console.log(`OrbitHost control plane listening on port ${PORT} (${MODE} mode).`));
