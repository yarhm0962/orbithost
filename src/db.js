import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import Database from 'better-sqlite3';
import session from 'express-session';

const dbPath = path.resolve(process.env.DATABASE_PATH || './.data/orbithost.sqlite');
fs.mkdirSync(path.dirname(dbPath), { recursive: true, mode: 0o700 });
export const db = new Database(dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL, source_type TEXT NOT NULL CHECK(source_type IN ('zip','git','demo')),
  source_path TEXT, repository_url TEXT, python_version TEXT NOT NULL DEFAULT '3.12',
  build_command TEXT NOT NULL DEFAULT '', start_command TEXT NOT NULL DEFAULT 'python main.py',
  status TEXT NOT NULL DEFAULT 'stopped', is_sample INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL, updated_at TEXT NOT NULL, last_deployed_at TEXT
);
CREATE INDEX IF NOT EXISTS projects_by_user ON projects(user_id, updated_at DESC);
CREATE TABLE IF NOT EXISTS env_vars (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  key TEXT NOT NULL, encrypted_value TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
  UNIQUE(project_id, key)
);
CREATE TABLE IF NOT EXISTS deployments (
  id TEXT PRIMARY KEY, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  sequence INTEGER NOT NULL, status TEXT NOT NULL, trigger TEXT NOT NULL DEFAULT 'manual',
  summary TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL, finished_at TEXT, duration_ms INTEGER,
  UNIQUE(project_id, sequence)
);
CREATE INDEX IF NOT EXISTS deployments_by_project ON deployments(project_id, sequence DESC);
CREATE TABLE IF NOT EXISTS project_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  stream TEXT NOT NULL, level TEXT NOT NULL DEFAULT 'info', message TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS logs_by_project ON project_logs(project_id, id DESC);
CREATE TABLE IF NOT EXISTS activities (
  id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  project_id TEXT REFERENCES projects(id) ON DELETE SET NULL, action TEXT NOT NULL,
  message TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS activity_by_user ON activities(user_id, id DESC);
CREATE TABLE IF NOT EXISTS sessions (
  sid TEXT PRIMARY KEY, sess TEXT NOT NULL, expire INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expire ON sessions(expire);
`);

db.prepare('DELETE FROM sessions WHERE expire < ?').run(Date.now());

export class SQLiteSessionStore extends session.Store {
  constructor() {
    super();
    this.getStmt = db.prepare('SELECT sess, expire FROM sessions WHERE sid = ?');
    this.setStmt = db.prepare('INSERT INTO sessions(sid,sess,expire) VALUES(?,?,?) ON CONFLICT(sid) DO UPDATE SET sess=excluded.sess, expire=excluded.expire');
    this.destroyStmt = db.prepare('DELETE FROM sessions WHERE sid = ?');
    this.touchStmt = db.prepare('UPDATE sessions SET expire = ?, sess = ? WHERE sid = ?');
  }
  get(sid, callback) {
    try {
      const row = this.getStmt.get(sid);
      if (!row) return callback(null, null);
      if (row.expire < Date.now()) { this.destroyStmt.run(sid); return callback(null, null); }
      callback(null, JSON.parse(row.sess));
    } catch (error) { callback(error); }
  }
  set(sid, sess, callback = () => {}) {
    try {
      const expire = sess.cookie?.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + 86400000;
      this.setStmt.run(sid, JSON.stringify(sess), expire);
      callback(null);
    } catch (error) { callback(error); }
  }
  touch(sid, sess, callback = () => {}) {
    try {
      const expire = sess.cookie?.expires ? new Date(sess.cookie.expires).getTime() : Date.now() + 86400000;
      this.touchStmt.run(expire, JSON.stringify(sess), sid);
      callback(null);
    } catch (error) { callback(error); }
  }
  destroy(sid, callback = () => {}) {
    try { this.destroyStmt.run(sid); callback(null); } catch (error) { callback(error); }
  }
}

export const now = () => new Date().toISOString();
export const uuid = () => crypto.randomUUID();

export function addActivity(userId, projectId, action, message) {
  db.prepare('INSERT INTO activities(user_id, project_id, action, message, created_at) VALUES(?,?,?,?,?)')
    .run(userId, projectId || null, action, message, now());
}
export function addLog(projectId, stream, level, message) {
  db.prepare('INSERT INTO project_logs(project_id, stream, level, message, created_at) VALUES(?,?,?,?,?)')
    .run(projectId, stream, level, String(message).slice(0, 4000), now());
  // Keep the local demo/test database bounded.
  db.prepare('DELETE FROM project_logs WHERE project_id = ? AND id NOT IN (SELECT id FROM project_logs WHERE project_id = ? ORDER BY id DESC LIMIT 1500)')
    .run(projectId, projectId);
}
