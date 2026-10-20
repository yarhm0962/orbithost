import crypto from 'node:crypto';
import net from 'node:net';

const b64 = (buf) => buf.toString('base64url');
export function encryptionKey(name = 'ENV_ENCRYPTION_KEY') {
  const raw = process.env[name] || '';
  if (!/^[a-f0-9]{64}$/i.test(raw)) {
    throw new Error(`${name} must be 64 hex characters (32 random bytes).`);
  }
  return Buffer.from(raw, 'hex');
}
export function encryptText(plain, keyName = 'ENV_ENCRYPTION_KEY') {
  const key = encryptionKey(keyName);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  return `v1.${b64(iv)}.${b64(cipher.getAuthTag())}.${b64(ciphertext)}`;
}
export function decryptText(payload, keyName = 'ENV_ENCRYPTION_KEY') {
  const parts = String(payload).split('.');
  if (parts.length !== 4 || parts[0] !== 'v1') throw new Error('Unsupported encrypted secret format.');
  const key = encryptionKey(keyName);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(parts[1], 'base64url'));
  decipher.setAuthTag(Buffer.from(parts[2], 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(parts[3], 'base64url')), decipher.final()]).toString('utf8');
}
export function safeText(value, max = 200) {
  if (typeof value !== 'string') return '';
  return value.trim().slice(0, max);
}
export function isValidEnvKey(key) { return /^[A-Za-z_][A-Za-z0-9_]{0,127}$/.test(key); }
export function isValidPythonVersion(v) { return ['3.10','3.11','3.12','3.13'].includes(v); }
export function safeHttpsRepository(input) {
  try {
    const u = new URL(input);
    if (u.protocol !== 'https:' || u.username || u.password || u.port || u.search || u.hash) return false;
    const host = u.hostname.toLowerCase();
    if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) return false;
    if (net.isIP(host) || /^[\d.]+$/.test(host)) return false;
    if (!/^[a-z0-9.-]+$/.test(host) || host.includes('..')) return false;
    return true;
  } catch { return false; }
}
export function maskSecrets(text, secrets = []) {
  let out = String(text ?? '');
  for (const secret of secrets) {
    if (typeof secret === 'string' && secret.length >= 4) out = out.split(secret).join('[REDACTED]');
  }
  return out.replace(/(token|password|secret|api[_-]?key)\s*([=:])\s*([^\s,;]+)/gi, '$1$2[REDACTED]')
    .replace(/(Bot\s+)[A-Za-z0-9._-]{20,}/g, '$1[REDACTED]');
}
