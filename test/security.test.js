import test from 'node:test';
import assert from 'node:assert/strict';
process.env.ENV_ENCRYPTION_KEY = 'a'.repeat(64);
const security = await import('../src/security.js');

test('AES-256-GCM secret encryption round-trips without storing plaintext', () => {
  const value = 'a-super-private-discord-token-value';
  const encrypted = security.encryptText(value);
  assert.notEqual(encrypted, value);
  assert.equal(encrypted.includes(value), false);
  assert.equal(security.decryptText(encrypted), value);
});

test('encrypted secret payload rejects tampering', () => {
  const encrypted = security.encryptText('private-value');
  const parts = encrypted.split('.');
  parts[3] = (parts[3][0] === 'A' ? 'B' : 'A') + parts[3].slice(1);
  assert.throws(() => security.decryptText(parts.join('.')));
});

test('environment variable names follow a safe allowlist', () => {
  assert.equal(security.isValidEnvKey('DISCORD_TOKEN'), true);
  assert.equal(security.isValidEnvKey('_PRIVATE_KEY_2'), true);
  assert.equal(security.isValidEnvKey('2TOKEN'), false);
  assert.equal(security.isValidEnvKey('TOKEN-NAME'), false);
});

test('only public HTTPS Git URLs without embedded credentials are accepted', () => {
  assert.equal(security.safeHttpsRepository('https://github.com/example/bot.git'), true);
  assert.equal(security.safeHttpsRepository('http://github.com/example/bot.git'), false);
  assert.equal(security.safeHttpsRepository('https://user:pass@github.com/example/bot.git'), false);
  assert.equal(security.safeHttpsRepository('https://127.0.0.1/private.git'), false);
  assert.equal(security.safeHttpsRepository('https://localhost/private.git'), false);
});

test('log redaction masks configured values and common credential assignments', () => {
  assert.equal(security.maskSecrets('ready token=actual-value', ['actual-value']), 'ready token=[REDACTED]');
  assert.match(security.maskSecrets('DISCORD_TOKEN=some-long-token-value'), /\[REDACTED\]/);
});
