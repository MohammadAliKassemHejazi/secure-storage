/**
 * AES-256-GCM file encryption with per-file key derivation.
 *
 * Key management:
 *   - A 256-bit master key is generated once and persisted in .master_key
 *   - Each file gets a unique random 16-byte salt
 *   - Per-file key = HKDF-SHA256(masterKey, salt, info=fileId)
 *     so compromising one file key reveals nothing about others
 *
 * Blob layout: [16B salt][12B nonce][16B GCM tag][ciphertext]
 */

const crypto = require('crypto');
const fs = require('fs');

const MASTER_KEY_PATH = '.master_key';

function loadMasterKey() {
  if (fs.existsSync(MASTER_KEY_PATH)) return fs.readFileSync(MASTER_KEY_PATH);
  const key = crypto.randomBytes(32);
  fs.writeFileSync(MASTER_KEY_PATH, key, { mode: 0o600 });
  return key;
}

const MASTER_KEY = loadMasterKey();

function deriveKey(fileId, salt) {
  return crypto.hkdfSync('sha256', MASTER_KEY, salt, Buffer.from(fileId), 32);
}

function encryptFile(data, fileId) {
  const salt  = crypto.randomBytes(16);
  const nonce = crypto.randomBytes(12);
  const key   = deriveKey(fileId, salt);

  const cipher    = crypto.createCipheriv('aes-256-gcm', key, nonce);
  const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag       = cipher.getAuthTag(); // 16 bytes

  const fileHash = crypto.createHash('sha256').update(data).digest('hex');
  const blob     = Buffer.concat([salt, nonce, tag, encrypted]);
  return { blob, fileHash };
}

function decryptFile(blob, fileId) {
  const salt       = blob.subarray(0, 16);
  const nonce      = blob.subarray(16, 28);
  const tag        = blob.subarray(28, 44);
  const ciphertext = blob.subarray(44);

  const key      = deriveKey(fileId, salt);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

module.exports = { encryptFile, decryptFile };
