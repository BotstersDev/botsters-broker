/**
 * Cryptographic utilities using Node.js crypto module
 */

import crypto from 'node:crypto';

// Generate a random UUID
export function generateId(): string {
  return crypto.randomUUID();
}

// Generate a random token with prefix
export function generateToken(prefix: string): string {
  const bytes = crypto.randomBytes(24);
  const base64 = bytes.toString('base64url');
  return prefix ? `${prefix}_${base64}` : base64;
}

// Hash a token (for storage) using SHA-256
export function hashToken(token: string): string {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// Derive an AES key from the master key (hex string)
function getKeyBuffer(masterKey: string): Buffer {
  return Buffer.from(masterKey, 'hex');
}

// Encrypt plaintext, return base64(iv + ciphertext + authTag)
export function encrypt(plaintext: string, masterKey: string): string {
  const key = getKeyBuffer(masterKey);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  // iv (12) + ciphertext + authTag (16)
  const combined = Buffer.concat([iv, encrypted, authTag]);
  return combined.toString('base64');
}

// Decrypt base64(iv + ciphertext + authTag), return plaintext
export function decrypt(encryptedB64: string, masterKey: string): string {
  const key = getKeyBuffer(masterKey);
  const combined = Buffer.from(encryptedB64, 'base64');

  const iv = combined.subarray(0, 12);
  const authTag = combined.subarray(combined.length - 16);
  const ciphertext = combined.subarray(12, combined.length - 16);

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);

  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);
  return decrypted.toString('utf8');
}

// Hash password using PBKDF2
export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16);
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
  return `${salt.toString('base64')}$${hash.toString('base64')}`;
}

// Verify password against stored hash
export function verifyPassword(password: string, storedHash: string): boolean {
  const [saltB64, hashB64] = storedHash.split('$');
  if (!saltB64 || !hashB64) return false;

  const salt = Buffer.from(saltB64, 'base64');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
  return hash.toString('base64') === hashB64;
}

// Generate a master key (for initial setup)
export function generateMasterKey(): string {
  return crypto.randomBytes(32).toString('hex');
}

// HMAC-SHA256 sign and return hex
export function hmacSign(data: string, key: string): string {
  return crypto.createHmac('sha256', key).update(data).digest('hex');
}

// SHA-256 hex digest
export function sha256Hex(data: Buffer | string): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

// HMAC-SHA256 returning raw buffer
export function hmacSha256(key: Buffer, data: string): Buffer {
  return crypto.createHmac('sha256', key).update(data).digest();
}
