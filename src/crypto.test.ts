/**
 * Tests for crypto module
 */

import { describe, it, expect } from 'vitest';
import { 
  generateId, 
  generateToken, 
  hashPassword, 
  verifyPassword,
  encrypt,
  decrypt 
} from './crypto.js';

describe('generateId', () => {
  it('generates a valid UUID', () => {
    const id = generateId();
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  });

  it('generates unique IDs', () => {
    const ids = new Set(Array.from({ length: 100 }, () => generateId()));
    expect(ids.size).toBe(100);
  });
});

describe('generateToken', () => {
  it('generates token with correct prefix', () => {
    const token = generateToken('seks_agent');
    expect(token).toMatch(/^seks_agent_[A-Za-z0-9_-]+$/);
  });

  it('generates tokens of sufficient length', () => {
    const token = generateToken('test');
    expect(token.length).toBeGreaterThan(20);
  });

  it('generates unique tokens', () => {
    const tokens = new Set(Array.from({ length: 100 }, () => generateToken('test')));
    expect(tokens.size).toBe(100);
  });
});

describe('password hashing', () => {
  it('hashes password', async () => {
    const hash = await hashPassword('test123');
    expect(hash).toBeTruthy();
    expect(hash).not.toBe('test123');
  });

  it('verifies correct password', async () => {
    const hash = await hashPassword('test123');
    const valid = await verifyPassword('test123', hash);
    expect(valid).toBe(true);
  });

  it('rejects incorrect password', async () => {
    const hash = await hashPassword('test123');
    const valid = await verifyPassword('wrong', hash);
    expect(valid).toBe(false);
  });

  it('generates different hashes for same password', async () => {
    const hash1 = await hashPassword('test123');
    const hash2 = await hashPassword('test123');
    expect(hash1).not.toBe(hash2); // Different salts
  });
});

describe('encryption', () => {
  const testKey = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';

  it('encrypts and decrypts data', async () => {
    const original = 'secret-api-key-12345';
    const encrypted = await encrypt(original, testKey);
    const decrypted = await decrypt(encrypted, testKey);
    expect(decrypted).toBe(original);
  });

  it('produces different ciphertext for same plaintext', async () => {
    const plaintext = 'same-secret';
    const encrypted1 = await encrypt(plaintext, testKey);
    const encrypted2 = await encrypt(plaintext, testKey);
    expect(encrypted1).not.toBe(encrypted2); // Different IVs
  });

  it('fails to decrypt with wrong key', async () => {
    const encrypted = await encrypt('secret', testKey);
    const wrongKey = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
    expect(() => decrypt(encrypted, wrongKey)).toThrow();
  });

  it('handles empty string', async () => {
    const encrypted = await encrypt('', testKey);
    const decrypted = await decrypt(encrypted, testKey);
    expect(decrypted).toBe('');
  });

  it('handles unicode', async () => {
    const original = '秘密のAPIキー 🔐';
    const encrypted = await encrypt(original, testKey);
    const decrypted = await decrypt(encrypted, testKey);
    expect(decrypted).toBe(original);
  });

  it('handles long strings', async () => {
    const original = 'x'.repeat(10000);
    const encrypted = await encrypt(original, testKey);
    const decrypted = await decrypt(encrypted, testKey);
    expect(decrypted).toBe(original);
  });
});
