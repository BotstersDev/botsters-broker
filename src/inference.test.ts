/**
 * Inference proxy tests
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { Hono } from 'hono';
import Database from 'better-sqlite3';
import * as db from './db.js';
import { encrypt } from './crypto.js';
import { inferenceRoutes } from './inference.js';
import type { Env } from './types.js';

const MASTER_KEY = 'a3b17f17299bb3c29f445fdf7b10d2d97ee0b9a73649b6ae3c477fa8c27ff0be';

import fs from 'node:fs';
import path from 'node:path';

function createTestApp() {
  const database = new Database(':memory:');
  database.pragma('journal_mode = WAL');
  database.pragma('foreign_keys = ON');

  // Apply schema
  const schemaPath = path.join(import.meta.dirname || '.', '..', 'schema.sql');
  const schema = fs.readFileSync(schemaPath, 'utf-8');
  database.exec(schema);

  const app = new Hono<{ Bindings: Env }>();
  app.use('*', async (c, next) => {
    c.env = { db: database, masterKey: MASTER_KEY };
    await next();
  });
  app.route('/', inferenceRoutes);

  return { app, database };
}

describe('Inference Proxy', () => {
  it('rejects unauthenticated requests', async () => {
    const { app } = createTestApp();
    const res = await app.request('/inference', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ provider: 'anthropic', model: 'test', messages: [] }),
    });
    expect(res.status).toBe(401);
  });

  it('rejects missing provider', async () => {
    const { app, database } = createTestApp();
    const account = db.createAccount(database, 'test@test.com', 'hash');
    const agent = db.createAgent(database, account.id, 'test-agent');
    const token = agent._plaintext_token;

    const res = await app.request('/inference', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({ model: 'test', messages: [] }),
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toContain('provider');
  });

  it('rejects unsupported provider', async () => {
    const { app, database } = createTestApp();
    const account = db.createAccount(database, 'test@test.com', 'hash');
    const agent = db.createAgent(database, account.id, 'test-agent');

    const res = await app.request('/inference', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${agent._plaintext_token}`,
      },
      body: JSON.stringify({ provider: 'fakeprovider', model: 'test', messages: [{ role: 'user', content: 'hi' }] }),
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toContain('Unsupported provider');
  });

  it('returns 404 when no API key configured', async () => {
    const { app, database } = createTestApp();
    const account = db.createAccount(database, 'test@test.com', 'hash');
    const agent = db.createAgent(database, account.id, 'test-agent');

    const res = await app.request('/inference', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${agent._plaintext_token}`,
      },
      body: JSON.stringify({ provider: 'anthropic', model: 'claude-haiku-3-5-20241022', messages: [{ role: 'user', content: 'hi' }] }),
    });
    expect(res.status).toBe(404);
    const body = await res.json();
    expect(body.error).toContain('API key');
  });

  it('lists providers with config status', async () => {
    const { app, database } = createTestApp();
    const account = db.createAccount(database, 'test@test.com', 'hash');
    const agent = db.createAgent(database, account.id, 'test-agent');

    // Add an Anthropic key
    const encryptedKey = encrypt('sk-ant-test', MASTER_KEY);
    db.createSecret(database, account.id, 'ANTHROPIC_TOKEN', 'anthropic', encryptedKey);

    const res = await app.request('/inference/providers', {
      headers: { 'Authorization': `Bearer ${agent._plaintext_token}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);

    const anthropic = body.providers.find((p: any) => p.name === 'anthropic');
    expect(anthropic.configured).toBe(true);

    const openai = body.providers.find((p: any) => p.name === 'openai');
    expect(openai.configured).toBe(false);
  });
});
