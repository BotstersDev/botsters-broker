/**
 * Tests for account-scoped REST API endpoints
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { Hono } from 'hono';
import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
import { accountRoutes } from './api-accounts.js';
import * as db from './db.js';
import type { Env } from './types.js';

const MASTER_KEY = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';

function createTestApp(): { app: Hono<{ Bindings: Env }>; database: Database.Database } {
  const database = new Database(':memory:');
  database.pragma('journal_mode = WAL');
  database.pragma('foreign_keys = ON');
  const schemaPath = path.join(import.meta.dirname || '.', '..', 'schema.sql');
  database.exec(fs.readFileSync(schemaPath, 'utf-8'));

  const app = new Hono<{ Bindings: Env }>();
  app.use('*', async (c, next) => {
    c.env = { db: database, masterKey: MASTER_KEY };
    await next();
  });
  app.route('/api', accountRoutes);
  return { app, database };
}

function adminHeaders() {
  return { 'X-Admin-Key': MASTER_KEY, 'Content-Type': 'application/json' };
}

describe('Account CRUD', () => {
  let app: Hono<{ Bindings: Env }>;
  let database: Database.Database;

  beforeEach(() => {
    ({ app, database } = createTestApp());
  });

  it('rejects without admin key', async () => {
    const res = await app.request('/api/accounts', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'test@test.com' }) });
    expect(res.status).toBe(401);
  });

  it('creates account', async () => {
    const res = await app.request('/api/accounts', { method: 'POST', headers: adminHeaders(), body: JSON.stringify({ email: 'test@test.com', name: 'Test' }) });
    expect(res.status).toBe(201);
    const data = await res.json() as any;
    expect(data.ok).toBe(true);
    expect(data.account.email).toBe('test@test.com');
  });

  it('gets account', async () => {
    const account = db.createAccount(database, 'test@test.com', 'hash');
    const res = await app.request(`/api/accounts/${account.id}`, { headers: adminHeaders() });
    const data = await res.json() as any;
    expect(data.ok).toBe(true);
    expect(data.account.email).toBe('test@test.com');
  });

  it('updates account', async () => {
    const account = db.createAccount(database, 'test@test.com', 'hash');
    const res = await app.request(`/api/accounts/${account.id}`, { method: 'PATCH', headers: adminHeaders(), body: JSON.stringify({ name: 'Updated', plan: 'monthly' }) });
    const data = await res.json() as any;
    expect(data.ok).toBe(true);
    expect(data.account.name).toBe('Updated');
    expect(data.account.plan).toBe('monthly');
  });

  it('deactivates account', async () => {
    const account = db.createAccount(database, 'test@test.com', 'hash');
    const res = await app.request(`/api/accounts/${account.id}`, { method: 'DELETE', headers: adminHeaders() });
    expect((await res.json() as any).ok).toBe(true);
    const found = db.getAccountById(database, account.id)!;
    expect(found.status).toBe('canceled');
  });
});

describe('Agent Management (account-scoped)', () => {
  let app: Hono<{ Bindings: Env }>;
  let database: Database.Database;
  let accountId: string;

  beforeEach(() => {
    ({ app, database } = createTestApp());
    accountId = db.createAccount(database, 'test@test.com', 'hash').id;
  });

  it('creates agent and returns token', async () => {
    const res = await app.request(`/api/accounts/${accountId}/agents`, { method: 'POST', headers: adminHeaders(), body: JSON.stringify({ name: 'Bot' }) });
    expect(res.status).toBe(201);
    const data = await res.json() as any;
    expect(data.agent.token).toMatch(/^seks_agent_/);
  });

  it('lists agents', async () => {
    db.createAgent(database, accountId, 'A');
    db.createAgent(database, accountId, 'B');
    const res = await app.request(`/api/accounts/${accountId}/agents`, { headers: adminHeaders() });
    const data = await res.json() as any;
    expect(data.agents).toHaveLength(2);
  });

  it('deletes agent', async () => {
    const agent = db.createAgent(database, accountId, 'A');
    const res = await app.request(`/api/accounts/${accountId}/agents/${agent.id}`, { method: 'DELETE', headers: adminHeaders() });
    expect((await res.json() as any).ok).toBe(true);
  });

  it('rotates agent token', async () => {
    const agent = db.createAgent(database, accountId, 'A');
    const res = await app.request(`/api/accounts/${accountId}/agents/${agent.id}/rotate-token`, { method: 'POST', headers: adminHeaders() });
    const data = await res.json() as any;
    expect(data.ok).toBe(true);
    expect(data.token).toMatch(/^seks_agent_/);
  });
});

describe('Secrets (account-scoped)', () => {
  let app: Hono<{ Bindings: Env }>;
  let database: Database.Database;
  let accountId: string;

  beforeEach(() => {
    ({ app, database } = createTestApp());
    accountId = db.createAccount(database, 'test@test.com', 'hash').id;
  });

  it('stores secret', async () => {
    const res = await app.request(`/api/accounts/${accountId}/secrets`, { method: 'POST', headers: adminHeaders(), body: JSON.stringify({ name: 'API_KEY', provider: 'openai', value: 'sk-test' }) });
    expect(res.status).toBe(201);
    const data = await res.json() as any;
    expect(data.secret.name).toBe('API_KEY');
  });

  it('lists secrets (metadata only)', async () => {
    db.createSecret(database, accountId, 'KEY', 'openai', 'enc');
    const res = await app.request(`/api/accounts/${accountId}/secrets`, { headers: adminHeaders() });
    const data = await res.json() as any;
    expect(data.secrets).toHaveLength(1);
    expect(data.secrets[0]).not.toHaveProperty('encrypted_value');
  });

  it('deletes secret', async () => {
    const secret = db.createSecret(database, accountId, 'KEY', 'openai', 'enc');
    const res = await app.request(`/api/accounts/${accountId}/secrets/${secret.id}`, { method: 'DELETE', headers: adminHeaders() });
    expect((await res.json() as any).ok).toBe(true);
  });
});

describe('Capability Grants (admin)', () => {
  let app: Hono<{ Bindings: Env }>;
  let database: Database.Database;
  let accountId: string;
  let agentId: string;
  let secretId: string;

  beforeEach(() => {
    ({ app, database } = createTestApp());
    accountId = db.createAccount(database, 'test@test.com', 'hash').id;
    agentId = db.createAgent(database, accountId, 'Bot').id;
    secretId = db.createSecret(database, accountId, 'HETZNER_TOKEN', 'hetzner', 'enc_value').id;
  });

  it('grants a capability', async () => {
    const res = await app.request(`/api/accounts/${accountId}/agents/${agentId}/capabilities`, {
      method: 'POST', headers: adminHeaders(),
      body: JSON.stringify({ provider: 'hetzner', capability: 'servers.list', secret_id: secretId }),
    });
    expect(res.status).toBe(201);
    const data = await res.json() as any;
    expect(data.ok).toBe(true);
    expect(data.grant.provider).toBe('hetzner');
  });

  it('lists capability grants', async () => {
    db.grantCapability(database, agentId, 'hetzner', 'servers.list', secretId);
    const res = await app.request(`/api/accounts/${accountId}/agents/${agentId}/capabilities`, { headers: adminHeaders() });
    const data = await res.json() as any;
    expect(data.grants).toHaveLength(1);
  });

  it('revokes a capability grant', async () => {
    const grant = db.grantCapability(database, agentId, 'hetzner', 'servers.list', secretId);
    const res = await app.request(`/api/accounts/${accountId}/agents/${agentId}/capabilities/${grant.id}`, {
      method: 'DELETE', headers: adminHeaders(),
    });
    expect((await res.json() as any).ok).toBe(true);
    expect(db.listCapabilityGrants(database, agentId)).toHaveLength(0);
  });

  it('grants all capabilities (wildcard)', async () => {
    const res = await app.request(`/api/accounts/${accountId}/agents/${agentId}/grant-all`, {
      method: 'POST', headers: adminHeaders(),
      body: JSON.stringify({ secret_id: secretId, provider: 'hetzner' }),
    });
    expect(res.status).toBe(201);
    const data = await res.json() as any;
    expect(data.grant.capability).toBe('*');
  });

  it('auto-grants on secret creation', async () => {
    const res = await app.request(`/api/accounts/${accountId}/secrets`, {
      method: 'POST', headers: adminHeaders(),
      body: JSON.stringify({ name: 'NEW_KEY', provider: 'github', value: 'ghp_test' }),
    });
    expect(res.status).toBe(201);
    const grants = db.listCapabilityGrants(database, agentId);
    const githubGrant = grants.find(g => g.provider === 'github');
    expect(githubGrant).toBeTruthy();
    expect(githubGrant!.capability).toBe('*');
  });
});

describe('Provision', () => {
  let app: Hono<{ Bindings: Env }>;
  let database: Database.Database;

  beforeEach(() => {
    ({ app, database } = createTestApp());
  });

  it('provisions account + default agent', async () => {
    const res = await app.request('/api/provision', { method: 'POST', headers: adminHeaders(), body: JSON.stringify({ email: 'new@customer.com', name: 'New Customer', plan: 'monthly' }) });
    expect(res.status).toBe(201);
    const data = await res.json() as any;
    expect(data.ok).toBe(true);
    expect(data.account_id).toBeTruthy();
    expect(data.agent_id).toBeTruthy();
    expect(data.agent_token).toMatch(/^seks_agent_/);
    expect(data.temp_password).toBeTruthy();

    // Verify account created
    const account = db.getAccountById(database, data.account_id)!;
    expect(account.email).toBe('new@customer.com');
    expect(account.plan).toBe('monthly');
  });

  it('rejects duplicate provision', async () => {
    db.createAccount(database, 'existing@customer.com', 'hash');
    const res = await app.request('/api/provision', { method: 'POST', headers: adminHeaders(), body: JSON.stringify({ email: 'existing@customer.com' }) });
    expect(res.status).toBe(409);
  });

  it('deprovisions account', async () => {
    const account = db.createAccount(database, 'test@test.com', 'hash');
    const res = await app.request(`/api/provision/${account.id}`, { method: 'DELETE', headers: adminHeaders() });
    expect((await res.json() as any).ok).toBe(true);
    expect(db.getAccountById(database, account.id)!.status).toBe('canceled');
  });
});
