import { describe, it, expect, beforeEach, vi } from 'vitest';
import { Hono } from 'hono';
import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
import * as db from './db.js';
import { createNotifyRoutes } from './api-notify.js';
import type { Env } from './types.js';
import type { WsHub } from './ws-hub.js';

const MASTER_KEY = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';

function createBaseDatabase(): Database.Database {
  const database = new Database(':memory:');
  database.pragma('journal_mode = WAL');
  database.pragma('foreign_keys = ON');
  const schemaPath = path.join(import.meta.dirname || '.', '..', 'schema.sql');
  database.exec(fs.readFileSync(schemaPath, 'utf-8'));
  db.migrateMultiActuatorAssignments(database);
  return database;
}

function adminHeaders() {
  return { 'X-Admin-Key': MASTER_KEY, 'Content-Type': 'application/json' };
}

describe('Notify API', () => {
  let database: Database.Database;

  beforeEach(() => {
    database = createBaseDatabase();
  });

  it('rejects without admin key', async () => {
    const hubStub = {
      getActuatorConnection: vi.fn(() => null),
      bufferWakeMessage: vi.fn(),
    } as unknown as WsHub;

    const app = new Hono<{ Bindings: Env }>();
    app.use('*', async (c, next) => {
      c.env = { db: database, masterKey: MASTER_KEY };
      await next();
    });
    app.route('/v1', createNotifyRoutes(hubStub));

    const res = await app.request('/v1/notify/siofra', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: 'wake up' }),
    });
    expect(res.status).toBe(401);
  });

  it('returns agent_not_found for unknown agent name', async () => {
    const hubStub = {
      getActuatorConnection: vi.fn(() => null),
      bufferWakeMessage: vi.fn(),
    } as unknown as WsHub;

    const app = new Hono<{ Bindings: Env }>();
    app.use('*', async (c, next) => {
      c.env = { db: database, masterKey: MASTER_KEY };
      await next();
    });
    app.route('/v1', createNotifyRoutes(hubStub));

    const res = await app.request('/v1/notify/nonexistent', {
      method: 'POST',
      headers: adminHeaders(),
      body: JSON.stringify({ text: 'wake up' }),
    });
    expect(res.status).toBe(404);
    const body = await res.json() as any;
    expect(body.ok).toBe(false);
    expect(body.error).toBe('agent_not_found');
  });

  it('returns no_ego_connection and buffers wake when no websocket is connected', async () => {
    const account = db.createAccount(database, 'test@test.com', 'hash');
    const agent = db.createAgent(database, account.id, 'siofra');
    const actuator = db.createActuator(database, account.id, 'ego', 'brain', agent.id);
    db.updateActuatorStatus(database, actuator.id, 'online');

    const bufferWakeMessage = vi.fn();
    const hubStub = {
      getActuatorConnection: vi.fn(() => null),
      bufferWakeMessage,
    } as unknown as WsHub;

    const app = new Hono<{ Bindings: Env }>();
    app.use('*', async (c, next) => {
      c.env = { db: database, masterKey: MASTER_KEY };
      await next();
    });
    app.route('/v1', createNotifyRoutes(hubStub));

    const res = await app.request('/v1/notify/siofra', {
      method: 'POST',
      headers: adminHeaders(),
      body: JSON.stringify({ text: 'new inbox message', source: 'family-inbox' }),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.ok).toBe(false);
    expect(body.error).toBe('no_ego_connection');
    expect(body.buffered).toBe(true);
    expect(bufferWakeMessage).toHaveBeenCalledTimes(1);
  });

  it('returns ok when a brain actuator websocket is connected', async () => {
    const account = db.createAccount(database, 'test@test.com', 'hash');
    const agent = db.createAgent(database, account.id, 'siofra');
    const actuator = db.createActuator(database, account.id, 'ego', 'brain', agent.id);
    db.updateActuatorStatus(database, actuator.id, 'online');

    const send = vi.fn();
    const hubStub = {
      getActuatorConnection: vi.fn(() => ({ ws: { send } })),
      bufferWakeMessage: vi.fn(),
    } as unknown as WsHub;

    const app = new Hono<{ Bindings: Env }>();
    app.use('*', async (c, next) => {
      c.env = { db: database, masterKey: MASTER_KEY };
      await next();
    });
    app.route('/v1', createNotifyRoutes(hubStub));

    const res = await app.request('/v1/notify/siofra', {
      method: 'POST',
      headers: adminHeaders(),
      body: JSON.stringify({ text: 'new inbox message', source: 'family-inbox' }),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.ok).toBe(true);
    expect(send).toHaveBeenCalledTimes(1);
    expect(JSON.parse(send.mock.calls[0][0]).type).toBe('wake');
  });
});
