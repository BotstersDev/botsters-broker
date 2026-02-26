/**
 * Notify API tests — POST /v1/notify/:agentName
 */
import { describe, it, expect, vi } from 'vitest';
import { Hono } from 'hono';
import Database from 'better-sqlite3';
import * as db from './db.js';
import { createNotifyRoutes } from './api-notify.js';
import type { WsHub } from './ws-hub.js';
import type { Env } from './types.js';

import fs from 'node:fs';
import path from 'node:path';

const MASTER_KEY = 'a3b17f17299bb3c29f445fdf7b10d2d97ee0b9a73649b6ae3c477fa8c27ff0be';

function adminHeaders(body?: object) {
  const h: Record<string, string> = {
    'X-Admin-Key': MASTER_KEY,
    'Content-Type': 'application/json',
  };
  return h;
}

function setupDb(): Database.Database {
  const database = new Database(':memory:');
  database.pragma('journal_mode = WAL');
  database.pragma('foreign_keys = ON');
  const schemaPath = path.join(import.meta.dirname || '.', '..', 'schema.sql');
  const schema = fs.readFileSync(schemaPath, 'utf-8');
  database.exec(schema);
  db.migrateMultiActuatorAssignments(database);
  return database;
}

function createTestApp(database: Database.Database, hubStub: Partial<WsHub>) {
  const app = new Hono<{ Bindings: Env }>();
  app.use('*', async (c, next) => {
    c.env = { db: database, masterKey: MASTER_KEY } as any;
    await next();
  });
  app.route('/v1', createNotifyRoutes(hubStub as WsHub));
  return app;
}

/** Create account + agent + brain actuator, return ids */
function seedAgent(database: Database.Database, agentName = 'siofra') {
  const account = db.createAccount(database, `${agentName}@test.com`, 'hash', 'Test');
  const agent = db.createAgent(database, account.id, agentName);
  const actuator = db.createActuator(database, account.id, `${agentName}-ego`, 'brain', agent.id);
  db.updateActuatorStatus(database, actuator.id, 'online');
  return { account, agent, actuator };
}

describe('POST /v1/notify/:agentName', () => {
  it('rejects unauthenticated requests', async () => {
    const database = setupDb();
    const app = createTestApp(database, {
      getActuatorConnection: vi.fn(),
      bufferWakeMessage: vi.fn(),
    });

    const res = await app.request('/v1/notify/siofra', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text: 'hello' }),
    });

    expect(res.status).toBe(401);
    const body = await res.json() as any;
    expect(body.ok).toBe(false);
  });

  it('returns 404 for unknown agent', async () => {
    const database = setupDb();
    const app = createTestApp(database, {
      getActuatorConnection: vi.fn(),
      bufferWakeMessage: vi.fn(),
    });

    const res = await app.request('/v1/notify/nonexistent', {
      method: 'POST',
      headers: adminHeaders(),
      body: JSON.stringify({ text: 'hello' }),
    });

    expect(res.status).toBe(404);
    const body = await res.json() as any;
    expect(body.error).toBe('agent_not_found');
  });

  it('returns 400 when text is missing', async () => {
    const database = setupDb();
    seedAgent(database, 'siofra');
    const app = createTestApp(database, {
      getActuatorConnection: vi.fn(),
      bufferWakeMessage: vi.fn(),
    });

    const res = await app.request('/v1/notify/siofra', {
      method: 'POST',
      headers: adminHeaders(),
      body: JSON.stringify({ source: 'test' }),
    });

    expect(res.status).toBe(400);
    const body = await res.json() as any;
    expect(body.error).toBe('text_required');
  });

  it('delivers wake to connected brain actuator', async () => {
    const database = setupDb();
    const { agent, actuator } = seedAgent(database, 'siofra');

    const send = vi.fn();
    const hubStub = {
      getActuatorConnection: vi.fn(() => ({ ws: { send }, role: 'actuator' })),
      bufferWakeMessage: vi.fn(),
    };

    const app = createTestApp(database, hubStub);

    const res = await app.request('/v1/notify/siofra', {
      method: 'POST',
      headers: adminHeaders(),
      body: JSON.stringify({ text: 'new inbox message', source: 'family-inbox' }),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.ok).toBe(true);

    // Verify wake was sent over WebSocket
    expect(send).toHaveBeenCalledTimes(1);
    const payload = JSON.parse(send.mock.calls[0][0]);
    expect(payload.type).toBe('wake');
    expect(payload.text).toBe('new inbox message');
    expect(payload.source).toBe('family-inbox');
    expect(payload.ts).toBeDefined();
  });

  it('buffers wake when no brain actuator is connected', async () => {
    const database = setupDb();
    seedAgent(database, 'siofra');
    // Set actuator offline so the SQL query finds no online brain actuators
    database.prepare("UPDATE actuators SET status = 'offline'").run();

    const bufferWakeMessage = vi.fn();
    const hubStub = {
      getActuatorConnection: vi.fn(() => null),
      bufferWakeMessage,
    };

    const app = createTestApp(database, hubStub);

    const res = await app.request('/v1/notify/siofra', {
      method: 'POST',
      headers: adminHeaders(),
      body: JSON.stringify({ text: 'buffered message', source: 'test' }),
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.ok).toBe(false);
    expect(body.error).toBe('no_ego_connection');
    expect(body.buffered).toBe(true);

    expect(bufferWakeMessage).toHaveBeenCalledWith(
      expect.any(String), // agentId
      'buffered message',
      'test',
      expect.any(String), // ts
    );
  });

  it('defaults source to "unknown" when omitted', async () => {
    const database = setupDb();
    seedAgent(database, 'annie');

    const send = vi.fn();
    const hubStub = {
      getActuatorConnection: vi.fn(() => ({ ws: { send }, role: 'actuator' })),
      bufferWakeMessage: vi.fn(),
    };

    const app = createTestApp(database, hubStub);

    const res = await app.request('/v1/notify/annie', {
      method: 'POST',
      headers: adminHeaders(),
      body: JSON.stringify({ text: 'ping' }),
    });

    expect(res.status).toBe(200);
    const payload = JSON.parse(send.mock.calls[0][0]);
    expect(payload.source).toBe('unknown');
  });
});
