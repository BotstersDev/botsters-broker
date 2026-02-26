/**
 * SEKS Broker - Cloud-native secret management for AI agents
 *
 * Node.js + Hono + better-sqlite3 + WebSocket
 */

import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';

import { apiRoutes } from './api.js';
import { accountRoutes } from './api-accounts.js';
import { createNotifyRoutes } from './api-notify.js';
import { inferenceRoutes } from './inference.js';
import { webRoutes } from './web.js';
import { WsHub } from './ws-hub.js';
import { CommandRouter } from './command-router.js';
import * as db from './db.js';
import { loadConfig } from './config.js';
import type { Env } from './types.js';

// Load config
const config = loadConfig();

// Ensure data directory exists
const dbDir = path.dirname(config.dbPath);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

// Initialize SQLite database
const database = new Database(config.dbPath);
database.pragma('journal_mode = WAL');
database.pragma('foreign_keys = ON');

// Apply schema
const schemaPath = path.join(import.meta.dirname || '.', '..', 'schema.sql');
if (fs.existsSync(schemaPath)) {
  const schema = fs.readFileSync(schemaPath, 'utf-8');
  database.exec(schema);
  console.log('Schema applied successfully');
}

db.migrateMultiActuatorAssignments(database);

// Build Hono app with env bindings
const app = new Hono<{ Bindings: Env }>();

// Create WebSocket hub and router first
const hub = new WsHub(database, config);
const router = new CommandRouter(database, hub, config.masterKey);
const notifyRoutes = createNotifyRoutes(hub);
hub.setRouter(router);

// Inject env bindings into every request
app.use('*', async (c, next) => {
  c.env = { db: database, masterKey: config.masterKey, commandRouter: router };
  await next();
});

// Middleware
app.use('*', logger());
app.use('/v1/*', cors());
app.use('/api/*', cors());

// API routes
app.route('/v1', apiRoutes);

// Account management API routes
app.route('/api', accountRoutes);
app.route('/v1/api', accountRoutes);
app.route('/v1', notifyRoutes);

// Inference proxy routes (the spine's core capability)
app.route('/v1', inferenceRoutes);

// Web UI routes
app.route('/', webRoutes);

// ─── REST command API (for testing / brain HTTP fallback) ──────────────────────

// List connected actuators
app.get('/v1/actuators', async (c) => {
  const conns = hub.getActiveConnections().filter(c => c.role === 'actuator');
  return c.json(conns.map(a => ({
    actuatorId: a.actuatorId,
    agentId: a.agentId,
    assignedAgentIds: a.assignedAgentIds,
    capabilities: a.capabilities,
    connId: a.connId,
  })));
});

// Select actuator for agent
app.post('/v1/actuator/select', async (c) => {
  const authHeader = c.req.header('authorization');
  const token = authHeader?.replace(/^Bearer\s+/i, '');
  if (!token) return c.json({ error: 'Missing auth token' }, 401);

  const agent = db.getAgentByToken(database, token);
  if (!agent) return c.json({ error: 'Invalid token' }, 401);

  const body = await c.req.json<{ actuator_id: string | null }>();
  const actuatorId = body.actuator_id;

  // Validate if non-null
  if (actuatorId) {
    if (!db.isActuatorAssignedToAgent(database, agent.id, actuatorId)) {
      return c.json({ error: 'Actuator not found or not owned by this agent' }, 404);
    }
  }

  db.selectActuator(database, agent.id, actuatorId);
  return c.json({ ok: true, selected_actuator_id: actuatorId });
});

// Get currently selected actuator
app.get('/v1/actuator/selected', async (c) => {
  const authHeader = c.req.header('authorization');
  const token = authHeader?.replace(/^Bearer\s+/i, '');
  if (!token) return c.json({ error: 'Missing auth token' }, 401);

  const agent = db.getAgentByToken(database, token);
  if (!agent) return c.json({ error: 'Invalid token' }, 401);

  const actuator = db.getSelectedActuator(database, agent.id);
  if (actuator) {
    return c.json({ actuator_id: actuator.id, name: actuator.name, type: actuator.type, status: actuator.status });
  }

  // Check auto-select (enabled assignments only)
  const resolved = db.resolveActuatorForAgent(database, agent.id);
  if (resolved) {
    return c.json({ actuator_id: resolved.id, name: resolved.name, type: resolved.type, status: resolved.status, auto_selected: !agent.selected_actuator_id });
  }

  return c.json({ actuator_id: null, message: 'No actuator selected' });
});

// Send command to actuator via REST
app.post('/v1/command', async (c) => {
  const authHeader = c.req.header('authorization');
  const xApiKey = c.req.header('x-api-key');
  const token = authHeader?.replace(/^Bearer\s+/i, '') || xApiKey;
  if (!token) return c.json({ error: 'Missing auth token' }, 401);

  // Authenticate — agent token or actuator token
  let agentId: string;
  let accountId: string;

  const agent = db.getAgentByToken(database, token);
  if (agent) {
    agentId = agent.id;
    accountId = agent.account_id;
  } else if (token.startsWith('seks_actuator_')) {
    const actuator = db.getActuatorByToken(database, token);
    if (!actuator) return c.json({ error: 'Invalid token' }, 401);
    const owner = db.resolveAgentForActuator(database, actuator.id);
    if (!owner) return c.json({ error: 'Invalid token' }, 401);
    agentId = owner.id;
    accountId = owner.account_id;
  } else {
    return c.json({ error: 'Invalid token' }, 401);
  }

  const body = await c.req.json<{
    capability: string;
    actuator_id?: string;
    payload: unknown;
    ttl_seconds?: number;
    sync?: boolean;
    timeout_ms?: number;
  }>();

  if (!body.capability || !body.payload) {
    return c.json({ error: 'capability and payload required' }, 400);
  }

  const { commandId, error } = router.handleCommandRequest(agentId, accountId, {
    type: 'command_request',
    id: `rest_${Date.now()}`,
    capability: body.capability,
    actuator_id: body.actuator_id,
    payload: body.payload,
    ttl_seconds: body.ttl_seconds,
  });

  if (!commandId && !error) {
    // Null behavior — no valid actuator resolved
    return c.json({ status: 'completed', result: null });
  }
  if (!commandId) {
    return c.json({ status: 'error', error }, 400);
  }

  // Sync mode: wait for result and return it in the HTTP response
  if (body.sync !== false) {
    const timeoutMs = Math.min(body.timeout_ms || 30000, 60000);
    const result = await router.waitForResult(commandId, timeoutMs);
    if (result) {
      return c.json({ status: result.status, command_id: commandId, result: result.result });
    }
    return c.json({ status: 'timeout', command_id: commandId, message: 'Command sent but result not received within timeout' }, 202);
  }

  return c.json({ status: 'sent', command_id: commandId, message: 'Command routed. Results delivered via WS to brain.' });
});

// Start the hub (router already created above)
hub.start();

// Start HTTP server with WebSocket upgrade handling
const server = serve({
  fetch: app.fetch,
  port: config.port,
}, (info) => {
  console.log(`SEKS Broker listening on http://localhost:${info.port}`);
});

// Handle WebSocket upgrades
server.on('upgrade', (request, socket, head) => {
  const url = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`);
  if (url.pathname === '/ws') {
    hub.handleUpgrade(request, socket, head);
  } else {
    socket.destroy();
  }
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('Shutting down...');
  hub.stop();
  database.close();
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('Shutting down...');
  hub.stop();
  database.close();
  process.exit(0);
});
