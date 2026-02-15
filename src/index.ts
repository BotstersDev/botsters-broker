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

import { apiRoutes } from './api';
import { webRoutes } from './web';
import { WsHub } from './ws-hub';
import { CommandRouter } from './command-router';
import { loadConfig } from './config';
import type { Env } from './types';

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

// Build Hono app with env bindings
const app = new Hono<{ Bindings: Env }>();

// Inject env bindings into every request
app.use('*', async (c, next) => {
  c.env = { db: database, masterKey: config.masterKey };
  await next();
});

// Middleware
app.use('*', logger());
app.use('/v1/*', cors());
app.use('/api/*', cors());

// API routes
app.route('/v1', apiRoutes);
app.route('', apiRoutes);

// Web UI routes
app.route('/', webRoutes);

// Create WebSocket hub
const hub = new WsHub(database, config);
const router = new CommandRouter(database, hub, config.masterKey);
hub.setRouter(router);
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
