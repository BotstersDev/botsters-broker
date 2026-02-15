/**
 * Type definitions for SEKS Broker (Node.js)
 */

import type Database from 'better-sqlite3';

export interface AppEnv {
  db: Database.Database;
  masterKey: string;
}

// Database models

export interface Account {
  id: string;
  email: string;
  password_hash: string;
  name: string | null;
  created_at: string;
}

// Backwards compat alias
export type Client = Account;

export interface Agent {
  id: string;
  account_id: string;
  name: string;
  token_hash: string;
  scopes: string;
  created_at: string;
  last_seen_at: string | null;
  // transient: plaintext token only available at creation time
  _plaintext_token?: string;
}

export interface Secret {
  id: string;
  account_id: string;
  name: string;
  provider: string;
  encrypted_value: string;
  metadata: string | null;
  created_at: string;
  updated_at: string;
}

export interface AuditEntry {
  id: string;
  account_id: string;
  agent_id: string | null;
  action: string;
  resource: string | null;
  status: string;
  ip_address: string | null;
  details: string | null;
  created_at: string;
}

export interface Session {
  id: string;
  account_id: string;
  expires_at: string;
  created_at: string;
}

export interface FakeToken {
  id: string;
  agent_id: string;
  provider: string;
  token: string;
  created_at: string;
  last_used_at: string | null;
}

export interface SecretAccess {
  secret_id: string;
  agent_id: string;
  created_at: string;
}

export interface Actuator {
  id: string;
  agent_id: string;
  name: string;
  type: string;
  status: string;
  last_seen_at: string | null;
  created_at: string;
}

export interface Capability {
  id: string;
  actuator_id: string;
  capability: string;
  constraints: string | null;
  created_at: string;
}

export interface Command {
  id: string;
  agent_id: string;
  actuator_id: string | null;
  capability: string;
  payload: string;
  status: string;
  result: string | null;
  created_at: string;
  delivered_at: string | null;
  completed_at: string | null;
  ttl_seconds: number;
}

// API types

export interface SecretGetRequest {
  name: string;
}

export interface SecretGetResponse {
  ok: boolean;
  value?: string;
  error?: string;
}

export interface SecretListResponse {
  ok: boolean;
  secrets: Array<{ name: string; provider: string }>;
}

export interface ProxyRequest {
  service: string;
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: unknown;
}

export interface ProxyResponse {
  ok: boolean;
  status?: number;
  body?: unknown;
  error?: string;
}

// Legacy compat: Env maps to the Hono bindings shape
export interface Env {
  db: Database.Database;
  masterKey: string;
}
