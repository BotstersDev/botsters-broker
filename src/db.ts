/**
 * Database operations for SEKS Broker (better-sqlite3)
 */

import type Database from 'better-sqlite3';
import { generateId, generateToken, hashToken } from './crypto';
import type { Account, Agent, Secret, AuditEntry, Session, FakeToken, SecretAccess, Actuator, Capability, Command } from './types';

// ─── Accounts (formerly Clients) ──────────────────────────────────────────────

export function createAccount(db: Database.Database, email: string, passwordHash: string, name?: string): Account {
  const id = generateId();
  const now = new Date().toISOString();
  db.prepare(
    'INSERT INTO accounts (id, email, password_hash, name, created_at) VALUES (?, ?, ?, ?, ?)'
  ).run(id, email, passwordHash, name ?? null, now);
  return { id, email, password_hash: passwordHash, name: name ?? null, created_at: now };
}

export function getAccountByEmail(db: Database.Database, email: string): Account | null {
  return db.prepare('SELECT * FROM accounts WHERE email = ?').get(email) as Account | undefined ?? null;
}

export function getAccountById(db: Database.Database, id: string): Account | null {
  return db.prepare('SELECT * FROM accounts WHERE id = ?').get(id) as Account | undefined ?? null;
}

// Backwards compat aliases
export const createClient = createAccount;
export const getClientByEmail = getAccountByEmail;
export const getClientById = getAccountById;

// ─── Agents ────────────────────────────────────────────────────────────────────

export function createAgent(db: Database.Database, accountId: string, name: string): Agent & { _plaintext_token: string } {
  const id = `agent_${generateId().split('-')[0]}`;
  const plaintextToken = generateToken('seks_agent');
  const tokenHash = hashToken(plaintextToken);
  const now = new Date().toISOString();

  db.prepare(
    'INSERT INTO agents (id, account_id, name, token_hash, scopes, created_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(id, accountId, name, tokenHash, '[]', now);

  return { id, account_id: accountId, name, token_hash: tokenHash, scopes: '[]', created_at: now, last_seen_at: null, _plaintext_token: plaintextToken };
}

export function getAgentByTokenHash(db: Database.Database, tokenHash: string): Agent | null {
  return db.prepare('SELECT * FROM agents WHERE token_hash = ?').get(tokenHash) as Agent | undefined ?? null;
}

export function getAgentByToken(db: Database.Database, token: string): Agent | null {
  const h = hashToken(token);
  return getAgentByTokenHash(db, h);
}

export function getAgentById(db: Database.Database, id: string): Agent | null {
  return db.prepare('SELECT * FROM agents WHERE id = ?').get(id) as Agent | undefined ?? null;
}

export function listAgents(db: Database.Database, accountId: string): Agent[] {
  return db.prepare('SELECT * FROM agents WHERE account_id = ? ORDER BY created_at DESC').all(accountId) as Agent[];
}

export function deleteAgent(db: Database.Database, id: string, accountId: string): void {
  db.prepare('DELETE FROM agents WHERE id = ? AND account_id = ?').run(id, accountId);
}

export function updateAgentLastSeen(db: Database.Database, id: string): void {
  const now = new Date().toISOString();
  db.prepare('UPDATE agents SET last_seen_at = ? WHERE id = ?').run(now, id);
}

// ─── Secrets ───────────────────────────────────────────────────────────────────

export function createSecret(db: Database.Database, accountId: string, name: string, provider: string, encryptedValue: string): Secret {
  const id = generateId();
  const now = new Date().toISOString();
  db.prepare(
    'INSERT INTO secrets (id, account_id, name, provider, encrypted_value, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(id, accountId, name, provider, encryptedValue, now, now);
  return { id, account_id: accountId, name, provider, encrypted_value: encryptedValue, metadata: null, created_at: now, updated_at: now };
}

export function getSecret(db: Database.Database, accountId: string, name: string, agentId?: string): Secret | null {
  if (agentId) {
    return db.prepare(`
      SELECT s.* FROM secrets s
      WHERE s.account_id = ? AND s.name = ?
        AND (
          NOT EXISTS (SELECT 1 FROM secret_access sa WHERE sa.secret_id = s.id)
          OR EXISTS (SELECT 1 FROM secret_access sa WHERE sa.secret_id = s.id AND sa.agent_id = ?)
        )
    `).get(accountId, name, agentId) as Secret | undefined ?? null;
  }
  return db.prepare('SELECT * FROM secrets WHERE account_id = ? AND name = ?').get(accountId, name) as Secret | undefined ?? null;
}

export function listSecrets(db: Database.Database, accountId: string, agentId?: string): Secret[] {
  if (agentId) {
    return db.prepare(`
      SELECT s.* FROM secrets s
      WHERE s.account_id = ?
        AND (
          NOT EXISTS (SELECT 1 FROM secret_access sa WHERE sa.secret_id = s.id)
          OR EXISTS (SELECT 1 FROM secret_access sa WHERE sa.secret_id = s.id AND sa.agent_id = ?)
        )
      ORDER BY s.name
    `).all(accountId, agentId) as Secret[];
  }
  return db.prepare('SELECT * FROM secrets WHERE account_id = ? ORDER BY name').all(accountId) as Secret[];
}

export function deleteSecret(db: Database.Database, id: string, accountId: string): void {
  db.prepare('DELETE FROM secrets WHERE id = ? AND account_id = ?').run(id, accountId);
}

export function getSecretById(db: Database.Database, id: string, accountId: string): Secret | null {
  return db.prepare('SELECT * FROM secrets WHERE id = ? AND account_id = ?').get(id, accountId) as Secret | undefined ?? null;
}

export function updateSecret(db: Database.Database, id: string, accountId: string, name: string, provider: string, encryptedValue?: string): void {
  const now = new Date().toISOString();
  if (encryptedValue) {
    db.prepare('UPDATE secrets SET name = ?, provider = ?, encrypted_value = ?, updated_at = ? WHERE id = ? AND account_id = ?')
      .run(name, provider, encryptedValue, now, id, accountId);
  } else {
    db.prepare('UPDATE secrets SET name = ?, provider = ?, updated_at = ? WHERE id = ? AND account_id = ?')
      .run(name, provider, now, id, accountId);
  }
}

// ─── Audit Log ─────────────────────────────────────────────────────────────────

export function logAudit(db: Database.Database, accountId: string, agentId: string | null, action: string, resource: string | null, status: string, ipAddress?: string | null, details?: string | null): void {
  const id = generateId();
  const now = new Date().toISOString();
  db.prepare(
    'INSERT INTO audit_log (id, account_id, agent_id, action, resource, status, ip_address, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(id, accountId, agentId, action, resource, status, ipAddress ?? null, details ?? null, now);
}

export function listAudit(db: Database.Database, accountId: string, limit: number = 100): AuditEntry[] {
  return db.prepare('SELECT * FROM audit_log WHERE account_id = ? ORDER BY created_at DESC LIMIT ?').all(accountId, limit) as AuditEntry[];
}

// ─── Sessions ──────────────────────────────────────────────────────────────────

export function createSession(db: Database.Database, accountId: string): Session {
  const id = generateId();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 24 * 60 * 60 * 1000);
  db.prepare('INSERT INTO sessions (id, account_id, expires_at, created_at) VALUES (?, ?, ?, ?)')
    .run(id, accountId, expiresAt.toISOString(), now.toISOString());
  return { id, account_id: accountId, expires_at: expiresAt.toISOString(), created_at: now.toISOString() };
}

export function getSession(db: Database.Database, id: string): Session | null {
  const result = db.prepare('SELECT * FROM sessions WHERE id = ?').get(id) as Session | undefined;
  if (!result) return null;
  if (new Date(result.expires_at) < new Date()) {
    deleteSession(db, id);
    return null;
  }
  return result;
}

export function deleteSession(db: Database.Database, id: string): void {
  db.prepare('DELETE FROM sessions WHERE id = ?').run(id);
}

// ─── Fake Tokens ───────────────────────────────────────────────────────────────

export function createFakeToken(db: Database.Database, agentId: string, provider: string): FakeToken {
  const id = generateId();
  const token = `seks_${provider}_${generateToken('').slice(0, 24)}`;
  const now = new Date().toISOString();
  db.prepare('DELETE FROM fake_tokens WHERE agent_id = ? AND provider = ?').run(agentId, provider);
  db.prepare('INSERT INTO fake_tokens (id, agent_id, provider, token, created_at) VALUES (?, ?, ?, ?, ?)').run(id, agentId, provider, token, now);
  return { id, agent_id: agentId, provider, token, created_at: now, last_used_at: null };
}

export function getFakeTokenByToken(db: Database.Database, token: string): FakeToken | null {
  return db.prepare('SELECT * FROM fake_tokens WHERE token = ?').get(token) as FakeToken | undefined ?? null;
}

export function listFakeTokens(db: Database.Database, agentId: string): FakeToken[] {
  return db.prepare('SELECT * FROM fake_tokens WHERE agent_id = ? ORDER BY provider').all(agentId) as FakeToken[];
}

export function deleteFakeToken(db: Database.Database, id: string, agentId: string): void {
  db.prepare('DELETE FROM fake_tokens WHERE id = ? AND agent_id = ?').run(id, agentId);
}

export function updateFakeTokenLastUsed(db: Database.Database, id: string): void {
  const now = new Date().toISOString();
  db.prepare('UPDATE fake_tokens SET last_used_at = ? WHERE id = ?').run(now, id);
}

// ─── Secret Access ─────────────────────────────────────────────────────────────

export function getSecretAccess(db: Database.Database, secretId: string): SecretAccess[] {
  return db.prepare('SELECT * FROM secret_access WHERE secret_id = ?').all(secretId) as SecretAccess[];
}

export function setSecretAccess(db: Database.Database, secretId: string, agentIds: string[]): void {
  db.prepare('DELETE FROM secret_access WHERE secret_id = ?').run(secretId);
  if (agentIds.length === 0) return;
  const now = new Date().toISOString();
  const stmt = db.prepare('INSERT INTO secret_access (secret_id, agent_id, created_at) VALUES (?, ?, ?)');
  for (const agentId of agentIds) {
    stmt.run(secretId, agentId, now);
  }
}

// ─── Actuators ─────────────────────────────────────────────────────────────────

export function createActuator(db: Database.Database, agentId: string, name: string, type: string = 'vps'): Actuator {
  const id = generateId();
  const now = new Date().toISOString();
  db.prepare('INSERT INTO actuators (id, agent_id, name, type, status, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(id, agentId, name, type, 'offline', now);
  return { id, agent_id: agentId, name, type, status: 'offline', last_seen_at: null, created_at: now };
}

export function getActuatorById(db: Database.Database, id: string): Actuator | null {
  return db.prepare('SELECT * FROM actuators WHERE id = ?').get(id) as Actuator | undefined ?? null;
}

export function listActuators(db: Database.Database, agentId: string): Actuator[] {
  return db.prepare('SELECT * FROM actuators WHERE agent_id = ? ORDER BY created_at DESC').all(agentId) as Actuator[];
}

export function listActuatorsByAccount(db: Database.Database, accountId: string): Actuator[] {
  return db.prepare(`
    SELECT a.* FROM actuators a
    JOIN agents ag ON a.agent_id = ag.id
    WHERE ag.account_id = ?
    ORDER BY a.created_at DESC
  `).all(accountId) as Actuator[];
}

export function deleteActuator(db: Database.Database, id: string): void {
  db.prepare('DELETE FROM actuators WHERE id = ?').run(id);
}

export function updateActuatorStatus(db: Database.Database, id: string, status: string): void {
  const now = new Date().toISOString();
  db.prepare('UPDATE actuators SET status = ?, last_seen_at = ? WHERE id = ?').run(status, now, id);
}

// ─── Capabilities ──────────────────────────────────────────────────────────────

export function addCapability(db: Database.Database, actuatorId: string, capability: string, constraints?: string): Capability {
  const id = generateId();
  const now = new Date().toISOString();
  db.prepare('INSERT OR REPLACE INTO capabilities (id, actuator_id, capability, constraints, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(id, actuatorId, capability, constraints ?? null, now);
  return { id, actuator_id: actuatorId, capability, constraints: constraints ?? null, created_at: now };
}

export function removeCapability(db: Database.Database, actuatorId: string, capability: string): void {
  db.prepare('DELETE FROM capabilities WHERE actuator_id = ? AND capability = ?').run(actuatorId, capability);
}

export function listCapabilities(db: Database.Database, actuatorId: string): Capability[] {
  return db.prepare('SELECT * FROM capabilities WHERE actuator_id = ? ORDER BY capability').all(actuatorId) as Capability[];
}

export function findActuatorWithCapability(db: Database.Database, agentId: string, capability: string, onlineOnly: boolean = true): Actuator | null {
  const statusFilter = onlineOnly ? "AND a.status = 'online'" : '';
  return db.prepare(`
    SELECT a.* FROM actuators a
    JOIN capabilities c ON c.actuator_id = a.id
    WHERE a.agent_id = ? AND c.capability = ? ${statusFilter}
    LIMIT 1
  `).get(agentId, capability) as Actuator | undefined ?? null;
}

// ─── Command Queue ─────────────────────────────────────────────────────────────

export function createCommand(db: Database.Database, agentId: string, actuatorId: string | null, capability: string, payload: string, ttlSeconds: number = 300): Command {
  const id = generateId();
  const now = new Date().toISOString();
  db.prepare(
    'INSERT INTO command_queue (id, agent_id, actuator_id, capability, payload, status, created_at, ttl_seconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(id, agentId, actuatorId, capability, payload, 'pending', now, ttlSeconds);
  return { id, agent_id: agentId, actuator_id: actuatorId, capability, payload, status: 'pending', result: null, created_at: now, delivered_at: null, completed_at: null, ttl_seconds: ttlSeconds };
}

export function getCommandById(db: Database.Database, id: string): Command | null {
  return db.prepare('SELECT * FROM command_queue WHERE id = ?').get(id) as Command | undefined ?? null;
}

export function getPendingCommands(db: Database.Database, actuatorId: string): Command[] {
  return db.prepare("SELECT * FROM command_queue WHERE (actuator_id = ? OR actuator_id IS NULL) AND status = 'pending' ORDER BY created_at ASC").all(actuatorId) as Command[];
}

export function updateCommandStatus(db: Database.Database, id: string, status: string, result?: string): void {
  const now = new Date().toISOString();
  if (status === 'delivered') {
    db.prepare('UPDATE command_queue SET status = ?, delivered_at = ? WHERE id = ?').run(status, now, id);
  } else if (status === 'completed' || status === 'failed') {
    db.prepare('UPDATE command_queue SET status = ?, result = ?, completed_at = ? WHERE id = ?').run(status, result ?? null, now, id);
  } else {
    db.prepare('UPDATE command_queue SET status = ? WHERE id = ?').run(status, id);
  }
}

export function listRecentCommands(db: Database.Database, agentId: string, limit: number = 50): Command[] {
  return db.prepare('SELECT * FROM command_queue WHERE agent_id = ? ORDER BY created_at DESC LIMIT ?').all(agentId, limit) as Command[];
}

export function listRecentCommandsByAccount(db: Database.Database, accountId: string, limit: number = 50): Command[] {
  return db.prepare(`
    SELECT cq.* FROM command_queue cq
    JOIN agents ag ON cq.agent_id = ag.id
    WHERE ag.account_id = ?
    ORDER BY cq.created_at DESC LIMIT ?
  `).all(accountId, limit) as Command[];
}

export function expireStaleCommands(db: Database.Database): number {
  const result = db.prepare(`
    UPDATE command_queue SET status = 'expired'
    WHERE status IN ('pending', 'delivered')
      AND datetime(created_at, '+' || ttl_seconds || ' seconds') < datetime('now')
  `).run();
  return result.changes;
}
