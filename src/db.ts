/**
 * Database operations for SEKS Broker (better-sqlite3)
 */

import type Database from 'better-sqlite3';
import { generateId, generateToken, hashToken } from './crypto.js';
import type { Account, Agent, Secret, AuditEntry, Session, FakeToken, SecretAccess, Actuator, Capability, Command, CapabilityGrant } from './types.js';

// ─── Accounts (formerly Clients) ──────────────────────────────────────────────

export function createAccount(db: Database.Database, email: string, passwordHash: string, name?: string, plan?: string): Account {
  const id = generateId();
  const now = new Date().toISOString();
  const accountPlan = plan ?? 'free';
  db.prepare(
    'INSERT INTO accounts (id, email, password_hash, name, plan, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(id, email, passwordHash, name ?? null, accountPlan, 'active', now, now);
  return { id, email, password_hash: passwordHash, name: name ?? null, stripe_customer: null, plan: accountPlan, status: 'active', created_at: now, updated_at: now };
}

export function updateAccount(db: Database.Database, id: string, fields: { name?: string; email?: string; plan?: string; status?: string; stripe_customer?: string }): void {
  const now = new Date().toISOString();
  const sets: string[] = ['updated_at = ?'];
  const values: any[] = [now];
  if (fields.name !== undefined) { sets.push('name = ?'); values.push(fields.name); }
  if (fields.email !== undefined) { sets.push('email = ?'); values.push(fields.email); }
  if (fields.plan !== undefined) { sets.push('plan = ?'); values.push(fields.plan); }
  if (fields.status !== undefined) { sets.push('status = ?'); values.push(fields.status); }
  if (fields.stripe_customer !== undefined) { sets.push('stripe_customer = ?'); values.push(fields.stripe_customer); }
  values.push(id);
  db.prepare(`UPDATE accounts SET ${sets.join(', ')} WHERE id = ?`).run(...values);
}

export function deactivateAccount(db: Database.Database, id: string): void {
  const now = new Date().toISOString();
  db.prepare("UPDATE accounts SET status = 'canceled', updated_at = ? WHERE id = ?").run(now, id);
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

  const agent = { id, account_id: accountId, name, token_hash: tokenHash, scopes: '[]', created_at: now, last_seen_at: null, _plaintext_token: plaintextToken };

  // Auto-create null actuator for new agents
  ensureNullActuator(db, id);

  return agent;
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

export function rotateAgentToken(db: Database.Database, id: string, accountId: string): { token: string; tokenHash: string } | null {
  const agent = db.prepare('SELECT * FROM agents WHERE id = ? AND account_id = ?').get(id, accountId) as Agent | undefined;
  if (!agent) return null;
  const newToken = generateToken('seks_agent');
  const newHash = hashToken(newToken);
  db.prepare('UPDATE agents SET token_hash = ? WHERE id = ?').run(newHash, id);
  return { token: newToken, tokenHash: newHash };
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

export function getSecretsByPrefix(db: Database.Database, accountId: string, namePrefix: string, agentId?: string): Secret[] {
  const pattern = `${namePrefix}%`;
  if (agentId) {
    return db.prepare(`
      SELECT s.* FROM secrets s
      WHERE s.account_id = ? AND s.name LIKE ?
        AND (
          NOT EXISTS (SELECT 1 FROM secret_access sa WHERE sa.secret_id = s.id)
          OR EXISTS (SELECT 1 FROM secret_access sa WHERE sa.secret_id = s.id AND sa.agent_id = ?)
        )
      ORDER BY s.name
    `).all(accountId, pattern, agentId) as Secret[];
  }
  return db.prepare('SELECT * FROM secrets WHERE account_id = ? AND name LIKE ? ORDER BY name').all(accountId, pattern) as Secret[];
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

export function isSecretGlobal(db: Database.Database, secretId: string): boolean {
  const row = db.prepare('SELECT COUNT(*) as count FROM secret_access WHERE secret_id = ?').get(secretId) as { count: number };
  return row.count === 0;
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

/** Well-known null actuator ID — commands sent here are acknowledged but not executed */
export const NULL_ACTUATOR_ID = 'actuator_null';

/**
 * Ensure the null actuator exists for a given agent.
 * The null actuator is a /dev/null equivalent — commands are accepted and immediately
 * completed with exit code 0 and empty output. Safe default for unconfigured agents.
 */
export function ensureNullActuator(db: Database.Database, agentId: string): Actuator {
  const existing = db.prepare('SELECT * FROM actuators WHERE id = ? AND agent_id = ?').get(`${NULL_ACTUATOR_ID}_${agentId}`, agentId) as Actuator | undefined;
  if (existing) return existing;
  const id = `${NULL_ACTUATOR_ID}_${agentId}`;
  const now = new Date().toISOString();
  db.prepare('INSERT INTO actuators (id, agent_id, name, type, status, created_at) VALUES (?, ?, ?, ?, ?, ?)').run(id, agentId, '/dev/null', 'null', 'online', now);
  return { id, agent_id: agentId, name: '/dev/null', type: 'null', status: 'online', last_seen_at: null, created_at: now };
}

export function isNullActuator(actuatorId: string): boolean {
  return actuatorId.startsWith(NULL_ACTUATOR_ID);
}

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

// ─── Capability Grants ─────────────────────────────────────────────────────────

export function grantCapability(db: Database.Database, agentId: string, provider: string, capability: string, secretId: string, constraints?: string): CapabilityGrant {
  const id = generateId();
  const now = new Date().toISOString();
  db.prepare(
    'INSERT OR REPLACE INTO capability_grants (id, agent_id, provider, capability, secret_id, constraints, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(id, agentId, provider, capability, secretId, constraints ?? null, now);
  return { id, agent_id: agentId, provider, capability, secret_id: secretId, constraints: constraints ?? null, created_at: now };
}

export function revokeCapability(db: Database.Database, grantId: string): void {
  db.prepare('DELETE FROM capability_grants WHERE id = ?').run(grantId);
}

export function listCapabilityGrants(db: Database.Database, agentId: string): CapabilityGrant[] {
  return db.prepare('SELECT * FROM capability_grants WHERE agent_id = ? ORDER BY provider, capability').all(agentId) as CapabilityGrant[];
}

export function resolveCapability(db: Database.Database, agentId: string, provider: string, capability: string): string | null {
  // Try exact match first
  const exact = db.prepare(
    'SELECT secret_id FROM capability_grants WHERE agent_id = ? AND provider = ? AND capability = ?'
  ).get(agentId, provider, capability) as { secret_id: string } | undefined;
  if (exact) return exact.secret_id;

  // Try wildcard match
  const wildcard = db.prepare(
    "SELECT secret_id FROM capability_grants WHERE agent_id = ? AND provider = ? AND capability = '*'"
  ).get(agentId, provider) as { secret_id: string } | undefined;
  return wildcard?.secret_id ?? null;
}

export function grantAllCapabilities(db: Database.Database, agentId: string, secretId: string, provider: string): CapabilityGrant {
  return grantCapability(db, agentId, provider, '*', secretId);
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
