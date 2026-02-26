/**
 * Database operations for SEKS Broker (better-sqlite3)
 */
import type Database from 'better-sqlite3';
import { generateId, generateToken, hashToken, encrypt } from './crypto.js';
import type { Account, Agent, Secret, AuditEntry, Session, FakeToken, SecretAccess, Actuator, Capability, Command, CapabilityGrant } from './types.js';

// ─── Accounts (formerly Clients) ──────────────────────────────────────────────
export function createAccount(db: Database.Database, email: string, passwordHash: string, name?: string, plan?: string): Account {
    const id = generateId();
    const now = new Date().toISOString();
    const accountPlan = plan ?? 'free';
    db.prepare('INSERT INTO accounts (id, email, password_hash, name, plan, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(id, email, passwordHash, name ?? null, accountPlan, 'active', now, now);
    return { id, email, password_hash: passwordHash, name: name ?? null, stripe_customer: null, plan: accountPlan, status: 'active', created_at: now, updated_at: now };
}
export function updateAccount(db: Database.Database, id: string, fields: { name?: string; email?: string; plan?: string; status?: string; stripe_customer?: string }): void {
    const now = new Date().toISOString();
    const sets = ['updated_at = ?'];
    const values: any[] = [now];
    if (fields.name !== undefined) {
        sets.push('name = ?');
        values.push(fields.name);
    }
    if (fields.email !== undefined) {
        sets.push('email = ?');
        values.push(fields.email);
    }
    if (fields.plan !== undefined) {
        sets.push('plan = ?');
        values.push(fields.plan);
    }
    if (fields.status !== undefined) {
        sets.push('status = ?');
        values.push(fields.status);
    }
    if (fields.stripe_customer !== undefined) {
        sets.push('stripe_customer = ?');
        values.push(fields.stripe_customer);
    }
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
export function listAccounts(db: Database.Database): Account[] {
    return db.prepare('SELECT * FROM accounts ORDER BY created_at DESC').all() as Account[];
}
// Backwards compat aliases
export const createClient = createAccount;
export const getClientByEmail = getAccountByEmail;
export const getClientById = getAccountById;
// ─── Agents ────────────────────────────────────────────────────────────────────
export function createAgent(db: Database.Database, accountId: string, name: string, masterKey?: string): Agent & { _plaintext_token: string } {
    const id = `agent_${generateId().split('-')[0]}`;
    const plaintextToken = generateToken('seks_agent');
    const tokenHash = hashToken(plaintextToken);
    const encryptedToken = masterKey ? encrypt(plaintextToken, masterKey) : null;
    const now = new Date().toISOString();
    db.prepare('INSERT INTO agents (id, account_id, name, token_hash, encrypted_token, scopes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(id, accountId, name, tokenHash, encryptedToken, '[]', now);
    const agent = { id, account_id: accountId, name, token_hash: tokenHash, encrypted_token: encryptedToken, scopes: '[]', created_at: now, last_seen_at: null, selected_actuator_id: null, _plaintext_token: plaintextToken };
    return agent;
}
export function getAgentByTokenHash(db: Database.Database, tokenHash: string): Agent | null {
    return db.prepare('SELECT * FROM agents WHERE token_hash = ?').get(tokenHash) as Agent | undefined ?? null;
}
export function getAgentByToken(db: Database.Database, token: string): Agent | null {
    const h = hashToken(token);
    return getAgentByTokenHash(db, h);
}
export function getActuatorByToken(db: Database.Database, token: string): Actuator | null {
    const h = hashToken(token);
    return db.prepare('SELECT * FROM actuators WHERE token_hash = ?').get(h) as Actuator | undefined ?? null;
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
export function rotateAgentToken(db: Database.Database, id: string, accountId: string, masterKey?: string): { token: string; tokenHash: string } | null {
    const agent = db.prepare('SELECT * FROM agents WHERE id = ? AND account_id = ?').get(id, accountId) as Agent | undefined;
    if (!agent)
        return null;
    const newToken = generateToken('seks_agent');
    const newHash = hashToken(newToken);
    const encryptedToken = masterKey ? encrypt(newToken, masterKey) : null;
    db.prepare('UPDATE agents SET token_hash = ?, encrypted_token = ? WHERE id = ?').run(newHash, encryptedToken, id);
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
    db.prepare('INSERT INTO secrets (id, account_id, name, provider, encrypted_value, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(id, accountId, name, provider, encryptedValue, now, now);
    return { id, account_id: accountId, name, provider, encrypted_value: encryptedValue, metadata: null, created_at: now, updated_at: now };
}
export function getSecretsByPrefix(db: Database.Database, accountId: string, namePrefix: string, agentId?: string | null): Secret[] {
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
export function getSecret(db: Database.Database, accountId: string, name: string, agentId?: string | null): Secret | null {
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
export function listSecrets(db: Database.Database, accountId: string, agentId?: string | null): Secret[] {
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
    }
    else {
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
    db.prepare('INSERT INTO audit_log (id, account_id, agent_id, action, resource, status, ip_address, details, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)').run(id, accountId, agentId, action, resource, status, ipAddress ?? null, details ?? null, now);
}
export function listAudit(db: Database.Database, accountId: string, opts?: { limit?: number; action?: string; agentId?: string; after?: string; before?: string }): Array<AuditEntry & { agent_name: string | null }> {
    const limit = opts?.limit ?? 200;
    const conditions = ['a.account_id = ?'];
    const params: any[] = [accountId];
    if (opts?.action) {
        conditions.push('a.action = ?');
        params.push(opts.action);
    }
    if (opts?.agentId) {
        conditions.push('a.agent_id = ?');
        params.push(opts.agentId);
    }
    if (opts?.after) {
        conditions.push('a.created_at >= ?');
        params.push(opts.after);
    }
    if (opts?.before) {
        conditions.push('a.created_at <= ?');
        params.push(opts.before);
    }
    params.push(limit);
    const sql = `SELECT a.*, ag.name as agent_name FROM audit_log a LEFT JOIN agents ag ON a.agent_id = ag.id WHERE ${conditions.join(' AND ')} ORDER BY a.created_at DESC LIMIT ?`;
    return db.prepare(sql).all(...params) as Array<AuditEntry & { agent_name: string | null }>;
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
    if (!result)
        return null;
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
    if (agentIds.length === 0)
        return;
    const now = new Date().toISOString();
    const stmt = db.prepare('INSERT INTO secret_access (secret_id, agent_id, created_at) VALUES (?, ?, ?)');
    for (const agentId of agentIds) {
        stmt.run(secretId, agentId, now);
    }
}
// ─── Actuators ─────────────────────────────────────────────────────────────────
// ─── Actuator Selection ────────────────────────────────────────────────────────
export function selectActuator(db: Database.Database, agentId: string, actuatorId: string | null): void {
    db.prepare('UPDATE agents SET selected_actuator_id = ? WHERE id = ?').run(actuatorId, agentId);
}
export function getSelectedActuator(db: Database.Database, agentId: string): Actuator | null {
    const agent = db.prepare('SELECT selected_actuator_id FROM agents WHERE id = ?').get(agentId) as { selected_actuator_id: string | null } | undefined;
    if (!agent?.selected_actuator_id)
        return null;
    return db.prepare('SELECT * FROM actuators WHERE id = ?').get(agent.selected_actuator_id) as Actuator | undefined ?? null;
}
/**
 * Select which actuator handles commands for an agent.
 *
 * This is SELECTION, not routing. An agent has one selected actuator, period.
 * There is no capability-based routing — all commands go to the selected actuator.
 *
 * Selection logic:
 * 1. Explicit actuator_id (caller override) — if invalid, return null (no fallthrough)
 * 2. Persisted selection (agents.selected_actuator_id) — if set but invalid, return null
 * 3. Implicit auto-selection — ONLY when selected_actuator_id is NULL AND exactly one
 *    non-brain actuator exists. Persists the selection for future calls.
 * 4. Return null — multiple candidates or none; agent must explicitly select via
 *    POST /v1/actuator/select
 *
 * Brain-type actuators (ego actuators) are never candidates for command execution.
 * They exist solely for push notifications back to the brain.
 */
export function resolveActuatorForAgent(db: Database.Database, agentId: string, explicitId?: string): Actuator | null {
    // Step 1: explicit override
    if (explicitId) {
        const assigned = db.prepare("SELECT 1 FROM agent_actuator_assignments WHERE agent_id = ? AND actuator_id = ? AND enabled = 1").get(agentId, explicitId) as { 1: number } | undefined;
        if (!assigned) return null; // invalid explicit = null, no fallthrough
        return db.prepare("SELECT * FROM actuators WHERE id = ?").get(explicitId) as Actuator | undefined ?? null;
    }
    // Step 2: persisted selection
    const agent = db.prepare("SELECT selected_actuator_id FROM agents WHERE id = ?").get(agentId) as { selected_actuator_id: string | null } | undefined;
    if (agent?.selected_actuator_id) {
        const assigned = db.prepare("SELECT 1 FROM agent_actuator_assignments WHERE agent_id = ? AND actuator_id = ? AND enabled = 1").get(agentId, agent.selected_actuator_id) as { 1: number } | undefined;
        if (!assigned) return null; // invalid selection = null, no fallthrough
        return db.prepare("SELECT * FROM actuators WHERE id = ?").get(agent.selected_actuator_id) as Actuator | undefined ?? null;
    }
    // Step 3: implicit auto-selection — only non-brain actuators, only if exactly one
    const actuators = db.prepare("SELECT a.* FROM actuators a JOIN agent_actuator_assignments aa ON a.id = aa.actuator_id WHERE aa.agent_id = ? AND aa.enabled = 1 AND a.type != 'brain'").all(agentId) as Actuator[];
    if (actuators.length === 1) {
        selectActuator(db, agentId, actuators[0].id);
        return actuators[0];
    }
    // Step 4: null behavior
    return null;
}
export function createActuator(db: Database.Database, accountId: string, name: string, type = 'vps', initialAgentId?: string): Actuator {
    const id = generateId();
    const now = new Date().toISOString();
    db.prepare("INSERT INTO actuators (id, account_id, agent_id, name, type, status, enabled, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)").run(id, accountId, "sentinel", name, type, "offline", 1, now);
    if (initialAgentId) {
        db.prepare("INSERT INTO agent_actuator_assignments (agent_id, actuator_id, enabled, assigned_at) VALUES (?, ?, 1, ?)").run(initialAgentId, id, now);
    }
    return { id, account_id: accountId, agent_id: "sentinel", name, type, status: "offline", enabled: 1, last_seen_at: null, created_at: now, token_hash: null, encrypted_token: null };
}
export function getActuatorById(db: Database.Database, id: string): Actuator | null {
    return db.prepare('SELECT * FROM actuators WHERE id = ?').get(id) as Actuator | undefined ?? null;
}
export function listActuators(db: Database.Database, agentId: string): Actuator[] {
    return db.prepare("SELECT a.* FROM actuators a JOIN agent_actuator_assignments aa ON a.id = aa.actuator_id WHERE aa.agent_id = ? ORDER BY a.created_at DESC").all(agentId) as Actuator[];
}
export function listActuatorsByAccount(db: Database.Database, accountId: string): Actuator[] {
    return db.prepare("SELECT DISTINCT a.* FROM actuators a JOIN agent_actuator_assignments aa ON a.id = aa.actuator_id JOIN agents ag ON aa.agent_id = ag.id WHERE ag.account_id = ? ORDER BY a.created_at DESC").all(accountId) as Actuator[];
}
export function deleteActuator(db: Database.Database, id: string): void {
    db.prepare('DELETE FROM actuators WHERE id = ?').run(id);
}
export function rotateActuatorToken(db: Database.Database, id: string, masterKey?: string): { token: string; tokenHash: string } | null {
    const actuator = db.prepare('SELECT * FROM actuators WHERE id = ?').get(id) as Actuator | undefined;
    if (!actuator)
        return null;
    const newToken = generateToken('seks_actuator');
    const newHash = hashToken(newToken);
    const encryptedToken = masterKey ? encrypt(newToken, masterKey) : null;
    db.prepare('UPDATE actuators SET token_hash = ?, encrypted_token = ? WHERE id = ?').run(newHash, encryptedToken, id);
    return { token: newToken, tokenHash: newHash };
}
export function getActuatorByTokenHash(db: Database.Database, tokenHash: string): Actuator | null {
    return db.prepare('SELECT * FROM actuators WHERE token_hash = ?').get(tokenHash) as Actuator | undefined ?? null;
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
// findActuatorWithCapability — DELETED. There is no capability-based routing.
// Actuator selection is handled solely by resolveActuatorForAgent().
// ─── Capability Grants ─────────────────────────────────────────────────────────
export function grantCapability(db: Database.Database, agentId: string, provider: string, capability: string, secretId: string | null, constraints?: string): CapabilityGrant {
    const id = generateId();
    const now = new Date().toISOString();
    db.prepare('INSERT OR REPLACE INTO capability_grants (id, agent_id, provider, capability, secret_id, constraints, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)').run(id, agentId, provider, capability, secretId, constraints ?? null, now);
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
    const exact = db.prepare('SELECT secret_id FROM capability_grants WHERE agent_id = ? AND provider = ? AND capability = ?').get(agentId, provider, capability) as { secret_id: string } | undefined;
    if (exact)
        return exact.secret_id;
    // Try wildcard match
    const wildcard = db.prepare("SELECT secret_id FROM capability_grants WHERE agent_id = ? AND provider = ? AND capability = '*'").get(agentId, provider) as { secret_id: string } | undefined;
    return wildcard?.secret_id ?? null;
}
export function grantAllCapabilities(db: Database.Database, agentId: string, secretId: string, provider: string): CapabilityGrant {
    return grantCapability(db, agentId, provider, '*', secretId);
}
// ─── Command Queue ─────────────────────────────────────────────────────────────
export function createCommand(db: Database.Database, agentId: string, actuatorId: string | null, capability: string, payload: string, ttlSeconds = 300): Command {
    const id = generateId();
    const now = new Date().toISOString();
    db.prepare('INSERT INTO command_queue (id, agent_id, actuator_id, capability, payload, status, created_at, ttl_seconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(id, agentId, actuatorId, capability, payload, 'pending', now, ttlSeconds);
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
    }
    else if (status === 'completed' || status === 'failed') {
        db.prepare('UPDATE command_queue SET status = ?, result = ?, completed_at = ? WHERE id = ?').run(status, result ?? null, now, id);
    }
    else {
        db.prepare('UPDATE command_queue SET status = ? WHERE id = ?').run(status, id);
    }
}
export function listRecentCommands(db: Database.Database, agentId: string, limit = 50): Command[] {
    return db.prepare('SELECT * FROM command_queue WHERE agent_id = ? ORDER BY created_at DESC LIMIT ?').all(agentId, limit) as Command[];
}
export function listRecentCommandsByAccount(db: Database.Database, accountId: string, limit = 50): Command[] {
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
// Functions missing from dist/db.js after accidental overwrite
// These implement multi-actuator assignment support

function hasColumn(db: Database.Database, table: string, column: string): boolean {
    const cols = db.prepare(`PRAGMA table_info(${table})`).all() as Array<any>;
    return cols.some((c: any) => c.name === column);
}

export function migrateMultiActuatorAssignments(db: Database.Database): void {
    if (!hasColumn(db, 'actuators', 'enabled')) {
        db.exec('ALTER TABLE actuators ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1');
    }
    if (!hasColumn(db, 'actuators', 'account_id')) {
        db.exec('ALTER TABLE actuators ADD COLUMN account_id TEXT');
    }
    if (!hasColumn(db, 'agents', 'selected_actuator_id')) {
        db.exec('ALTER TABLE agents ADD COLUMN selected_actuator_id TEXT');
    }
    if (!hasColumn(db, 'agents', 'encrypted_token')) {
        db.exec('ALTER TABLE agents ADD COLUMN encrypted_token TEXT');
    }
    if (!hasColumn(db, 'actuators', 'token_hash')) {
        db.exec('ALTER TABLE actuators ADD COLUMN token_hash TEXT');
    }
    if (!hasColumn(db, 'actuators', 'encrypted_token')) {
        db.exec('ALTER TABLE actuators ADD COLUMN encrypted_token TEXT');
    }
    db.exec(`
        CREATE TABLE IF NOT EXISTS agent_actuator_assignments (
            agent_id TEXT NOT NULL,
            actuator_id TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            assigned_at TEXT NOT NULL,
            PRIMARY KEY (agent_id, actuator_id),
            FOREIGN KEY (agent_id) REFERENCES agents(id) ON DELETE CASCADE,
            FOREIGN KEY (actuator_id) REFERENCES actuators(id) ON DELETE CASCADE
        );
        CREATE INDEX IF NOT EXISTS idx_assignments_agent ON agent_actuator_assignments(agent_id);
        CREATE INDEX IF NOT EXISTS idx_assignments_actuator ON agent_actuator_assignments(actuator_id);
        CREATE INDEX IF NOT EXISTS idx_actuators_account_id ON actuators(account_id);
    `);
    // Backfill account ownership from legacy actuator->agent relationship
    db.exec(`
        UPDATE actuators SET account_id = (
            SELECT ag.account_id FROM agents ag WHERE ag.id = actuators.agent_id
        ) WHERE account_id IS NULL AND agent_id IS NOT NULL AND agent_id != 'sentinel';
    `);
    // Backfill assignments from legacy ownership
    db.exec(`
        INSERT OR IGNORE INTO agent_actuator_assignments (agent_id, actuator_id, enabled, assigned_at)
        SELECT a.agent_id, a.id, COALESCE(a.enabled, 1), COALESCE(a.created_at, datetime('now'))
        FROM actuators a WHERE a.agent_id IS NOT NULL AND a.agent_id != 'sentinel';
    `);
    // Clear stale selected_actuator_id
    db.exec(`
        UPDATE agents SET selected_actuator_id = NULL
        WHERE selected_actuator_id IS NOT NULL
        AND NOT EXISTS (
            SELECT 1 FROM agent_actuator_assignments aa
            WHERE aa.agent_id = agents.id
            AND aa.actuator_id = agents.selected_actuator_id
            AND aa.enabled = 1
        );
    `);
    // Safe mode tables
    if (!hasColumn(db, 'agents', 'safe')) {
        db.exec('ALTER TABLE agents ADD COLUMN safe INTEGER NOT NULL DEFAULT 0');
    }
    db.exec("CREATE TABLE IF NOT EXISTS broker_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)");
    db.exec("INSERT OR IGNORE INTO broker_settings (key, value) VALUES ('global_safe', '0')");
}

export function getAgentByName(db: Database.Database, name: string): Agent | null {
    return db.prepare('SELECT * FROM agents WHERE name = ?').get(name) as Agent | undefined ?? null;
}

export function listActuatorAssignments(db: Database.Database, actuatorId: string): Array<{ agent_id: string; actuator_id: string; enabled: number; assigned_at: string }> {
    return db.prepare('SELECT * FROM agent_actuator_assignments WHERE actuator_id = ?').all(actuatorId) as Array<{ agent_id: string; actuator_id: string; enabled: number; assigned_at: string }>;
}

export function assignActuatorToAgent(db: Database.Database, agentId: string, actuatorId: string, enabled = 1): boolean {
    const agent = db.prepare('SELECT * FROM agents WHERE id = ?').get(agentId) as Agent | undefined;
    const actuator = db.prepare('SELECT * FROM actuators WHERE id = ?').get(actuatorId) as Actuator | undefined;
    if (!agent || !actuator) return false;
    if (agent.account_id !== actuator.account_id) return false;
    const now = new Date().toISOString();
    db.prepare('INSERT OR REPLACE INTO agent_actuator_assignments (agent_id, actuator_id, enabled, assigned_at) VALUES (?, ?, ?, ?)').run(agentId, actuatorId, enabled, now);
    return true;
}

export function removeActuatorAssignment(db: Database.Database, agentId: string, actuatorId: string): void {
    db.prepare('DELETE FROM agent_actuator_assignments WHERE agent_id = ? AND actuator_id = ?').run(agentId, actuatorId);
}

export function toggleAgentActuatorAssignmentEnabled(db: Database.Database, agentId: string, actuatorId: string): boolean {
    const row = db.prepare('SELECT enabled FROM agent_actuator_assignments WHERE agent_id = ? AND actuator_id = ?').get(agentId, actuatorId) as { enabled: number } | undefined;
    if (!row) return false;
    db.prepare('UPDATE agent_actuator_assignments SET enabled = ? WHERE agent_id = ? AND actuator_id = ?').run(row.enabled ? 0 : 1, agentId, actuatorId);
    return true;
}

export function isActuatorAssignedToAgent(db: Database.Database, agentId: string, actuatorId: string, enabledOnly = true): boolean {
    const filter = enabledOnly ? ' AND enabled = 1' : '';
    const row = db.prepare(`SELECT 1 FROM agent_actuator_assignments WHERE agent_id = ? AND actuator_id = ?${filter}`).get(agentId, actuatorId) as { 1: number } | undefined;
    return !!row;
}

export function getEnabledAgentIdsForActuator(db: Database.Database, actuatorId: string): string[] {
    const rows = db.prepare('SELECT agent_id FROM agent_actuator_assignments WHERE actuator_id = ? AND enabled = 1').all(actuatorId) as Array<{ agent_id: string }>;
    return rows.map(r => r.agent_id);
}

export function resolveAgentForActuator(db: Database.Database, actuatorId: string): Agent | null {
    const assignment = db.prepare("SELECT agent_id FROM agent_actuator_assignments WHERE actuator_id = ? AND enabled = 1").get(actuatorId) as { agent_id: string } | undefined;
    if (!assignment) return null;
    return db.prepare("SELECT * FROM agents WHERE id = ?").get(assignment.agent_id) as Agent | undefined ?? null;
}

export function listAgentActuatorAssignmentsByAccount(db: Database.Database, accountId: string): Array<{ agent_id: string; actuator_id: string; enabled: number; assigned_at: string }> {
    return db.prepare(`
        SELECT aa.* FROM agent_actuator_assignments aa
        JOIN agents ag ON ag.id = aa.agent_id
        WHERE ag.account_id = ?
    `).all(accountId) as Array<{ agent_id: string; actuator_id: string; enabled: number; assigned_at: string }>;
}

// ─── Safe Mode ─────────────────────────────────────────────────────────────────

export function getAgentSafe(db: Database.Database, agentId: string): boolean {
    const row = db.prepare('SELECT safe FROM agents WHERE id = ?').get(agentId) as { safe: number } | undefined;
    return row ? !!row.safe : false;
}

export function setAgentSafe(db: Database.Database, agentId: string, safe: boolean): void {
    db.prepare('UPDATE agents SET safe = ? WHERE id = ?').run(safe ? 1 : 0, agentId);
}

export function getGlobalSafe(db: Database.Database): boolean {
    const row = db.prepare('SELECT value FROM broker_settings WHERE key = ?').get('global_safe') as { value: string } | undefined;
    return row ? row.value === '1' : false;
}

export function setGlobalSafe(db: Database.Database, safe: boolean): void {
    db.prepare('INSERT OR REPLACE INTO broker_settings (key, value) VALUES (?, ?)').run('global_safe', safe ? '1' : '0');
}