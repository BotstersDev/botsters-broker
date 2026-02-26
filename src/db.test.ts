/**
 * Tests for database operations using in-memory SQLite
 */

import { describe, it, expect, beforeEach } from 'vitest';
import Database from 'better-sqlite3';
import fs from 'node:fs';
import path from 'node:path';
import * as db from './db.js';

function createTestDb(): Database.Database {
  const testDb = new Database(':memory:');
  testDb.pragma('journal_mode = WAL');
  testDb.pragma('foreign_keys = ON');
  const schemaPath = path.join(import.meta.dirname || '.', '..', 'schema.sql');
  const schema = fs.readFileSync(schemaPath, 'utf-8');
  testDb.exec(schema);
  return testDb;
}

describe('Accounts', () => {
  let testDb: Database.Database;

  beforeEach(() => { testDb = createTestDb(); });

  it('creates an account', () => {
    const account = db.createAccount(testDb, 'test@example.com', 'hash123', 'Test User');
    expect(account.id).toBeTruthy();
    expect(account.email).toBe('test@example.com');
    expect(account.name).toBe('Test User');
    expect(account.plan).toBe('free');
    expect(account.status).toBe('active');
  });

  it('gets account by email', () => {
    db.createAccount(testDb, 'test@example.com', 'hash123');
    const found = db.getAccountByEmail(testDb, 'test@example.com');
    expect(found).toBeTruthy();
    expect(found!.email).toBe('test@example.com');
  });

  it('gets account by id', () => {
    const account = db.createAccount(testDb, 'test@example.com', 'hash123');
    const found = db.getAccountById(testDb, account.id);
    expect(found).toBeTruthy();
    expect(found!.id).toBe(account.id);
  });

  it('updates account fields', () => {
    const account = db.createAccount(testDb, 'test@example.com', 'hash123');
    db.updateAccount(testDb, account.id, { name: 'Updated', plan: 'monthly', stripe_customer: 'cus_123' });
    const updated = db.getAccountById(testDb, account.id)!;
    expect(updated.name).toBe('Updated');
    expect(updated.plan).toBe('monthly');
    expect(updated.stripe_customer).toBe('cus_123');
  });

  it('deactivates account', () => {
    const account = db.createAccount(testDb, 'test@example.com', 'hash123');
    db.deactivateAccount(testDb, account.id);
    const found = db.getAccountById(testDb, account.id)!;
    expect(found.status).toBe('canceled');
  });
});

describe('Agents', () => {
  let testDb: Database.Database;
  let accountId: string;

  beforeEach(() => {
    testDb = createTestDb();
    accountId = db.createAccount(testDb, 'test@example.com', 'hash123').id;
  });

  it('creates agent with token', () => {
    const agent = db.createAgent(testDb, accountId, 'My Agent');
    expect(agent.id).toMatch(/^agent_/);
    expect(agent.name).toBe('My Agent');
    expect(agent._plaintext_token).toMatch(/^seks_agent_/);
  });

  it('finds agent by token', () => {
    const agent = db.createAgent(testDb, accountId, 'My Agent');
    const found = db.getAgentByToken(testDb, agent._plaintext_token);
    expect(found).toBeTruthy();
    expect(found!.id).toBe(agent.id);
  });

  it('lists agents for account', () => {
    db.createAgent(testDb, accountId, 'Agent 1');
    db.createAgent(testDb, accountId, 'Agent 2');
    const agents = db.listAgents(testDb, accountId);
    expect(agents).toHaveLength(2);
  });

  it('deletes agent', () => {
    const agent = db.createAgent(testDb, accountId, 'Agent');
    db.deleteAgent(testDb, agent.id, accountId);
    const found = db.getAgentById(testDb, agent.id);
    expect(found).toBeNull();
  });

  it('rotates agent token', () => {
    const agent = db.createAgent(testDb, accountId, 'Agent');
    const oldHash = agent.token_hash;
    const result = db.rotateAgentToken(testDb, agent.id, accountId)!;
    expect(result.token).toMatch(/^seks_agent_/);
    const updated = db.getAgentById(testDb, agent.id)!;
    expect(updated.token_hash).not.toBe(oldHash);
    // Old token should no longer work
    expect(db.getAgentByToken(testDb, agent._plaintext_token)).toBeNull();
    // New token should work
    expect(db.getAgentByToken(testDb, result.token)).toBeTruthy();
  });
});

describe('Secrets', () => {
  let testDb: Database.Database;
  let accountId: string;

  beforeEach(() => {
    testDb = createTestDb();
    accountId = db.createAccount(testDb, 'test@example.com', 'hash123').id;
  });

  it('creates and retrieves secret', () => {
    db.createSecret(testDb, accountId, 'API_KEY', 'openai', 'encrypted_value');
    const found = db.getSecret(testDb, accountId, 'API_KEY');
    expect(found).toBeTruthy();
    expect(found!.name).toBe('API_KEY');
    expect(found!.provider).toBe('openai');
  });

  it('lists secrets for account', () => {
    db.createSecret(testDb, accountId, 'KEY_1', 'openai', 'enc1');
    db.createSecret(testDb, accountId, 'KEY_2', 'github', 'enc2');
    const secrets = db.listSecrets(testDb, accountId);
    expect(secrets).toHaveLength(2);
  });

  it('deletes secret', () => {
    const secret = db.createSecret(testDb, accountId, 'API_KEY', 'openai', 'enc');
    db.deleteSecret(testDb, secret.id, accountId);
    expect(db.getSecret(testDb, accountId, 'API_KEY')).toBeNull();
  });

  it('updates secret', () => {
    const secret = db.createSecret(testDb, accountId, 'API_KEY', 'openai', 'enc');
    db.updateSecret(testDb, secret.id, accountId, 'RENAMED_KEY', 'github', 'new_enc');
    const found = db.getSecretById(testDb, secret.id, accountId);
    expect(found!.name).toBe('RENAMED_KEY');
    expect(found!.provider).toBe('github');
  });
});

describe('Secret Access Control', () => {
  let testDb: Database.Database;
  let accountId: string;
  let agentA: string;
  let agentB: string;

  beforeEach(() => {
    testDb = createTestDb();
    accountId = db.createAccount(testDb, 'test@example.com', 'hash123').id;
    agentA = db.createAgent(testDb, accountId, 'Agent A').id;
    agentB = db.createAgent(testDb, accountId, 'Agent B').id;
  });

  it('global secret is accessible by all agents', () => {
    db.createSecret(testDb, accountId, 'GLOBAL_KEY', 'other', 'enc');
    expect(db.getSecret(testDb, accountId, 'GLOBAL_KEY', agentA)).toBeTruthy();
    expect(db.getSecret(testDb, accountId, 'GLOBAL_KEY', agentB)).toBeTruthy();
  });

  it('scoped secret is only accessible by assigned agent', () => {
    const secret = db.createSecret(testDb, accountId, 'SCOPED_KEY', 'other', 'enc');
    db.setSecretAccess(testDb, secret.id, [agentA]);

    expect(db.getSecret(testDb, accountId, 'SCOPED_KEY', agentA)).toBeTruthy();
    expect(db.getSecret(testDb, accountId, 'SCOPED_KEY', agentB)).toBeNull();
  });

  it('admin (no agent) sees all secrets', () => {
    const s1 = db.createSecret(testDb, accountId, 'KEY_1', 'other', 'enc');
    db.createSecret(testDb, accountId, 'KEY_2', 'other', 'enc');
    db.setSecretAccess(testDb, s1.id, [agentA]);

    const all = db.listSecrets(testDb, accountId);
    expect(all).toHaveLength(2);
  });

  it('agent only sees accessible secrets in list', () => {
    const s1 = db.createSecret(testDb, accountId, 'GLOBAL', 'other', 'enc');
    const s2 = db.createSecret(testDb, accountId, 'FOR_A', 'other', 'enc');
    const s3 = db.createSecret(testDb, accountId, 'FOR_B', 'other', 'enc');
    db.setSecretAccess(testDb, s2.id, [agentA]);
    db.setSecretAccess(testDb, s3.id, [agentB]);

    const agentASecrets = db.listSecrets(testDb, accountId, agentA);
    const names = agentASecrets.map(s => s.name);
    expect(names).toContain('GLOBAL');
    expect(names).toContain('FOR_A');
    expect(names).not.toContain('FOR_B');
  });

  it('isSecretGlobal returns true for unrestricted secrets', () => {
    const secret = db.createSecret(testDb, accountId, 'KEY', 'other', 'enc');
    expect(db.isSecretGlobal(testDb, secret.id)).toBe(true);
  });

  it('isSecretGlobal returns false for restricted secrets', () => {
    const secret = db.createSecret(testDb, accountId, 'KEY', 'other', 'enc');
    db.setSecretAccess(testDb, secret.id, [agentA]);
    expect(db.isSecretGlobal(testDb, secret.id)).toBe(false);
  });

  it('setSecretAccess replaces existing access', () => {
    const secret = db.createSecret(testDb, accountId, 'KEY', 'other', 'enc');
    db.setSecretAccess(testDb, secret.id, [agentA]);
    db.setSecretAccess(testDb, secret.id, [agentB]);
    const access = db.getSecretAccess(testDb, secret.id);
    expect(access).toHaveLength(1);
    expect(access[0].agent_id).toBe(agentB);
  });
});

describe('Actuators & Capabilities', () => {
  let testDb: Database.Database;
  let accountId: string;
  let agentId: string;

  beforeEach(() => {
    testDb = createTestDb();
    accountId = db.createAccount(testDb, 'test@example.com', 'hash123').id;
    agentId = db.createAgent(testDb, accountId, 'Agent').id;
  });

  it('creates actuator with assignment', () => {
    const act = db.createActuator(testDb, accountId, 'My VPS', 'vps', agentId);
    expect(act.id).toBeTruthy();
    expect(act.name).toBe('My VPS');
    expect(act.status).toBe('offline');
    expect(act.agent_id).toBe('sentinel');
    // Assignment row should exist
    const assignments = db.listActuatorAssignments(testDb, act.id);
    expect(assignments).toHaveLength(1);
    expect(assignments[0].agent_id).toBe(agentId);
  });

  it('creates actuator without initial agent', () => {
    const act = db.createActuator(testDb, accountId, 'Unassigned VPS', 'vps');
    expect(act.id).toBeTruthy();
    const assignments = db.listActuatorAssignments(testDb, act.id);
    expect(assignments).toHaveLength(0);
  });

  it('lists actuators for agent via assignments', () => {
    db.createActuator(testDb, accountId, 'VPS 1', 'vps', agentId);
    db.createActuator(testDb, accountId, 'VPS 2', 'vps', agentId);
    expect(db.listActuators(testDb, agentId)).toHaveLength(2);
  });

  it('lists actuators by account via assignments', () => {
    db.createActuator(testDb, accountId, 'VPS 1', 'vps', agentId);
    expect(db.listActuatorsByAccount(testDb, accountId)).toHaveLength(1);
  });

  it('updates actuator status', () => {
    const act = db.createActuator(testDb, accountId, 'VPS', 'vps', agentId);
    db.updateActuatorStatus(testDb, act.id, 'online');
    const found = db.getActuatorById(testDb, act.id)!;
    expect(found.status).toBe('online');
    expect(found.last_seen_at).toBeTruthy();
  });

  it('manages capabilities', () => {
    const act = db.createActuator(testDb, accountId, 'VPS', 'vps', agentId);
    db.addCapability(testDb, act.id, 'git', '{"repos": ["*"]}');
    db.addCapability(testDb, act.id, 'shell');
    expect(db.listCapabilities(testDb, act.id)).toHaveLength(2);
    db.removeCapability(testDb, act.id, 'shell');
    expect(db.listCapabilities(testDb, act.id)).toHaveLength(1);
  });

  it('resolveActuatorForAgent auto-selects single non-brain actuator', () => {
    const vps = db.createActuator(testDb, accountId, 'VPS', 'vps', agentId);
    const brain = db.createActuator(testDb, accountId, 'Ego', 'brain', agentId);
    const resolved = db.resolveActuatorForAgent(testDb, agentId);
    expect(resolved).toBeTruthy();
    expect(resolved!.id).toBe(vps.id);
    // Should have persisted the selection
    const agent = db.getAgentById(testDb, agentId)!;
    expect(agent.selected_actuator_id).toBe(vps.id);
  });

  it('resolveActuatorForAgent returns null with multiple non-brain actuators', () => {
    db.createActuator(testDb, accountId, 'VPS 1', 'vps', agentId);
    db.createActuator(testDb, accountId, 'VPS 2', 'vps', agentId);
    expect(db.resolveActuatorForAgent(testDb, agentId)).toBeNull();
  });

  it('resolveActuatorForAgent uses persisted selection', () => {
    const vps1 = db.createActuator(testDb, accountId, 'VPS 1', 'vps', agentId);
    db.createActuator(testDb, accountId, 'VPS 2', 'vps', agentId);
    db.selectActuator(testDb, agentId, vps1.id);
    const resolved = db.resolveActuatorForAgent(testDb, agentId);
    expect(resolved).toBeTruthy();
    expect(resolved!.id).toBe(vps1.id);
  });

  it('resolveActuatorForAgent explicit override returns null for unassigned', () => {
    const vps = db.createActuator(testDb, accountId, 'VPS', 'vps', agentId);
    const agent2 = db.createAgent(testDb, accountId, 'Agent 2');
    // vps is not assigned to agent2
    expect(db.resolveActuatorForAgent(testDb, agent2.id, vps.id)).toBeNull();
  });

  it('resolveAgentForActuator returns owning agent', () => {
    const vps = db.createActuator(testDb, accountId, 'VPS', 'vps', agentId);
    const owner = db.resolveAgentForActuator(testDb, vps.id);
    expect(owner).toBeTruthy();
    expect(owner!.id).toBe(agentId);
  });

  it('resolveAgentForActuator returns null for unassigned', () => {
    const vps = db.createActuator(testDb, accountId, 'Unassigned', 'vps');
    expect(db.resolveAgentForActuator(testDb, vps.id)).toBeNull();
  });

  it('assignActuatorToAgent rejects cross-account', () => {
    const account2 = db.createAccount(testDb, 'other@example.com', 'hash').id;
    const agent2 = db.createAgent(testDb, account2, 'Other Agent').id;
    const vps = db.createActuator(testDb, accountId, 'VPS', 'vps', agentId);
    expect(db.assignActuatorToAgent(testDb, agent2, vps.id)).toBe(false);
  });

  it('deletes actuator and cascades capabilities', () => {
    const act = db.createActuator(testDb, accountId, 'VPS', 'vps', agentId);
    db.addCapability(testDb, act.id, 'git');
    db.deleteActuator(testDb, act.id);
    expect(db.getActuatorById(testDb, act.id)).toBeNull();
    expect(db.listCapabilities(testDb, act.id)).toHaveLength(0);
  });
});

describe('Capability Grants', () => {
  let testDb: Database.Database;
  let accountId: string;
  let agentId: string;
  let secretId: string;

  beforeEach(() => {
    testDb = createTestDb();
    accountId = db.createAccount(testDb, 'test@example.com', 'hash123').id;
    agentId = db.createAgent(testDb, accountId, 'Agent').id;
    secretId = db.createSecret(testDb, accountId, 'HETZNER_TOKEN', 'hetzner', 'enc_value').id;
  });

  it('grants and lists capabilities', () => {
    db.grantCapability(testDb, agentId, 'hetzner', 'servers.list', secretId);
    db.grantCapability(testDb, agentId, 'hetzner', 'servers.create', secretId);
    const grants = db.listCapabilityGrants(testDb, agentId);
    expect(grants).toHaveLength(2);
    expect(grants[0].provider).toBe('hetzner');
  });

  it('revokes capability', () => {
    const grant = db.grantCapability(testDb, agentId, 'hetzner', 'servers.list', secretId);
    db.revokeCapability(testDb, grant.id);
    expect(db.listCapabilityGrants(testDb, agentId)).toHaveLength(0);
  });

  it('resolves exact capability', () => {
    db.grantCapability(testDb, agentId, 'hetzner', 'servers.list', secretId);
    const resolved = db.resolveCapability(testDb, agentId, 'hetzner', 'servers.list');
    expect(resolved).toBe(secretId);
  });

  it('resolves wildcard capability', () => {
    db.grantAllCapabilities(testDb, agentId, secretId, 'hetzner');
    const resolved = db.resolveCapability(testDb, agentId, 'hetzner', 'anything.here');
    expect(resolved).toBe(secretId);
  });

  it('prefers exact match over wildcard', () => {
    const secret2Id = db.createSecret(testDb, accountId, 'HETZNER_READONLY', 'hetzner', 'enc2').id;
    db.grantAllCapabilities(testDb, agentId, secretId, 'hetzner');
    db.grantCapability(testDb, agentId, 'hetzner', 'servers.list', secret2Id);
    const resolved = db.resolveCapability(testDb, agentId, 'hetzner', 'servers.list');
    expect(resolved).toBe(secret2Id);
  });

  it('returns null for ungranted capability', () => {
    expect(db.resolveCapability(testDb, agentId, 'hetzner', 'servers.list')).toBeNull();
  });

  it('cascades on agent delete', () => {
    db.grantCapability(testDb, agentId, 'hetzner', 'servers.list', secretId);
    db.deleteAgent(testDb, agentId, accountId);
    expect(db.listCapabilityGrants(testDb, agentId)).toHaveLength(0);
  });

  it('cascades on secret delete', () => {
    db.grantCapability(testDb, agentId, 'hetzner', 'servers.list', secretId);
    db.deleteSecret(testDb, secretId, accountId);
    expect(db.listCapabilityGrants(testDb, agentId)).toHaveLength(0);
  });
});

describe('Command Queue', () => {
  let testDb: Database.Database;
  let agentId: string;
  let actuatorId: string;

  beforeEach(() => {
    testDb = createTestDb();
    const accountId = db.createAccount(testDb, 'test@example.com', 'hash123').id;
    agentId = db.createAgent(testDb, accountId, 'Agent').id;
    actuatorId = db.createActuator(testDb, accountId, 'VPS', 'vps', agentId).id;
  });

  it('creates and retrieves command', () => {
    const cmd = db.createCommand(testDb, agentId, actuatorId, 'git', '{"action":"clone"}');
    expect(cmd.status).toBe('pending');
    const found = db.getCommandById(testDb, cmd.id)!;
    expect(found.capability).toBe('git');
  });

  it('updates command status', () => {
    const cmd = db.createCommand(testDb, agentId, actuatorId, 'git', '{}');
    db.updateCommandStatus(testDb, cmd.id, 'delivered');
    expect(db.getCommandById(testDb, cmd.id)!.status).toBe('delivered');
    expect(db.getCommandById(testDb, cmd.id)!.delivered_at).toBeTruthy();
  });

  it('completes command with result', () => {
    const cmd = db.createCommand(testDb, agentId, actuatorId, 'git', '{}');
    db.updateCommandStatus(testDb, cmd.id, 'completed', '{"output":"done"}');
    const found = db.getCommandById(testDb, cmd.id)!;
    expect(found.status).toBe('completed');
    expect(found.result).toBe('{"output":"done"}');
    expect(found.completed_at).toBeTruthy();
  });

  it('gets pending commands for actuator', () => {
    db.createCommand(testDb, agentId, actuatorId, 'git', '{}');
    db.createCommand(testDb, agentId, actuatorId, 'shell', '{}');
    const pending = db.getPendingCommands(testDb, actuatorId);
    expect(pending).toHaveLength(2);
  });

  it('lists recent commands', () => {
    db.createCommand(testDb, agentId, actuatorId, 'git', '{}');
    expect(db.listRecentCommands(testDb, agentId)).toHaveLength(1);
  });
});

describe('Sessions', () => {
  let testDb: Database.Database;
  let accountId: string;

  beforeEach(() => {
    testDb = createTestDb();
    accountId = db.createAccount(testDb, 'test@example.com', 'hash123').id;
  });

  it('creates and retrieves session', () => {
    const session = db.createSession(testDb, accountId);
    expect(session.id).toBeTruthy();
    const found = db.getSession(testDb, session.id);
    expect(found).toBeTruthy();
    expect(found!.account_id).toBe(accountId);
  });

  it('deletes session', () => {
    const session = db.createSession(testDb, accountId);
    db.deleteSession(testDb, session.id);
    expect(db.getSession(testDb, session.id)).toBeNull();
  });
});

describe('Audit Log', () => {
  let testDb: Database.Database;
  let accountId: string;

  beforeEach(() => {
    testDb = createTestDb();
    accountId = db.createAccount(testDb, 'test@example.com', 'hash123').id;
  });

  it('logs and lists audit entries', () => {
    db.logAudit(testDb, accountId, null, 'test.action', 'resource', 'success');
    db.logAudit(testDb, accountId, null, 'test.action2', null, 'error');
    const entries = db.listAudit(testDb, accountId);
    expect(entries).toHaveLength(2);
    const actions = entries.map(e => e.action);
    expect(actions).toContain('test.action');
    expect(actions).toContain('test.action2');
  });
});
