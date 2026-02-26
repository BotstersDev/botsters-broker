/**
 * REST API routes for account-scoped management (Phase 1.3)
 *
 * These endpoints use admin key authentication (via X-Admin-Key header)
 * for programmatic account management by the store or admin tools.
 */

import { Hono } from 'hono';
import type { Env } from './types.js';
import * as db from './db.js';
import { encrypt, hashPassword, generateToken, hashToken } from './crypto.js';

export const accountRoutes = new Hono<{ Bindings: Env }>();

// ─── Admin Auth Helper ─────────────────────────────────────────────────────────

function authenticateAdmin(c: any): boolean {
  const adminKey = c.req.header('X-Admin-Key');
  return !!adminKey && adminKey === c.env.masterKey;
}

function requireAdmin(c: any): Response | null {
  if (!authenticateAdmin(c)) {
    return c.json({ ok: false, error: 'Unauthorized: invalid or missing X-Admin-Key' }, 401);
  }
  return null;
}

// ─── Account CRUD ──────────────────────────────────────────────────────────────

// GET /api/accounts — list all accounts
accountRoutes.get('/accounts', (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const accounts = db.listAccounts(c.env.db);
  return c.json({ ok: true, accounts: accounts.map(a => ({ id: a.id, email: a.email, name: a.name, plan: a.plan, status: a.status, created_at: a.created_at })) });
});

// POST /api/accounts — create account
accountRoutes.post('/accounts', async (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const body = await c.req.json<{ email: string; password?: string; name?: string; plan?: string }>();
  if (!body.email) return c.json({ ok: false, error: 'Missing email' }, 400);

  const existing = db.getAccountByEmail(c.env.db, body.email);
  if (existing) return c.json({ ok: false, error: 'Account with this email already exists' }, 409);

  const pwHash = hashPassword(body.password || generateToken('').slice(0, 16));
  const account = db.createAccount(c.env.db, body.email, pwHash, body.name, body.plan);
  db.logAudit(c.env.db, account.id, null, 'account.create', null, 'success');

  return c.json({ ok: true, account: { id: account.id, email: account.email, name: account.name, plan: account.plan, status: account.status, created_at: account.created_at } }, 201);
});

// GET /api/accounts/:id — get account
accountRoutes.get('/accounts/:id', (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const account = db.getAccountById(c.env.db, c.req.param('id'));
  if (!account) return c.json({ ok: false, error: 'Account not found' }, 404);

  return c.json({ ok: true, account: { id: account.id, email: account.email, name: account.name, plan: account.plan, status: account.status, stripe_customer: account.stripe_customer, created_at: account.created_at, updated_at: account.updated_at } });
});

// PATCH /api/accounts/:id — update account
accountRoutes.patch('/accounts/:id', async (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const id = c.req.param('id');
  const account = db.getAccountById(c.env.db, id);
  if (!account) return c.json({ ok: false, error: 'Account not found' }, 404);

  const body = await c.req.json<{ name?: string; email?: string; plan?: string; status?: string; stripe_customer?: string }>();
  db.updateAccount(c.env.db, id, body);
  db.logAudit(c.env.db, id, null, 'account.update', null, 'success', null, JSON.stringify(Object.keys(body)));

  const updated = db.getAccountById(c.env.db, id);
  return c.json({ ok: true, account: { id: updated!.id, email: updated!.email, name: updated!.name, plan: updated!.plan, status: updated!.status, stripe_customer: updated!.stripe_customer, created_at: updated!.created_at, updated_at: updated!.updated_at } });
});

// DELETE /api/accounts/:id — deactivate account
accountRoutes.delete('/accounts/:id', (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const id = c.req.param('id');
  const account = db.getAccountById(c.env.db, id);
  if (!account) return c.json({ ok: false, error: 'Account not found' }, 404);

  db.deactivateAccount(c.env.db, id);
  db.logAudit(c.env.db, id, null, 'account.deactivate', null, 'success');

  return c.json({ ok: true });
});

// ─── Agent Management (account-scoped) ─────────────────────────────────────────

// POST /api/accounts/:id/agents — create agent
accountRoutes.post('/accounts/:id/agents', async (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const accountId = c.req.param('id');
  const account = db.getAccountById(c.env.db, accountId);
  if (!account) return c.json({ ok: false, error: 'Account not found' }, 404);

  const body = await c.req.json<{ name: string }>();
  if (!body.name) return c.json({ ok: false, error: 'Missing name' }, 400);

  const agent = db.createAgent(c.env.db, accountId, body.name, c.env.masterKey);
  db.logAudit(c.env.db, accountId, agent.id, 'agent.create', null, 'success');

  return c.json({ ok: true, agent: { id: agent.id, name: agent.name, token: agent._plaintext_token, created_at: agent.created_at } }, 201);
});

// GET /api/accounts/:id/agents — list agents
accountRoutes.get('/accounts/:id/agents', (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const accountId = c.req.param('id');
  const account = db.getAccountById(c.env.db, accountId);
  if (!account) return c.json({ ok: false, error: 'Account not found' }, 404);

  const agents = db.listAgents(c.env.db, accountId);
  return c.json({ ok: true, agents: agents.map(a => ({ id: a.id, name: a.name, scopes: a.scopes, created_at: a.created_at, last_seen_at: a.last_seen_at })) });
});

// DELETE /api/accounts/:id/agents/:agentId — remove agent
accountRoutes.delete('/accounts/:id/agents/:agentId', (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const accountId = c.req.param('id');
  const agentId = c.req.param('agentId');
  db.deleteAgent(c.env.db, agentId, accountId);
  db.logAudit(c.env.db, accountId, agentId, 'agent.delete', null, 'success');

  return c.json({ ok: true });
});

// POST /api/accounts/:id/agents/:agentId/rotate-token — rotate agent token
accountRoutes.post('/accounts/:id/agents/:agentId/rotate-token', (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const accountId = c.req.param('id');
  const agentId = c.req.param('agentId');
  const result = db.rotateAgentToken(c.env.db, agentId, accountId, c.env.masterKey);
  if (!result) return c.json({ ok: false, error: 'Agent not found' }, 404);

  db.logAudit(c.env.db, accountId, agentId, 'agent.rotate-token', null, 'success');

  return c.json({ ok: true, token: result.token });
});

// ─── Actuator Management (account-scoped) ──────────────────────────────────────

// POST /api/agents/:id/actuators — register actuator (and assign to agent)
accountRoutes.post('/agents/:agentId/actuators', async (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const agentId = c.req.param('agentId');
  const agent = db.getAgentById(c.env.db, agentId);
  if (!agent) return c.json({ ok: false, error: 'Agent not found' }, 404);

  const body = await c.req.json<{ name: string; type?: string }>();
  if (!body.name) return c.json({ ok: false, error: 'Missing name' }, 400);

  const actuator = db.createActuator(c.env.db, agent.account_id, body.name, body.type || 'vps', agentId);
  db.logAudit(c.env.db, agent.account_id, agentId, 'actuator.create', actuator.id, 'success');

  return c.json({ ok: true, actuator }, 201);
});

// GET /api/agents/:id/actuators — list actuators
accountRoutes.get('/agents/:agentId/actuators', (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const agentId = c.req.param('agentId');
  const agent = db.getAgentById(c.env.db, agentId);
  if (!agent) return c.json({ ok: false, error: 'Agent not found' }, 404);

  const actuators = db.listActuators(c.env.db, agentId);
  const withCaps = actuators.map(a => ({
    ...a,
    assignment: db.listActuatorAssignments(c.env.db, a.id).find(asg => asg.agent_id === agentId) || null,
    capabilities: db.listCapabilities(c.env.db, a.id),
  }));
  return c.json({ ok: true, actuators: withCaps });
});

// PATCH /api/agents/:id/actuators/:actId — update capabilities
accountRoutes.patch('/agents/:agentId/actuators/:actId', async (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const agentId = c.req.param('agentId');
  const actId = c.req.param('actId');
  const agent = db.getAgentById(c.env.db, agentId);
  if (!agent) return c.json({ ok: false, error: 'Agent not found' }, 404);
  const actuator = db.getActuatorById(c.env.db, actId);
  if (!actuator || actuator.account_id !== agent.account_id) return c.json({ ok: false, error: 'Actuator not found' }, 404);

  const body = await c.req.json<{ capabilities?: Array<{ capability: string; constraints?: string }> }>();
  if (body.capabilities) {
    // Replace all capabilities
    const existing = db.listCapabilities(c.env.db, actId);
    for (const cap of existing) {
      db.removeCapability(c.env.db, actId, cap.capability);
    }
    for (const cap of body.capabilities) {
      db.addCapability(c.env.db, actId, cap.capability, cap.constraints);
    }
  }

  db.logAudit(c.env.db, agent.account_id, agentId, 'actuator.update', actId, 'success');

  const caps = db.listCapabilities(c.env.db, actId);
  return c.json({ ok: true, actuator: { ...actuator, capabilities: caps } });
});

// DELETE /api/agents/:id/actuators/:actId — deregister actuator
accountRoutes.delete('/agents/:agentId/actuators/:actId', (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const agentId = c.req.param('agentId');
  const actId = c.req.param('actId');
  const agent = db.getAgentById(c.env.db, agentId);
  if (!agent) return c.json({ ok: false, error: 'Agent not found' }, 404);
  const actuator = db.getActuatorById(c.env.db, actId);
  if (!actuator || actuator.account_id !== agent.account_id) return c.json({ ok: false, error: 'Actuator not found' }, 404);

  db.deleteActuator(c.env.db, actId);
  db.logAudit(c.env.db, agent.account_id, agentId, 'actuator.delete', actId, 'success');

  return c.json({ ok: true });
});

// POST /api/agents/:agentId/actuators/:actId/assign — assign actuator to agent
accountRoutes.post('/agents/:agentId/actuators/:actId/assign', async (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const agentId = c.req.param('agentId');
  const actId = c.req.param('actId');
  const body = await c.req.json<{ enabled?: boolean }>();
  const ok = db.assignActuatorToAgent(c.env.db, agentId, actId, body.enabled === false ? 0 : 1);
  if (!ok) return c.json({ ok: false, error: 'Agent/actuator not found or account mismatch' }, 400);

  const agent = db.getAgentById(c.env.db, agentId)!;
  db.logAudit(c.env.db, agent.account_id, agentId, 'actuator.assign', actId, 'success');
  return c.json({ ok: true });
});

// DELETE /api/agents/:agentId/actuators/:actId/assign — remove assignment
accountRoutes.delete('/agents/:agentId/actuators/:actId/assign', (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const agentId = c.req.param('agentId');
  const actId = c.req.param('actId');
  const agent = db.getAgentById(c.env.db, agentId);
  if (!agent) return c.json({ ok: false, error: 'Agent not found' }, 404);
  db.removeActuatorAssignment(c.env.db, agentId, actId);
  db.logAudit(c.env.db, agent.account_id, agentId, 'actuator.unassign', actId, 'success');
  return c.json({ ok: true });
});

// POST /api/agents/:agentId/actuators/:actId/toggle-assignment — toggle assignment enabled
accountRoutes.post('/agents/:agentId/actuators/:actId/toggle-assignment', (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const agentId = c.req.param('agentId');
  const actId = c.req.param('actId');
  const agent = db.getAgentById(c.env.db, agentId);
  if (!agent) return c.json({ ok: false, error: 'Agent not found' }, 404);
  const ok = db.toggleAgentActuatorAssignmentEnabled(c.env.db, agentId, actId);
  if (!ok) return c.json({ ok: false, error: 'Assignment not found' }, 404);
  db.logAudit(c.env.db, agent.account_id, agentId, 'actuator.assignment.toggle', actId, 'success');
  return c.json({ ok: true });
});

// ─── Capability Grants (account-scoped) ────────────────────────────────────────

// POST /api/accounts/:id/agents/:agentId/capabilities — grant a capability
accountRoutes.post('/accounts/:id/agents/:agentId/capabilities', async (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const accountId = c.req.param('id');
  const agentId = c.req.param('agentId');
  const agent = db.getAgentById(c.env.db, agentId);
  if (!agent || agent.account_id !== accountId) return c.json({ ok: false, error: 'Agent not found' }, 404);

  const body = await c.req.json<{ provider: string; capability: string; secret_id: string; constraints?: string }>();
  if (!body.provider || !body.capability || !body.secret_id) return c.json({ ok: false, error: 'Missing provider, capability, or secret_id' }, 400);

  const grant = db.grantCapability(c.env.db, agentId, body.provider, body.capability, body.secret_id, body.constraints);
  db.logAudit(c.env.db, accountId, agentId, 'capability.grant', `${body.provider}/${body.capability}`, 'success');

  return c.json({ ok: true, grant }, 201);
});

// GET /api/accounts/:id/agents/:agentId/capabilities — list grants
accountRoutes.get('/accounts/:id/agents/:agentId/capabilities', (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const accountId = c.req.param('id');
  const agentId = c.req.param('agentId');
  const agent = db.getAgentById(c.env.db, agentId);
  if (!agent || agent.account_id !== accountId) return c.json({ ok: false, error: 'Agent not found' }, 404);

  const grants = db.listCapabilityGrants(c.env.db, agentId);
  return c.json({ ok: true, grants });
});

// DELETE /api/accounts/:id/agents/:agentId/capabilities/:grantId — revoke
accountRoutes.delete('/accounts/:id/agents/:agentId/capabilities/:grantId', (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const accountId = c.req.param('id');
  const agentId = c.req.param('agentId');
  const grantId = c.req.param('grantId');
  const agent = db.getAgentById(c.env.db, agentId);
  if (!agent || agent.account_id !== accountId) return c.json({ ok: false, error: 'Agent not found' }, 404);

  db.revokeCapability(c.env.db, grantId);
  db.logAudit(c.env.db, accountId, agentId, 'capability.revoke', grantId, 'success');

  return c.json({ ok: true });
});

// POST /api/accounts/:id/agents/:agentId/grant-all — convenience: grant provider/*
accountRoutes.post('/accounts/:id/agents/:agentId/grant-all', async (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const accountId = c.req.param('id');
  const agentId = c.req.param('agentId');
  const agent = db.getAgentById(c.env.db, agentId);
  if (!agent || agent.account_id !== accountId) return c.json({ ok: false, error: 'Agent not found' }, 404);

  const body = await c.req.json<{ secret_id: string; provider: string }>();
  if (!body.secret_id || !body.provider) return c.json({ ok: false, error: 'Missing secret_id or provider' }, 400);

  const grant = db.grantAllCapabilities(c.env.db, agentId, body.secret_id, body.provider);
  db.logAudit(c.env.db, accountId, agentId, 'capability.grant-all', `${body.provider}/*`, 'success');

  return c.json({ ok: true, grant }, 201);
});

// ─── Secrets (account-scoped) ──────────────────────────────────────────────────

// POST /api/accounts/:id/secrets — store credential
accountRoutes.post('/accounts/:id/secrets', async (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const accountId = c.req.param('id');
  const account = db.getAccountById(c.env.db, accountId);
  if (!account) return c.json({ ok: false, error: 'Account not found' }, 404);

  const body = await c.req.json<{ name: string; provider: string; value: string; scope?: string[] }>();
  if (!body.name || !body.value) return c.json({ ok: false, error: 'Missing name or value' }, 400);

  const encrypted = encrypt(body.value, c.env.masterKey);
  const secret = db.createSecret(c.env.db, accountId, body.name, body.provider || 'other', encrypted);

  if (body.scope && body.scope.length > 0) {
    db.setSecretAccess(c.env.db, secret.id, body.scope);
  }

  // Auto-grant provider/* to all agents in the account
  const agents = db.listAgents(c.env.db, accountId);
  const provider = body.provider || 'other';
  for (const agent of agents) {
    try {
      db.grantAllCapabilities(c.env.db, agent.id, secret.id, provider);
    } catch {
      // Ignore duplicates (agent may already have a grant for this provider)
    }
  }

  db.logAudit(c.env.db, accountId, null, 'secret.create', body.name, 'success');

  return c.json({ ok: true, secret: { id: secret.id, name: secret.name, provider: secret.provider, created_at: secret.created_at } }, 201);
});

// GET /api/accounts/:id/secrets — list (metadata only)
accountRoutes.get('/accounts/:id/secrets', (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const accountId = c.req.param('id');
  const account = db.getAccountById(c.env.db, accountId);
  if (!account) return c.json({ ok: false, error: 'Account not found' }, 404);

  const secrets = db.listSecrets(c.env.db, accountId);
  return c.json({ ok: true, secrets: secrets.map(s => ({ id: s.id, name: s.name, provider: s.provider, created_at: s.created_at, updated_at: s.updated_at })) });
});

// DELETE /api/accounts/:id/secrets/:secretId — remove credential
accountRoutes.delete('/accounts/:id/secrets/:secretId', (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const accountId = c.req.param('id');
  const secretId = c.req.param('secretId');
  const secret = db.getSecretById(c.env.db, secretId, accountId);
  if (!secret) return c.json({ ok: false, error: 'Secret not found' }, 404);

  db.deleteSecret(c.env.db, secretId, accountId);
  db.logAudit(c.env.db, accountId, null, 'secret.delete', secret.name, 'success');

  return c.json({ ok: true });
});

// ─── Provision (Store Integration) ─────────────────────────────────────────────

// POST /api/provision — called by seksbot-store on signup
accountRoutes.post('/provision', async (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const body = await c.req.json<{ email: string; name?: string; plan?: string; stripe_customer?: string }>();
  if (!body.email) return c.json({ ok: false, error: 'Missing email' }, 400);

  // Check for existing account
  const existing = db.getAccountByEmail(c.env.db, body.email);
  if (existing) return c.json({ ok: false, error: 'Account already exists', account_id: existing.id }, 409);

  // Create account with random password (user will set via web UI or store)
  const tempPassword = generateToken('').slice(0, 24);
  const pwHash = hashPassword(tempPassword);
  const account = db.createAccount(c.env.db, body.email, pwHash, body.name, body.plan);

  if (body.stripe_customer) {
    db.updateAccount(c.env.db, account.id, { stripe_customer: body.stripe_customer });
  }

  // Create default agent
  const agent = db.createAgent(c.env.db, account.id, 'default', c.env.masterKey);

  db.logAudit(c.env.db, account.id, agent.id, 'provision.create', null, 'success');

  return c.json({
    ok: true,
    account_id: account.id,
    agent_id: agent.id,
    agent_token: agent._plaintext_token,
    temp_password: tempPassword,
  }, 201);
});

// DELETE /api/provision/:accountId — called on account deletion
accountRoutes.delete('/provision/:accountId', (c) => {
  const denied = requireAdmin(c);
  if (denied) return denied;

  const accountId = c.req.param('accountId');
  const account = db.getAccountById(c.env.db, accountId);
  if (!account) return c.json({ ok: false, error: 'Account not found' }, 404);

  db.deactivateAccount(c.env.db, accountId);
  db.logAudit(c.env.db, accountId, null, 'provision.deactivate', null, 'success');

  return c.json({ ok: true });
});
