/**
 * REST API routes for agents
 */

import { Hono } from 'hono';
import type { Agent, Env, SecretGetRequest, ProxyRequest } from './types';
import * as db from './db';
import { decrypt, encrypt, hashPassword } from './crypto';

export const apiRoutes = new Hono<{ Bindings: Env }>();

// ─── Auth Helper ───────────────────────────────────────────────────────────────

async function authenticateAgent(c: any): Promise<Agent | null> {
  const authHeader = c.req.header('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return null;
  }
  
  const token = authHeader.slice(7);

  // Check for scoped token first
  if (token.startsWith('seks_scoped_')) {
    const masterKey = getMasterKey(c.env);
    const payload = await verifyScopedToken(token, masterKey);
    if (!payload) return null;

    const agent = await db.getAgentById(c.env.DB, payload.agent_id);
    if (!agent || agent.client_id !== payload.client_id) return null;

    c.executionCtx.waitUntil(db.updateAgentLastSeen(c.env.DB, agent.id));
    // Stash scoped info on the context for downstream capability checks
    c.set('scopedToken', payload);
    return agent;
  }

  const agent = await db.getAgentByToken(c.env.DB, token);
  
  if (agent) {
    // Update last seen (fire and forget)
    c.executionCtx.waitUntil(db.updateAgentLastSeen(c.env.DB, agent.id));
  }
  
  return agent;
}

function getMasterKey(env: Env): string {
  // In production, this should be set via wrangler secret
  // For dev, generate an ephemeral one (data won't persist across restarts)
  return env.MASTER_KEY || 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
}

// ─── Health Check ──────────────────────────────────────────────────────────────

apiRoutes.get('/health', (c) => {
  return c.json({ status: 'ok', version: '0.1.0' });
});

// ─── Admin: Bulk Import Secrets ────────────────────────────────────────────────
// POST /v1/admin/import
// Body: { adminKey: string, email: string, secrets: { name, value, provider }[] }

apiRoutes.post('/admin/import', async (c) => {
  const body = await c.req.json<{
    adminKey: string;
    email: string;
    password?: string;
    secrets: Array<{ name: string; value: string; provider?: string }>;
  }>();
  
  // Verify admin key matches MASTER_KEY (simple auth for bootstrap)
  const masterKey = getMasterKey(c.env);
  if (body.adminKey !== masterKey) {
    return c.json({ ok: false, error: 'Invalid admin key' }, 401);
  }
  
  // Find or create client
  let client = await db.getClientByEmail(c.env.DB, body.email);
  if (!client) {
    const pwHash = await hashPassword(body.password || 'changeme');
    client = await db.createClient(c.env.DB, body.email, pwHash);
  }
  
  // Import secrets
  const results: Array<{ name: string; status: string }> = [];
  for (const secret of body.secrets) {
    try {
      const encrypted = await encrypt(secret.value, masterKey);
      const provider = secret.provider || guessProvider(secret.name);
      await db.createSecret(c.env.DB, client.id, secret.name, provider, encrypted);
      results.push({ name: secret.name, status: 'created' });
    } catch (e: any) {
      if (e.message?.includes('UNIQUE constraint')) {
        results.push({ name: secret.name, status: 'exists' });
      } else {
        results.push({ name: secret.name, status: `error: ${e.message}` });
      }
    }
  }
  
  return c.json({ ok: true, clientId: client.id, results });
});

function guessProvider(name: string): string {
  const n = name.toUpperCase();
  if (n.includes('OPENAI')) return 'openai';
  if (n.includes('ANTHROPIC') || n.includes('CLAUDE')) return 'anthropic';
  if (n.includes('GEMINI') || n.includes('GOOGLE')) return 'google';
  if (n.includes('AWS')) return 'aws';
  if (n.includes('GITHUB')) return 'github';
  if (n.includes('CLOUDFLARE')) return 'cloudflare';
  if (n.includes('NOTION')) return 'notion';
  if (n.includes('BRAVE')) return 'brave';
  return 'other';
}

// ─── Scoped Tokens ─────────────────────────────────────────────────────────────
//
// POST /v1/tokens/scoped
// Mints a short-lived scoped token for skill execution.
// The scoped token is an HMAC-SHA256 signed JSON payload containing:
//   - agent_id, client_id, skillName, capabilities, exp
// Only the declared capabilities are usable with the scoped token.

apiRoutes.post('/tokens/scoped', async (c) => {
  const agent = await authenticateAgent(c);
  if (!agent) {
    return c.json({ ok: false, error: 'Unauthorized' }, 401);
  }

  const body = await c.req.json<{
    skillName: string;
    capabilities: string[];
    ttlSeconds?: number;
  }>();

  if (!body.skillName || !Array.isArray(body.capabilities) || body.capabilities.length === 0) {
    return c.json({ ok: false, error: 'Missing skillName or capabilities' }, 400);
  }

  // Enforce TTL limits: default 5min, max 30min
  const ttl = Math.min(Math.max(body.ttlSeconds || 300, 10), 1800);
  const now = Date.now();
  const expiresAt = new Date(now + ttl * 1000).toISOString();

  // Check agent scopes — if agent has scopes defined, scoped token can't escalate
  const agentScopes: string[] = JSON.parse(agent.scopes || '[]');
  if (agentScopes.length > 0) {
    const disallowed = body.capabilities.filter(cap => !agentScopes.includes(cap));
    if (disallowed.length > 0) {
      await db.logAudit(c.env.DB, agent.client_id, agent.id, 'token.scoped', body.skillName, 'denied', null, `escalation: ${disallowed.join(',')}`);
      return c.json({ ok: false, error: `Capabilities exceed agent scope: ${disallowed.join(', ')}` }, 403);
    }
  }

  // Build the token payload
  const payload = {
    type: 'scoped',
    agent_id: agent.id,
    client_id: agent.client_id,
    skill: body.skillName,
    caps: body.capabilities,
    iat: now,
    exp: now + ttl * 1000,
  };

  // Sign it with HMAC-SHA256 using the master key
  const masterKey = getMasterKey(c.env);
  const payloadB64 = btoa(JSON.stringify(payload));
  const sig = await hmacSign(payloadB64, masterKey);
  const token = `seks_scoped_${payloadB64}.${sig}`;

  await db.logAudit(c.env.DB, agent.client_id, agent.id, 'token.scoped', body.skillName, 'success', null, `caps=${body.capabilities.join(',')},ttl=${ttl}s`);

  return c.json({ ok: true, token, expiresAt });
});

// Verify and decode a scoped token (used internally by proxy/secret endpoints)
async function verifyScopedToken(token: string, masterKey: string): Promise<{
  agent_id: string;
  client_id: string;
  skill: string;
  caps: string[];
  exp: number;
} | null> {
  if (!token.startsWith('seks_scoped_')) return null;
  const stripped = token.slice('seks_scoped_'.length);
  const dotIdx = stripped.lastIndexOf('.');
  if (dotIdx === -1) return null;

  const payloadB64 = stripped.slice(0, dotIdx);
  const sig = stripped.slice(dotIdx + 1);

  // Verify signature
  const expectedSig = await hmacSign(payloadB64, masterKey);
  if (sig !== expectedSig) return null;

  try {
    const payload = JSON.parse(atob(payloadB64));
    if (payload.type !== 'scoped') return null;
    if (Date.now() > payload.exp) return null; // expired
    return payload;
  } catch {
    return null;
  }
}

// HMAC-SHA256 sign and return hex
async function hmacSign(data: string, key: string): Promise<string> {
  const encoder = new TextEncoder();
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    encoder.encode(key),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(data));
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ─── Get Secret ────────────────────────────────────────────────────────────────

apiRoutes.post('/secrets/get', async (c) => {
  const agent = await authenticateAgent(c);
  if (!agent) {
    return c.json({ ok: false, error: 'Unauthorized' }, 401);
  }
  
  const body = await c.req.json<SecretGetRequest>();
  if (!body.name) {
    return c.json({ ok: false, error: 'Missing "name" field' }, 400);
  }
  
  // Pass agent.id to filter by access permissions
  const secret = await db.getSecret(c.env.DB, agent.client_id, body.name, agent.id);
  if (!secret) {
    await db.logAudit(c.env.DB, agent.client_id, agent.id, 'secret.get', body.name, 'not_found');
    return c.json({ ok: false, error: `Secret '${body.name}' not found` }, 404);
  }
  
  try {
    const value = await decrypt(secret.encrypted_value, getMasterKey(c.env));
    await db.logAudit(c.env.DB, agent.client_id, agent.id, 'secret.get', body.name, 'success');
    return c.json({ ok: true, value });
  } catch (e) {
    return c.json({ ok: false, error: 'Failed to decrypt secret' }, 500);
  }
});

// ─── List Secrets ──────────────────────────────────────────────────────────────

apiRoutes.post('/secrets/list', async (c) => {
  const agent = await authenticateAgent(c);
  if (!agent) {
    return c.json({ ok: false, secrets: [] }, 401);
  }
  
  // Pass agent.id to filter by access permissions
  const secrets = await db.listSecrets(c.env.DB, agent.client_id, agent.id);
  const secretInfos = secrets.map(s => ({ name: s.name, provider: s.provider }));
  
  await db.logAudit(c.env.DB, agent.client_id, agent.id, 'secret.list', null, 'success');
  return c.json({ ok: true, secrets: secretInfos });
});

// ─── Proxy Request ─────────────────────────────────────────────────────────────

const SERVICE_CONFIG: Record<string, { baseUrl: string; secretName: string; authHeader: string; authFormat?: string }> = {
  openai: {
    baseUrl: 'https://api.openai.com',
    secretName: 'OPENAI_API_KEY',
    authHeader: 'Authorization',
    authFormat: 'Bearer',
  },
  anthropic: {
    baseUrl: 'https://api.anthropic.com',
    secretName: 'ANTHROPIC_API_KEY',
    authHeader: 'x-api-key',
  },
  claude: {
    baseUrl: 'https://api.anthropic.com',
    secretName: 'ANTHROPIC_API_KEY',
    authHeader: 'x-api-key',
  },
  github: {
    baseUrl: 'https://api.github.com',
    secretName: 'GITHUB_PERSONAL_ACCESS_TOKEN',
    authHeader: 'Authorization',
    authFormat: 'Bearer',
  },
  notion: {
    baseUrl: 'https://api.notion.com',
    secretName: 'NOTION_API_KEY',
    authHeader: 'Authorization',
    authFormat: 'Bearer',
  },
  gemini: {
    baseUrl: 'https://generativelanguage.googleapis.com',
    secretName: 'GEMINI_API_KEY',
    authHeader: 'x-goog-api-key',
  },
  cloudflare: {
    baseUrl: 'https://api.cloudflare.com',
    secretName: 'CLOUDFLARE_API_TOKEN',
    authHeader: 'Authorization',
    authFormat: 'Bearer',
  },
  brave: {
    baseUrl: 'https://api.search.brave.com',
    secretName: 'BRAVE_BASE_AI_TOKEN',
    authHeader: 'X-Subscription-Token',
  },
};

apiRoutes.post('/proxy/request', async (c) => {
  const agent = await authenticateAgent(c);
  if (!agent) {
    return c.json({ ok: false, error: 'Unauthorized' }, 401);
  }
  
  const body = await c.req.json<ProxyRequest>();
  
  const config = SERVICE_CONFIG[body.service];
  if (!config) {
    return c.json({ ok: false, error: `Unknown service: ${body.service}` }, 400);
  }
  
  // Get the API key (with agent access check)
  const secret = await db.getSecret(c.env.DB, agent.client_id, config.secretName, agent.id);
  if (!secret) {
    return c.json({ ok: false, error: `No ${config.secretName} configured (or agent lacks access)` }, 404);
  }
  
  let apiKey: string;
  try {
    apiKey = await decrypt(secret.encrypted_value, getMasterKey(c.env));
  } catch (e) {
    return c.json({ ok: false, error: 'Failed to decrypt secret' }, 500);
  }
  
  // Build upstream request
  const url = `${config.baseUrl}${body.path}`;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...body.headers,
  };
  
  // Add auth header
  if (config.authHeader === 'Authorization') {
    headers['Authorization'] = `Bearer ${apiKey}`;
  } else {
    headers[config.authHeader] = apiKey;
  }
  
  // Add Anthropic-specific headers
  if (body.service === 'anthropic' || body.service === 'claude') {
    headers['anthropic-version'] = '2023-06-01';
  }
  
  // Remove any auth headers from user-provided headers
  delete headers['authorization'];
  delete headers['x-api-key'];
  
  try {
    const response = await fetch(url, {
      method: body.method.toUpperCase(),
      headers,
      body: body.body ? JSON.stringify(body.body) : undefined,
    });
    
    const status = response.status;
    let responseBody: unknown;
    try {
      responseBody = await response.json();
    } catch {
      responseBody = await response.text();
    }
    
    await db.logAudit(
      c.env.DB, agent.client_id, agent.id, 'proxy.request',
      body.service, 'success', null, `status=${status}`
    );
    
    return c.json({
      ok: status >= 200 && status < 300,
      status,
      body: responseBody,
    });
  } catch (e) {
    const error = e instanceof Error ? e.message : 'Unknown error';
    await db.logAudit(
      c.env.DB, agent.client_id, agent.id, 'proxy.request',
      body.service, 'error', null, error
    );
    return c.json({ ok: false, error: `Request failed: ${error}` }, 502);
  }
});

// ─── S3 Presigned URLs ─────────────────────────────────────────────────────────
//
// POST /api/s3/presign
// Generates a presigned S3 URL so agents can upload/download without AWS keys.

const ALLOWED_S3_BUCKETS = new Set([
  'seksbot-shared-lfs',
]);

apiRoutes.post('/api/s3/presign', async (c) => {
  const agent = await authenticateAgent(c);
  if (!agent) {
    return c.json({ ok: false, error: 'Unauthorized' }, 401);
  }

  const body = await c.req.json<{
    bucket: string;
    key: string;
    method: 'GET' | 'PUT';
    expiresIn?: number;
    contentType?: string;
    region?: string;
  }>();

  // Validate required fields
  if (!body.bucket || !body.key || !body.method) {
    return c.json({ ok: false, error: 'Missing required fields: bucket, key, method' }, 400);
  }

  if (body.method !== 'GET' && body.method !== 'PUT') {
    return c.json({ ok: false, error: 'method must be "GET" or "PUT"' }, 400);
  }

  // Bucket allowlist check
  if (!ALLOWED_S3_BUCKETS.has(body.bucket)) {
    await db.logAudit(c.env.DB, agent.client_id, agent.id, 's3.presign', body.bucket, 'denied', null, `bucket not allowed: ${body.bucket}`);
    return c.json({ ok: false, error: `Bucket '${body.bucket}' is not in the allowlist` }, 403);
  }

  const expiresIn = Math.min(body.expiresIn || 3600, 604800); // max 7 days
  const region = body.region || 'us-west-2';

  // Get AWS credentials
  const accessKeySecret = await db.getSecret(c.env.DB, agent.client_id, 'AWS_ACCESS_KEY_ID', agent.id);
  const secretKeySecret = await db.getSecret(c.env.DB, agent.client_id, 'AWS_SECRET_ACCESS_KEY', agent.id);

  if (!accessKeySecret || !secretKeySecret) {
    return c.json({ ok: false, error: 'AWS credentials not configured (or agent lacks access)' }, 404);
  }

  let accessKeyId: string;
  let secretAccessKey: string;
  try {
    accessKeyId = await decrypt(accessKeySecret.encrypted_value, getMasterKey(c.env));
    secretAccessKey = await decrypt(secretKeySecret.encrypted_value, getMasterKey(c.env));
  } catch (e) {
    return c.json({ ok: false, error: 'Failed to decrypt AWS credentials' }, 500);
  }

  try {
    const url = await generatePresignedUrl({
      method: body.method,
      bucket: body.bucket,
      key: body.key,
      region,
      accessKeyId,
      secretAccessKey,
      expiresIn,
      contentType: body.contentType,
    });

    await db.logAudit(
      c.env.DB, agent.client_id, agent.id, 's3.presign',
      `s3://${body.bucket}/${body.key}`, 'success', null,
      `${body.method} expires=${expiresIn}s`
    );

    return c.json({ ok: true, url, expiresIn });
  } catch (e) {
    const error = e instanceof Error ? e.message : 'Unknown error';
    await db.logAudit(c.env.DB, agent.client_id, agent.id, 's3.presign', body.bucket, 'error', null, error);
    return c.json({ ok: false, error: `Failed to generate presigned URL: ${error}` }, 500);
  }
});

// ─── Passthrough Proxy ─────────────────────────────────────────────────────────
// 
// Routes like /api/openai/* forward to api.openai.com with credential injection.
// Agent uses fake token generated from the UI: Authorization: Bearer seks_openai_abc123...
// Broker looks up the fake token, finds the agent, substitutes real API key.
//
// Example:
//   POST /api/openai/v1/chat/completions
//   Authorization: Bearer seks_openai_Kx7mN2pQ...
//   → POST https://api.openai.com/v1/chat/completions
//   Authorization: Bearer sk-real-openai-key...

// Generic passthrough handler
async function handlePassthrough(c: any, provider: string) {
  const config = SERVICE_CONFIG[provider];
  if (!config) {
    return c.json({ error: `Unknown provider: ${provider}` }, 400);
  }

  // Extract the fake token from Authorization header
  const authHeader = c.req.header('Authorization') || '';
  let token = '';
  if (authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7);
  } else if (authHeader.startsWith('seks_')) {
    token = authHeader;
  } else {
    // For non-Bearer auth (like x-api-key), check that header
    token = c.req.header(config.authHeader) || '';
  }

  if (!token.startsWith('seks_')) {
    return c.json({ error: 'Invalid token format. Expected: seks_<provider>_<random>' }, 401);
  }

  // Look up fake token in database
  const fakeToken = await db.getFakeTokenByToken(c.env.DB, token);
  if (!fakeToken) {
    return c.json({ error: 'Invalid or expired token' }, 401);
  }

  if (fakeToken.provider !== provider) {
    return c.json({ error: `Token provider mismatch: expected ${provider}, got ${fakeToken.provider}` }, 401);
  }

  // Get the agent
  const agentRecord = await db.getAgentById(c.env.DB, fakeToken.agent_id);
  if (!agentRecord) {
    return c.json({ error: 'Agent not found' }, 401);
  }

  // Update last seen
  c.executionCtx.waitUntil(db.updateAgentLastSeen(c.env.DB, agentRecord.id));
  c.executionCtx.waitUntil(db.updateFakeTokenLastUsed(c.env.DB, fakeToken.id));

  // Get the real API key (with agent access check)
  const secret = await db.getSecret(c.env.DB, agentRecord.client_id, config.secretName, agentRecord.id);
  if (!secret) {
    return c.json({ error: `No ${config.secretName} configured for this account (or agent lacks access)` }, 404);
  }

  let apiKey: string;
  try {
    apiKey = await decrypt(secret.encrypted_value, getMasterKey(c.env));
  } catch (e) {
    return c.json({ error: 'Failed to decrypt secret' }, 500);
  }

  // Build the upstream URL
  const path = c.req.path.replace(`/api/${provider}`, '') || '/';
  const query = c.req.url.includes('?') ? c.req.url.split('?')[1] : '';
  const upstreamUrl = `${config.baseUrl}${path}${query ? '?' + query : ''}`;

  // Build headers, replacing auth
  const headers = new Headers();
  for (const [key, value] of c.req.raw.headers.entries()) {
    // Skip headers we'll replace or that shouldn't be forwarded
    const lowerKey = key.toLowerCase();
    if (lowerKey === 'host' || lowerKey === 'authorization' || lowerKey === config.authHeader.toLowerCase()) {
      continue;
    }
    headers.set(key, value);
  }

  // Add the real auth header
  if (config.authFormat === 'Bearer') {
    headers.set(config.authHeader, `Bearer ${apiKey}`);
  } else {
    headers.set(config.authHeader, apiKey);
  }

  // Add provider-specific headers
  if (provider === 'anthropic' || provider === 'claude') {
    headers.set('anthropic-version', '2023-06-01');
  }

  // Forward the request
  try {
    const body = c.req.raw.body;
    const response = await fetch(upstreamUrl, {
      method: c.req.method,
      headers,
      body: ['GET', 'HEAD'].includes(c.req.method) ? undefined : body,
    });

    // Log the request
    await db.logAudit(
      c.env.DB, agentRecord.client_id, agentRecord.id, 'passthrough',
      provider, response.ok ? 'success' : 'error', null, `${c.req.method} ${path} → ${response.status}`
    );

    // Return the response as-is
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  } catch (e) {
    const error = e instanceof Error ? e.message : 'Unknown error';
    await db.logAudit(
      c.env.DB, agentRecord.client_id, agentRecord.id, 'passthrough',
      provider, 'error', null, error
    );
    return c.json({ error: `Request failed: ${error}` }, 502);
  }
}

// Register passthrough routes for each provider
apiRoutes.all('/api/openai/*', (c) => handlePassthrough(c, 'openai'));
apiRoutes.all('/api/anthropic/*', (c) => handlePassthrough(c, 'anthropic'));
apiRoutes.all('/api/claude/*', (c) => handlePassthrough(c, 'claude'));
apiRoutes.all('/api/github/*', (c) => handlePassthrough(c, 'github'));
apiRoutes.all('/api/notion/*', (c) => handlePassthrough(c, 'notion'));
apiRoutes.all('/api/gemini/*', (c) => handlePassthrough(c, 'gemini'));
apiRoutes.all('/api/cloudflare/*', (c) => handlePassthrough(c, 'cloudflare'));
apiRoutes.all('/api/brave/*', (c) => handlePassthrough(c, 'brave'));

// ─── AWS S3 Passthrough with SigV4 Signing ─────────────────────────────────────
//
// Routes: /api/aws/s3/<region>/<bucket>/<key>
// Example: /api/aws/s3/us-west-2/my-bucket/path/to/file.txt
//
// The broker:
// 1. Parses region, bucket, key from URL
// 2. Fetches AWS credentials from database
// 3. Signs the request using SigV4
// 4. Forwards to S3

apiRoutes.all('/api/aws/s3/:region/*', async (c) => {
  const region = c.req.param('region');
  const pathAfterRegion = c.req.path.replace(`/api/aws/s3/${region}/`, '');
  
  // Parse bucket and key from path
  const slashIndex = pathAfterRegion.indexOf('/');
  const bucket = slashIndex === -1 ? pathAfterRegion : pathAfterRegion.slice(0, slashIndex);
  const key = slashIndex === -1 ? '' : pathAfterRegion.slice(slashIndex + 1);
  
  if (!bucket) {
    return c.json({ error: 'Missing bucket in path. Use: /api/aws/s3/<region>/<bucket>/<key>' }, 400);
  }

  // Extract the fake token
  const authHeader = c.req.header('Authorization') || '';
  let token = '';
  if (authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7);
  } else if (authHeader.startsWith('seks_')) {
    token = authHeader;
  }

  if (!token.startsWith('seks_')) {
    return c.json({ error: 'Invalid token format. Expected: seks_aws_<random>' }, 401);
  }

  // Look up fake token
  const fakeToken = await db.getFakeTokenByToken(c.env.DB, token);
  if (!fakeToken || fakeToken.provider !== 'aws') {
    return c.json({ error: 'Invalid or expired AWS token' }, 401);
  }

  // Get the agent
  const agentRecord = await db.getAgentById(c.env.DB, fakeToken.agent_id);
  if (!agentRecord) {
    return c.json({ error: 'Agent not found' }, 401);
  }

  // Update last seen
  c.executionCtx.waitUntil(db.updateAgentLastSeen(c.env.DB, agentRecord.id));
  c.executionCtx.waitUntil(db.updateFakeTokenLastUsed(c.env.DB, fakeToken.id));

  // Get AWS credentials (with agent access check)
  const accessKeySecret = await db.getSecret(c.env.DB, agentRecord.client_id, 'AWS_ACCESS_KEY_ID', agentRecord.id);
  const secretKeySecret = await db.getSecret(c.env.DB, agentRecord.client_id, 'AWS_SECRET_ACCESS_KEY', agentRecord.id);
  
  if (!accessKeySecret || !secretKeySecret) {
    return c.json({ error: 'AWS credentials not configured (or agent lacks access)' }, 404);
  }

  let accessKeyId: string;
  let secretAccessKey: string;
  try {
    accessKeyId = await decrypt(accessKeySecret.encrypted_value, getMasterKey(c.env));
    secretAccessKey = await decrypt(secretKeySecret.encrypted_value, getMasterKey(c.env));
  } catch (e) {
    return c.json({ error: 'Failed to decrypt AWS credentials' }, 500);
  }

  // Build S3 request
  const method = c.req.method;
  const host = `${bucket}.s3.${region}.amazonaws.com`;
  const path = key ? `/${key}` : '/';
  const query = c.req.url.includes('?') ? c.req.url.split('?')[1] : '';
  
  // Get request body for PUT/POST
  let body: ArrayBuffer | null = null;
  if (!['GET', 'HEAD', 'DELETE'].includes(method)) {
    body = await c.req.arrayBuffer();
  }

  try {
    // Sign and send the request
    const signedRequest = await signAwsRequest({
      method,
      host,
      path,
      query,
      region,
      service: 's3',
      accessKeyId,
      secretAccessKey,
      body,
      headers: {
        'host': host,
      },
    });

    const url = `https://${host}${path}${query ? '?' + query : ''}`;
    const response = await fetch(url, {
      method,
      headers: signedRequest.headers,
      body: body,
    });

    // Log the request
    await db.logAudit(
      c.env.DB, agentRecord.client_id, agentRecord.id, 'passthrough',
      'aws/s3', response.ok ? 'success' : 'error', null, 
      `${method} s3://${bucket}/${key} → ${response.status}`
    );

    // Return the response
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: response.headers,
    });
  } catch (e) {
    const error = e instanceof Error ? e.message : 'Unknown error';
    await db.logAudit(
      c.env.DB, agentRecord.client_id, agentRecord.id, 'passthrough',
      'aws/s3', 'error', null, error
    );
    return c.json({ error: `S3 request failed: ${error}` }, 502);
  }
});

// ─── AWS SigV4 Signing ─────────────────────────────────────────────────────────

interface AwsSignRequest {
  method: string;
  host: string;
  path: string;
  query: string;
  region: string;
  service: string;
  accessKeyId: string;
  secretAccessKey: string;
  body: ArrayBuffer | null;
  headers: Record<string, string>;
}

async function signAwsRequest(req: AwsSignRequest): Promise<{ headers: Record<string, string> }> {
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '').slice(0, 15) + 'Z';
  const dateStamp = amzDate.slice(0, 8);
  
  // Hash the payload
  const payloadHash = await sha256Hex(req.body || new ArrayBuffer(0));
  
  // Build canonical headers
  const headers: Record<string, string> = {
    ...req.headers,
    'x-amz-date': amzDate,
    'x-amz-content-sha256': payloadHash,
  };
  
  const sortedHeaderKeys = Object.keys(headers).sort();
  const canonicalHeaders = sortedHeaderKeys
    .map(k => `${k.toLowerCase()}:${headers[k].trim()}`)
    .join('\n') + '\n';
  const signedHeaders = sortedHeaderKeys.map(k => k.toLowerCase()).join(';');
  
  // Build canonical request
  const canonicalRequest = [
    req.method,
    req.path || '/',
    req.query || '',
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');
  
  // Create string to sign
  const algorithm = 'AWS4-HMAC-SHA256';
  const credentialScope = `${dateStamp}/${req.region}/${req.service}/aws4_request`;
  const canonicalRequestHash = await sha256Hex(new TextEncoder().encode(canonicalRequest));
  const stringToSign = [algorithm, amzDate, credentialScope, canonicalRequestHash].join('\n');
  
  // Derive signing key
  const kDate = await hmacSha256(new TextEncoder().encode('AWS4' + req.secretAccessKey), dateStamp);
  const kRegion = await hmacSha256(kDate, req.region);
  const kService = await hmacSha256(kRegion, req.service);
  const kSigning = await hmacSha256(kService, 'aws4_request');
  
  // Calculate signature
  const signature = await hmacSha256Hex(kSigning, stringToSign);
  
  // Build authorization header
  const authHeader = `${algorithm} Credential=${req.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  
  return {
    headers: {
      ...headers,
      'Authorization': authHeader,
    },
  };
}

async function sha256Hex(data: ArrayBuffer | string): Promise<string> {
  const buffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const hash = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmacSha256(key: ArrayBuffer | Uint8Array, data: string): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(data));
}

async function hmacSha256Hex(key: ArrayBuffer, data: string): Promise<string> {
  const sig = await hmacSha256(key, data);
  return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ─── S3 Presigned URL Generation (Query String Auth) ────────────────────────────

interface PresignParams {
  method: string;
  bucket: string;
  key: string;
  region: string;
  accessKeyId: string;
  secretAccessKey: string;
  expiresIn: number;
  contentType?: string;
}

function uriEncode(str: string, encodeSlash = true): string {
  return str.split('').map(ch => {
    if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
        (ch >= '0' && ch <= '9') || ch === '_' || ch === '-' || ch === '~' || ch === '.') {
      return ch;
    }
    if (ch === '/' && !encodeSlash) return ch;
    return '%' + ch.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0');
  }).join('');
}

async function generatePresignedUrl(params: PresignParams): Promise<string> {
  const { method, bucket, key, region, accessKeyId, secretAccessKey, expiresIn, contentType } = params;

  const host = `${bucket}.s3.${region}.amazonaws.com`;
  const path = '/' + key;
  const algorithm = 'AWS4-HMAC-SHA256';

  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '').slice(0, 15) + 'Z';
  const dateStamp = amzDate.slice(0, 8);
  const credentialScope = `${dateStamp}/${region}/s3/aws4_request`;
  const credential = `${accessKeyId}/${credentialScope}`;

  // Build canonical query string (sorted)
  const queryParams: Record<string, string> = {
    'X-Amz-Algorithm': algorithm,
    'X-Amz-Credential': credential,
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': String(expiresIn),
    'X-Amz-SignedHeaders': contentType ? 'content-type;host' : 'host',
  };

  const canonicalQueryString = Object.keys(queryParams)
    .sort()
    .map(k => `${uriEncode(k)}=${uriEncode(queryParams[k])}`)
    .join('&');

  // Canonical headers
  let canonicalHeaders = `host:${host}\n`;
  let signedHeaders = 'host';
  if (contentType) {
    canonicalHeaders = `content-type:${contentType}\nhost:${host}\n`;
    signedHeaders = 'content-type;host';
  }

  // For presigned URLs, payload is UNSIGNED-PAYLOAD
  const canonicalRequest = [
    method,
    uriEncode(path, false),
    canonicalQueryString,
    canonicalHeaders,
    signedHeaders,
    'UNSIGNED-PAYLOAD',
  ].join('\n');

  // String to sign
  const canonicalRequestHash = await sha256Hex(new TextEncoder().encode(canonicalRequest));
  const stringToSign = [algorithm, amzDate, credentialScope, canonicalRequestHash].join('\n');

  // Derive signing key
  const kDate = await hmacSha256(new TextEncoder().encode('AWS4' + secretAccessKey), dateStamp);
  const kRegion = await hmacSha256(kDate, region);
  const kService = await hmacSha256(kRegion, 's3');
  const kSigning = await hmacSha256(kService, 'aws4_request');

  // Signature
  const signature = await hmacSha256Hex(kSigning, stringToSign);

  return `https://${host}${uriEncode(path, false)}?${canonicalQueryString}&X-Amz-Signature=${signature}`;
}
