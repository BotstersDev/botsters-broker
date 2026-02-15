/**
 * REST API routes for agents
 */

import { Hono } from 'hono';
import type { Agent, Env } from './types';
import * as db from './db';
import { decrypt, encrypt, hashPassword, hmacSign, sha256Hex, hmacSha256 } from './crypto';

export const apiRoutes = new Hono<{ Bindings: Env }>();

// ─── Auth Helper ───────────────────────────────────────────────────────────────

function authenticateAgent(c: any): Agent | null {
  const authHeader = c.req.header('Authorization');
  if (!authHeader?.startsWith('Bearer ')) return null;

  const token = authHeader.slice(7);
  const { db: database, masterKey } = c.env;

  // Check for scoped token first
  if (token.startsWith('seks_scoped_')) {
    const payload = verifyScopedToken(token, masterKey);
    if (!payload) return null;
    const agent = db.getAgentById(database, payload.agent_id);
    if (!agent || agent.account_id !== payload.account_id) return null;
    db.updateAgentLastSeen(database, agent.id);
    c.set('scopedToken', payload);
    return agent;
  }

  const agent = db.getAgentByToken(database, token);
  if (agent) db.updateAgentLastSeen(database, agent.id);
  return agent;
}

function getMasterKey(env: Env): string {
  return env.masterKey;
}

// ─── Health Check ──────────────────────────────────────────────────────────────

apiRoutes.get('/health', (c) => {
  return c.json({ status: 'ok', version: '0.2.0' });
});

// ─── Admin: Bulk Import Secrets ────────────────────────────────────────────────

apiRoutes.post('/admin/import', async (c) => {
  const body = await c.req.json<{
    adminKey: string;
    email: string;
    password?: string;
    secrets: Array<{ name: string; value: string; provider?: string }>;
  }>();

  const masterKey = getMasterKey(c.env);
  if (body.adminKey !== masterKey) {
    return c.json({ ok: false, error: 'Invalid admin key' }, 401);
  }

  let account = db.getAccountByEmail(c.env.db, body.email);
  if (!account) {
    const pwHash = hashPassword(body.password || 'changeme');
    account = db.createAccount(c.env.db, body.email, pwHash);
  }

  const results: Array<{ name: string; status: string }> = [];
  for (const secret of body.secrets) {
    try {
      const encrypted = encrypt(secret.value, masterKey);
      const provider = secret.provider || guessProvider(secret.name);
      db.createSecret(c.env.db, account.id, secret.name, provider, encrypted);
      results.push({ name: secret.name, status: 'created' });
    } catch (e: any) {
      if (e.message?.includes('UNIQUE constraint')) {
        results.push({ name: secret.name, status: 'exists' });
      } else {
        results.push({ name: secret.name, status: `error: ${e.message}` });
      }
    }
  }

  return c.json({ ok: true, accountId: account.id, results });
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

apiRoutes.post('/tokens/scoped', async (c) => {
  const agent = authenticateAgent(c);
  if (!agent) return c.json({ ok: false, error: 'Unauthorized' }, 401);

  const body = await c.req.json<{
    skillName: string;
    capabilities: string[];
    ttlSeconds?: number;
  }>();

  if (!body.skillName || !Array.isArray(body.capabilities) || body.capabilities.length === 0) {
    return c.json({ ok: false, error: 'Missing skillName or capabilities' }, 400);
  }

  const ttl = Math.min(Math.max(body.ttlSeconds || 300, 10), 1800);
  const now = Date.now();
  const expiresAt = new Date(now + ttl * 1000).toISOString();

  const agentScopes: string[] = JSON.parse(agent.scopes || '[]');
  if (agentScopes.length > 0) {
    const disallowed = body.capabilities.filter(cap => !agentScopes.includes(cap));
    if (disallowed.length > 0) {
      db.logAudit(c.env.db, agent.account_id, agent.id, 'token.scoped', body.skillName, 'denied', null, `escalation: ${disallowed.join(',')}`);
      return c.json({ ok: false, error: `Capabilities exceed agent scope: ${disallowed.join(', ')}` }, 403);
    }
  }

  const payload = {
    type: 'scoped',
    agent_id: agent.id,
    account_id: agent.account_id,
    skill: body.skillName,
    caps: body.capabilities,
    iat: now,
    exp: now + ttl * 1000,
  };

  const masterKey = getMasterKey(c.env);
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64');
  const sig = hmacSign(payloadB64, masterKey);
  const token = `seks_scoped_${payloadB64}.${sig}`;

  db.logAudit(c.env.db, agent.account_id, agent.id, 'token.scoped', body.skillName, 'success', null, `caps=${body.capabilities.join(',')},ttl=${ttl}s`);

  return c.json({ ok: true, token, expiresAt });
});

function verifyScopedToken(token: string, masterKey: string): {
  agent_id: string;
  account_id: string;
  skill: string;
  caps: string[];
  exp: number;
} | null {
  if (!token.startsWith('seks_scoped_')) return null;
  const stripped = token.slice('seks_scoped_'.length);
  const dotIdx = stripped.lastIndexOf('.');
  if (dotIdx === -1) return null;

  const payloadB64 = stripped.slice(0, dotIdx);
  const sig = stripped.slice(dotIdx + 1);

  const expectedSig = hmacSign(payloadB64, masterKey);
  if (sig !== expectedSig) return null;

  try {
    const payload = JSON.parse(Buffer.from(payloadB64, 'base64').toString());
    if (payload.type !== 'scoped') return null;
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}

// ─── Scoped Token Capability Enforcement ───────────────────────────────────────

function secretToProvider(secretName: string): string | null {
  const n = secretName.toUpperCase();
  if (n.includes('OPENAI')) return 'openai';
  if (n.includes('ANTHROPIC') || n.includes('CLAUDE')) return 'anthropic';
  if (n.includes('GEMINI') || n.includes('GOOGLE')) return 'google';
  if (n.includes('AWS')) return 'aws';
  if (n.includes('GITHUB')) return 'github';
  if (n.includes('CLOUDFLARE')) return 'cloudflare';
  if (n.includes('NOTION')) return 'notion';
  if (n.includes('BRAVE')) return 'brave';
  return null;
}

function checkScopedCapability(c: any, provider: string): boolean {
  const scoped = c.get('scopedToken') as { caps?: string[] } | undefined;
  if (!scoped?.caps) return true;
  return scoped.caps.includes(provider) || scoped.caps.includes('*');
}

// ─── Get Secret ────────────────────────────────────────────────────────────────

apiRoutes.post('/secrets/get', async (c) => {
  const agent = authenticateAgent(c);
  if (!agent) return c.json({ ok: false, error: 'Unauthorized' }, 401);

  const body = await c.req.json<{ name: string }>();
  if (!body.name) return c.json({ ok: false, error: 'Missing "name" field' }, 400);

  const provider = secretToProvider(body.name);
  if (provider && !checkScopedCapability(c, provider)) {
    db.logAudit(c.env.db, agent.account_id, agent.id, 'secret.get', body.name, 'denied', null, 'scoped token lacks capability');
    return c.json({ ok: false, error: `Scoped token does not have '${provider}' capability` }, 403);
  }

  const secret = db.getSecret(c.env.db, agent.account_id, body.name, agent.id);
  if (!secret) {
    db.logAudit(c.env.db, agent.account_id, agent.id, 'secret.get', body.name, 'not_found');
    return c.json({ ok: false, error: `Secret '${body.name}' not found` }, 404);
  }

  try {
    const value = decrypt(secret.encrypted_value, getMasterKey(c.env));
    db.logAudit(c.env.db, agent.account_id, agent.id, 'secret.get', body.name, 'success');
    return c.json({ ok: true, value });
  } catch {
    return c.json({ ok: false, error: 'Failed to decrypt secret' }, 500);
  }
});

// ─── List Secrets ──────────────────────────────────────────────────────────────

apiRoutes.post('/secrets/list', async (c) => {
  const agent = authenticateAgent(c);
  if (!agent) return c.json({ ok: false, secrets: [] }, 401);

  const secrets = db.listSecrets(c.env.db, agent.account_id, agent.id);

  const scopedInfo: { caps?: string[] } | undefined = (c as any).get('scopedToken');
  let filtered = secrets;
  if (scopedInfo?.caps) {
    filtered = secrets.filter((s: any) => {
      const provider = secretToProvider(s.name);
      if (!provider) return false;
      return scopedInfo.caps!.includes(provider) || scopedInfo.caps!.includes('*');
    });
  }
  const secretInfos = filtered.map((s: any) => ({ name: s.name, provider: s.provider }));

  db.logAudit(c.env.db, agent.account_id, agent.id, 'secret.list', null, 'success');
  return c.json({ ok: true, secrets: secretInfos });
});

// ─── Proxy Request ─────────────────────────────────────────────────────────────

const SERVICE_CONFIG: Record<string, { baseUrl: string; secretName: string; authHeader: string; authFormat?: string }> = {
  openai: { baseUrl: 'https://api.openai.com', secretName: 'OPENAI_API_KEY', authHeader: 'Authorization', authFormat: 'Bearer' },
  anthropic: { baseUrl: 'https://api.anthropic.com', secretName: 'ANTHROPIC_API_KEY', authHeader: 'x-api-key' },
  claude: { baseUrl: 'https://api.anthropic.com', secretName: 'ANTHROPIC_API_KEY', authHeader: 'x-api-key' },
  github: { baseUrl: 'https://api.github.com', secretName: 'GITHUB_PERSONAL_ACCESS_TOKEN', authHeader: 'Authorization', authFormat: 'Bearer' },
  notion: { baseUrl: 'https://api.notion.com', secretName: 'NOTION_API_KEY', authHeader: 'Authorization', authFormat: 'Bearer' },
  gemini: { baseUrl: 'https://generativelanguage.googleapis.com', secretName: 'GEMINI_API_KEY', authHeader: 'x-goog-api-key' },
  cloudflare: { baseUrl: 'https://api.cloudflare.com', secretName: 'CLOUDFLARE_API_TOKEN', authHeader: 'Authorization', authFormat: 'Bearer' },
  brave: { baseUrl: 'https://api.search.brave.com', secretName: 'BRAVE_BASE_AI_TOKEN', authHeader: 'X-Subscription-Token' },
};

apiRoutes.post('/proxy/request', async (c) => {
  const agent = authenticateAgent(c);
  if (!agent) return c.json({ ok: false, error: 'Unauthorized' }, 401);

  const body = await c.req.json<{ service: string; method: string; path: string; headers?: Record<string, string>; body?: unknown }>();
  const config = SERVICE_CONFIG[body.service];
  if (!config) return c.json({ ok: false, error: `Unknown service: ${body.service}` }, 400);

  if (!checkScopedCapability(c, body.service)) {
    db.logAudit(c.env.db, agent.account_id, agent.id, 'proxy.request', body.service, 'denied', null, 'scoped token lacks capability');
    return c.json({ ok: false, error: `Scoped token does not have '${body.service}' capability` }, 403);
  }

  const secret = db.getSecret(c.env.db, agent.account_id, config.secretName, agent.id);
  if (!secret) return c.json({ ok: false, error: `No ${config.secretName} configured (or agent lacks access)` }, 404);

  let apiKey: string;
  try {
    apiKey = decrypt(secret.encrypted_value, getMasterKey(c.env));
  } catch {
    return c.json({ ok: false, error: 'Failed to decrypt secret' }, 500);
  }

  const url = `${config.baseUrl}${body.path}`;
  const headers: Record<string, string> = { 'Content-Type': 'application/json', ...body.headers };

  if (config.authHeader === 'Authorization') {
    headers['Authorization'] = `Bearer ${apiKey}`;
  } else {
    headers[config.authHeader] = apiKey;
  }

  if (body.service === 'anthropic' || body.service === 'claude') {
    headers['anthropic-version'] = '2023-06-01';
  }

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
    try { responseBody = await response.json(); } catch { responseBody = await response.text(); }

    db.logAudit(c.env.db, agent.account_id, agent.id, 'proxy.request', body.service, 'success', null, `status=${status}`);
    return c.json({ ok: status >= 200 && status < 300, status, body: responseBody });
  } catch (e) {
    const error = e instanceof Error ? e.message : 'Unknown error';
    db.logAudit(c.env.db, agent.account_id, agent.id, 'proxy.request', body.service, 'error', null, error);
    return c.json({ ok: false, error: `Request failed: ${error}` }, 502);
  }
});

// ─── Passthrough Proxy ─────────────────────────────────────────────────────────

async function handlePassthrough(c: any, provider: string) {
  const config = SERVICE_CONFIG[provider];
  if (!config) return c.json({ error: `Unknown provider: ${provider}` }, 400);

  const authHeader = c.req.header('Authorization') || '';
  let token = '';
  if (authHeader.startsWith('Bearer ')) token = authHeader.slice(7);
  else if (authHeader.startsWith('seks_')) token = authHeader;
  else token = c.req.header(config.authHeader) || '';

  if (!token.startsWith('seks_')) {
    return c.json({ error: 'Invalid token format. Expected: seks_<provider>_<random>' }, 401);
  }

  const fakeToken = db.getFakeTokenByToken(c.env.db, token);
  if (!fakeToken) return c.json({ error: 'Invalid or expired token' }, 401);
  if (fakeToken.provider !== provider) return c.json({ error: `Token provider mismatch` }, 401);

  const agentRecord = db.getAgentById(c.env.db, fakeToken.agent_id);
  if (!agentRecord) return c.json({ error: 'Agent not found' }, 401);

  db.updateAgentLastSeen(c.env.db, agentRecord.id);
  db.updateFakeTokenLastUsed(c.env.db, fakeToken.id);

  const secret = db.getSecret(c.env.db, agentRecord.account_id, config.secretName, agentRecord.id);
  if (!secret) return c.json({ error: `No ${config.secretName} configured` }, 404);

  let apiKey: string;
  try { apiKey = decrypt(secret.encrypted_value, getMasterKey(c.env)); }
  catch { return c.json({ error: 'Failed to decrypt secret' }, 500); }

  const path = c.req.path.replace(`/api/${provider}`, '') || '/';
  const query = c.req.url.includes('?') ? c.req.url.split('?')[1] : '';
  const upstreamUrl = `${config.baseUrl}${path}${query ? '?' + query : ''}`;

  const headers = new Headers();
  for (const [key, value] of c.req.raw.headers.entries()) {
    const lowerKey = key.toLowerCase();
    if (lowerKey === 'host' || lowerKey === 'authorization' || lowerKey === config.authHeader.toLowerCase()) continue;
    headers.set(key, value);
  }

  if (config.authFormat === 'Bearer') headers.set(config.authHeader, `Bearer ${apiKey}`);
  else headers.set(config.authHeader, apiKey);

  if (provider === 'anthropic' || provider === 'claude') headers.set('anthropic-version', '2023-06-01');

  try {
    const body = c.req.raw.body;
    const response = await fetch(upstreamUrl, {
      method: c.req.method,
      headers,
      body: ['GET', 'HEAD'].includes(c.req.method) ? undefined : body,
    });

    db.logAudit(c.env.db, agentRecord.account_id, agentRecord.id, 'passthrough', provider, response.ok ? 'success' : 'error', null, `${c.req.method} ${path} → ${response.status}`);

    return new Response(response.body, { status: response.status, statusText: response.statusText, headers: response.headers });
  } catch (e) {
    const error = e instanceof Error ? e.message : 'Unknown error';
    db.logAudit(c.env.db, agentRecord.account_id, agentRecord.id, 'passthrough', provider, 'error', null, error);
    return c.json({ error: `Request failed: ${error}` }, 502);
  }
}

apiRoutes.all('/api/openai/*', (c) => handlePassthrough(c, 'openai'));
apiRoutes.all('/api/anthropic/*', (c) => handlePassthrough(c, 'anthropic'));
apiRoutes.all('/api/claude/*', (c) => handlePassthrough(c, 'claude'));
apiRoutes.all('/api/github/*', (c) => handlePassthrough(c, 'github'));
apiRoutes.all('/api/notion/*', (c) => handlePassthrough(c, 'notion'));
apiRoutes.all('/api/gemini/*', (c) => handlePassthrough(c, 'gemini'));
apiRoutes.all('/api/cloudflare/*', (c) => handlePassthrough(c, 'cloudflare'));
apiRoutes.all('/api/brave/*', (c) => handlePassthrough(c, 'brave'));

// ─── S3 Presigned URLs ─────────────────────────────────────────────────────────

const ALLOWED_S3_BUCKETS = new Set(['seksbot-shared-lfs']);

apiRoutes.post('/api/s3/presign', async (c) => {
  const agent = authenticateAgent(c);
  if (!agent) return c.json({ ok: false, error: 'Unauthorized' }, 401);

  const body = await c.req.json<{ bucket: string; key: string; method: 'GET' | 'PUT'; expiresIn?: number; contentType?: string; region?: string }>();

  if (!body.bucket || !body.key || !body.method) return c.json({ ok: false, error: 'Missing required fields' }, 400);
  if (body.method !== 'GET' && body.method !== 'PUT') return c.json({ ok: false, error: 'method must be GET or PUT' }, 400);

  if (!ALLOWED_S3_BUCKETS.has(body.bucket)) {
    db.logAudit(c.env.db, agent.account_id, agent.id, 's3.presign', body.bucket, 'denied', null, 'bucket not allowed');
    return c.json({ ok: false, error: `Bucket '${body.bucket}' not allowed` }, 403);
  }

  const expiresIn = Math.min(body.expiresIn || 3600, 604800);
  const region = body.region || 'us-west-2';

  const accessKeySecret = db.getSecret(c.env.db, agent.account_id, 'AWS_ACCESS_KEY_ID', agent.id);
  const secretKeySecret = db.getSecret(c.env.db, agent.account_id, 'AWS_SECRET_ACCESS_KEY', agent.id);
  if (!accessKeySecret || !secretKeySecret) return c.json({ ok: false, error: 'AWS credentials not configured' }, 404);

  let accessKeyId: string, secretAccessKey: string;
  try {
    accessKeyId = decrypt(accessKeySecret.encrypted_value, getMasterKey(c.env));
    secretAccessKey = decrypt(secretKeySecret.encrypted_value, getMasterKey(c.env));
  } catch { return c.json({ ok: false, error: 'Failed to decrypt AWS credentials' }, 500); }

  try {
    const url = generatePresignedUrl({ method: body.method, bucket: body.bucket, key: body.key, region, accessKeyId, secretAccessKey, expiresIn, contentType: body.contentType });
    db.logAudit(c.env.db, agent.account_id, agent.id, 's3.presign', `s3://${body.bucket}/${body.key}`, 'success', null, `${body.method} expires=${expiresIn}s`);
    return c.json({ ok: true, url, expiresIn });
  } catch (e) {
    const error = e instanceof Error ? e.message : 'Unknown error';
    db.logAudit(c.env.db, agent.account_id, agent.id, 's3.presign', body.bucket, 'error', null, error);
    return c.json({ ok: false, error: `Failed: ${error}` }, 500);
  }
});

// ─── AWS S3 Passthrough ────────────────────────────────────────────────────────

apiRoutes.all('/api/aws/s3/:region/*', async (c) => {
  const region = c.req.param('region');
  const pathAfterRegion = c.req.path.replace(`/api/aws/s3/${region}/`, '');
  const slashIndex = pathAfterRegion.indexOf('/');
  const bucket = slashIndex === -1 ? pathAfterRegion : pathAfterRegion.slice(0, slashIndex);
  const key = slashIndex === -1 ? '' : pathAfterRegion.slice(slashIndex + 1);
  if (!bucket) return c.json({ error: 'Missing bucket' }, 400);

  const authHeader = c.req.header('Authorization') || '';
  let token = '';
  if (authHeader.startsWith('Bearer ')) token = authHeader.slice(7);
  else if (authHeader.startsWith('seks_')) token = authHeader;
  if (!token.startsWith('seks_')) return c.json({ error: 'Invalid token' }, 401);

  const fakeToken = db.getFakeTokenByToken(c.env.db, token);
  if (!fakeToken || fakeToken.provider !== 'aws') return c.json({ error: 'Invalid AWS token' }, 401);

  const agentRecord = db.getAgentById(c.env.db, fakeToken.agent_id);
  if (!agentRecord) return c.json({ error: 'Agent not found' }, 401);

  db.updateAgentLastSeen(c.env.db, agentRecord.id);
  db.updateFakeTokenLastUsed(c.env.db, fakeToken.id);

  const accessKeySecret = db.getSecret(c.env.db, agentRecord.account_id, 'AWS_ACCESS_KEY_ID', agentRecord.id);
  const secretKeySecret = db.getSecret(c.env.db, agentRecord.account_id, 'AWS_SECRET_ACCESS_KEY', agentRecord.id);
  if (!accessKeySecret || !secretKeySecret) return c.json({ error: 'AWS credentials not configured' }, 404);

  let accessKeyId: string, secretAccessKey: string;
  try {
    accessKeyId = decrypt(accessKeySecret.encrypted_value, getMasterKey(c.env));
    secretAccessKey = decrypt(secretKeySecret.encrypted_value, getMasterKey(c.env));
  } catch { return c.json({ error: 'Failed to decrypt' }, 500); }

  const method = c.req.method;
  const host = `${bucket}.s3.${region}.amazonaws.com`;
  const s3path = key ? `/${key}` : '/';
  const query = c.req.url.includes('?') ? c.req.url.split('?')[1] : '';

  let body: ArrayBuffer | null = null;
  if (!['GET', 'HEAD', 'DELETE'].includes(method)) {
    body = await c.req.arrayBuffer();
  }

  try {
    const signedRequest = signAwsRequest({ method, host, path: s3path, query, region, service: 's3', accessKeyId, secretAccessKey, body });
    const url = `https://${host}${s3path}${query ? '?' + query : ''}`;
    const response = await fetch(url, { method, headers: signedRequest.headers, body });
    db.logAudit(c.env.db, agentRecord.account_id, agentRecord.id, 'passthrough', 'aws/s3', response.ok ? 'success' : 'error', null, `${method} s3://${bucket}/${key} → ${response.status}`);
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers: response.headers });
  } catch (e) {
    const error = e instanceof Error ? e.message : 'Unknown error';
    db.logAudit(c.env.db, agentRecord.account_id, agentRecord.id, 'passthrough', 'aws/s3', 'error', null, error);
    return c.json({ error: `S3 request failed: ${error}` }, 502);
  }
});

// ─── AWS SigV4 Signing (Node.js sync) ──────────────────────────────────────────

interface AwsSignRequest {
  method: string; host: string; path: string; query: string;
  region: string; service: string; accessKeyId: string; secretAccessKey: string;
  body: ArrayBuffer | null; headers?: Record<string, string>;
}

function signAwsRequest(req: AwsSignRequest): { headers: Record<string, string> } {
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '').slice(0, 15) + 'Z';
  const dateStamp = amzDate.slice(0, 8);

  const payloadHash = sha256Hex(req.body ? Buffer.from(req.body) : Buffer.alloc(0));

  const headers: Record<string, string> = {
    ...req.headers,
    host: req.host,
    'x-amz-date': amzDate,
    'x-amz-content-sha256': payloadHash,
  };

  const sortedHeaderKeys = Object.keys(headers).sort();
  const canonicalHeaders = sortedHeaderKeys.map(k => `${k.toLowerCase()}:${headers[k].trim()}`).join('\n') + '\n';
  const signedHeaders = sortedHeaderKeys.map(k => k.toLowerCase()).join(';');

  const canonicalRequest = [req.method, req.path || '/', req.query || '', canonicalHeaders, signedHeaders, payloadHash].join('\n');

  const algorithm = 'AWS4-HMAC-SHA256';
  const credentialScope = `${dateStamp}/${req.region}/${req.service}/aws4_request`;
  const canonicalRequestHash = sha256Hex(canonicalRequest);
  const stringToSign = [algorithm, amzDate, credentialScope, canonicalRequestHash].join('\n');

  const kDate = hmacSha256(Buffer.from('AWS4' + req.secretAccessKey), dateStamp);
  const kRegion = hmacSha256(kDate, req.region);
  const kService = hmacSha256(kRegion, req.service);
  const kSigning = hmacSha256(kService, 'aws4_request');
  const signature = hmacSha256(kSigning, stringToSign).toString('hex');

  const authHeader = `${algorithm} Credential=${req.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return { headers: { ...headers, 'Authorization': authHeader } };
}

// ─── S3 Presigned URL Generation ────────────────────────────────────────────────

interface PresignParams {
  method: string; bucket: string; key: string; region: string;
  accessKeyId: string; secretAccessKey: string; expiresIn: number; contentType?: string;
}

function uriEncode(str: string, encodeSlash = true): string {
  return str.split('').map(ch => {
    if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch === '_' || ch === '-' || ch === '~' || ch === '.') return ch;
    if (ch === '/' && !encodeSlash) return ch;
    return '%' + ch.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0');
  }).join('');
}

function generatePresignedUrl(params: PresignParams): string {
  const { method, bucket, key, region, accessKeyId, secretAccessKey, expiresIn, contentType } = params;
  const host = `${bucket}.s3.${region}.amazonaws.com`;
  const path = '/' + key;
  const algorithm = 'AWS4-HMAC-SHA256';

  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '').slice(0, 15) + 'Z';
  const dateStamp = amzDate.slice(0, 8);
  const credentialScope = `${dateStamp}/${region}/s3/aws4_request`;
  const credential = `${accessKeyId}/${credentialScope}`;

  const queryParams: Record<string, string> = {
    'X-Amz-Algorithm': algorithm,
    'X-Amz-Credential': credential,
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': String(expiresIn),
    'X-Amz-SignedHeaders': contentType ? 'content-type;host' : 'host',
  };

  const canonicalQueryString = Object.keys(queryParams).sort().map(k => `${uriEncode(k)}=${uriEncode(queryParams[k])}`).join('&');

  let canonicalHeaders = `host:${host}\n`;
  let signedHeaders = 'host';
  if (contentType) {
    canonicalHeaders = `content-type:${contentType}\nhost:${host}\n`;
    signedHeaders = 'content-type;host';
  }

  const canonicalRequest = [method, uriEncode(path, false), canonicalQueryString, canonicalHeaders, signedHeaders, 'UNSIGNED-PAYLOAD'].join('\n');
  const canonicalRequestHash = sha256Hex(canonicalRequest);
  const stringToSign = [algorithm, amzDate, credentialScope, canonicalRequestHash].join('\n');

  const kDate = hmacSha256(Buffer.from('AWS4' + secretAccessKey), dateStamp);
  const kRegion = hmacSha256(kDate, region);
  const kService = hmacSha256(kRegion, 's3');
  const kSigning = hmacSha256(kService, 'aws4_request');
  const signature = hmacSha256(kSigning, stringToSign).toString('hex');

  return `https://${host}${uriEncode(path, false)}?${canonicalQueryString}&X-Amz-Signature=${signature}`;
}

// ─── Actuator REST API ─────────────────────────────────────────────────────────

apiRoutes.get('/actuators', (c) => {
  const agent = authenticateAgent(c);
  if (!agent) return c.json({ ok: false, error: 'Unauthorized' }, 401);
  const actuators = db.listActuators(c.env.db, agent.id);
  const withCaps = actuators.map(a => ({ ...a, capabilities: db.listCapabilities(c.env.db, a.id) }));
  return c.json({ ok: true, actuators: withCaps });
});

apiRoutes.post('/actuators', async (c) => {
  const agent = authenticateAgent(c);
  if (!agent) return c.json({ ok: false, error: 'Unauthorized' }, 401);
  const body = await c.req.json<{ name: string; type?: string }>();
  if (!body.name) return c.json({ ok: false, error: 'Missing name' }, 400);
  const actuator = db.createActuator(c.env.db, agent.id, body.name, body.type || 'vps');
  return c.json({ ok: true, actuator }, 201);
});

apiRoutes.delete('/actuators/:id', (c) => {
  const agent = authenticateAgent(c);
  if (!agent) return c.json({ ok: false, error: 'Unauthorized' }, 401);
  const id = c.req.param('id');
  const actuator = db.getActuatorById(c.env.db, id);
  if (!actuator || actuator.agent_id !== agent.id) return c.json({ ok: false, error: 'Not found' }, 404);
  db.deleteActuator(c.env.db, id);
  return c.json({ ok: true });
});

apiRoutes.post('/actuators/:id/capabilities', async (c) => {
  const agent = authenticateAgent(c);
  if (!agent) return c.json({ ok: false, error: 'Unauthorized' }, 401);
  const id = c.req.param('id');
  const actuator = db.getActuatorById(c.env.db, id);
  if (!actuator || actuator.agent_id !== agent.id) return c.json({ ok: false, error: 'Not found' }, 404);
  const body = await c.req.json<{ capability: string; constraints?: string }>();
  if (!body.capability) return c.json({ ok: false, error: 'Missing capability' }, 400);
  const cap = db.addCapability(c.env.db, id, body.capability, body.constraints);
  return c.json({ ok: true, capability: cap }, 201);
});

apiRoutes.delete('/actuators/:id/capabilities/:cap', (c) => {
  const agent = authenticateAgent(c);
  if (!agent) return c.json({ ok: false, error: 'Unauthorized' }, 401);
  const id = c.req.param('id');
  const cap = c.req.param('cap');
  const actuator = db.getActuatorById(c.env.db, id);
  if (!actuator || actuator.agent_id !== agent.id) return c.json({ ok: false, error: 'Not found' }, 404);
  db.removeCapability(c.env.db, id, cap);
  return c.json({ ok: true });
});

apiRoutes.get('/commands', (c) => {
  const agent = authenticateAgent(c);
  if (!agent) return c.json({ ok: false, error: 'Unauthorized' }, 401);
  const commands = db.listRecentCommands(c.env.db, agent.id, 50);
  return c.json({ ok: true, commands });
});
