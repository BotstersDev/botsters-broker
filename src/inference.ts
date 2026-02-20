/**
 * Inference Proxy — The spine's core capability.
 *
 * Proxies LLM API calls on behalf of agents, injecting credentials server-side.
 * The brain never sees the API key. The spine logs everything.
 */

import { Hono } from 'hono';
import type { Agent, Env } from './types.js';
import * as db from './db.js';
import { decrypt, encrypt } from './crypto.js';

export const inferenceRoutes = new Hono<{ Bindings: Env }>();

// ─── Round-Robin State ─────────────────────────────────────────────────────────
// In-memory counter per provider for round-robin token rotation.
// Resets on process restart (fine — no need for persistence).
const roundRobinCounters = new Map<string, number>();

function nextRoundRobin(provider: string, total: number): number {
  const current = roundRobinCounters.get(provider) ?? 0;
  const next = (current + 1) % total;
  roundRobinCounters.set(provider, next);
  return current;
}

// ─── Types ─────────────────────────────────────────────────────────────────────

interface InferenceRequest {
  provider: string;           // "anthropic" | "openai"
  model: string;              // "claude-sonnet-4-20250514" | "gpt-4o" etc.
  messages: unknown[];        // Provider-native message format
  max_tokens?: number;
  stream?: boolean;           // Default true
  system?: string | unknown;  // System prompt (string for Anthropic, array for some)
  temperature?: number;
  top_p?: number;
  // Pass-through: any other provider-specific fields
  [key: string]: unknown;
}

interface ProviderConfig {
  baseUrl: string;
  messagesPath: string;
  secretName: string;
  authHeader: string;
  authFormat?: 'Bearer' | 'raw';
  extraHeaders?: Record<string, string>;
  buildBody: (req: InferenceRequest) => Record<string, unknown>;
}

// ─── Token Type Detection ──────────────────────────────────────────────────────

type AnthropicTokenType = 'api-key' | 'oauth';

function detectAnthropicTokenType(token: string): AnthropicTokenType {
  if (token.startsWith('sk-ant-oat01-')) return 'oauth';
  // Default to API key for sk-ant-api03-* and any other format
  return 'api-key';
}

function buildAnthropicAuthHeaders(token: string): Record<string, string> {
  const tokenType = detectAnthropicTokenType(token);
  if (tokenType === 'oauth') {
    return {
      'Authorization': `Bearer ${token}`,
      'anthropic-version': '2023-06-01',
      'anthropic-beta': 'oauth-2025-04-20',
    };
  }
  return {
    'x-api-key': token,
    'anthropic-version': '2023-06-01',
  };
}

type OpenAITokenType = 'api-key' | 'oauth-access' | 'oauth-bundle';

type OpenAIOAuthBundle = {
  access: string;
  refresh?: string;
  expires?: number;
  accountId?: string;
};

function parseOpenAIOAuthBundle(raw: string): OpenAIOAuthBundle | null {
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const access = typeof parsed.access === 'string' ? parsed.access : undefined;
    if (!access) return null;
    return {
      access,
      refresh: typeof parsed.refresh === 'string' ? parsed.refresh : undefined,
      expires: typeof parsed.expires === 'number' ? parsed.expires : undefined,
      accountId: typeof parsed.accountId === 'string' ? parsed.accountId : undefined,
    };
  } catch {
    return null;
  }
}

function detectOpenAITokenType(token: string): OpenAITokenType {
  if (token.startsWith('sk-')) return 'api-key';
  if (token.trim().startsWith('{')) {
    const bundle = parseOpenAIOAuthBundle(token);
    if (bundle) return 'oauth-bundle';
  }
  return 'oauth-access';
}

function resolveOpenAIAuth(token: string): { authHeaderValue: string; mode: OpenAITokenType; expires?: number; bundle?: OpenAIOAuthBundle } {
  const mode = detectOpenAITokenType(token);
  if (mode === 'oauth-bundle') {
    const bundle = parseOpenAIOAuthBundle(token);
    if (!bundle?.access) {
      throw new Error('Invalid OpenAI OAuth bundle: missing access token');
    }
    return {
      authHeaderValue: `Bearer ${bundle.access}`,
      mode,
      expires: bundle.expires,
      bundle,
    };
  }
  if (mode === 'api-key') {
    return {
      authHeaderValue: `Bearer ${token}`,
      mode,
    };
  }
  return {
    authHeaderValue: `Bearer ${token}`,
    mode,
  };
}

const OPENAI_CODEX_CLIENT_ID = 'app_EMoamEEZ73f0CkXaXp7hrann';
const OPENAI_CODEX_TOKEN_URL = 'https://auth.openai.com/oauth/token';

async function refreshOpenAICodexBundle(bundle: OpenAIOAuthBundle): Promise<OpenAIOAuthBundle | null> {
  if (!bundle.refresh) return null;
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: bundle.refresh,
    client_id: OPENAI_CODEX_CLIENT_ID,
  });
  const response = await fetch(OPENAI_CODEX_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  if (!response.ok) return null;
  const json = await response.json() as { access_token?: string; refresh_token?: string; expires_in?: number };
  if (!json.access_token || !json.refresh_token || typeof json.expires_in !== 'number') return null;
  return {
    access: json.access_token,
    refresh: json.refresh_token,
    expires: Date.now() + (json.expires_in * 1000),
    accountId: bundle.accountId,
  };
}

function persistOpenAICodexBundle(c: any, agent: Agent, bundle: OpenAIOAuthBundle): void {
  const target = db.getSecret(c.env.db, agent.account_id, 'OPENAI_TOKEN', agent.id);
  if (!target) return;
  const encryptedValue = encrypt(JSON.stringify(bundle), c.env.masterKey);
  db.updateSecret(c.env.db, target.id, agent.account_id, target.name, target.provider, encryptedValue);
}

function extractTextContent(content: unknown): string {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    const texts = content
      .map((part) => {
        if (typeof part === 'string') return part;
        if (part && typeof part === 'object' && 'text' in part && typeof (part as { text?: unknown }).text === 'string') {
          return (part as { text: string }).text;
        }
        return '';
      })
      .filter(Boolean);
    return texts.join('\n');
  }
  return '';
}

function buildOpenAICodexBody(req: InferenceRequest): Record<string, unknown> {
  const messages = req.messages as Array<{ role?: string; content?: unknown }>;
  const systemFromMessages = messages.find((m) => m.role === 'system');
  const instructions = (typeof req.system === 'string' ? req.system : extractTextContent(req.system)) || extractTextContent(systemFromMessages?.content) || 'You are a helpful assistant.';
  const input = messages
    .filter((m) => m.role !== 'system')
    .map((m) => ({
      role: m.role ?? 'user',
      content: [{ type: 'input_text', text: extractTextContent(m.content) }],
    }));

  return {
    model: req.model,
    instructions,
    input,
    stream: true,
    store: false,
  };
}

// ─── Provider Configs ──────────────────────────────────────────────────────────

const PROVIDERS: Record<string, ProviderConfig> = {
  anthropic: {
    baseUrl: 'https://api.anthropic.com',
    messagesPath: '/v1/messages',
    secretName: 'ANTHROPIC_TOKEN',
    authHeader: 'x-api-key',       // Default; overridden by dynamic auth for OAuth
    authFormat: 'raw',
    extraHeaders: {
      'anthropic-version': '2023-06-01',
    },
    buildBody: (req) => {
      const body: Record<string, unknown> = {
        model: req.model,
        messages: req.messages,
        max_tokens: req.max_tokens ?? 4096,
        stream: req.stream !== false,
      };
      if (req.system !== undefined) body.system = req.system;
      if (req.temperature !== undefined) body.temperature = req.temperature;
      if (req.top_p !== undefined) body.top_p = req.top_p;
      // Pass through any Anthropic-specific fields
      for (const key of ['metadata', 'stop_sequences', 'tools', 'tool_choice', 'thinking']) {
        if (req[key] !== undefined) body[key] = req[key];
      }
      return body;
    },
  },

  openai: {
    baseUrl: 'https://api.openai.com',
    messagesPath: '/v1/chat/completions',
    secretName: 'OPENAI_TOKEN',
    authHeader: 'Authorization',
    authFormat: 'Bearer',
    buildBody: (req) => {
      const body: Record<string, unknown> = {
        model: req.model,
        messages: req.messages,
        stream: req.stream !== false,
      };
      if (req.max_tokens !== undefined) body.max_tokens = req.max_tokens;
      if (req.system !== undefined) {
        // OpenAI uses a system message in the messages array
        // If caller passed system separately, prepend it
        body.messages = [{ role: 'system', content: req.system }, ...(req.messages as unknown[])];
      }
      if (req.temperature !== undefined) body.temperature = req.temperature;
      if (req.top_p !== undefined) body.top_p = req.top_p;
      // Pass through OpenAI-specific fields
      for (const key of ['tools', 'tool_choice', 'response_format', 'frequency_penalty', 'presence_penalty', 'logprobs']) {
        if (req[key] !== undefined) body[key] = req[key];
      }
      return body;
    },
  },
};

// ─── Auth Helper ───────────────────────────────────────────────────────────────

function authenticateAgent(c: any): Agent | null {
  // Support multiple auth headers for different provider conventions:
  //   1. X-Agent-Token: <token>  — explicit agent auth (preferred for OpenAI proxy
  //      where Authorization carries the provider credential)
  //   2. Authorization: Bearer <token>  — standard
  //   3. x-api-key: <token>  — Anthropic SDK convention
  const xAgentToken = c.req.header('X-Agent-Token');
  const authHeader = c.req.header('Authorization');
  const xApiKey = c.req.header('x-api-key');
  let token: string | undefined;
  if (xAgentToken) {
    token = xAgentToken;
  } else if (authHeader?.startsWith('Bearer ')) {
    token = authHeader.slice(7);
  } else if (xApiKey) {
    token = xApiKey;
  }
  if (!token) return null;
  const agent = db.getAgentByToken(c.env.db, token);
  if (agent) db.updateAgentLastSeen(c.env.db, agent.id);
  return agent;
}

// ─── Inference Proxy Endpoint ──────────────────────────────────────────────────

inferenceRoutes.post('/inference', async (c) => {
  const startTime = Date.now();

  // 1. Authenticate
  const agent = authenticateAgent(c);
  if (!agent) return c.json({ error: 'Unauthorized' }, 401);

  // 2. Parse request
  let req: InferenceRequest;
  try {
    req = await c.req.json<InferenceRequest>();
  } catch {
    return c.json({ error: 'Invalid JSON body' }, 400);
  }

  if (!req.provider) return c.json({ error: 'Missing "provider" field' }, 400);
  if (!req.model) return c.json({ error: 'Missing "model" field' }, 400);
  if (!req.messages || !Array.isArray(req.messages)) return c.json({ error: 'Missing or invalid "messages" field' }, 400);

  // 3. Resolve provider config
  const providerConfig = PROVIDERS[req.provider];
  if (!providerConfig) {
    return c.json({ error: `Unsupported provider: ${req.provider}. Supported: ${Object.keys(PROVIDERS).join(', ')}` }, 400);
  }

  // 4. Check capability grant
  const capabilityName = `inference/${req.provider}`;
  const secretId = db.resolveCapability(c.env.db, agent.id, 'inference', req.provider);

  // If no explicit inference capability, fall back to checking if the secret exists directly
  let apiKey: string;
  if (secretId) {
    const secret = db.getSecretById(c.env.db, secretId, agent.account_id);
    if (!secret) {
      db.logAudit(c.env.db, agent.account_id, agent.id, 'inference.request', capabilityName, 'denied', null, 'secret not found');
      return c.json({ error: 'API key not found for provider' }, 404);
    }
    try {
      apiKey = decrypt(secret.encrypted_value, c.env.masterKey);
    } catch {
      return c.json({ error: 'Failed to decrypt API key' }, 500);
    }
  } else {
    // Fall back: look up the provider's secret by name
    const secret = db.getSecret(c.env.db, agent.account_id, providerConfig.secretName, agent.id);
    if (!secret) {
      db.logAudit(c.env.db, agent.account_id, agent.id, 'inference.request', capabilityName, 'denied', null, 'no key configured');
      return c.json({ error: `No ${req.provider} API key configured. Store secret '${providerConfig.secretName}' in the broker.` }, 404);
    }
    try {
      apiKey = decrypt(secret.encrypted_value, c.env.masterKey);
    } catch {
      return c.json({ error: 'Failed to decrypt API key' }, 500);
    }
  }

  let authMode: string | undefined;
  let oauthExpires: number | undefined;
  if (req.provider === 'openai') {
    try {
      const openaiAuth = resolveOpenAIAuth(apiKey);
      authMode = openaiAuth.mode;
      oauthExpires = openaiAuth.expires;
    } catch (e) {
      const error = e instanceof Error ? e.message : 'Invalid OpenAI auth material';
      db.logAudit(c.env.db, agent.account_id, agent.id, 'inference.request', capabilityName, 'denied', null, error);
      return c.json({ error }, 400);
    }
  }

  // 5. Log the request (no content — privacy)
  db.logAudit(
    c.env.db, agent.account_id, agent.id,
    'inference.request', capabilityName, 'pending',
    c.req.header('x-forwarded-for') || c.req.header('x-real-ip') || null,
    JSON.stringify({
      model: req.model,
      stream: req.stream !== false,
      messageCount: req.messages.length,
      authMode,
      oauthExpires,
    })
  );

  // 6. Build provider request
  let providerBody: Record<string, unknown> = providerConfig.buildBody(req);
  let url = `${providerConfig.baseUrl}${providerConfig.messagesPath}`;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  let openaiAuthForRetry: { authHeaderValue: string; mode: OpenAITokenType; expires?: number; bundle?: OpenAIOAuthBundle } | undefined;

  // Dynamic auth headers — provider-specific token handling
  if (req.provider === 'anthropic') {
    Object.assign(headers, buildAnthropicAuthHeaders(apiKey));
  } else if (req.provider === 'openai') {
    let openaiAuth = resolveOpenAIAuth(apiKey);
    if (openaiAuth.expires && Date.now() > openaiAuth.expires && openaiAuth.bundle?.refresh) {
      const refreshed = await refreshOpenAICodexBundle(openaiAuth.bundle);
      if (refreshed) {
        persistOpenAICodexBundle(c, agent, refreshed);
        openaiAuth = {
          authHeaderValue: `Bearer ${refreshed.access}`,
          mode: 'oauth-bundle',
          expires: refreshed.expires,
          bundle: refreshed,
        };
      }
    }
    if (openaiAuth.expires && Date.now() > openaiAuth.expires) {
      return c.json({ error: 'OpenAI OAuth token appears expired in broker secret; re-auth required.' }, 401);
    }
    openaiAuthForRetry = openaiAuth;
    headers['Authorization'] = openaiAuth.authHeaderValue;

    // Codex OAuth parity path (mirrors OpenClaw codex backend behavior)
    if (openaiAuth.mode === 'oauth-bundle') {
      url = 'https://chatgpt.com/backend-api/codex/responses';
      providerBody = buildOpenAICodexBody(req);
      headers['User-Agent'] = 'CodexBar';
      headers['Accept'] = 'text/event-stream';
      if (openaiAuth.bundle?.accountId) {
        headers['ChatGPT-Account-Id'] = openaiAuth.bundle.accountId;
      }
    }
  } else {
    // Generic provider auth
    if (providerConfig.extraHeaders) Object.assign(headers, providerConfig.extraHeaders);
    if (providerConfig.authFormat === 'Bearer') {
      headers[providerConfig.authHeader] = `Bearer ${apiKey}`;
    } else {
      headers[providerConfig.authHeader] = apiKey;
    }
  }

  // 7. Proxy the request
  try {
    let response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(providerBody),
    });

    if (req.provider === 'openai' && response.status === 401 && openaiAuthForRetry?.bundle?.refresh) {
      const refreshed = await refreshOpenAICodexBundle(openaiAuthForRetry.bundle);
      if (refreshed) {
        persistOpenAICodexBundle(c, agent, refreshed);
        headers['Authorization'] = `Bearer ${refreshed.access}`;
        response = await fetch(url, {
          method: 'POST',
          headers,
          body: JSON.stringify(providerBody),
        });
      }
    }

    const latencyMs = Date.now() - startTime;

    if (!response.ok) {
      const errorText = await response.text();
      db.logAudit(
        c.env.db, agent.account_id, agent.id,
        'inference.error', capabilityName, 'error', null,
        JSON.stringify({ model: req.model, status: response.status, latencyMs, error: errorText.slice(0, 500) })
      );
      // Pass through the provider's error status and body
      return new Response(errorText, {
        status: response.status,
        headers: { 'Content-Type': response.headers.get('Content-Type') || 'application/json' },
      });
    }

    // 8. Stream the response back
    const forceStream = req.provider === 'openai' && openaiAuthForRetry?.mode === 'oauth-bundle';
    const upstreamIsSse = response.headers.get('Content-Type')?.includes('text/event-stream') ?? false;
    if ((req.stream !== false || forceStream) && (upstreamIsSse || forceStream)) {
      // SSE streaming — passthrough the stream, log completion after
      db.logAudit(
        c.env.db, agent.account_id, agent.id,
        'inference.streaming', capabilityName, 'success', null,
        JSON.stringify({ model: req.model, latencyMs })
      );

      // Return the SSE stream directly — don't buffer it
      return new Response(response.body, {
        status: 200,
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
          'X-Spine-Latency-Ms': String(latencyMs),
          'X-Spine-Provider': req.provider,
        },
      });
    } else {
      // Non-streaming — read full response, log usage, return
      const responseBody = await response.text();
      const latencyMs = Date.now() - startTime;

      // Try to extract token usage from response
      let tokensIn = 0, tokensOut = 0;
      try {
        const parsed = JSON.parse(responseBody);
        if (parsed.usage) {
          tokensIn = parsed.usage.input_tokens || parsed.usage.prompt_tokens || 0;
          tokensOut = parsed.usage.output_tokens || parsed.usage.completion_tokens || 0;
        }
      } catch { /* best effort */ }

      db.logAudit(
        c.env.db, agent.account_id, agent.id,
        'inference.complete', capabilityName, 'success', null,
        JSON.stringify({ model: req.model, latencyMs, tokensIn, tokensOut })
      );

      return new Response(responseBody, {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'X-Spine-Latency-Ms': String(latencyMs),
          'X-Spine-Provider': req.provider,
          'X-Spine-Tokens-In': String(tokensIn),
          'X-Spine-Tokens-Out': String(tokensOut),
        },
      });
    }
  } catch (e) {
    const latencyMs = Date.now() - startTime;
    const error = e instanceof Error ? e.message : 'Unknown error';
    db.logAudit(
      c.env.db, agent.account_id, agent.id,
      'inference.error', capabilityName, 'error', null,
      JSON.stringify({ model: req.model, latencyMs, error })
    );
    return c.json({ error: `Provider request failed: ${error}` }, 502);
  }
});

// ─── Transparent Proxy Routes ──────────────────────────────────────────────────
// These routes match the real provider API paths so OpenClaw can use the broker
// as a drop-in base URL replacement. The agent's broker token comes in the
// Authorization header; the broker swaps it for the real API key.

/**
 * Resolve ALL API keys for a provider, given an authenticated agent.
 * Returns an array of decrypted keys for round-robin use.
 * Tries capability grants first, falls back to secret lookup by prefix.
 */
function resolveProviderKeys(c: any, agent: Agent, provider: string): { apiKeys: string[] } | { error: string; status: number } {
  const providerConfig = PROVIDERS[provider];
  if (!providerConfig) {
    return { error: `Unsupported provider: ${provider}`, status: 400 };
  }

  // First try capability grants (single key path — for explicit per-agent grants)
  const secretId = db.resolveCapability(c.env.db, agent.id, 'inference', provider);
  if (secretId) {
    const secret = db.getSecretById(c.env.db, secretId, agent.account_id);
    if (!secret) return { error: 'API key not found', status: 404 };
    try {
      return { apiKeys: [decrypt(secret.encrypted_value, c.env.masterKey)] };
    } catch {
      return { error: 'Failed to decrypt API key', status: 500 };
    }
  }

  // Fall back: find ALL secrets matching the provider's secret name prefix
  // e.g. ANTHROPIC_TOKEN, ANTHROPIC_TOKEN_2, ANTHROPIC_TOKEN_3, ...
  const secrets = db.getSecretsByPrefix(c.env.db, agent.account_id, providerConfig.secretName, agent.id);
  if (secrets.length === 0) {
    return { error: `No ${provider} API key configured. Store secret '${providerConfig.secretName}' in the broker.`, status: 404 };
  }

  const apiKeys: string[] = [];
  for (const secret of secrets) {
    try {
      apiKeys.push(decrypt(secret.encrypted_value, c.env.masterKey));
    } catch {
      // Skip bad keys, log warning
      db.logAudit(c.env.db, agent.account_id, agent.id, 'key.decrypt_error', `inference/${provider}`, 'error', null,
        `Failed to decrypt secret ${secret.name}`);
    }
  }

  if (apiKeys.length === 0) {
    return { error: 'Failed to decrypt any API keys', status: 500 };
  }

  return { apiKeys };
}

/** Pick one key via round-robin from a resolved set */
function pickKey(provider: string, apiKeys: string[]): string {
  if (apiKeys.length === 1) return apiKeys[0];
  const idx = nextRoundRobin(provider, apiKeys.length);
  return apiKeys[idx];
}

/** Legacy single-key resolver (for the /inference endpoint that doesn't retry) */
function resolveProviderKey(c: any, agent: Agent, provider: string): { apiKey: string } | { error: string; status: number } {
  const result = resolveProviderKeys(c, agent, provider);
  if ('error' in result) return result;
  return { apiKey: pickKey(provider, result.apiKeys) };
}

// Anthropic transparent proxy: POST /v1/proxy/anthropic/v1/messages
// Supports round-robin across multiple ANTHROPIC_TOKEN secrets with 429 retry.
inferenceRoutes.post('/proxy/anthropic/*', async (c) => {
  const startTime = Date.now();
  const agent = authenticateAgent(c);
  if (!agent) return c.json({ error: 'Unauthorized' }, 401);

  const result = resolveProviderKeys(c, agent, 'anthropic');
  if ('error' in result) {
    db.logAudit(c.env.db, agent.account_id, agent.id, 'proxy.request', 'inference/anthropic', 'denied', null, result.error);
    return c.json({ error: result.error }, result.status as any);
  }

  const { apiKeys } = result;
  const fullPath = c.req.path;
  const providerPath = fullPath.replace(/^\/v1\/proxy\/anthropic/, '');
  const url = `https://api.anthropic.com${providerPath}`;

  const requestBody = await c.req.raw.clone().text();
  const contentType = c.req.header('content-type') || 'application/json';

  let model = 'unknown';
  try { model = JSON.parse(requestBody).model || 'unknown'; } catch {}

  // Forward anthropic-beta and anthropic-version from client if present
  const clientBeta = c.req.header('anthropic-beta');
  const clientVersion = c.req.header('anthropic-version');

  // Try up to N keys (round-robin start, retry on 429)
  const maxAttempts = Math.min(apiKeys.length, 5); // cap retries at 5
  let lastError: Response | null = null;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const apiKey = pickKey('anthropic', apiKeys);

    const authHeaders = buildAnthropicAuthHeaders(apiKey);
    const headers: Record<string, string> = {
      'Content-Type': contentType,
      ...authHeaders,
    };

    if (clientBeta) {
      if (headers['anthropic-beta'] && clientBeta !== headers['anthropic-beta']) {
        headers['anthropic-beta'] = `${headers['anthropic-beta']},${clientBeta}`;
      } else {
        headers['anthropic-beta'] = clientBeta;
      }
    }
    if (clientVersion) headers['anthropic-version'] = clientVersion;

    db.logAudit(c.env.db, agent.account_id, agent.id, 'proxy.request', 'inference/anthropic', 'pending', null,
      JSON.stringify({ model, path: providerPath, attempt: attempt + 1, totalKeys: apiKeys.length }));

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers,
        body: requestBody,
      });

      const latencyMs = Date.now() - startTime;

      // On 429 (rate limit) or 529 (overloaded), try the next key
      if ((response.status === 429 || response.status === 529) && attempt < maxAttempts - 1) {
        const errorText = await response.text();
        db.logAudit(c.env.db, agent.account_id, agent.id, 'proxy.rate_limited', 'inference/anthropic', 'retry', null,
          JSON.stringify({ model, status: response.status, attempt: attempt + 1, latencyMs }));
        lastError = new Response(errorText, {
          status: response.status,
          headers: { 'Content-Type': response.headers.get('Content-Type') || 'application/json' },
        });
        continue;
      }

      if (!response.ok) {
        const errorText = await response.text();
        db.logAudit(c.env.db, agent.account_id, agent.id, 'proxy.error', 'inference/anthropic', 'error', null,
          JSON.stringify({ model, status: response.status, latencyMs }));
        return new Response(errorText, {
          status: response.status,
          headers: { 'Content-Type': response.headers.get('Content-Type') || 'application/json' },
        });
      }

      // SSE streaming passthrough
      if (response.headers.get('Content-Type')?.includes('text/event-stream')) {
        db.logAudit(c.env.db, agent.account_id, agent.id, 'proxy.streaming', 'inference/anthropic', 'success', null,
          JSON.stringify({ model, latencyMs, keyIndex: attempt + 1, totalKeys: apiKeys.length }));
        return new Response(response.body, {
          status: 200,
          headers: {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
          },
        });
      }

      // Non-streaming passthrough
      const responseBody = await response.text();
      db.logAudit(c.env.db, agent.account_id, agent.id, 'proxy.complete', 'inference/anthropic', 'success', null,
        JSON.stringify({ model, latencyMs, keyIndex: attempt + 1, totalKeys: apiKeys.length }));
      return new Response(responseBody, {
        status: 200,
        headers: { 'Content-Type': response.headers.get('Content-Type') || 'application/json' },
      });
    } catch (e) {
      const error = e instanceof Error ? e.message : 'Unknown error';
      db.logAudit(c.env.db, agent.account_id, agent.id, 'proxy.error', 'inference/anthropic', 'error', null,
        JSON.stringify({ model, error, attempt: attempt + 1 }));
      if (attempt === maxAttempts - 1) {
        return c.json({ error: `Provider request failed: ${error}` }, 502);
      }
    }
  }

  // All keys exhausted — return the last 429/529
  if (lastError) return lastError;
  return c.json({ error: 'All provider keys exhausted' }, 429);
});

// OpenAI transparent proxy: POST /v1/proxy/openai/*
inferenceRoutes.post('/proxy/openai/*', async (c) => {
  const startTime = Date.now();
  const agent = authenticateAgent(c);
  if (!agent) return c.json({ error: 'Unauthorized' }, 401);

  const result = resolveProviderKey(c, agent, 'openai');
  if ('error' in result) {
    db.logAudit(c.env.db, agent.account_id, agent.id, 'proxy.request', 'inference/openai', 'denied', null, result.error);
    return c.json({ error: result.error }, result.status as any);
  }

  let openaiAuth: { authHeaderValue: string; mode: OpenAITokenType; expires?: number; bundle?: OpenAIOAuthBundle };
  try {
    openaiAuth = resolveOpenAIAuth(result.apiKey);
  } catch (e) {
    const error = e instanceof Error ? e.message : 'Invalid OpenAI auth material';
    db.logAudit(c.env.db, agent.account_id, agent.id, 'proxy.request', 'inference/openai', 'denied', null, error);
    return c.json({ error }, 400);
  }

  if (openaiAuth.expires && Date.now() > openaiAuth.expires && openaiAuth.bundle?.refresh) {
    const refreshed = await refreshOpenAICodexBundle(openaiAuth.bundle);
    if (refreshed) {
      persistOpenAICodexBundle(c, agent, refreshed);
      openaiAuth = {
        authHeaderValue: `Bearer ${refreshed.access}`,
        mode: 'oauth-bundle',
        expires: refreshed.expires,
        bundle: refreshed,
      };
    }
  }

  if (openaiAuth.expires && Date.now() > openaiAuth.expires) {
    const error = 'OpenAI OAuth token appears expired in broker secret; re-auth required.';
    db.logAudit(c.env.db, agent.account_id, agent.id, 'proxy.request', 'inference/openai', 'denied', null, error);
    return c.json({ error }, 401);
  }

  const fullPath = c.req.path;
  const providerPath = fullPath.replace(/^\/v1\/proxy\/openai/, '');

  const requestBody = await c.req.raw.clone().text();
  const contentType = c.req.header('content-type') || 'application/json';

  let model = 'unknown';
  let parsedBody: Record<string, unknown> | null = null;
  try { parsedBody = JSON.parse(requestBody); model = (parsedBody as any)?.model || 'unknown'; } catch {}

  // Codex OAuth parity: rewrite to chatgpt.com/backend-api/codex/responses
  const isCodexOAuth = openaiAuth.mode === 'oauth-bundle';
  let url: string;
  let finalBody: string;
  const headers: Record<string, string> = {
    'Authorization': openaiAuth.authHeaderValue,
  };

  if (isCodexOAuth && parsedBody) {
    url = 'https://chatgpt.com/backend-api/codex/responses';
    // Build Codex-compatible body from the OpenAI Responses API shape
    const codexBody: Record<string, unknown> = {
      model: model,
      instructions: (parsedBody as any).instructions ?? 'You are a helpful assistant.',
      input: (parsedBody as any).input ?? [],
      stream: true,
      store: false,
    };
    finalBody = JSON.stringify(codexBody);
    headers['Content-Type'] = 'application/json';
    headers['User-Agent'] = 'CodexBar';
    headers['Accept'] = 'text/event-stream';
    if (openaiAuth.bundle?.accountId) {
      headers['ChatGPT-Account-Id'] = openaiAuth.bundle.accountId;
    }
  } else {
    url = `https://api.openai.com${providerPath}`;
    finalBody = requestBody;
    headers['Content-Type'] = contentType;
  }

  db.logAudit(c.env.db, agent.account_id, agent.id, 'proxy.request', 'inference/openai', 'pending', null,
    JSON.stringify({ model, path: isCodexOAuth ? '/codex/responses' : providerPath, authMode: openaiAuth.mode, oauthExpires: openaiAuth.expires }));

  try {
    let response = await fetch(url, {
      method: 'POST',
      headers,
      body: finalBody,
    });

    if (response.status === 401 && openaiAuth.bundle?.refresh) {
      const refreshed = await refreshOpenAICodexBundle(openaiAuth.bundle);
      if (refreshed) {
        persistOpenAICodexBundle(c, agent, refreshed);
        headers['Authorization'] = `Bearer ${refreshed.access}`;
        response = await fetch(url, {
          method: 'POST',
          headers,
          body: finalBody,
        });
      }
    }

    const latencyMs = Date.now() - startTime;

    if (!response.ok) {
      const errorText = await response.text();
      db.logAudit(c.env.db, agent.account_id, agent.id, 'proxy.error', 'inference/openai', 'error', null,
        JSON.stringify({ model, status: response.status, latencyMs }));
      return new Response(errorText, {
        status: response.status,
        headers: { 'Content-Type': response.headers.get('Content-Type') || 'application/json' },
      });
    }

    const upstreamCt = response.headers.get('Content-Type') || '';
    if (upstreamCt.includes('text/event-stream') || isCodexOAuth) {
      db.logAudit(c.env.db, agent.account_id, agent.id, 'proxy.streaming', 'inference/openai', 'success', null,
        JSON.stringify({ model, latencyMs }));
      return new Response(response.body, {
        status: 200,
        headers: {
          'Content-Type': 'text/event-stream',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
        },
      });
    }

    const responseBody = await response.text();
    db.logAudit(c.env.db, agent.account_id, agent.id, 'proxy.complete', 'inference/openai', 'success', null,
      JSON.stringify({ model, latencyMs }));
    return new Response(responseBody, {
      status: 200,
      headers: { 'Content-Type': response.headers.get('Content-Type') || 'application/json' },
    });
  } catch (e) {
    const error = e instanceof Error ? e.message : 'Unknown error';
    db.logAudit(c.env.db, agent.account_id, agent.id, 'proxy.error', 'inference/openai', 'error', null,
      JSON.stringify({ model, error }));
    return c.json({ error: `Provider request failed: ${error}` }, 502);
  }
});

// ─── List Supported Providers ──────────────────────────────────────────────────

inferenceRoutes.get('/inference/providers', (c) => {
  const agent = authenticateAgent(c);
  if (!agent) return c.json({ error: 'Unauthorized' }, 401);

  const providers = Object.entries(PROVIDERS).map(([name, config]) => {
    const secret = db.getSecret(c.env.db, agent.account_id, config.secretName, agent.id);
    return {
      name,
      configured: !!secret,
      secretName: config.secretName,
    };
  });

  return c.json({ ok: true, providers });
});
