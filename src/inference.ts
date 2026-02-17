/**
 * Inference Proxy — The spine's core capability.
 *
 * Proxies LLM API calls on behalf of agents, injecting credentials server-side.
 * The brain never sees the API key. The spine logs everything.
 */

import { Hono } from 'hono';
import type { Agent, Env } from './types.js';
import * as db from './db.js';
import { decrypt } from './crypto.js';

export const inferenceRoutes = new Hono<{ Bindings: Env }>();

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

// ─── Provider Configs ──────────────────────────────────────────────────────────

const PROVIDERS: Record<string, ProviderConfig> = {
  anthropic: {
    baseUrl: 'https://api.anthropic.com',
    messagesPath: '/v1/messages',
    secretName: 'ANTHROPIC_API_KEY',
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
    secretName: 'OPENAI_API_KEY',
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
  // Support both Authorization: Bearer <token> and x-api-key: <token>
  // The latter is needed because Anthropic SDK sends broker tokens via x-api-key
  // when the broker is configured as a baseUrl replacement
  const authHeader = c.req.header('Authorization');
  const xApiKey = c.req.header('x-api-key');
  let token: string | undefined;
  if (authHeader?.startsWith('Bearer ')) {
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

  // 5. Log the request (no content — privacy)
  db.logAudit(
    c.env.db, agent.account_id, agent.id,
    'inference.request', capabilityName, 'pending',
    c.req.header('x-forwarded-for') || c.req.header('x-real-ip') || null,
    JSON.stringify({ model: req.model, stream: req.stream !== false, messageCount: req.messages.length })
  );

  // 6. Build provider request
  const providerBody = providerConfig.buildBody(req);
  const url = `${providerConfig.baseUrl}${providerConfig.messagesPath}`;

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };

  // Dynamic auth headers — Anthropic needs token-type detection (API key vs OAuth)
  if (req.provider === 'anthropic') {
    Object.assign(headers, buildAnthropicAuthHeaders(apiKey));
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
    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(providerBody),
    });

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
    if (req.stream !== false && response.headers.get('Content-Type')?.includes('text/event-stream')) {
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
 * Resolve API key for a provider, given an authenticated agent.
 * Tries capability grants first, falls back to direct secret lookup.
 */
function resolveProviderKey(c: any, agent: Agent, provider: string): { apiKey: string } | { error: string; status: number } {
  const providerConfig = PROVIDERS[provider];
  if (!providerConfig) {
    return { error: `Unsupported provider: ${provider}`, status: 400 };
  }

  const secretId = db.resolveCapability(c.env.db, agent.id, 'inference', provider);
  if (secretId) {
    const secret = db.getSecretById(c.env.db, secretId, agent.account_id);
    if (!secret) return { error: 'API key not found', status: 404 };
    try {
      return { apiKey: decrypt(secret.encrypted_value, c.env.masterKey) };
    } catch {
      return { error: 'Failed to decrypt API key', status: 500 };
    }
  }

  const secret = db.getSecret(c.env.db, agent.account_id, providerConfig.secretName, agent.id);
  if (!secret) return { error: `No ${provider} API key configured`, status: 404 };
  try {
    return { apiKey: decrypt(secret.encrypted_value, c.env.masterKey) };
  } catch {
    return { error: 'Failed to decrypt API key', status: 500 };
  }
}

// Anthropic transparent proxy: POST /v1/proxy/anthropic/v1/messages
inferenceRoutes.post('/proxy/anthropic/*', async (c) => {
  const startTime = Date.now();
  const agent = authenticateAgent(c);
  if (!agent) return c.json({ error: 'Unauthorized' }, 401);

  const result = resolveProviderKey(c, agent, 'anthropic');
  if ('error' in result) {
    db.logAudit(c.env.db, agent.account_id, agent.id, 'proxy.request', 'inference/anthropic', 'denied', null, result.error);
    return c.json({ error: result.error }, result.status as any);
  }

  // Build the real Anthropic URL from the path suffix
  const fullPath = c.req.path;  // e.g. /v1/proxy/anthropic/v1/messages
  const providerPath = fullPath.replace(/^\/v1\/proxy\/anthropic/, '');
  const url = `https://api.anthropic.com${providerPath}`;

  // Build auth headers based on token type
  const authHeaders = buildAnthropicAuthHeaders(result.apiKey);

  // Forward the request body and relevant headers
  const requestBody = await c.req.raw.clone().text();
  const contentType = c.req.header('content-type') || 'application/json';

  // Extract model from body for audit (best effort)
  let model = 'unknown';
  try { model = JSON.parse(requestBody).model || 'unknown'; } catch {}

  db.logAudit(c.env.db, agent.account_id, agent.id, 'proxy.request', 'inference/anthropic', 'pending', null,
    JSON.stringify({ model, path: providerPath }));

  const headers: Record<string, string> = {
    'Content-Type': contentType,
    ...authHeaders,
  };

  // Forward anthropic-beta and anthropic-version from client if present
  const clientBeta = c.req.header('anthropic-beta');
  if (clientBeta) {
    // Merge with our auth beta header if both exist
    if (headers['anthropic-beta'] && clientBeta !== headers['anthropic-beta']) {
      headers['anthropic-beta'] = `${headers['anthropic-beta']},${clientBeta}`;
    } else {
      headers['anthropic-beta'] = clientBeta;
    }
  }
  const clientVersion = c.req.header('anthropic-version');
  if (clientVersion) headers['anthropic-version'] = clientVersion;

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers,
      body: requestBody,
    });

    const latencyMs = Date.now() - startTime;

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

    // Non-streaming passthrough
    const responseBody = await response.text();
    db.logAudit(c.env.db, agent.account_id, agent.id, 'proxy.complete', 'inference/anthropic', 'success', null,
      JSON.stringify({ model, latencyMs }));
    return new Response(responseBody, {
      status: 200,
      headers: { 'Content-Type': response.headers.get('Content-Type') || 'application/json' },
    });
  } catch (e) {
    const error = e instanceof Error ? e.message : 'Unknown error';
    db.logAudit(c.env.db, agent.account_id, agent.id, 'proxy.error', 'inference/anthropic', 'error', null,
      JSON.stringify({ model, error }));
    return c.json({ error: `Provider request failed: ${error}` }, 502);
  }
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

  const fullPath = c.req.path;
  const providerPath = fullPath.replace(/^\/v1\/proxy\/openai/, '');
  const url = `https://api.openai.com${providerPath}`;

  const requestBody = await c.req.raw.clone().text();
  const contentType = c.req.header('content-type') || 'application/json';

  let model = 'unknown';
  try { model = JSON.parse(requestBody).model || 'unknown'; } catch {}

  db.logAudit(c.env.db, agent.account_id, agent.id, 'proxy.request', 'inference/openai', 'pending', null,
    JSON.stringify({ model, path: providerPath }));

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': contentType,
        'Authorization': `Bearer ${result.apiKey}`,
      },
      body: requestBody,
    });

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

    if (response.headers.get('Content-Type')?.includes('text/event-stream')) {
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
