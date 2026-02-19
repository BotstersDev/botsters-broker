/**
 * Web Search Capability — Tiered Brave Search with automatic fallback
 *
 * Two-tier token strategy:
 *   1. FREE_BRAVE_AI_TOKEN  — free tier (2,000/mo cap)
 *   2. BRAVE_BASE_AI_TOKEN  — paid tier (no cap, billed per 1,000)
 *
 * If both exist: try free first, fall back to paid on 429.
 * If only one exists: use it.
 * If neither exists: error.
 *
 * The brain never sees either token.
 */

import type { Context } from 'hono';
import * as db from './db.js';
import { decrypt } from './crypto.js';

const BRAVE_SEARCH_ENDPOINT = 'https://api.search.brave.com/res/v1/web/search';
const DEFAULT_TIMEOUT_MS = 15_000;

interface WebSearchParams {
  query: string;
  count?: number;
  country?: string;
  search_lang?: string;
  ui_lang?: string;
  freshness?: string;
}

interface WebSearchResult {
  ok: boolean;
  tier?: 'free' | 'paid';
  status?: number;
  body?: unknown;
  error?: string;
}

function getMasterKey(env: any): string {
  return env.masterKey;
}

function resolveToken(c: Context, agent: any, secretName: string): string | null {
  const secret = db.getSecret(c.env.db, agent.account_id, secretName, agent.id);
  if (!secret) return null;
  try {
    return decrypt(secret.encrypted_value, getMasterKey(c.env));
  } catch {
    return null;
  }
}

function buildSearchUrl(params: WebSearchParams): string {
  const url = new URL(BRAVE_SEARCH_ENDPOINT);
  url.searchParams.set('q', params.query);
  if (params.count) url.searchParams.set('count', String(Math.min(params.count, 20)));
  if (params.country) url.searchParams.set('country', params.country);
  if (params.search_lang) url.searchParams.set('search_lang', params.search_lang);
  if (params.ui_lang) url.searchParams.set('ui_lang', params.ui_lang);
  if (params.freshness) url.searchParams.set('freshness', params.freshness);
  return url.toString();
}

async function searchWithToken(searchUrl: string, token: string): Promise<{ ok: boolean; status: number; body: unknown }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DEFAULT_TIMEOUT_MS);

  try {
    const res = await fetch(searchUrl, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
        'X-Subscription-Token': token,
      },
      signal: controller.signal,
    });

    const status = res.status;
    let body: unknown;
    try { body = await res.json(); } catch { body = await res.text(); }

    return { ok: res.ok, status, body };
  } finally {
    clearTimeout(timeout);
  }
}

export async function handleWebSearch(c: Context, agent: any): Promise<Response> {
  const body = await c.req.json<WebSearchParams>();

  if (!body.query?.trim()) {
    return c.json({ ok: false, error: 'Missing required field: query' }, 400);
  }

  const freeToken = resolveToken(c, agent, 'FREE_BRAVE_AI_TOKEN');
  const paidToken = resolveToken(c, agent, 'BRAVE_BASE_AI_TOKEN');

  if (!freeToken && !paidToken) {
    db.logAudit(c.env.db, agent.account_id, agent.id, 'web_search', 'brave', 'denied', null, 'no tokens configured');
    return c.json({ ok: false, error: 'No Brave Search tokens configured (FREE_BRAVE_AI_TOKEN or BRAVE_BASE_AI_TOKEN)' }, 404);
  }

  const searchUrl = buildSearchUrl(body);
  let result: WebSearchResult;

  // Tier 1: Try free token first
  if (freeToken) {
    const res = await searchWithToken(searchUrl, freeToken);

    if (res.ok) {
      db.logAudit(c.env.db, agent.account_id, agent.id, 'web_search', 'brave', 'success', null, 'tier=free');
      return c.json({ ok: true, tier: 'free', body: res.body });
    }

    // 429 = rate limited, fall through to paid
    if (res.status === 429 && paidToken) {
      db.logAudit(c.env.db, agent.account_id, agent.id, 'web_search', 'brave', 'fallback', null, 'free tier 429, trying paid');
    } else if (res.status === 429) {
      // No paid token to fall back to
      db.logAudit(c.env.db, agent.account_id, agent.id, 'web_search', 'brave', 'error', null, 'free tier 429, no paid fallback');
      return c.json({ ok: false, tier: 'free', error: 'Free tier rate limited (429) and no paid token configured' }, 429);
    } else {
      // Other error on free tier — don't fall through, report it
      db.logAudit(c.env.db, agent.account_id, agent.id, 'web_search', 'brave', 'error', null, `free tier error ${res.status}`);
      return c.json({ ok: false, tier: 'free', status: res.status, error: `Brave API error (${res.status})`, body: res.body }, res.status as any);
    }
  }

  // Tier 2: Paid token (either fallback from 429 or only token available)
  if (paidToken) {
    const tier = freeToken ? 'paid (fallback)' : 'paid';
    const res = await searchWithToken(searchUrl, paidToken);

    if (res.ok) {
      db.logAudit(c.env.db, agent.account_id, agent.id, 'web_search', 'brave', 'success', null, `tier=${tier}`);
      return c.json({ ok: true, tier: 'paid', body: res.body });
    }

    db.logAudit(c.env.db, agent.account_id, agent.id, 'web_search', 'brave', 'error', null, `${tier} error ${res.status}`);
    return c.json({ ok: false, tier: 'paid', status: res.status, error: `Brave API error (${res.status})`, body: res.body }, res.status as any);
  }

  // Should never reach here
  return c.json({ ok: false, error: 'No tokens available' }, 500);
}
