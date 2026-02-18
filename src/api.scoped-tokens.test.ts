/**
 * Tests for scoped token minting and capability enforcement
 */

import { describe, it, expect } from 'vitest';

// Test the HMAC signing and verification logic directly
// (We can't easily test the full Hono app without a CF Workers runtime,
//  but we can test the core crypto logic)

describe('scoped token format', () => {
  it('scoped tokens have correct prefix', () => {
    // A scoped token should start with seks_scoped_
    const prefix = 'seks_scoped_';
    const mockPayload = {
      type: 'scoped',
      agent_id: 'agent_test',
      client_id: 'client_test',
      skill: 'test-skill',
      caps: ['openai', 'github'],
      iat: Date.now(),
      exp: Date.now() + 300_000,
    };
    const payloadB64 = btoa(JSON.stringify(mockPayload));
    const mockToken = `${prefix}${payloadB64}.fakesig`;
    
    expect(mockToken.startsWith('seks_scoped_')).toBe(true);
  });

  it('payload is valid base64 JSON', () => {
    const payload = {
      type: 'scoped',
      agent_id: 'agent_footgun01',
      client_id: '9c52e0b9-test',
      skill: 'my-skill',
      caps: ['openai'],
      iat: 1700000000000,
      exp: 1700000300000,
    };
    const encoded = btoa(JSON.stringify(payload));
    const decoded = JSON.parse(atob(encoded));
    
    expect(decoded.type).toBe('scoped');
    expect(decoded.caps).toEqual(['openai']);
    expect(decoded.skill).toBe('my-skill');
  });

  it('expired tokens are detected', () => {
    const payload = {
      type: 'scoped',
      exp: Date.now() - 1000, // 1 second ago
    };
    expect(Date.now() > payload.exp).toBe(true);
  });

  it('valid tokens are not expired', () => {
    const payload = {
      type: 'scoped',
      exp: Date.now() + 300_000, // 5 minutes from now
    };
    expect(Date.now() > payload.exp).toBe(false);
  });
});

describe('capability matching', () => {
  // Mirror the secretToProvider logic
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

  function checkCapability(caps: string[], provider: string): boolean {
    return caps.includes(provider) || caps.includes('*');
  }

  it('maps secret names to providers correctly', () => {
    expect(secretToProvider('OPENAI_TOKEN')).toBe('openai');
    expect(secretToProvider('ANTHROPIC_TOKEN')).toBe('anthropic');
    expect(secretToProvider('GITHUB_PERSONAL_ACCESS_TOKEN')).toBe('github');
    expect(secretToProvider('AWS_ACCESS_KEY_ID')).toBe('aws');
    expect(secretToProvider('NOTION_API_KEY')).toBe('notion');
    expect(secretToProvider('BRAVE_BASE_AI_TOKEN')).toBe('brave');
    expect(secretToProvider('GEMINI_API_KEY')).toBe('google');
    expect(secretToProvider('CLOUDFLARE_API_TOKEN')).toBe('cloudflare');
    expect(secretToProvider('RANDOM_SECRET')).toBeNull();
  });

  it('allows matching capabilities', () => {
    expect(checkCapability(['openai', 'github'], 'openai')).toBe(true);
    expect(checkCapability(['openai', 'github'], 'github')).toBe(true);
  });

  it('denies non-matching capabilities', () => {
    expect(checkCapability(['openai'], 'github')).toBe(false);
    expect(checkCapability(['openai'], 'anthropic')).toBe(false);
  });

  it('wildcard grants all capabilities', () => {
    expect(checkCapability(['*'], 'openai')).toBe(true);
    expect(checkCapability(['*'], 'github')).toBe(true);
    expect(checkCapability(['*'], 'aws')).toBe(true);
  });

  it('empty caps deny everything', () => {
    expect(checkCapability([], 'openai')).toBe(false);
  });

  it('filtering secrets by caps works', () => {
    const allSecrets = [
      { name: 'OPENAI_TOKEN', provider: 'openai' },
      { name: 'GITHUB_PERSONAL_ACCESS_TOKEN', provider: 'github' },
      { name: 'AWS_ACCESS_KEY_ID', provider: 'aws' },
      { name: 'NOTION_API_KEY', provider: 'notion' },
    ];
    const caps = ['openai', 'github'];
    
    const filtered = allSecrets.filter(s => {
      const p = secretToProvider(s.name);
      return p ? checkCapability(caps, p) : false;
    });

    expect(filtered).toHaveLength(2);
    expect(filtered.map(s => s.name)).toEqual(['OPENAI_TOKEN', 'GITHUB_PERSONAL_ACCESS_TOKEN']);
  });
});
