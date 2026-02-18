/**
 * Web UI routes for human administration
 */

import { Hono } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import type { Env, Account, Agent, Secret, AuditEntry } from './types.js';
import * as db from './db.js';
import { encrypt, decrypt, hashPassword, verifyPassword } from './crypto.js';
import { html, raw } from 'hono/html';
import type { HtmlEscapedString } from 'hono/utils/html';

export const webRoutes = new Hono<{ Bindings: Env }>();

// ─── Helpers ───────────────────────────────────────────────────────────────────

function getSessionAccount(c: any): string | null {
  const sessionId = getCookie(c, 'session');
  if (!sessionId) return null;
  const session = db.getSession(c.env.db, sessionId);
  return session?.account_id ?? null;
}

function getMasterKey(env: Env): string {
  return env.masterKey;
}

function redirect(path: string) {
  return new Response(null, { status: 302, headers: { Location: path } });
}

// ─── Templates ─────────────────────────────────────────────────────────────────

const baseStyles = `
  :root {
    --bg: #0a0a0a; --bg-secondary: #141414; --bg-tertiary: #1f1f1f;
    --text: #e5e5e5; --text-muted: #737373;
    --accent: #22c55e; --accent-hover: #16a34a;
    --danger: #ef4444; --warning: #f59e0b; --border: #262626;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; min-height: 100vh; }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }
  .container { max-width: 1200px; margin: 0 auto; padding: 0 1rem; }
  nav { background: var(--bg-secondary); border-bottom: 1px solid var(--border); padding: 1rem; }
  nav .container { display: flex; justify-content: space-between; align-items: center; }
  nav .logo { font-weight: bold; font-size: 1.25rem; color: var(--text); }
  nav .logo span { color: var(--accent); }
  nav ul { display: flex; list-style: none; gap: 1.5rem; }
  nav a { color: var(--text-muted); }
  nav a:hover, nav a.active { color: var(--text); text-decoration: none; }
  main { padding: 2rem 0; }
  h1, h2, h3 { margin-bottom: 1rem; }
  .card { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 0.5rem; padding: 1.5rem; margin-bottom: 1rem; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .stat { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 0.5rem; padding: 1.5rem; text-align: center; }
  .stat-value { font-size: 2.5rem; font-weight: bold; color: var(--accent); }
  .stat-label { color: var(--text-muted); font-size: 0.875rem; text-transform: uppercase; }
  .form-group { margin-bottom: 1rem; }
  label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
  input, select { width: 100%; padding: 0.75rem; background: var(--bg-tertiary); border: 1px solid var(--border); border-radius: 0.375rem; color: var(--text); font-size: 1rem; }
  input:focus, select:focus { outline: none; border-color: var(--accent); }
  .btn { display: inline-flex; align-items: center; gap: 0.5rem; padding: 0.75rem 1.5rem; border: none; border-radius: 0.375rem; font-size: 1rem; font-weight: 500; cursor: pointer; }
  .btn-primary { background: var(--accent); color: #000; }
  .btn-primary:hover { background: var(--accent-hover); }
  .btn-danger { background: var(--danger); color: #fff; }
  .btn-ghost { background: transparent; color: var(--text-muted); border: 1px solid var(--border); }
  .btn-sm { padding: 0.5rem 1rem; font-size: 0.875rem; }
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 0.75rem; text-align: left; border-bottom: 1px solid var(--border); }
  th { color: var(--text-muted); font-weight: 500; font-size: 0.875rem; text-transform: uppercase; }
  .alert { padding: 1rem; border-radius: 0.375rem; margin-bottom: 1rem; }
  .alert-error { background: rgba(239, 68, 68, 0.1); border: 1px solid var(--danger); color: var(--danger); }
  .badge { display: inline-block; padding: 0.25rem 0.5rem; border-radius: 9999px; font-size: 0.75rem; }
  .badge-success { background: rgba(34, 197, 94, 0.2); color: var(--accent); }
  .badge-warning { background: rgba(245, 158, 11, 0.2); color: var(--warning); }
  .badge-muted { background: var(--bg-tertiary); color: var(--text-muted); }
  .badge-danger { background: rgba(239, 68, 68, 0.2); color: var(--danger); }
  .token { font-family: monospace; font-size: 0.875rem; background: var(--bg-tertiary); padding: 0.25rem 0.5rem; border-radius: 0.25rem; }
  .empty { text-align: center; padding: 3rem; color: var(--text-muted); }
  .auth-container { max-width: 400px; margin: 4rem auto; padding: 0 1rem; }
  .auth-card { background: var(--bg-secondary); border: 1px solid var(--border); border-radius: 0.5rem; padding: 2rem; }
  .text-muted { color: var(--text-muted); }
  .text-center { text-align: center; }
  .mt-2 { margin-top: 1rem; }
  .mb-2 { margin-bottom: 1rem; }
  .flex { display: flex; }
  .justify-between { justify-content: space-between; }
  .items-center { align-items: center; }
  .gap-2 { gap: 0.5rem; }
`;

function layout(title: string, content: string | HtmlEscapedString | Promise<HtmlEscapedString>, nav?: string | HtmlEscapedString | Promise<HtmlEscapedString>) {
  return html`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} - SEKS Broker</title>
  <style>${baseStyles}</style>
</head>
<body>
  ${nav ? html`<nav><div class="container">${nav}</div></nav>` : ''}
  ${content}
</body>
</html>`;
}

function navBar(active: string) {
  return html`
    <div class="logo"><span>SEKS</span> Broker</div>
    <ul>
      <li><a href="/dashboard" class="${active === 'dashboard' ? 'active' : ''}">Dashboard</a></li>
      <li><a href="/secrets" class="${active === 'secrets' ? 'active' : ''}">Secrets</a></li>
      <li><a href="/agents" class="${active === 'agents' ? 'active' : ''}">Agents</a></li>
      <li><a href="/actuators" class="${active === 'actuators' ? 'active' : ''}">Actuators</a></li>
      <li><a href="/activity" class="${active === 'activity' ? 'active' : ''}">Activity</a></li>
    </ul>
    <form method="POST" action="/logout" style="margin: 0;">
      <button type="submit" class="btn btn-ghost btn-sm">Logout</button>
    </form>
  `;
}

// ─── Routes ────────────────────────────────────────────────────────────────────

webRoutes.get('/', (c) => {
  const content = html`
    <div class="auth-container" style="max-width: 600px; margin-top: 6rem;">
      <div class="text-center mb-2">
        <h1 style="font-size: 3rem; margin-bottom: 0.5rem;">
          <span style="color: var(--accent);">SEKS</span> Broker
        </h1>
        <p class="text-muted" style="font-size: 1.25rem;">Cloud-native secret management for AI agents</p>
      </div>
      <div class="card" style="margin-top: 3rem;">
        <h2 class="text-center">Bring Your Own Keys</h2>
        <p class="text-muted text-center" style="margin-bottom: 1.5rem;">Everything just works. Your agents, your keys, zero setup friction.</p>
        <div class="text-center">
          <a href="/login" class="btn btn-primary" style="font-size: 1.125rem; padding: 1rem 2rem;">Get Started →</a>
        </div>
      </div>
    </div>
  `;
  return c.html(layout('Welcome', content));
});

webRoutes.get('/login', (c) => {
  const content = html`
    <div class="auth-container">
      <div class="auth-card">
        <h1 class="text-center"><span style="color: var(--accent);">SEKS</span> Broker</h1>
        <form method="POST" action="/login">
          <div class="form-group">
            <label for="email">Email</label>
            <input type="email" id="email" name="email" required placeholder="you@example.com">
          </div>
          <div class="form-group">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" required placeholder="••••••••">
          </div>
          <button type="submit" class="btn btn-primary" style="width: 100%;">Sign In</button>
        </form>
        <p class="text-muted text-center mt-2" style="font-size: 0.875rem;">New here? Just enter your email and password to create an account.</p>
      </div>
    </div>
  `;
  return c.html(layout('Login', content));
});

webRoutes.post('/login', async (c) => {
  const body = await c.req.parseBody();
  const email = body.email as string;
  const password = body.password as string;

  let account = db.getAccountByEmail(c.env.db, email);

  if (!account) {
    const hash = hashPassword(password);
    account = db.createAccount(c.env.db, email, hash);
  } else {
    const valid = verifyPassword(password, account.password_hash);
    if (!valid) {
      const content = html`
        <div class="auth-container">
          <div class="auth-card">
            <h1 class="text-center"><span style="color: var(--accent);">SEKS</span> Broker</h1>
            <div class="alert alert-error">Invalid email or password</div>
            <form method="POST" action="/login">
              <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required value="${email}">
              </div>
              <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
              </div>
              <button type="submit" class="btn btn-primary" style="width: 100%;">Sign In</button>
            </form>
          </div>
        </div>
      `;
      return c.html(layout('Login', content));
    }
  }

  const session = db.createSession(c.env.db, account.id);
  setCookie(c, 'session', session.id, { path: '/', httpOnly: true, sameSite: 'Lax' });
  return c.redirect('/dashboard');
});

webRoutes.post('/logout', (c) => {
  const sessionId = getCookie(c, 'session');
  if (sessionId) db.deleteSession(c.env.db, sessionId);
  deleteCookie(c, 'session');
  return redirect('/login');
});

webRoutes.get('/dashboard', (c) => {
  const accountId = getSessionAccount(c);
  if (!accountId) return redirect('/login');

  const account = db.getAccountById(c.env.db, accountId);
  const secrets = db.listSecrets(c.env.db, accountId);
  const agents = db.listAgents(c.env.db, accountId);
  const actuators = db.listActuatorsByAccount(c.env.db, accountId);

  const content = html`
    <main>
      <div class="container">
        <h1>Welcome${account?.name ? `, ${account.name}` : ''}</h1>
        <div class="stats">
          <div class="stat"><div class="stat-value">${secrets.length}</div><div class="stat-label">Secrets</div></div>
          <div class="stat"><div class="stat-value">${agents.length}</div><div class="stat-label">Agents</div></div>
          <div class="stat"><div class="stat-value">${actuators.length}</div><div class="stat-label">Actuators</div></div>
          <div class="stat"><div class="stat-value">${actuators.filter(a => a.status === 'online').length}</div><div class="stat-label">Online</div></div>
        </div>
        <div class="card">
          <h2>Quick Start</h2>
          <ol style="padding-left: 1.5rem; color: var(--text-muted);">
            <li style="margin-bottom: 0.5rem;"><strong style="color: var(--text);">Add your API keys</strong> — Go to <a href="/secrets">Secrets</a></li>
            <li style="margin-bottom: 0.5rem;"><strong style="color: var(--text);">Create an agent</strong> — Go to <a href="/agents">Agents</a></li>
            <li style="margin-bottom: 0.5rem;"><strong style="color: var(--text);">Register actuators</strong> — Go to <a href="/actuators">Actuators</a></li>
            <li><strong style="color: var(--text);">Use the API</strong> — Your agent can now access secrets and command actuators</li>
          </ol>
        </div>
      </div>
    </main>
  `;
  return c.html(layout('Dashboard', content, navBar('dashboard')));
});

// ─── Secrets ───────────────────────────────────────────────────────────────────

webRoutes.get('/secrets', (c) => {
  const accountId = getSessionAccount(c);
  if (!accountId) return redirect('/login');

  const secrets = db.listSecrets(c.env.db, accountId);
  const agents = db.listAgents(c.env.db, accountId);
  const agentMap = new Map(agents.map(a => [a.id, a.name]));

  const secretsWithAccess = secrets.map(s => {
    const access = db.getSecretAccess(c.env.db, s.id);
    return { ...s, access };
  });

  const rows = raw(secretsWithAccess.map(s => {
    const accessBadge = s.access.length === 0
      ? html`<span class="badge badge-success">All agents</span>`
      : html`<span class="badge badge-muted">${s.access.map(a => agentMap.get(a.agent_id) || 'Unknown').join(', ')}</span>`;
    return html`
      <tr>
        <td><code class="token">${s.name}</code></td>
        <td>${s.provider}</td>
        <td>${accessBadge}</td>
        <td class="text-muted">${s.created_at.split('T')[0]}</td>
        <td>
          <div class="flex gap-2">
            <a href="/secrets/${s.id}/reveal" class="btn btn-ghost btn-sm">Reveal</a>
            <a href="/secrets/${s.id}/edit" class="btn btn-ghost btn-sm">Edit</a>
            <form method="POST" action="/secrets/${s.id}/delete" onsubmit="return confirm('Delete this secret?');" style="margin: 0;">
              <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
          </div>
        </td>
      </tr>
    `;
  }).join(''));

  const content = html`
    <main>
      <div class="container">
        <div class="flex justify-between items-center mb-2">
          <h1>Secrets</h1>
          <a href="/secrets/add" class="btn btn-primary">+ Add Secret</a>
        </div>
        <div class="card">
          ${secrets.length === 0 ? html`
            <div class="empty"><p>No secrets configured yet</p><a href="/secrets/add" class="btn btn-primary mt-2">+ Add Secret</a></div>
          ` : html`
            <table>
              <thead><tr><th>Name</th><th>Provider</th><th>Access</th><th>Created</th><th></th></tr></thead>
              <tbody>${rows}</tbody>
            </table>
          `}
        </div>
      </div>
    </main>
  `;
  return c.html(layout('Secrets', content, navBar('secrets')));
});

webRoutes.get('/secrets/add', (c) => {
  const accountId = getSessionAccount(c);
  if (!accountId) return redirect('/login');

  const agents = db.listAgents(c.env.db, accountId);

  const agentCheckboxes = agents.length > 0 ? raw(agents.map(a => html`
    <label style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem;">
      <input type="checkbox" name="agents" value="${a.id}">
      <span>${a.name}</span>
    </label>
  `).join('')) : html`<p class="text-muted">No agents created yet. <a href="/agents">Create one first.</a></p>`;

  const content = html`
    <main>
      <div class="container" style="max-width: 600px;">
        <h1>Add Secret</h1>
        <div class="card">
          <form method="POST" action="/secrets/add">
            <div class="form-group">
              <label for="name">Secret Name</label>
              <input type="text" id="name" name="name" required placeholder="OPENAI_TOKEN" pattern="[A-Z0-9_]+">
              <small class="text-muted">Use uppercase with underscores</small>
            </div>
            <div class="form-group">
              <label for="provider">Provider</label>
              <select id="provider" name="provider" required>
                <option value="anthropic">Anthropic (Claude)</option>
                <option value="openai">OpenAI</option>
                <option value="google">Google AI / Gemini</option>
                <option value="aws">AWS</option>
                <option value="github">GitHub</option>
                <option value="cloudflare">Cloudflare</option>
                <option value="notion">Notion</option>
                <option value="brave">Brave Search</option>
                <option value="elevenlabs">ElevenLabs</option>
                <option value="doppler">Doppler</option>
                <option value="other">Other</option>
              </select>
            </div>
            <div class="form-group">
              <label for="value">Secret Value</label>
              <div style="display: flex; gap: 0.5rem;">
                <input type="password" id="value" name="value" required placeholder="sk-..." style="flex: 1;">
                <button type="button" onclick="toggleSecret()" class="btn btn-ghost" id="toggleBtn">Show</button>
              </div>
            </div>
            <div class="form-group">
              <label>Agent Access</label>
              <div style="background: var(--bg-tertiary); padding: 1rem; border-radius: 0.375rem; border: 1px solid var(--border);">
                <label style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.75rem;">
                  <input type="checkbox" id="globalAccess" checked onchange="toggleAgentSelection()">
                  <strong>All agents</strong> <span class="text-muted">(global)</span>
                </label>
                <div id="agentSelection" style="display: none; padding-left: 1.5rem; border-left: 2px solid var(--border);">
                  ${agentCheckboxes}
                </div>
              </div>
            </div>
            <script>
              function toggleSecret() { const i = document.getElementById('value'), b = document.getElementById('toggleBtn'); if (i.type === 'password') { i.type = 'text'; b.textContent = 'Hide'; } else { i.type = 'password'; b.textContent = 'Show'; } }
              function toggleAgentSelection() { const g = document.getElementById('globalAccess'), s = document.getElementById('agentSelection'); s.style.display = g.checked ? 'none' : 'block'; if (g.checked) document.querySelectorAll('input[name="agents"]').forEach(cb => cb.checked = false); }
            </script>
            <div class="flex gap-2">
              <button type="submit" class="btn btn-primary">Save Secret</button>
              <a href="/secrets" class="btn btn-ghost">Cancel</a>
            </div>
          </form>
        </div>
      </div>
    </main>
  `;
  return c.html(layout('Add Secret', content, navBar('secrets')));
});

webRoutes.post('/secrets/add', async (c) => {
  const accountId = getSessionAccount(c);
  if (!accountId) return redirect('/login');

  const body = await c.req.parseBody();
  const name = body.name as string;
  const provider = body.provider as string;
  const value = body.value as string;
  let agentIds: string[] = [];
  const agents = body.agents;
  if (agents) agentIds = Array.isArray(agents) ? agents as string[] : [agents as string];

  const encrypted = encrypt(value, getMasterKey(c.env));
  const secret = db.createSecret(c.env.db, accountId, name, provider, encrypted);
  db.setSecretAccess(c.env.db, secret.id, agentIds);
  return redirect('/secrets');
});

webRoutes.post('/secrets/:id/delete', (c) => {
  const accountId = getSessionAccount(c);
  if (!accountId) return redirect('/login');
  db.deleteSecret(c.env.db, c.req.param('id'), accountId);
  return redirect('/secrets');
});

webRoutes.get('/secrets/:id/edit', (c) => {
  const accountId = getSessionAccount(c);
  if (!accountId) return redirect('/login');
  const id = c.req.param('id');
  const secret = db.getSecretById(c.env.db, id, accountId);
  if (!secret) return redirect('/secrets');
  const agents = db.listAgents(c.env.db, accountId);
  const currentAccess = db.getSecretAccess(c.env.db, id);
  const currentAgentIds = new Set(currentAccess.map(a => a.agent_id));
  const isGlobal = currentAccess.length === 0;

  const providers = [
    { value: 'anthropic', label: 'Anthropic (Claude)' }, { value: 'openai', label: 'OpenAI' },
    { value: 'google', label: 'Google AI / Gemini' }, { value: 'aws', label: 'AWS' },
    { value: 'github', label: 'GitHub' }, { value: 'cloudflare', label: 'Cloudflare' },
    { value: 'notion', label: 'Notion' }, { value: 'brave', label: 'Brave Search' },
    { value: 'elevenlabs', label: 'ElevenLabs' }, { value: 'doppler', label: 'Doppler' },
    { value: 'other', label: 'Other' },
  ];

  const providerOptions = raw(providers.map(p =>
    `<option value="${p.value}"${p.value === secret.provider ? ' selected' : ''}>${p.label}</option>`
  ).join(''));

  const agentCheckboxes = agents.length > 0 ? raw(agents.map(a => html`
    <label style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem;">
      <input type="checkbox" name="agents" value="${a.id}" ${currentAgentIds.has(a.id) ? 'checked' : ''}>
      <span>${a.name}</span>
    </label>
  `).join('')) : html`<p class="text-muted">No agents created yet.</p>`;

  const content = html`
    <main>
      <div class="container" style="max-width: 600px;">
        <h1>Edit Secret</h1>
        <div class="card">
          <form method="POST" action="/secrets/${id}/edit">
            <div class="form-group">
              <label for="name">Secret Name</label>
              <input type="text" id="name" name="name" required value="${secret.name}" pattern="[A-Z0-9_]+">
            </div>
            <div class="form-group">
              <label for="provider">Provider</label>
              <select id="provider" name="provider" required>${providerOptions}</select>
            </div>
            <div class="form-group">
              <label for="value">New Secret Value <span class="text-muted">(leave blank to keep current)</span></label>
              <div style="display: flex; gap: 0.5rem;">
                <input type="password" id="value" name="value" placeholder="Leave blank to keep current" style="flex: 1;">
                <button type="button" onclick="toggleSecret()" class="btn btn-ghost" id="toggleBtn">Show</button>
              </div>
            </div>
            <div class="form-group">
              <label>Agent Access</label>
              <div style="background: var(--bg-tertiary); padding: 1rem; border-radius: 0.375rem; border: 1px solid var(--border);">
                <label style="display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.75rem;">
                  <input type="checkbox" id="globalAccess" ${isGlobal ? 'checked' : ''} onchange="toggleAgentSelection()">
                  <strong>All agents</strong> <span class="text-muted">(global)</span>
                </label>
                <div id="agentSelection" style="display: ${isGlobal ? 'none' : 'block'}; padding-left: 1.5rem; border-left: 2px solid var(--border);">
                  ${agentCheckboxes}
                </div>
              </div>
            </div>
            <div class="flex gap-2">
              <button type="submit" class="btn btn-primary">Save Changes</button>
              <a href="/secrets" class="btn btn-ghost">Cancel</a>
            </div>
          </form>
        </div>
      </div>
      <script>
        function toggleSecret() { const i = document.getElementById('value'), b = document.getElementById('toggleBtn'); if (i.type === 'password') { i.type = 'text'; b.textContent = 'Hide'; } else { i.type = 'password'; b.textContent = 'Show'; } }
        function toggleAgentSelection() { const g = document.getElementById('globalAccess'), s = document.getElementById('agentSelection'); s.style.display = g.checked ? 'none' : 'block'; if (g.checked) document.querySelectorAll('input[name="agents"]').forEach(cb => cb.checked = false); }
      </script>
    </main>
  `;
  return c.html(layout('Edit Secret', content, navBar('secrets')));
});

webRoutes.post('/secrets/:id/edit', async (c) => {
  const accountId = getSessionAccount(c);
  if (!accountId) return redirect('/login');
  const id = c.req.param('id');
  const body = await c.req.parseBody();
  const name = body.name as string;
  const provider = body.provider as string;
  const value = body.value as string;
  let agentIds: string[] = [];
  const agents = body.agents;
  if (agents) agentIds = Array.isArray(agents) ? agents as string[] : [agents as string];

  let encryptedValue: string | undefined;
  if (value && value.trim()) encryptedValue = encrypt(value, getMasterKey(c.env));

  db.updateSecret(c.env.db, id, accountId, name, provider, encryptedValue);
  db.setSecretAccess(c.env.db, id, agentIds);
  return redirect('/secrets');
});

webRoutes.get('/secrets/:id/reveal', (c) => {
  const accountId = getSessionAccount(c);
  if (!accountId) return redirect('/login');
  const id = c.req.param('id');
  const secret = db.getSecretById(c.env.db, id, accountId);
  if (!secret) return redirect('/secrets');

  let value: string;
  try { value = decrypt(secret.encrypted_value, getMasterKey(c.env)); }
  catch { value = '[decryption failed]'; }

  const content = html`
    <main>
      <div class="container" style="max-width: 600px;">
        <h1>Secret: ${secret.name}</h1>
        <div class="card">
          <div class="form-group"><label>Provider</label><div class="text-muted">${secret.provider}</div></div>
          <div class="form-group"><label>Value</label><div style="background: var(--bg-tertiary); padding: 1rem; border-radius: 0.375rem; font-family: monospace; word-break: break-all;">${value}</div></div>
          <div class="form-group"><label>Created</label><div class="text-muted">${secret.created_at}</div></div>
          <a href="/secrets" class="btn btn-ghost">← Back to Secrets</a>
        </div>
      </div>
    </main>
  `;
  return c.html(layout('Secret Details', content, navBar('secrets')));
});

// ─── Agents ────────────────────────────────────────────────────────────────────

webRoutes.get('/agents', (c) => {
  const accountId = getSessionAccount(c);
  if (!accountId) return redirect('/login');

  const agents = db.listAgents(c.env.db, accountId);

  // Note: with token_hash, we can't show plaintext tokens for existing agents.
  // Only at creation time. We show the hash prefix as identifier.
  const rows = raw(agents.map(a => html`
    <tr>
      <td><strong>${a.name}</strong></td>
      <td><code class="token">${a.token_hash.slice(0, 16)}...</code></td>
      <td class="text-muted">${a.created_at.split('T')[0]}</td>
      <td class="text-muted">${a.last_seen_at?.split('T')[0] || 'Never'}</td>
      <td>
        <div class="flex gap-2">
          <a href="/agents/${a.id}" class="btn btn-ghost btn-sm">Proxy Tokens</a>
          <form method="POST" action="/agents/${a.id}/delete" onsubmit="return confirm('Delete this agent?');" style="margin: 0;">
            <button type="submit" class="btn btn-danger btn-sm">Delete</button>
          </form>
        </div>
      </td>
    </tr>
  `).join(''));

  const content = html`
    <main>
      <div class="container">
        <h1>Agents</h1>
        <div class="card">
          <h3>Create Agent</h3>
          <form method="POST" action="/agents/add" class="flex gap-2">
            <input type="text" name="name" placeholder="Agent name" required style="flex: 1;">
            <button type="submit" class="btn btn-primary">Create</button>
          </form>
        </div>
        <div class="card">
          <h3>Your Agents</h3>
          ${agents.length === 0 ? html`<div class="empty"><p>No agents created yet</p></div>` : html`
            <table>
              <thead><tr><th>Name</th><th>Token Hash</th><th>Created</th><th>Last Seen</th><th></th></tr></thead>
              <tbody>${rows}</tbody>
            </table>
          `}
        </div>
      </div>
    </main>
  `;
  return c.html(layout('Agents', content, navBar('agents')));
});

webRoutes.post('/agents/add', async (c) => {
  const accountId = getSessionAccount(c);
  if (!accountId) return redirect('/login');
  const body = await c.req.parseBody();
  const name = body.name as string;

  const agent = db.createAgent(c.env.db, accountId, name);

  // Show the plaintext token once
  const content = html`
    <main>
      <div class="container" style="max-width: 600px;">
        <h1>Agent Created: ${name}</h1>
        <div class="alert" style="background: rgba(34, 197, 94, 0.1); border: 1px solid var(--accent); color: var(--accent);">
          ⚠️ Save this token now! It will never be shown again.
        </div>
        <div class="card">
          <label>Agent Token</label>
          <div style="background: var(--bg-tertiary); padding: 1rem; border-radius: 0.375rem; font-family: monospace; word-break: break-all; margin-top: 0.5rem;">
            ${agent._plaintext_token}
          </div>
          <button type="button" class="btn btn-ghost btn-sm mt-2" onclick="navigator.clipboard.writeText('${agent._plaintext_token}').then(() => this.textContent = 'Copied!')">Copy Token</button>
        </div>
        <a href="/agents" class="btn btn-primary mt-2">← Back to Agents</a>
      </div>
    </main>
  `;
  return c.html(layout('Agent Created', content, navBar('agents')));
});

webRoutes.post('/agents/:id/delete', (c) => {
  const accountId = getSessionAccount(c);
  if (!accountId) return redirect('/login');
  db.deleteAgent(c.env.db, c.req.param('id'), accountId);
  return redirect('/agents');
});

webRoutes.get('/agents/:id', (c) => {
  const accountId = getSessionAccount(c);
  if (!accountId) return redirect('/login');
  const id = c.req.param('id');
  const agents = db.listAgents(c.env.db, accountId);
  const agent = agents.find(a => a.id === id);
  if (!agent) return redirect('/agents');

  const fakeTokens = db.listFakeTokens(c.env.db, id);
  const providers = ['openai', 'anthropic', 'github', 'notion', 'gemini', 'cloudflare', 'brave', 'aws'];

  const tokenRows = raw(fakeTokens.map(t => html`
    <tr>
      <td><strong>${t.provider}</strong></td>
      <td>
        <code class="token">${t.token}</code>
        <button type="button" class="btn btn-ghost btn-sm" style="margin-left: 0.5rem; padding: 0.25rem 0.5rem;" onclick="copyToken('${t.token}', this)">Copy</button>
      </td>
      <td class="text-muted">${t.created_at.split('T')[0]}</td>
      <td class="text-muted">${t.last_used_at?.split('T')[0] || 'Never'}</td>
      <td>
        <form method="POST" action="/agents/${id}/tokens/${t.provider}/renew" style="margin: 0; display: inline;">
          <button type="submit" class="btn btn-ghost btn-sm">Renew</button>
        </form>
      </td>
    </tr>
  `).join(''));

  const existingProviders = new Set(fakeTokens.map(t => t.provider));
  const availableProviders = providers.filter(p => !existingProviders.has(p));

  const content = html`
    <main>
      <div class="container">
        <div class="flex justify-between items-center mb-2">
          <h1>Agent: ${agent.name}</h1>
          <a href="/agents" class="btn btn-ghost">← Back</a>
        </div>
        <div class="card">
          <h3>Proxy Tokens</h3>
          <p class="text-muted mb-2">Use these tokens with the passthrough proxy.</p>
          ${fakeTokens.length === 0 ? html`<div class="empty"><p>No proxy tokens generated yet</p></div>` : html`
            <table>
              <thead><tr><th>Provider</th><th>Token</th><th>Created</th><th>Last Used</th><th></th></tr></thead>
              <tbody>${tokenRows}</tbody>
            </table>
          `}
          ${availableProviders.length > 0 ? html`
            <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--border);">
              <h4>Generate New Token</h4>
              <form method="POST" action="/agents/${id}/tokens" class="flex gap-2" style="margin-top: 0.5rem;">
                <select name="provider" required style="flex: 1;">
                  ${raw(availableProviders.map(p => `<option value="${p}">${p}</option>`).join(''))}
                </select>
                <button type="submit" class="btn btn-primary">Generate</button>
              </form>
            </div>
          ` : ''}
        </div>
      </div>
      <script>
        function copyToken(token, btn) { navigator.clipboard.writeText(token).then(() => { const o = btn.textContent; btn.textContent = 'Copied!'; btn.style.color = 'var(--accent)'; setTimeout(() => { btn.textContent = o; btn.style.color = ''; }, 1500); }); }
      </script>
    </main>
  `;
  return c.html(layout(`Agent: ${agent.name}`, content, navBar('agents')));
});

webRoutes.post('/agents/:id/tokens', async (c) => {
  const accountId = getSessionAccount(c);
  if (!accountId) return redirect('/login');
  const id = c.req.param('id');
  const body = await c.req.parseBody();
  const provider = body.provider as string;
  const agents = db.listAgents(c.env.db, accountId);
  if (!agents.find(a => a.id === id)) return redirect('/agents');
  db.createFakeToken(c.env.db, id, provider);
  return redirect(`/agents/${id}`);
});

webRoutes.post('/agents/:id/tokens/:provider/renew', (c) => {
  const accountId = getSessionAccount(c);
  if (!accountId) return redirect('/login');
  const id = c.req.param('id');
  const provider = c.req.param('provider');
  const agents = db.listAgents(c.env.db, accountId);
  if (!agents.find(a => a.id === id)) return redirect('/agents');
  db.createFakeToken(c.env.db, id, provider);
  return redirect(`/agents/${id}`);
});

// ─── Actuators ─────────────────────────────────────────────────────────────────

webRoutes.get('/actuators', (c) => {
  const accountId = getSessionAccount(c);
  if (!accountId) return redirect('/login');

  const agents = db.listAgents(c.env.db, accountId);
  const agentMap = new Map(agents.map(a => [a.id, a.name]));
  const actuators = db.listActuatorsByAccount(c.env.db, accountId);

  const rows = raw(actuators.map(a => {
    const caps = db.listCapabilities(c.env.db, a.id);
    const statusBadge = a.status === 'online'
      ? html`<span class="badge badge-success">online</span>`
      : a.status === 'suspended'
      ? html`<span class="badge badge-danger">suspended</span>`
      : html`<span class="badge badge-muted">offline</span>`;
    return html`
      <tr>
        <td><strong>${a.name}</strong></td>
        <td class="text-muted">${agentMap.get(a.agent_id) || 'Unknown'}</td>
        <td>${a.type}</td>
        <td>${statusBadge}</td>
        <td>${caps.length > 0 ? caps.map(c => html`<span class="badge badge-muted" style="margin-right: 0.25rem;">${c.capability}</span>`).join('') : html`<span class="text-muted">none</span>`}</td>
        <td class="text-muted">${a.last_seen_at?.replace('T', ' ').split('.')[0] || 'Never'}</td>
        <td>
          <div class="flex gap-2">
            <a href="/actuators/${a.id}" class="btn btn-ghost btn-sm">Manage</a>
            <form method="POST" action="/actuators/${a.id}/delete" onsubmit="return confirm('Delete this actuator?');" style="margin: 0;">
              <button type="submit" class="btn btn-danger btn-sm">Delete</button>
            </form>
          </div>
        </td>
      </tr>
    `;
  }).join(''));

  const content = html`
    <main>
      <div class="container">
        <div class="flex justify-between items-center mb-2">
          <h1>Actuators</h1>
        </div>
        <div class="card">
          <h3>Register Actuator</h3>
          <form method="POST" action="/actuators/add" class="flex gap-2">
            <input type="text" name="name" placeholder="Actuator name" required style="flex: 2;">
            <select name="agent_id" required style="flex: 1;">
              ${raw(agents.map(a => `<option value="${a.id}">${a.name}</option>`).join(''))}
            </select>
            <select name="type" style="flex: 1;">
              <option value="vps">VPS</option>
              <option value="desktop">Desktop</option>
              <option value="mobile">Mobile</option>
            </select>
            <button type="submit" class="btn btn-primary">Register</button>
          </form>
        </div>
        <div class="card">
          ${actuators.length === 0 ? html`<div class="empty"><p>No actuators registered yet</p></div>` : html`
            <table>
              <thead><tr><th>Name</th><th>Agent</th><th>Type</th><th>Status</th><th>Capabilities</th><th>Last Seen</th><th></th></tr></thead>
              <tbody>${rows}</tbody>
            </table>
          `}
        </div>
      </div>
    </main>
  `;
  return c.html(layout('Actuators', content, navBar('actuators')));
});

webRoutes.post('/actuators/add', async (c) => {
  const accountId = getSessionAccount(c);
  if (!accountId) return redirect('/login');
  const body = await c.req.parseBody();
  const name = body.name as string;
  const agentId = body.agent_id as string;
  const type = body.type as string || 'vps';

  // Verify agent belongs to this account
  const agents = db.listAgents(c.env.db, accountId);
  if (!agents.find(a => a.id === agentId)) return redirect('/actuators');

  db.createActuator(c.env.db, agentId, name, type);
  return redirect('/actuators');
});

webRoutes.get('/actuators/:id', (c) => {
  const accountId = getSessionAccount(c);
  if (!accountId) return redirect('/login');
  const id = c.req.param('id');
  const actuator = db.getActuatorById(c.env.db, id);
  if (!actuator) return redirect('/actuators');

  // Verify ownership
  const agent = db.getAgentById(c.env.db, actuator.agent_id);
  if (!agent || agent.account_id !== accountId) return redirect('/actuators');

  const caps = db.listCapabilities(c.env.db, id);
  const commands = db.listRecentCommands(c.env.db, actuator.agent_id, 20);
  const actuatorCommands = commands.filter(cmd => cmd.actuator_id === id || cmd.actuator_id === null);

  const allCaps = ['git', 'docker', 'filesystem', 'shell', 'network', 'credential', 'admin'];
  const existingCaps = new Set(caps.map(c => c.capability));
  const availableCaps = allCaps.filter(c => !existingCaps.has(c));

  const capRows = raw(caps.map(cap => html`
    <tr>
      <td><code class="token">${cap.capability}</code></td>
      <td class="text-muted">${cap.constraints || 'none'}</td>
      <td>
        <form method="POST" action="/actuators/${id}/capabilities/${cap.capability}/delete" style="margin: 0;">
          <button type="submit" class="btn btn-danger btn-sm">Remove</button>
        </form>
      </td>
    </tr>
  `).join(''));

  const cmdRows = raw(actuatorCommands.map(cmd => {
    const statusBadge = cmd.status === 'completed' ? 'badge-success'
      : cmd.status === 'failed' ? 'badge-danger'
      : cmd.status === 'delivered' ? 'badge-warning'
      : 'badge-muted';
    return html`
      <tr>
        <td class="text-muted">${cmd.created_at.replace('T', ' ').split('.')[0]}</td>
        <td><code class="token">${cmd.capability}</code></td>
        <td><span class="badge ${statusBadge}">${cmd.status}</span></td>
        <td class="text-muted">${cmd.completed_at ? cmd.completed_at.replace('T', ' ').split('.')[0] : '-'}</td>
      </tr>
    `;
  }).join(''));

  const content = html`
    <main>
      <div class="container">
        <div class="flex justify-between items-center mb-2">
          <h1>Actuator: ${actuator.name}</h1>
          <a href="/actuators" class="btn btn-ghost">← Back</a>
        </div>
        <div class="card">
          <h3>Details</h3>
          <p><strong>ID:</strong> <code class="token">${actuator.id}</code></p>
          <p><strong>Type:</strong> ${actuator.type}</p>
          <p><strong>Status:</strong> <span class="badge ${actuator.status === 'online' ? 'badge-success' : 'badge-muted'}">${actuator.status}</span></p>
          <p><strong>Agent:</strong> ${agent.name}</p>
          <p><strong>Last Seen:</strong> ${actuator.last_seen_at || 'Never'}</p>
        </div>
        <div class="card">
          <h3>Capabilities</h3>
          ${caps.length > 0 ? html`
            <table>
              <thead><tr><th>Capability</th><th>Constraints</th><th></th></tr></thead>
              <tbody>${capRows}</tbody>
            </table>
          ` : html`<p class="text-muted">No capabilities assigned</p>`}
          ${availableCaps.length > 0 ? html`
            <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--border);">
              <form method="POST" action="/actuators/${id}/capabilities" class="flex gap-2">
                <select name="capability" required style="flex: 1;">
                  ${raw(availableCaps.map(c => `<option value="${c}">${c}</option>`).join(''))}
                </select>
                <input type="text" name="constraints" placeholder="Constraints (JSON, optional)" style="flex: 2;">
                <button type="submit" class="btn btn-primary btn-sm">Add</button>
              </form>
            </div>
          ` : ''}
        </div>
        <div class="card">
          <h3>Recent Commands</h3>
          ${actuatorCommands.length > 0 ? html`
            <table>
              <thead><tr><th>Time</th><th>Capability</th><th>Status</th><th>Completed</th></tr></thead>
              <tbody>${cmdRows}</tbody>
            </table>
          ` : html`<p class="text-muted">No commands yet</p>`}
        </div>
      </div>
    </main>
  `;
  return c.html(layout(`Actuator: ${actuator.name}`, content, navBar('actuators')));
});

webRoutes.post('/actuators/:id/delete', (c) => {
  const accountId = getSessionAccount(c);
  if (!accountId) return redirect('/login');
  const id = c.req.param('id');
  const actuator = db.getActuatorById(c.env.db, id);
  if (!actuator) return redirect('/actuators');
  const agent = db.getAgentById(c.env.db, actuator.agent_id);
  if (!agent || agent.account_id !== accountId) return redirect('/actuators');
  db.deleteActuator(c.env.db, id);
  return redirect('/actuators');
});

webRoutes.post('/actuators/:id/capabilities', async (c) => {
  const accountId = getSessionAccount(c);
  if (!accountId) return redirect('/login');
  const id = c.req.param('id');
  const body = await c.req.parseBody();
  const capability = body.capability as string;
  const constraints = body.constraints as string || undefined;
  const actuator = db.getActuatorById(c.env.db, id);
  if (!actuator) return redirect('/actuators');
  const agent = db.getAgentById(c.env.db, actuator.agent_id);
  if (!agent || agent.account_id !== accountId) return redirect('/actuators');
  db.addCapability(c.env.db, id, capability, constraints);
  return redirect(`/actuators/${id}`);
});

webRoutes.post('/actuators/:id/capabilities/:cap/delete', (c) => {
  const accountId = getSessionAccount(c);
  if (!accountId) return redirect('/login');
  const id = c.req.param('id');
  const cap = c.req.param('cap');
  const actuator = db.getActuatorById(c.env.db, id);
  if (!actuator) return redirect('/actuators');
  const agent = db.getAgentById(c.env.db, actuator.agent_id);
  if (!agent || agent.account_id !== accountId) return redirect('/actuators');
  db.removeCapability(c.env.db, id, cap);
  return redirect(`/actuators/${id}`);
});

// ─── Activity ──────────────────────────────────────────────────────────────────

webRoutes.get('/activity', (c) => {
  const accountId = getSessionAccount(c);
  if (!accountId) return redirect('/login');

  const entries = db.listAudit(c.env.db, accountId, 100);

  const rows = raw(entries.map(e => html`
    <tr>
      <td class="text-muted">${e.created_at.replace('T', ' ').split('.')[0]}</td>
      <td>${e.agent_id || '-'}</td>
      <td>${e.action}</td>
      <td>${e.resource ? html`<code class="token">${e.resource}</code>` : '-'}</td>
      <td><span class="badge ${e.status === 'success' ? 'badge-success' : 'badge-muted'}">${e.status}</span></td>
    </tr>
  `).join(''));

  const content = html`
    <main>
      <div class="container">
        <h1>Activity Log</h1>
        <div class="card">
          ${entries.length === 0 ? html`<div class="empty"><p>No activity recorded yet</p></div>` : html`
            <table>
              <thead><tr><th>Time</th><th>Agent</th><th>Action</th><th>Resource</th><th>Status</th></tr></thead>
              <tbody>${rows}</tbody>
            </table>
          `}
        </div>
      </div>
    </main>
  `;
  return c.html(layout('Activity', content, navBar('activity')));
});
