-- SEKS Broker Database Schema (v0.2 - Node.js / SQLite)

-- Accounts (human users who own API keys) — renamed from 'clients'
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Agents (AI agents that access secrets)
CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT UNIQUE NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at TEXT
);

-- Secrets (encrypted API keys and credentials)
CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    provider TEXT NOT NULL,
    encrypted_value TEXT NOT NULL,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(account_id, name)
);

-- Audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    agent_id TEXT,
    action TEXT NOT NULL,
    resource TEXT,
    status TEXT NOT NULL,
    ip_address TEXT,
    details TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Sessions (web UI authentication)
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Fake tokens (proxy passthrough tokens)
CREATE TABLE IF NOT EXISTS fake_tokens (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    token TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used_at TEXT,
    UNIQUE(agent_id, provider)
);

-- Secret access (junction table for per-agent secrets)
CREATE TABLE IF NOT EXISTS secret_access (
    secret_id TEXT NOT NULL REFERENCES secrets(id) ON DELETE CASCADE,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (secret_id, agent_id)
);

-- Actuators (remote execution environments connected via WebSocket)
CREATE TABLE IF NOT EXISTS actuators (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'vps',
    status TEXT NOT NULL DEFAULT 'offline',
    last_seen_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Capabilities (what an actuator can do)
CREATE TABLE IF NOT EXISTS capabilities (
    id TEXT PRIMARY KEY,
    actuator_id TEXT NOT NULL REFERENCES actuators(id) ON DELETE CASCADE,
    capability TEXT NOT NULL,
    constraints TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(actuator_id, capability)
);

-- Command queue (pending/completed commands for actuators)
CREATE TABLE IF NOT EXISTS command_queue (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id),
    actuator_id TEXT,
    capability TEXT NOT NULL,
    payload TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    result TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    delivered_at TEXT,
    completed_at TEXT,
    ttl_seconds INTEGER DEFAULT 300
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_secret_access_secret ON secret_access(secret_id);
CREATE INDEX IF NOT EXISTS idx_secret_access_agent ON secret_access(agent_id);
CREATE INDEX IF NOT EXISTS idx_agents_account ON agents(account_id);
CREATE INDEX IF NOT EXISTS idx_agents_token_hash ON agents(token_hash);
CREATE INDEX IF NOT EXISTS idx_secrets_account ON secrets(account_id);
CREATE INDEX IF NOT EXISTS idx_audit_account ON audit_log(account_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_account ON sessions(account_id);
CREATE INDEX IF NOT EXISTS idx_fake_tokens_token ON fake_tokens(token);
CREATE INDEX IF NOT EXISTS idx_fake_tokens_agent ON fake_tokens(agent_id);
CREATE INDEX IF NOT EXISTS idx_actuators_agent ON actuators(agent_id);
CREATE INDEX IF NOT EXISTS idx_actuators_status ON actuators(status);
CREATE INDEX IF NOT EXISTS idx_capabilities_actuator ON capabilities(actuator_id);
CREATE INDEX IF NOT EXISTS idx_command_queue_agent ON command_queue(agent_id);
CREATE INDEX IF NOT EXISTS idx_command_queue_actuator ON command_queue(actuator_id);
CREATE INDEX IF NOT EXISTS idx_command_queue_status ON command_queue(status);
