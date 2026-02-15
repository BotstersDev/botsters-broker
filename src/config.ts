/**
 * Configuration loaded from environment variables
 */

export interface BrokerConfig {
  port: number;
  dbPath: string;
  masterKey: string;
  wsHeartbeatMs: number;
  commandTtlMs: number;
}

export function loadConfig(): BrokerConfig {
  const masterKey = process.env.MASTER_KEY;
  if (!masterKey) {
    console.error('FATAL: MASTER_KEY environment variable is required');
    process.exit(1);
  }

  return {
    port: parseInt(process.env.HTTP_PORT || '8787', 10),
    dbPath: process.env.DB_PATH || './data/broker.db',
    masterKey,
    wsHeartbeatMs: parseInt(process.env.WS_HEARTBEAT_MS || '30000', 10),
    commandTtlMs: parseInt(process.env.COMMAND_TTL_MS || '300000', 10),
  };
}
