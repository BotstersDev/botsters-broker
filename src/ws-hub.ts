/**
 * WebSocket Hub — manages brain and actuator connections
 */

import type { IncomingMessage } from 'node:http';
import type { Duplex } from 'node:stream';
import { WebSocketServer, WebSocket } from 'ws';
import type Database from 'better-sqlite3';
import * as db from './db';
import { hashToken } from './crypto';
import { serialize, deserialize, makeError } from './protocol';
import type { CommandRouter } from './command-router';
import type { BrokerConfig } from './config';

export interface Connection {
  ws: WebSocket;
  agentId: string;
  accountId: string;
  role: 'brain' | 'actuator';
  actuatorId?: string;
  capabilities?: string[];
  connId: string;
  alive: boolean;
}

export class WsHub {
  private wss: WebSocketServer;
  private connections = new Map<string, Connection>();
  private agentBrains = new Map<string, string>(); // agentId → connId
  private agentActuators = new Map<string, Map<string, string>>(); // agentId → (actuatorId → connId)
  private heartbeatInterval: ReturnType<typeof setInterval> | null = null;
  private router!: CommandRouter;

  constructor(
    private database: Database.Database,
    private config: BrokerConfig,
  ) {
    this.wss = new WebSocketServer({ noServer: true });
  }

  setRouter(router: CommandRouter) {
    this.router = router;
  }

  start() {
    this.heartbeatInterval = setInterval(() => this.heartbeat(), this.config.wsHeartbeatMs);
  }

  stop() {
    if (this.heartbeatInterval) clearInterval(this.heartbeatInterval);
    for (const conn of this.connections.values()) {
      conn.ws.close(1001, 'Server shutting down');
    }
    this.wss.close();
  }

  /**
   * Handle HTTP upgrade request
   */
  handleUpgrade(request: IncomingMessage, socket: Duplex, head: Buffer) {
    const url = new URL(request.url || '/', `http://${request.headers.host || 'localhost'}`);
    const token = url.searchParams.get('token');
    const role = url.searchParams.get('role') as 'brain' | 'actuator' | null;
    const actuatorId = url.searchParams.get('actuator_id');

    if (!token || !role || !['brain', 'actuator'].includes(role)) {
      socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
      socket.destroy();
      return;
    }

    if (role === 'actuator' && !actuatorId) {
      socket.write('HTTP/1.1 400 Bad Request\r\n\r\n');
      socket.destroy();
      return;
    }

    // Authenticate
    const agent = db.getAgentByToken(this.database, token);
    if (!agent) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }

    // For actuator role, verify actuator exists and belongs to this agent
    if (role === 'actuator') {
      const actuator = db.getActuatorById(this.database, actuatorId!);
      if (!actuator || actuator.agent_id !== agent.id) {
        socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
        socket.destroy();
        return;
      }
    }

    this.wss.handleUpgrade(request, socket, head, (ws) => {
      this.onConnection(ws, agent.id, agent.account_id, role, actuatorId ?? undefined);
    });
  }

  private onConnection(ws: WebSocket, agentId: string, accountId: string, role: 'brain' | 'actuator', actuatorId?: string) {
    const connId = `${role}_${agentId}_${actuatorId || 'brain'}_${Date.now()}`;
    const capabilities = actuatorId ? db.listCapabilities(this.database, actuatorId).map(c => c.capability) : undefined;

    const conn: Connection = { ws, agentId, accountId, role, actuatorId, capabilities, connId, alive: true };
    this.connections.set(connId, conn);

    if (role === 'brain') {
      // Disconnect existing brain for this agent
      const existingId = this.agentBrains.get(agentId);
      if (existingId) {
        const existing = this.connections.get(existingId);
        if (existing) existing.ws.close(1008, 'Replaced by new connection');
      }
      this.agentBrains.set(agentId, connId);
    } else if (role === 'actuator' && actuatorId) {
      if (!this.agentActuators.has(agentId)) this.agentActuators.set(agentId, new Map());
      const existingId = this.agentActuators.get(agentId)!.get(actuatorId);
      if (existingId) {
        const existing = this.connections.get(existingId);
        if (existing) existing.ws.close(1008, 'Replaced by new connection');
      }
      this.agentActuators.get(agentId)!.set(actuatorId, connId);
      db.updateActuatorStatus(this.database, actuatorId, 'online');

      // Notify brain
      const brainConn = this.getBrainConnection(agentId);
      if (brainConn) {
        brainConn.ws.send(serialize({ type: 'actuator_online', actuator_id: actuatorId, name: '', capabilities: capabilities || [] }));
      }

      // Deliver queued commands
      if (this.router) this.router.deliverQueuedCommands(agentId, actuatorId);
    }

    db.updateAgentLastSeen(this.database, agentId);

    ws.on('message', (data) => {
      const msg = deserialize(data.toString());
      if (!msg) return;
      this.handleMessage(conn, msg);
    });

    ws.on('close', () => this.onDisconnect(connId));
    ws.on('error', () => this.onDisconnect(connId));
    ws.on('pong', () => { conn.alive = true; });
  }

  private handleMessage(conn: Connection, msg: any) {
    switch (msg.type) {
      case 'command_request':
        if (conn.role !== 'brain') return;
        this.router?.handleCommandRequest(conn.agentId, conn.accountId, msg);
        break;
      case 'command_result':
        if (conn.role !== 'actuator') return;
        this.router?.handleCommandResult(conn.agentId, msg);
        break;
      case 'credential_request':
        this.router?.handleCredentialRequest(conn.agentId, conn.accountId, msg, conn.ws);
        break;
      case 'ping':
        conn.ws.send(serialize({ type: 'pong', ts: msg.ts }));
        break;
      case 'pong':
        conn.alive = true;
        break;
    }
  }

  private onDisconnect(connId: string) {
    const conn = this.connections.get(connId);
    if (!conn) return;
    this.connections.delete(connId);

    if (conn.role === 'brain') {
      if (this.agentBrains.get(conn.agentId) === connId) {
        this.agentBrains.delete(conn.agentId);
      }
    } else if (conn.role === 'actuator' && conn.actuatorId) {
      const actuatorMap = this.agentActuators.get(conn.agentId);
      if (actuatorMap?.get(conn.actuatorId) === connId) {
        actuatorMap.delete(conn.actuatorId);
      }
      db.updateActuatorStatus(this.database, conn.actuatorId, 'offline');

      // Notify brain
      const brainConn = this.getBrainConnection(conn.agentId);
      if (brainConn) {
        brainConn.ws.send(serialize({ type: 'actuator_offline', actuator_id: conn.actuatorId, reason: 'disconnected' }));
      }
    }
  }

  private heartbeat() {
    for (const [connId, conn] of this.connections) {
      if (!conn.alive) {
        conn.ws.terminate();
        this.onDisconnect(connId);
        continue;
      }
      conn.alive = false;
      conn.ws.ping();
    }
    // Also expire stale commands
    db.expireStaleCommands(this.database);
  }

  // ─── Public accessors ──────────────────────────────────────────────────────

  getBrainConnection(agentId: string): Connection | null {
    const connId = this.agentBrains.get(agentId);
    return connId ? this.connections.get(connId) ?? null : null;
  }

  getActuatorConnection(agentId: string, actuatorId: string): Connection | null {
    const connId = this.agentActuators.get(agentId)?.get(actuatorId);
    return connId ? this.connections.get(connId) ?? null : null;
  }

  getActiveConnections(): Connection[] {
    return Array.from(this.connections.values());
  }

  getConnectionCount(): { brains: number; actuators: number } {
    let brains = 0, actuators = 0;
    for (const conn of this.connections.values()) {
      if (conn.role === 'brain') brains++;
      else actuators++;
    }
    return { brains, actuators };
  }
}
