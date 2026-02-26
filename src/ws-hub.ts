/**
 * WebSocket Hub — manages brain and actuator connections
 */

import type { IncomingMessage } from 'node:http';
import type { Duplex } from 'node:stream';
import { WebSocketServer, WebSocket } from 'ws';
import type Database from 'better-sqlite3';
import * as db from './db.js';
import { serialize, deserialize } from './protocol.js';
import type { WakeDelivery } from './protocol.js';
import type { CommandRouter } from './command-router.js';
import type { BrokerConfig } from './config.js';
import { actuatorTap } from './actuator-tap.js';

export interface Connection {
  ws: WebSocket;
  agentId: string;
  accountId: string;
  role: 'brain' | 'actuator';
  actuatorId?: string;
  assignedAgentIds?: string[];
  capabilities?: string[];
  connId: string;
  alive: boolean;
}

export class WsHub {
  private wss: WebSocketServer;
  private connections = new Map<string, Connection>();
  private agentBrains = new Map<string, string>(); // agentId → connId
  private actuatorConnections = new Map<string, string>(); // actuatorId -> connId
  private wakeBuffer = new Map<string, WakeDelivery[]>(); // agentId -> buffered wake events
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

    // Authenticate — try agent token first, then actuator token
    let agentId: string;
    let accountId: string;
    let assignedAgentIds: string[] | undefined;

    const agent = db.getAgentByToken(this.database, token);
    if (agent) {
      agentId = agent.id;
      accountId = agent.account_id;

      // For actuator role with agent token, verify actuator is assigned to this agent.
      if (role === 'actuator') {
        if (!db.isActuatorAssignedToAgent(this.database, agent.id, actuatorId!)) {
          socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
          socket.destroy();
          return;
        }
        assignedAgentIds = db.getEnabledAgentIdsForActuator(this.database, actuatorId!);
      }
    } else if (role === 'actuator' && token.startsWith('seks_actuator_')) {
      // Try actuator-specific token
      const actuator = db.getActuatorByToken(this.database, token);
      if (!actuator || actuator.id !== actuatorId) {
        socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
        socket.destroy();
        return;
      }
      const ownerAgent = db.resolveAgentForActuator(this.database, actuator.id);
      if (!ownerAgent) {
        socket.write('HTTP/1.1 500 Internal Server Error\r\n\r\n');
        socket.destroy();
        return;
      }
      agentId = ownerAgent.id;
      accountId = ownerAgent.account_id;
      assignedAgentIds = db.getEnabledAgentIdsForActuator(this.database, actuator.id);
    } else {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }

    this.wss.handleUpgrade(request, socket, head, (ws) => {
      this.onConnection(ws, agentId, accountId, role, actuatorId ?? undefined, assignedAgentIds);
    });
  }

  private onConnection(ws: WebSocket, agentId: string, accountId: string, role: 'brain' | 'actuator', actuatorId?: string, assignedAgentIds?: string[]) {
    const connId = `${role}_${agentId}_${actuatorId || 'brain'}_${Date.now()}`;
    const capabilities = actuatorId ? db.listCapabilities(this.database, actuatorId).map(c => c.capability) : undefined;

    const conn: Connection = { ws, agentId, accountId, role, actuatorId, assignedAgentIds, capabilities, connId, alive: true };
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
      const existingId = this.actuatorConnections.get(actuatorId);
      if (existingId) {
        const existing = this.connections.get(existingId);
        if (existing) existing.ws.close(1008, 'Replaced by new connection');
      }
      this.actuatorConnections.set(actuatorId, connId);
      db.updateActuatorStatus(this.database, actuatorId, 'online');
      const actuator = db.getActuatorById(this.database, actuatorId);
      actuatorTap.publish({
        actuatorId,
        actuatorName: actuator?.name || actuatorId,
        timestamp: new Date().toISOString(),
        type: 'connect',
      });

      // Notify assigned brains
      const notifyAgents = assignedAgentIds || db.getEnabledAgentIdsForActuator(this.database, actuatorId);
      for (const assignedAgentId of notifyAgents) {
        const brainConn = this.getBrainConnection(assignedAgentId);
        if (brainConn) {
          brainConn.ws.send(serialize({ type: 'actuator_online', actuator_id: actuatorId, name: '', capabilities: capabilities || [] }));
        }
      }

      // Deliver queued commands
      if (this.router) {
        for (const assignedAgentId of notifyAgents) {
          this.router.deliverQueuedCommands(assignedAgentId, actuatorId);
        }
      }

      if (actuator?.type === 'brain') {
        const ownerAgent = db.getAgentById(this.database, agentId);
        console.log(`[ws-hub] Brain actuator connected: ${actuatorId} for agent ${ownerAgent?.name || agentId}`);
        for (const assignedAgentId of notifyAgents) {
          this.flushBufferedWakes(assignedAgentId, conn);
        }
      }
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
        if (!conn.actuatorId) return;
        this.router?.handleCommandResult(conn.actuatorId, msg);
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
      if (this.actuatorConnections.get(conn.actuatorId) === connId) {
        this.actuatorConnections.delete(conn.actuatorId);
      }
      db.updateActuatorStatus(this.database, conn.actuatorId, 'offline');
      const actuator = db.getActuatorById(this.database, conn.actuatorId);
      actuatorTap.publish({
        actuatorId: conn.actuatorId,
        actuatorName: actuator?.name || conn.actuatorId,
        timestamp: new Date().toISOString(),
        type: 'disconnect',
      });

      // Notify assigned brains
      const notifyAgents = conn.assignedAgentIds || db.getEnabledAgentIdsForActuator(this.database, conn.actuatorId);
      for (const assignedAgentId of notifyAgents) {
        const brainConn = this.getBrainConnection(assignedAgentId);
        if (brainConn) {
          brainConn.ws.send(serialize({ type: 'actuator_offline', actuator_id: conn.actuatorId, reason: 'disconnected' }));
        }
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

  getActuatorConnection(agentId: string, actuatorId: string, includeDisabledAssignments: boolean = false): Connection | null {
    if (!db.isActuatorAssignedToAgent(this.database, agentId, actuatorId, !includeDisabledAssignments)) return null;
    const connId = this.actuatorConnections.get(actuatorId);
    return connId ? this.connections.get(connId) ?? null : null;
  }

  bufferWakeMessage(agentId: string, text: string, source: string, ts?: string): WakeDelivery {
    const wake: WakeDelivery = {
      type: 'wake',
      text,
      source,
      ts: ts || new Date().toISOString(),
    };

    const existing = this.wakeBuffer.get(agentId) || [];
    existing.push(wake);
    while (existing.length > 5) {
      existing.shift();
    }
    this.wakeBuffer.set(agentId, existing);

    return wake;
  }

  flushBufferedWakes(agentId: string, conn: Connection): number {
    if (conn.role !== 'actuator') return 0;
    const buffered = this.wakeBuffer.get(agentId);
    if (!buffered || buffered.length === 0) return 0;

    for (const wake of buffered) {
      conn.ws.send(serialize(wake));
    }
    this.wakeBuffer.delete(agentId);
    return buffered.length;
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
