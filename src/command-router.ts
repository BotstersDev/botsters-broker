/**
 * Command Router — routes commands from brains to actuators
 */

import type Database from 'better-sqlite3';
import type { WsHub } from './ws-hub.js';
import * as db from './db.js';
import { isNullActuator } from './db.js';
import { decrypt } from './crypto.js';
import type { CommandRequest, CommandResult, CredentialRequest } from './protocol.js';
import { serialize, makeError } from './protocol.js';

export class CommandRouter {
  private pendingResults = new Map<string, { resolve: (result: any) => void; timer: ReturnType<typeof setTimeout> }>();

  constructor(
    private database: Database.Database,
    private hub: WsHub,
    private masterKey: string,
  ) {}

  /**
   * Handle a command request from a brain.
   * 
   * actuator_id is REQUIRED. No wildcard routing, no capability-based guessing.
   * The agent must know which actuator it's targeting. If it doesn't know,
   * it should query GET /v1/actuators first and pick one.
   */
  handleCommandRequest(agentId: string, accountId: string, msg: CommandRequest): { commandId: string | null; error?: string } {
    const brainConn = this.hub.getBrainConnection(agentId);

    // actuator_id is required — no implicit routing
    if (!msg.actuator_id || msg.actuator_id === '*') {
      const err = 'actuator_id is required. Query GET /v1/actuators to discover available actuators.';
      if (brainConn) brainConn.ws.send(serialize(makeError('actuator_required', err, msg.id)));
      return { commandId: null, error: err };
    }

    const actuatorId = msg.actuator_id;

    // Null actuator: immediately complete with empty success
    if (isNullActuator(actuatorId)) {
      const cmd = db.createCommand(this.database, agentId, actuatorId, msg.capability, JSON.stringify(msg.payload), 0);
      db.updateCommandStatus(this.database, cmd.id, 'completed', JSON.stringify({ stdout: '', stderr: '', exitCode: 0, null_actuator: true }));
      if (brainConn) {
        brainConn.ws.send(serialize({
          type: 'result_delivery', id: cmd.id, status: 'completed',
          result: { stdout: '', stderr: '', exitCode: 0, null_actuator: true },
        }));
      }
      return { commandId: cmd.id };
    }

    // Look up the actuator
    const actuator = db.getActuatorById(this.database, actuatorId);
    if (!actuator) {
      const err = `Actuator ${actuatorId} not found`;
      if (brainConn) brainConn.ws.send(serialize(makeError('not_found', err, msg.id)));
      return { commandId: null, error: err };
    }

    // Verify the actuator belongs to this agent
    if (actuator.agent_id !== agentId) {
      const err = 'Actuator does not belong to this agent';
      if (brainConn) brainConn.ws.send(serialize(makeError('forbidden', err, msg.id)));
      return { commandId: null, error: err };
    }

    // Verify the actuator has the requested capability
    const caps = db.listCapabilities(this.database, actuatorId);
    if (!caps.some(c => c.capability === msg.capability)) {
      const err = `Actuator ${actuatorId} lacks capability: ${msg.capability}. Available: ${caps.map(c => c.capability).join(', ') || 'none'}`;
      if (brainConn) brainConn.ws.send(serialize(makeError('no_capability', err, msg.id)));
      return { commandId: null, error: err };
    }

    // Create command record
    const cmd = db.createCommand(this.database, agentId, actuatorId, msg.capability, JSON.stringify(msg.payload), msg.ttl_seconds ?? 300);

    // Try to deliver
    const actuatorConn = this.hub.getActuatorConnection(agentId, actuatorId);
    if (actuatorConn) {
      actuatorConn.ws.send(serialize({ type: 'command_delivery', id: cmd.id, capability: msg.capability, payload: msg.payload }));
      db.updateCommandStatus(this.database, cmd.id, 'delivered');
    } else {
      // Actuator registered but not currently connected — command stays pending
      if (brainConn) {
        brainConn.ws.send(serialize({
          type: 'result_delivery', id: cmd.id, status: 'completed',
          result: { queued: true, command_id: cmd.id, reason: 'Actuator offline, command queued for delivery' },
        }));
      }
      return { commandId: cmd.id, error: 'Actuator offline, command queued' };
    }

    return { commandId: cmd.id };
  }

  /**
   * Handle a command result from an actuator
   */
  handleCommandResult(agentId: string, msg: CommandResult): void {
    const cmd = db.getCommandById(this.database, msg.id);
    if (!cmd || cmd.agent_id !== agentId) return;

    db.updateCommandStatus(this.database, msg.id, msg.status, JSON.stringify(msg.result));

    // Resolve any pending REST sync request
    const pending = this.pendingResults.get(msg.id);
    if (pending) {
      clearTimeout(pending.timer);
      this.pendingResults.delete(msg.id);
      pending.resolve({ status: msg.status, result: msg.result });
    }

    // Route result to brain via WS
    const brainConn = this.hub.getBrainConnection(agentId);
    if (brainConn) {
      brainConn.ws.send(serialize({ type: 'result_delivery', id: msg.id, status: msg.status, result: msg.result }));
    }
  }

  /**
   * Wait for a command result synchronously (for REST callers without WS brain connection).
   * Returns the result or null on timeout.
   */
  waitForResult(commandId: string, timeoutMs: number = 30000): Promise<{ status: string; result: any } | null> {
    return new Promise((resolve) => {
      // Check if already completed
      const cmd = db.getCommandById(this.database, commandId);
      if (cmd && (cmd.status === 'completed' || cmd.status === 'failed')) {
        resolve({ status: cmd.status, result: cmd.result ? JSON.parse(cmd.result) : null });
        return;
      }

      const timer = setTimeout(() => {
        this.pendingResults.delete(commandId);
        resolve(null);
      }, timeoutMs);

      this.pendingResults.set(commandId, { resolve, timer });
    });
  }

  /**
   * Handle a credential request from an agent (brain or actuator)
   */
  handleCredentialRequest(agentId: string, accountId: string, msg: CredentialRequest, ws: import('ws').WebSocket): void {
    const secret = db.getSecret(this.database, accountId, msg.secret_name, agentId);
    if (!secret) {
      ws.send(serialize({ type: 'credential_response', request_id: msg.request_id, ok: false, error: 'Secret not found or access denied' }));
      return;
    }
    try {
      const value = decrypt(secret.encrypted_value, this.masterKey);
      ws.send(serialize({ type: 'credential_response', request_id: msg.request_id, ok: true, value }));
      db.logAudit(this.database, accountId, agentId, 'credential.ws', msg.secret_name, 'success');
    } catch {
      ws.send(serialize({ type: 'credential_response', request_id: msg.request_id, ok: false, error: 'Decryption failed' }));
    }
  }

  /**
   * Deliver queued commands to a newly-connected actuator.
   * Only delivers commands explicitly targeted at this actuator (no wildcard pickup).
   */
  deliverQueuedCommands(agentId: string, actuatorId: string): void {
    const actuatorConn = this.hub.getActuatorConnection(agentId, actuatorId);
    if (!actuatorConn) return;

    const pending = db.getPendingCommands(this.database, actuatorId);
    for (const cmd of pending) {
      // Only deliver commands explicitly assigned to this actuator
      if (cmd.actuator_id !== actuatorId) continue;
      actuatorConn.ws.send(serialize({ type: 'command_delivery', id: cmd.id, capability: cmd.capability, payload: JSON.parse(cmd.payload) }));
      db.updateCommandStatus(this.database, cmd.id, 'delivered');
    }
  }
}
