/**
 * Command Router — routes commands from brains to actuators
 */

import type Database from 'better-sqlite3';
import type { WsHub } from './ws-hub.js';
import * as db from './db.js';
import { decrypt } from './crypto.js';
import type { CommandRequest, CommandResult, CredentialRequest } from './protocol.js';
import { serialize, makeError } from './protocol.js';
import { actuatorTap } from './actuator-tap.js';

export class CommandRouter {
  private pendingResults = new Map<string, { resolve: (result: any) => void; timer: ReturnType<typeof setTimeout> }>();

  private deriveAction(capability: string, payload: unknown): string {
    if (payload && typeof payload === 'object' && 'action' in payload && typeof (payload as { action?: unknown }).action === 'string') {
      return (payload as { action: string }).action;
    }
    return capability;
  }

  private publishActuatorError(actuatorId: string | null | undefined, commandId: string | undefined, data: string): void {
    if (!actuatorId) return;
    const actuator = db.getActuatorById(this.database, actuatorId);
    if (!actuator) return;
    actuatorTap.publish({
      actuatorId,
      actuatorName: actuator.name,
      timestamp: new Date().toISOString(),
      type: 'error',
      commandId,
      data,
    });
  }

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
    const action = this.deriveAction(msg.capability, msg.payload);

    // Safe mode check — block all commands when global or per-agent safe mode is active
    if (db.getGlobalSafe(this.database) || db.getAgentSafe(this.database, agentId)) {
      const err = 'Command blocked: safe mode is active';
      if (brainConn) brainConn.ws.send(serialize(makeError('safe_mode', err, msg.id)));
      db.logAudit(this.database, accountId, agentId, 'command.blocked.safe_mode', 'command', 'blocked');
      return { commandId: null, error: err };
    }

    // Resolve actuator through the selection chain
    const actuator = db.resolveActuatorForAgent(this.database, agentId, msg.actuator_id || undefined);

    // Null behavior: no valid actuator resolved
    if (!actuator) {
      if (brainConn) {
        brainConn.ws.send(serialize({
          type: 'result_delivery', id: msg.id, status: 'completed', result: null,
        }));
      }
      if (msg.actuator_id) {
        this.publishActuatorError(msg.actuator_id, msg.id, 'No valid actuator resolved');
      }
      return { commandId: null };
    }

    // Verify the actuator has the requested capability
    const caps = db.listCapabilities(this.database, actuator.id);
    if (!caps.some(c => c.capability === msg.capability)) {
      const err = `Actuator ${actuator.id} lacks capability: ${msg.capability}. Available: ${caps.map(c => c.capability).join(', ') || 'none'}`;
      if (brainConn) brainConn.ws.send(serialize(makeError('no_capability', err, msg.id)));
      this.publishActuatorError(actuator.id, msg.id, err);
      return { commandId: null, error: err };
    }

    // Create command record
    const cmd = db.createCommand(this.database, agentId, actuator.id, msg.capability, JSON.stringify(msg.payload), msg.ttl_seconds ?? 300);

    // Try to deliver
    const actuatorConn = this.hub.getActuatorConnection(agentId, actuator.id);
    if (actuatorConn) {
      actuatorConn.ws.send(serialize({ type: 'command_delivery', id: cmd.id, capability: msg.capability, payload: msg.payload }));
      db.updateCommandStatus(this.database, cmd.id, 'delivered');
      actuatorTap.publish({
        actuatorId: actuator.id,
        actuatorName: actuator.name,
        timestamp: new Date().toISOString(),
        type: 'command',
        commandId: cmd.id,
        action,
      });
    } else {
      // Actuator registered but not currently connected — command stays pending
      if (brainConn) {
        brainConn.ws.send(serialize({
          type: 'result_delivery', id: cmd.id, status: 'completed',
          result: { queued: true, command_id: cmd.id, reason: 'Actuator offline, command queued for delivery' },
        }));
      }
      this.publishActuatorError(actuator.id, cmd.id, 'Actuator offline, command queued for delivery');
      return { commandId: cmd.id, error: 'Actuator offline, command queued' };
    }

    return { commandId: cmd.id };
  }

  /**
   * Handle a command result from an actuator
   */
  handleCommandResult(actuatorId: string, msg: CommandResult): void {
    const cmd = db.getCommandById(this.database, msg.id);
    if (!cmd || cmd.actuator_id !== actuatorId) return;

    db.updateCommandStatus(this.database, msg.id, msg.status, JSON.stringify(msg.result));
    const actuator = db.getActuatorById(this.database, actuatorId);
    let durationMs: number | undefined = undefined;
    const startedAt = Date.parse(cmd.created_at);
    if (!Number.isNaN(startedAt)) durationMs = Math.max(0, Date.now() - startedAt);
    actuatorTap.publish({
      actuatorId,
      actuatorName: actuator?.name || actuatorId,
      timestamp: new Date().toISOString(),
      type: 'result',
      commandId: msg.id,
      status: msg.status === 'completed' ? 'ok' : 'error',
      durationMs,
    });

    // Resolve any pending REST sync request
    const pending = this.pendingResults.get(msg.id);
    if (pending) {
      clearTimeout(pending.timer);
      this.pendingResults.delete(msg.id);
      pending.resolve({ status: msg.status, result: msg.result });
    }

    // Route result to brain via WS
    const brainConn = this.hub.getBrainConnection(cmd.agent_id);
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
        const timedOutCmd = db.getCommandById(this.database, commandId);
        if (timedOutCmd) {
          this.publishActuatorError(timedOutCmd.actuator_id, commandId, 'Command timed out waiting for result');
        }
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
    const actuator = db.getActuatorById(this.database, actuatorId);

    const pending = db.getPendingCommands(this.database, actuatorId);
    for (const cmd of pending) {
      // Only deliver commands explicitly assigned to this actuator
      if (cmd.actuator_id !== actuatorId) continue;
      const payload = JSON.parse(cmd.payload);
      actuatorConn.ws.send(serialize({ type: 'command_delivery', id: cmd.id, capability: cmd.capability, payload }));
      db.updateCommandStatus(this.database, cmd.id, 'delivered');
      actuatorTap.publish({
        actuatorId,
        actuatorName: actuator?.name || actuatorId,
        timestamp: new Date().toISOString(),
        type: 'command',
        commandId: cmd.id,
        action: this.deriveAction(cmd.capability, payload),
      });
    }
  }
}
