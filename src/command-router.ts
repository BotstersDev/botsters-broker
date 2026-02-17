/**
 * Command Router — routes commands from brains to actuators
 */

import type Database from 'better-sqlite3';
import type { WsHub } from './ws-hub.js';
import * as db from './db.js';
import { decrypt } from './crypto.js';
import type { CommandRequest, CommandResult, CredentialRequest } from './protocol.js';
import { serialize, makeError } from './protocol.js';

export class CommandRouter {
  constructor(
    private database: Database.Database,
    private hub: WsHub,
    private masterKey: string,
  ) {}

  /**
   * Handle a command request from a brain
   */
  handleCommandRequest(agentId: string, accountId: string, msg: CommandRequest): void {
    const brainConn = this.hub.getBrainConnection(agentId);

    // Find target actuator
    let actuatorId = msg.actuator_id;
    let actuator;

    if (!actuatorId || actuatorId === '*') {
      // Find any online actuator with the capability
      actuator = db.findActuatorWithCapability(this.database, agentId, msg.capability, true);
      if (!actuator) {
        // Queue for later delivery
        const cmd = db.createCommand(this.database, agentId, null, msg.capability, JSON.stringify(msg.payload), msg.ttl_seconds ?? 300);
        if (brainConn) {
          brainConn.ws.send(serialize({ type: 'result_delivery', id: cmd.id, status: 'completed', result: { queued: true, command_id: cmd.id } }));
        }
        return;
      }
      actuatorId = actuator.id;
    } else {
      // Specific actuator
      actuator = db.getActuatorById(this.database, actuatorId);
      if (!actuator) {
        if (brainConn) brainConn.ws.send(serialize(makeError('not_found', `Actuator ${actuatorId} not found`, msg.id)));
        return;
      }
      // Verify ownership
      const agent = db.getAgentById(this.database, agentId);
      if (!agent || actuator.agent_id !== agentId) {
        if (brainConn) brainConn.ws.send(serialize(makeError('forbidden', 'Actuator does not belong to this agent', msg.id)));
        return;
      }
      // Check capability
      const caps = db.listCapabilities(this.database, actuatorId);
      if (!caps.some(c => c.capability === msg.capability)) {
        if (brainConn) brainConn.ws.send(serialize(makeError('no_capability', `Actuator lacks capability: ${msg.capability}`, msg.id)));
        return;
      }
    }

    // Create command record
    const cmd = db.createCommand(this.database, agentId, actuatorId!, msg.capability, JSON.stringify(msg.payload), msg.ttl_seconds ?? 300);

    // Try to deliver
    const actuatorConn = this.hub.getActuatorConnection(agentId, actuatorId!);
    if (actuatorConn) {
      actuatorConn.ws.send(serialize({ type: 'command_delivery', id: cmd.id, capability: msg.capability, payload: msg.payload }));
      db.updateCommandStatus(this.database, cmd.id, 'delivered');
    }
    // else: stays pending, will be delivered when actuator connects
  }

  /**
   * Handle a command result from an actuator
   */
  handleCommandResult(agentId: string, msg: CommandResult): void {
    const cmd = db.getCommandById(this.database, msg.id);
    if (!cmd || cmd.agent_id !== agentId) return;

    db.updateCommandStatus(this.database, msg.id, msg.status, JSON.stringify(msg.result));

    // Route result to brain
    const brainConn = this.hub.getBrainConnection(agentId);
    if (brainConn) {
      brainConn.ws.send(serialize({ type: 'result_delivery', id: msg.id, status: msg.status, result: msg.result }));
    }
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
   * Deliver queued commands to a newly-connected actuator
   */
  deliverQueuedCommands(agentId: string, actuatorId: string): void {
    const pending = db.getPendingCommands(this.database, actuatorId);
    const actuatorConn = this.hub.getActuatorConnection(agentId, actuatorId);
    if (!actuatorConn) return;

    // Also check for wildcard commands (actuator_id IS NULL) that match capabilities
    const caps = new Set(db.listCapabilities(this.database, actuatorId).map(c => c.capability));
    const wildcardPending = db.getPendingCommands(this.database, actuatorId);

    for (const cmd of wildcardPending) {
      if (cmd.actuator_id === null && !caps.has(cmd.capability)) continue;
      actuatorConn.ws.send(serialize({ type: 'command_delivery', id: cmd.id, capability: cmd.capability, payload: JSON.parse(cmd.payload) }));
      db.updateCommandStatus(this.database, cmd.id, 'delivered');
      // Assign actuator
      if (cmd.actuator_id === null) {
        this.database.prepare('UPDATE command_queue SET actuator_id = ? WHERE id = ?').run(actuatorId, cmd.id);
      }
    }
  }
}
