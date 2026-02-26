/**
 * WebSocket message protocol for brain ↔ broker ↔ actuator communication
 */

// ─── Message Types ─────────────────────────────────────────────────────────────

export interface CommandRequest {
  type: 'command_request';
  id: string;
  actuator_id?: string; // '*' or specific; omit for any
  capability: string;
  payload: unknown;
  ttl_seconds?: number;
}

export interface CommandDelivery {
  type: 'command_delivery';
  id: string;          // command id
  capability: string;
  payload: unknown;
}

export interface CommandResult {
  type: 'command_result';
  id: string;          // command id
  status: 'completed' | 'failed';
  result: unknown;
}

export interface ResultDelivery {
  type: 'result_delivery';
  id: string;
  status: 'completed' | 'failed';
  result: unknown;
}

export interface CredentialRequest {
  type: 'credential_request';
  request_id: string;
  secret_name: string;
}

export interface CredentialResponse {
  type: 'credential_response';
  request_id: string;
  ok: boolean;
  value?: string;
  error?: string;
}

export interface Ping {
  type: 'ping';
  ts: number;
}

export interface Pong {
  type: 'pong';
  ts: number;
}

export interface ActuatorOnline {
  type: 'actuator_online';
  actuator_id: string;
  name: string;
  capabilities: string[];
}

export interface ActuatorOffline {
  type: 'actuator_offline';
  actuator_id: string;
  reason?: string;
}

export interface WakeDelivery {
  type: 'wake';
  text: string;
  source: string;
  ts: string;
}

export interface ErrorMessage {
  type: 'error';
  code: string;
  message: string;
  ref_id?: string;  // related command/request id
}

export type BrokerMessage =
  | CommandRequest
  | CommandDelivery
  | CommandResult
  | ResultDelivery
  | CredentialRequest
  | CredentialResponse
  | Ping
  | Pong
  | ActuatorOnline
  | ActuatorOffline
  | WakeDelivery
  | ErrorMessage;

// ─── Helpers ───────────────────────────────────────────────────────────────────

export function serialize(msg: BrokerMessage): string {
  return JSON.stringify(msg);
}

export function deserialize(data: string): BrokerMessage | null {
  try {
    const msg = JSON.parse(data);
    if (!msg || typeof msg.type !== 'string') return null;
    return msg as BrokerMessage;
  } catch {
    return null;
  }
}

export function makeError(code: string, message: string, refId?: string): ErrorMessage {
  return { type: 'error', code, message, ref_id: refId };
}
