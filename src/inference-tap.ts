import { EventEmitter } from 'node:events';

export interface InferenceEvent {
  agentId: string;
  agentName: string;
  provider: string;
  method: string;
  path: string;
  timestamp: string;
  type: 'request' | 'chunk' | 'complete' | 'error';
  data?: string | null;
  model?: string | null;
  tokensIn?: number;
  tokensOut?: number;
}

class InferenceTap extends EventEmitter {
  publish(event: InferenceEvent): void {
    this.emit('inference', event);
    this.emit(`inference:${event.agentId}`, event);
  }

  subscribe(agentId: string | null, callback: (event: InferenceEvent) => void): () => void {
    const eventName = agentId ? `inference:${agentId}` : 'inference';
    this.on(eventName, callback);
    return () => this.off(eventName, callback);
  }
}

export const inferenceTap = new InferenceTap();
