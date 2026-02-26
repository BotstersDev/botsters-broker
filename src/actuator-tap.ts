import { EventEmitter } from 'node:events';

export interface ActuatorEvent {
  actuatorId: string;
  actuatorName: string;
  timestamp: string;
  type: 'command' | 'result' | 'connect' | 'disconnect' | 'error';
  data?: string | null;
  commandId?: string | null;
  action?: string | null;
  status?: string | null;
  durationMs?: number;
}

class ActuatorTap extends EventEmitter {
  publish(event: ActuatorEvent): void {
    this.emit('actuator', event);
    this.emit(`actuator:${event.actuatorId}`, event);
  }

  subscribe(actuatorId: string, callback: (event: ActuatorEvent) => void): () => void {
    const eventName = `actuator:${actuatorId}`;
    this.on(eventName, callback);
    return () => this.off(eventName, callback);
  }
}

export const actuatorTap = new ActuatorTap();
