import { Hono } from 'hono';
import type { Env, Actuator } from './types.js';
import * as db from './db.js';
import { serialize } from './protocol.js';
import type { WsHub } from './ws-hub.js';

function authenticateAdmin(c: any): boolean {
  const adminKey = c.req.header('X-Admin-Key');
  return !!adminKey && adminKey === c.env.masterKey;
}

function requireAdmin(c: any): Response | null {
  if (!authenticateAdmin(c)) {
    return c.json({ ok: false, error: 'Unauthorized: invalid or missing X-Admin-Key' }, 401);
  }
  return null;
}

export function createNotifyRoutes(hub: WsHub) {
  const notifyRoutes = new Hono<{ Bindings: Env }>();

  // POST /v1/notify/:agentName
  notifyRoutes.post('/notify/:agentName', async (c) => {
    const denied = requireAdmin(c);
    if (denied) return denied;

    const agentName = c.req.param('agentName');
    const agent = db.getAgentByName(c.env.db, agentName);
    if (!agent) {
      return c.json({ ok: false, error: 'agent_not_found' }, 404);
    }

    const body = await c.req.json<{ text?: string; source?: string }>();
    if (!body.text) {
      return c.json({ ok: false, error: 'text_required' }, 400);
    }

    const wakes = c.env.db.prepare(
      "SELECT * FROM actuators WHERE agent_id = ? AND type = 'brain' AND status = 'online' ORDER BY created_at DESC"
    ).all(agent.id) as Actuator[];

    const wakePayload = {
      type: 'wake' as const,
      text: body.text,
      source: body.source || 'unknown',
      ts: new Date().toISOString(),
    };

    for (const actuator of wakes) {
      const conn = hub.getActuatorConnection(agent.id, actuator.id, true);
      if (!conn) continue;
      conn.ws.send(serialize(wakePayload));
      return c.json({ ok: true });
    }

    hub.bufferWakeMessage(agent.id, wakePayload.text, wakePayload.source, wakePayload.ts);
    return c.json({ ok: false, error: 'no_ego_connection', buffered: true });
  });

  return notifyRoutes;
}
