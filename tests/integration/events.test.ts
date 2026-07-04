import { describe, it, expect, beforeAll } from 'vitest';
import { getHarness } from './setup.js';

async function createAgent(h: Awaited<ReturnType<typeof getHarness>>) {
  const r = await h.fastify.inject({ method: 'POST', url: '/agents', payload: { name: 'Event Agent', type: 'openclaw' } });
  return r.json().agent.id as string;
}

async function logEvent(h: Awaited<ReturnType<typeof getHarness>>, agentId: string, payload: Record<string, unknown>) {
  return h.fastify.inject({
    method: 'POST', url: `/agents/${agentId}/events`,
    payload: { agent_id: agentId, ...payload },
  });
}

describe('Event logging: hash chain + redaction', () => {
  let h: Awaited<ReturnType<typeof getHarness>>;

  beforeAll(async () => { h = await getHarness(); });

  it('chains event hashes and verifies the chain', async () => {
    const agentId = await createAgent(h);
    for (let i = 0; i < 3; i++) {
      await logEvent(h, agentId, {
        event_type: 'tool_call', action: `data:read:${i}`,
        resource: `/r/${i}`, result: 'success', details: { i },
      });
    }
    const exportRes = await h.fastify.inject({ method: 'GET', url: `/compliance/export/${agentId}` });
    expect(exportRes.statusCode).toBe(200);
    expect(exportRes.json().export.hash_chain.verified).toBe(true);
    expect(exportRes.json().export.hash_chain.events.length).toBe(3);
  });

  it('redacts AWS keys in event details and raises a critical alert', async () => {
    const agentId = await createAgent(h);
    const res = await logEvent(h, agentId, {
      event_type: 'tool_call', action: 'tool:config', resource: '/config',
      result: 'success',
      details: { env: 'AKIAIOSFODNN7EXAMPLE my key' },
    });
    expect(res.statusCode).toBe(200);

    const events = await h.fastify.inject({ method: 'GET', url: `/agents/${agentId}/events` });
    const stored = events.json().events[0];
    expect(JSON.stringify(stored.details)).not.toContain('AKIAIOSFODNN7EXAMPLE');
    expect(JSON.stringify(stored.details)).toContain('[AWS_ACCESS_KEY]');

    const alerts = await h.fastify.inject({ method: 'GET', url: '/alerts?acknowledged=false' });
    const sensitiveAlert = alerts.json().alerts.find((a: { type: string }) => a.type === 'sensitive_data_detected');
    expect(sensitiveAlert).toBeDefined();
    expect(sensitiveAlert.severity).toBe('critical');
  });

  it('returns 404 when logging events for a non-existent agent', async () => {
    const res = await logEvent(h, '00000000-0000-0000-0000-000000000000', {
      event_type: 'tool_call', result: 'success',
    });
    expect(res.statusCode).toBe(404);
  });

  it('detects a broken chain after direct tampering', async () => {
    const agentId = await createAgent(h);
    await logEvent(h, agentId, { event_type: 'e1', action: 'a1', resource: 'r1', result: 'success', details: {} });
    await logEvent(h, agentId, { event_type: 'e2', action: 'a2', resource: 'r2', result: 'success', details: {} });

    // Tamper: change the previous_hash of the second event
    await h.pool.query(
      `UPDATE agent_events SET previous_hash = 'deadbeef' WHERE agent_id = $1 AND event_type = 'e2'`,
      [agentId]
    );
    const exportRes = await h.fastify.inject({ method: 'GET', url: `/compliance/export/${agentId}` });
    expect(exportRes.json().export.hash_chain.verified).toBe(false);
  });
});