import { describe, it, expect, beforeAll } from 'vitest';
import { getHarness } from './setup.js';

async function createAgent(h: Awaited<ReturnType<typeof getHarness>>) {
  const r = await h.fastify.inject({ method: 'POST', url: '/agents', payload: { name: 'Quarantine Agent', type: 'custom' } });
  return r.json().agent.id as string;
}

describe('Quarantine and revoke', () => {
  let h: Awaited<ReturnType<typeof getHarness>>;

  beforeAll(async () => { h = await getHarness(); });

  it('quarantines an agent and creates a high alert', async () => {
    const agentId = await createAgent(h);
    const res = await h.fastify.inject({ method: 'POST', url: `/agents/${agentId}/quarantine` });
    expect(res.statusCode).toBe(200);
    expect(res.json().agent.quarantined).toBe(true);
    expect(res.json().alert.severity).toBe('high');
    expect(res.json().alert.type).toBe('agent_quarantined');
  });

  it('releases an agent from quarantine', async () => {
    const agentId = await createAgent(h);
    await h.fastify.inject({ method: 'POST', url: `/agents/${agentId}/quarantine` });
    const res = await h.fastify.inject({ method: 'POST', url: `/agents/${agentId}/unquarantine` });
    expect(res.json().agent.quarantined).toBe(false);
  });

  it('revokes an agent transactionally — appends revoked event + critical alert', async () => {
    const agentId = await createAgent(h);
    // Seed one prior event so the chain has a previous hash
    await h.fastify.inject({
      method: 'POST', url: `/agents/${agentId}/events`,
      payload: { agent_id: agentId, event_type: 'tool_call', action: 'a', resource: 'r', result: 'success', details: {} },
    });
    const res = await h.fastify.inject({ method: 'POST', url: `/agents/${agentId}/revoke` });
    expect(res.statusCode).toBe(200);
    expect(res.json().agent.active).toBe(false);
    expect(res.json().agent.quarantined).toBe(true);
    expect(res.json().alert.severity).toBe('critical');

    // The revoked event should be on the chain and chain still verified
    const exportRes = await h.fastify.inject({ method: 'GET', url: `/compliance/export/${agentId}` });
    const events = exportRes.json().export.events;
    expect(events.some((e: { event_type: string }) => e.event_type === 'revoked')).toBe(true);
    expect(exportRes.json().export.hash_chain.verified).toBe(true);
  });

  it('returns 404 when revoking a non-existent agent', async () => {
    const res = await h.fastify.inject({ method: 'POST', url: '/agents/00000000-0000-0000-0000-000000000000/revoke' });
    expect(res.statusCode).toBe(404);
  });
});