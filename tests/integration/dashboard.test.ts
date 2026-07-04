import { describe, it, expect, beforeAll } from 'vitest';
import { getHarness } from './setup.js';

async function seedData(h: Awaited<ReturnType<typeof getHarness>>) {
  const a1 = await h.fastify.inject({ method: 'POST', url: '/agents', payload: { name: 'D1', type: 'openclaw' } });
  const a2 = await h.fastify.inject({ method: 'POST', url: '/agents', payload: { name: 'D2', type: 'custom' } });
  await h.fastify.inject({ method: 'POST', url: `/agents/${a2.json().agent.id}/quarantine` });
  await h.fastify.inject({
    method: 'POST', url: `/agents/${a1.json().agent.id}/events`,
    payload: { agent_id: a1.json().agent.id, event_type: 'tool_call', action: 'data:read:x', resource: '/x', result: 'success', details: {} },
  });
  await h.fastify.inject({
    method: 'POST', url: `/agents/${a1.json().agent.id}/events`,
    payload: { agent_id: a1.json().agent.id, event_type: 'tool_call', action: 'data:delete:y', resource: '/y', result: 'denied', details: {} },
  });
}

describe('Dashboard', () => {
  let h: Awaited<ReturnType<typeof getHarness>>;

  beforeAll(async () => { h = await getHarness(); });

  it('summary returns correct counts', async () => {
    await seedData(h);
    const res = await h.fastify.inject({ method: 'GET', url: '/dashboard/summary' });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.agents.total).toBeGreaterThanOrEqual(2);
    expect(body.agents.quarantined).toBeGreaterThanOrEqual(1);
    expect(body.events.total).toBeGreaterThanOrEqual(2);
    expect(body.events.denied).toBeGreaterThanOrEqual(1);
  });

  it('events timeline returns events in a window', async () => {
    await seedData(h);
    const res = await h.fastify.inject({ method: 'GET', url: '/dashboard/events/timeline?hours=24' });
    expect(res.statusCode).toBe(200);
    expect(res.json().count).toBeGreaterThanOrEqual(1);
  });

  it('rejects invalid hours param with 400', async () => {
    const res = await h.fastify.inject({ method: 'GET', url: '/dashboard/events/timeline?hours=-1' });
    expect(res.statusCode).toBe(400);
  });

  it('compliance summary returns by-regulation breakdown', async () => {
    await seedData(h);
    const res = await h.fastify.inject({ method: 'GET', url: '/dashboard/compliance/summary' });
    expect(res.statusCode).toBe(200);
    expect(Array.isArray(res.json().by_regulation)).toBe(true);
    expect(res.json().overall).toHaveProperty('compliance_rate');
  });
});