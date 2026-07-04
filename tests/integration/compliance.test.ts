import { describe, it, expect, beforeAll } from 'vitest';
import { getHarness } from './setup.js';

async function createAgent(h: Awaited<ReturnType<typeof getHarness>>) {
  const r = await h.fastify.inject({ method: 'POST', url: '/agents', payload: { name: 'Comp Agent', type: 'langchain' } });
  return r.json().agent.id as string;
}

describe('Compliance mapping', () => {
  let h: Awaited<ReturnType<typeof getHarness>>;

  beforeAll(async () => { h = await getHarness(); });

  it('maps financial data access to FINRA with pending status', async () => {
    const agentId = await createAgent(h);
    await h.fastify.inject({
      method: 'POST', url: `/agents/${agentId}/events`,
      payload: {
        agent_id: agentId, event_type: 'data_access',
        action: 'data:read:transactions', resource: '/api/finance/transactions',
        result: 'success', details: { data_type: 'financial_data' },
      },
    });
    const res = await h.fastify.inject({ method: 'GET', url: `/compliance/${agentId}/finra` });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.evidence_count).toBeGreaterThan(0);
    expect(body.gaps).toContain('FINRA-4511');
    expect(body.compliant).toBe(false);
  });

  it('maps PII access to GDPR', async () => {
    const agentId = await createAgent(h);
    await h.fastify.inject({
      method: 'POST', url: `/agents/${agentId}/events`,
      payload: {
        agent_id: agentId, event_type: 'data_access',
        action: 'classify:pii', resource: '/api/hr/employees',
        result: 'success', details: { data_type: 'pii' },
      },
    });
    const res = await h.fastify.inject({ method: 'GET', url: `/compliance/${agentId}/gdpr` });
    expect(res.json().gaps).toContain('ART-22');
  });

  it('rejects invalid regulation with 400', async () => {
    const agentId = await createAgent(h);
    const res = await h.fastify.inject({ method: 'GET', url: `/compliance/${agentId}/not-a-regulation` });
    expect(res.statusCode).toBe(400);
  });

  it('generates a full compliance report across all regulations', async () => {
    const agentId = await createAgent(h);
    await h.fastify.inject({
      method: 'POST', url: `/agents/${agentId}/events`,
      payload: {
        agent_id: agentId, event_type: 'tool_call',
        action: 'data:read:pii', resource: '/x',
        result: 'success', details: { data_type: 'pii' },
      },
    });
    const res = await h.fastify.inject({ method: 'GET', url: `/compliance/reports/${agentId}` });
    expect(res.statusCode).toBe(200);
    const report = res.json().report;
    expect(report.compliance).toHaveProperty('gdpr');
    expect(report.compliance).toHaveProperty('ai_act');
  });
});