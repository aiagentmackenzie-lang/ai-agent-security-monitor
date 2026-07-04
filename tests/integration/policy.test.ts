import { describe, it, expect, beforeAll } from 'vitest';
import { getHarness } from './setup.js';

async function createAgent(h: Awaited<ReturnType<typeof getHarness>>, name = 'Policy Agent', type = 'openclaw') {
  const r = await h.fastify.inject({ method: 'POST', url: '/agents', payload: { name, type } });
  return r.json().agent.id as string;
}

async function createPolicy(h: Awaited<ReturnType<typeof getHarness>>, policy: Record<string, unknown>) {
  const r = await h.fastify.inject({ method: 'POST', url: '/policies', payload: policy });
  return r.json().policy;
}

describe('Policy evaluation', () => {
  let h: Awaited<ReturnType<typeof getHarness>>;

  beforeAll(async () => { h = await getHarness(); });

  it('denies when a deny rule matches', async () => {
    const agentId = await createAgent(h);
    await createPolicy(h, {
      name: 'Deny Delete',
      rules: [{ action: 'data:delete:*', resource: '*', effect: 'deny' }],
      agent_ids: ['*'], priority: 10,
    });
    const res = await h.fastify.inject({
      method: 'POST', url: '/policy/evaluate',
      payload: { agent_id: agentId, action: 'data:delete:users', resource: '/db/users' },
    });
    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.allowed).toBe(false);
    expect(body.reason).toContain('Deny Delete');
    expect(body.certificate_id).toMatch(/^cert_/);
  });

  it('default-deny (allowlist) blocks unmatched actions', async () => {
    const agentId = await createAgent(h);
    await createPolicy(h, {
      name: 'Allowlist',
      rules: [{ action: 'data:read:allowed', resource: '/allowed', effect: 'permit' }],
      agent_ids: ['*'], default_effect: 'deny', priority: 5,
    });
    const res = await h.fastify.inject({
      method: 'POST', url: '/policy/evaluate',
      payload: { agent_id: agentId, action: 'data:read:other', resource: '/other' },
    });
    expect(res.json().allowed).toBe(false);
    expect(res.json().reason).toContain('allowlist');
  });

  it('allows when permit rule matches in allowlist mode', async () => {
    const agentId = await createAgent(h);
    await createPolicy(h, {
      name: 'Allowlist2',
      rules: [{ action: 'data:read:allowed', resource: '/allowed', effect: 'permit' }],
      agent_ids: ['*'], default_effect: 'deny', priority: 5,
    });
    const res = await h.fastify.inject({
      method: 'POST', url: '/policy/evaluate',
      payload: { agent_id: agentId, action: 'data:read:allowed', resource: '/allowed' },
    });
    expect(res.json().allowed).toBe(true);
  });

  it('default-allows when no policy matches and no allowlist', async () => {
    const agentId = await createAgent(h);
    const res = await h.fastify.inject({
      method: 'POST', url: '/policy/evaluate',
      payload: { agent_id: agentId, action: 'noop', resource: 'noop' },
    });
    expect(res.json().allowed).toBe(true);
  });

  it('denies for a quarantined agent regardless of policy', async () => {
    const agentId = await createAgent(h);
    await createPolicy(h, {
      name: 'Permit All',
      rules: [{ action: '*', resource: '*', effect: 'permit' }],
      agent_ids: ['*'], priority: 1,
    });
    await h.fastify.inject({ method: 'POST', url: `/agents/${agentId}/quarantine` });
    const res = await h.fastify.inject({
      method: 'POST', url: '/policy/evaluate',
      payload: { agent_id: agentId, action: 'anything', resource: 'anything' },
    });
    expect(res.json().allowed).toBe(false);
    expect(res.json().reason).toContain('quarantined');
  });

  it('evaluates conditions — skips rule when condition not met', async () => {
    const agentId = await createAgent(h);
    await createPolicy(h, {
      name: 'Conditional Permit',
      rules: [{
        action: 'data:read:*', resource: '/secret', effect: 'permit',
        conditions: { data_classification: 'confidential' },
      }],
      agent_ids: ['*'], default_effect: 'deny', priority: 3,
    });
    // Without matching condition → allowlist default-deny
    const r1 = await h.fastify.inject({
      method: 'POST', url: '/policy/evaluate',
      payload: { agent_id: agentId, action: 'data:read:secret', resource: '/secret' },
    });
    expect(r1.json().allowed).toBe(false);
    // With matching condition → permit
    const r2 = await h.fastify.inject({
      method: 'POST', url: '/policy/evaluate',
      payload: {
        agent_id: agentId, action: 'data:read:secret', resource: '/secret',
        context: { data_classification: 'confidential' },
      },
    });
    expect(r2.json().allowed).toBe(true);
  });
});