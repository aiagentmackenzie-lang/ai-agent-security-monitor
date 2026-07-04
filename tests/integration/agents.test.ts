import { describe, it, expect, beforeAll } from 'vitest';
import { getHarness } from './setup.js';

describe('Agents CRUD', () => {
  let h: Awaited<ReturnType<typeof getHarness>>;

  beforeAll(async () => {
    h = await getHarness();
  });

  it('creates and retrieves an agent', async () => {
    const create = await h.fastify.inject({
      method: 'POST',
      url: '/agents',
      payload: { name: 'Test Agent', type: 'openclaw', owner: 'raphael' },
    });
    expect(create.statusCode).toBe(200);
    const created = create.json().agent;
    expect(created.name).toBe('Test Agent');
    expect(created.type).toBe('openclaw');
    expect(created.active).toBe(true);
    expect(created.quarantined).toBe(false);

    const get = await h.fastify.inject({ method: 'GET', url: `/agents/${created.id}` });
    expect(get.statusCode).toBe(200);
    expect(get.json().agent.id).toBe(created.id);
  });

  it('returns 404 for missing agent', async () => {
    const res = await h.fastify.inject({
      method: 'GET',
      url: '/agents/00000000-0000-0000-0000-000000000000',
    });
    expect(res.statusCode).toBe(404);
    expect(res.json().error).toBe('Agent not found');
  });

  it('rejects invalid agent type with 400', async () => {
    const res = await h.fastify.inject({
      method: 'POST',
      url: '/agents',
      payload: { name: 'Bad', type: 'not-a-real-type' },
    });
    expect(res.statusCode).toBe(400);
    const body = res.json();
    expect(body.error).toBe('Validation failed');
    expect(Array.isArray(body.details)).toBe(true);
  });

  it('patches an agent', async () => {
    const create = await h.fastify.inject({
      method: 'POST', url: '/agents',
      payload: { name: 'Patch Me', type: 'custom' },
    });
    const id = create.json().agent.id;
    const patch = await h.fastify.inject({
      method: 'PATCH', url: `/agents/${id}`,
      payload: { owner: 'new-owner' },
    });
    expect(patch.statusCode).toBe(200);
    expect(patch.json().agent.owner).toBe('new-owner');
  });

  it('soft-deletes an agent and returns 404 for a never-existing id', async () => {
    const create = await h.fastify.inject({
      method: 'POST', url: '/agents',
      payload: { name: 'Delete Me', type: 'custom' },
    });
    const id = create.json().agent.id;
    const del = await h.fastify.inject({ method: 'DELETE', url: `/agents/${id}` });
    expect(del.statusCode).toBe(200);
    expect(del.json().success).toBe(true);
    // Soft delete is idempotent on the same row; a never-existing id returns 404
    const del2 = await h.fastify.inject({ method: 'DELETE', url: '/agents/00000000-0000-0000-0000-000000000000' });
    expect(del2.statusCode).toBe(404);
  });

  it('lists agents', async () => {
    await h.fastify.inject({
      method: 'POST', url: '/agents',
      payload: { name: 'List Me', type: 'custom' },
    });
    const list = await h.fastify.inject({ method: 'GET', url: '/agents' });
    expect(list.statusCode).toBe(200);
    expect(Array.isArray(list.json().agents)).toBe(true);
    expect(list.json().agents.length).toBeGreaterThanOrEqual(1);
  });
});