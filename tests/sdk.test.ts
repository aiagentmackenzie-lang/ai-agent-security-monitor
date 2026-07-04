import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { PostgreSqlContainer } from '@testcontainers/postgresql';
import type { StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { Pool } from 'pg';
import { initDb } from '../src/db/init.js';
import { buildServer } from '../src/api/server.js';
import { loadTestConfig } from '../src/config.js';
import { createAgentClient, register, gate, log } from '../sdk/src/index.js';
import type { FastifyInstance } from 'fastify';

let container: StartedPostgreSqlContainer;
let pool: Pool;
let fastify: FastifyInstance;
let baseUrl: string;

beforeAll(async () => {
  container = await new PostgreSqlContainer('postgres:16-alpine')
    .withDatabase('ai_agent_security').withUsername('test').withPassword('test').start();
  const cs = `postgresql://${container.getUsername()}:${container.getPassword()}@${container.getHost()}:${container.getMappedPort(5432)}/${container.getDatabase()}`;
  pool = new Pool({ connectionString: cs });
  await initDb(cs);
  const config = loadTestConfig(cs, { devMode: true });
  const built = await buildServer({ config, pool, skipRateLimit: true });
  fastify = built.fastify;
  await fastify.listen({ port: 0, host: '127.0.0.1' });
  const a = fastify.server.address();
  const port = typeof a === 'object' && a ? a.port : 8000;
  baseUrl = `http://127.0.0.1:${port}`;
}, 120_000);

afterAll(async () => {
  if (fastify) await fastify.close();
  if (pool) await pool.end();
  if (container) await container.stop();
}, 60_000);

describe('Node SDK (camelCase mapping)', () => {
  it('register → gate → log round-trip via the client', async () => {
    const client = createAgentClient({ baseUrl });
    const { id } = await client.register({ name: 'SDK Agent', type: 'openclaw', owner: 'raphael' });
    expect(id).toBeTruthy();

    const decision = await client.gate({
      agentId: id, action: 'data:read:safe', resource: '/safe',
      context: { user: 'r', sessionId: 's1', dataClassification: 'public' },
    });
    expect(decision.allowed).toBe(true);
    expect(decision.agentId).toBe(id);
    expect(decision.certificateId).toMatch(/^cert_/);

    const ev = await client.log({
      agentId: id, eventType: 'tool_call', action: 'a', resource: 'r', result: 'success',
    });
    expect(ev.id).toBeTruthy();
  });

  it('convenience functions (register/gate/log) work without a client', async () => {
    const { id } = await register({ name: 'SDK Convenience', type: 'custom' }, { baseUrl });
    const d = await gate({ agentId: id, action: 'x', resource: 'y' }, { baseUrl });
    expect(d.allowed).toBe(true);
    const e = await log({ agentId: id, eventType: 'e', result: 'success' }, { baseUrl });
    expect(e.id).toBeTruthy();
  });

  it('hashes an apiKey on register (SHA-256 hex)', async () => {
    const client = createAgentClient({ baseUrl });
    const { id } = await client.register({ name: 'Keyed Agent', type: 'custom', apiKey: 'sk-test-123' });
    expect(id).toBeTruthy();
    // Verify the stored hash matches SHA-256 of the key
    const row = await pool.query('SELECT api_key_hash FROM agents WHERE id = $1', [id]);
    const expected = require('crypto').createHash('sha256').update('sk-test-123').digest('hex');
    expect(row.rows[0].api_key_hash).toBe(expected);
  });
});