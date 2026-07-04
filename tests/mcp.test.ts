import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { PostgreSqlContainer } from '@testcontainers/postgresql';
import type { StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { Pool } from 'pg';
import { initDb } from '../src/db/init.js';
import { buildServer } from '../src/api/server.js';
import { loadTestConfig } from '../src/config.js';
import { MCP_TOOLS, handleToolCall, createApiCall } from '../src/mcp/server.js';
import type { FastifyInstance } from 'fastify';

let container: StartedPostgreSqlContainer;
let pool: Pool;
let fastify: FastifyInstance;
let baseUrl: string;
let apiCall: ReturnType<typeof createApiCall>;
let agentId: string;

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
  const address = fastify.server.address();
  const port = typeof address === 'object' && address ? address.port : 8000;
  baseUrl = `http://127.0.0.1:${port}`;
  apiCall = createApiCall(baseUrl, '');

  const r = await fastify.inject({ method: 'POST', url: '/agents', payload: { name: 'MCP Unit Agent', type: 'openclaw' } });
  agentId = r.json().agent.id;
  await fastify.inject({
    method: 'POST', url: '/policies',
    payload: { name: 'Deny X', rules: [{ action: 'tool:x', resource: '*', effect: 'deny' }], agent_ids: ['*'], priority: 10 },
  });
}, 120_000);

afterAll(async () => {
  if (fastify) await fastify.close();
  if (pool) await pool.end();
  if (container) await container.stop();
}, 60_000);

describe('MCP tool registry', () => {
  it('exposes exactly the 5 governance tools with required fields', () => {
    const names = MCP_TOOLS.map(t => t.name);
    expect(names).toEqual(['gate_action', 'evaluate_tool_call', 'register_agent', 'log_event', 'query_compliance']);
    for (const t of MCP_TOOLS) {
      expect(t.description.length).toBeGreaterThan(0);
      expect(t.inputSchema.type).toBe('object');
    }
  });
});

describe('MCP handleToolCall', () => {
  it('gate_action returns allowed + certificate', async () => {
    const r = await handleToolCall('gate_action', { agent_id: agentId, action: 'data:read:safe', resource: '/safe' }, apiCall);
    const text = JSON.parse(r.content[0].text);
    expect(text.allowed).toBe(true);
    expect(text.certificate_id).toMatch(/^cert_/);
    expect(r.isError).toBeUndefined();
  });

  it('evaluate_tool_call denies and logs a tool_denied event', async () => {
    const r = await handleToolCall('evaluate_tool_call', {
      agent_id: agentId, tool_name: 'x', action: 'tool:x', resource: '/r', tool_args: { a: 1 },
    }, apiCall);
    expect(r.isError).toBe(true);
    const text = JSON.parse(r.content[0].text);
    expect(text.status).toBe('denied');
    expect(text.event_id).toBeTruthy();
  });

  it('register_agent creates an agent via the API', async () => {
    const r = await handleToolCall('register_agent', { name: 'Via MCP', type: 'custom' }, apiCall);
    const text = JSON.parse(r.content[0].text);
    expect(text.registered).toBe(true);
    expect(text.agent_id).toBeTruthy();
  });

  it('log_event records an event', async () => {
    const r = await handleToolCall('log_event', { agent_id: agentId, event_type: 'unit', result: 'success' }, apiCall);
    const text = JSON.parse(r.content[0].text);
    expect(text.recorded).toBe(true);
  });

  it('query_compliance returns regulation status', async () => {
    const r = await handleToolCall('query_compliance', { agent_id: agentId, regulation: 'gdpr' }, apiCall);
    const text = JSON.parse(r.content[0].text);
    expect(text.regulation).toBe('gdpr');
  });

  it('unknown tool returns an error result', async () => {
    const r = await handleToolCall('nope', {}, apiCall);
    expect(r.isError).toBe(true);
    expect(JSON.parse(r.content[0].text).error).toContain('Unknown tool');
  });

  it('surfaces API errors as error results', async () => {
    // Point apiCall at a dead URL
    const dead = createApiCall('http://127.0.0.1:1', '');
    const r = await handleToolCall('gate_action', { agent_id: agentId, action: 'a', resource: 'r' }, dead);
    expect(r.isError).toBe(true);
    expect(JSON.parse(r.content[0].text).error.length).toBeGreaterThan(0);
  });
});