import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { PostgreSqlContainer } from '@testcontainers/postgresql';
import type { StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { Pool } from 'pg';
import { initDb } from '../../src/db/init.js';
import { buildServer } from '../../src/api/server.js';
import { loadTestConfig } from '../../src/config.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import type { FastifyInstance } from 'fastify';

let container: StartedPostgreSqlContainer;
let pool: Pool;
let fastify: FastifyInstance;
let baseUrl: string;
let agentId: string;

beforeAll(async () => {
  container = await new PostgreSqlContainer('postgres:16-alpine')
    .withDatabase('ai_agent_security')
    .withUsername('test')
    .withPassword('test')
    .start();
  const connectionString = `postgresql://${container.getUsername()}:${container.getPassword()}@${container.getHost()}:${container.getMappedPort(5432)}/${container.getDatabase()}`;
  pool = new Pool({ connectionString });
  await initDb(connectionString);

  const config = loadTestConfig(connectionString, { devMode: true });
  const built = await buildServer({ config, pool, skipRateLimit: true });
  fastify = built.fastify;
  await fastify.listen({ port: 0, host: '127.0.0.1' });
  const address = fastify.server.address();
  const port = typeof address === 'object' && address ? address.port : 8000;
  baseUrl = `http://127.0.0.1:${port}`;

  const r = await fastify.inject({
    method: 'POST', url: '/agents',
    payload: { name: 'MCP Test Agent', type: 'openclaw' },
  });
  agentId = r.json().agent.id;

  await fastify.inject({
    method: 'POST', url: '/policies',
    payload: {
      name: 'Deny Dangerous',
      rules: [{ action: 'tool:dangerous', resource: '*', effect: 'deny' }],
      agent_ids: ['*'], priority: 10,
    },
  });
}, 120_000);

afterAll(async () => {
  if (fastify) await fastify.close();
  if (pool) await pool.end();
  if (container) await container.stop();
}, 60_000);

async function withMcpClient<T>(fn: (client: Client) => Promise<T>): Promise<T> {
  const transport = new StdioClientTransport({
    command: 'npx',
    args: ['tsx', 'src/mcp/server.ts'],
    env: { ...process.env, API_BASE_URL: baseUrl, API_KEY: '' } as Record<string, string>,
  });
  const client = new Client({ name: 'test-client', version: '0.1.0' }, { capabilities: {} });
  await client.connect(transport);
  try {
    return await fn(client);
  } finally {
    await client.close();
  }
}

describe('MCP server end-to-end', () => {
  it('lists the 5 governance tools', async () => {
    const tools = await withMcpClient(async (c) => {
      const r = await c.listTools();
      return r.tools.map(t => t.name);
    });
    expect(tools).toEqual(
      expect.arrayContaining(['gate_action', 'evaluate_tool_call', 'register_agent', 'log_event', 'query_compliance'])
    );
    expect(tools.length).toBe(5);
  }, 90_000);

  it('gate_action permits an allowed action and returns a certificate', async () => {
    const result = await withMcpClient(async (c) => {
      return c.callTool({
        name: 'gate_action',
        arguments: { agent_id: agentId, action: 'data:read:safe', resource: '/safe' },
      });
    });
    const text = JSON.parse(result.content[0].text);
    expect(text.allowed).toBe(true);
    expect(text.certificate_id).toMatch(/^cert_/);
  }, 90_000);

  it('evaluate_tool_call denies a dangerous tool and logs a denied event', async () => {
    const result = await withMcpClient(async (c) => {
      return c.callTool({
        name: 'evaluate_tool_call',
        arguments: {
          agent_id: agentId, tool_name: 'rm_rf',
          action: 'tool:dangerous', resource: '/fs',
          tool_args: { path: '/' },
        },
      });
    });
    expect(result.isError).toBe(true);
    const text = JSON.parse(result.content[0].text);
    expect(text.status).toBe('denied');
    expect(text.event_id).toBeTruthy();

    const events = await fastify.inject({ method: 'GET', url: `/agents/${agentId}/events` });
    const denied = events.json().events.find((e: { event_type: string }) => e.event_type === 'tool_denied');
    expect(denied).toBeDefined();
    expect(JSON.stringify(denied.details)).toContain('rm_rf');
  }, 90_000);

  it('log_event records an event', async () => {
    const result = await withMcpClient(async (c) => {
      return c.callTool({
        name: 'log_event',
        arguments: { agent_id: agentId, event_type: 'manual', action: 'check', resource: '/x', result: 'success' },
      });
    });
    const text = JSON.parse(result.content[0].text);
    expect(text.recorded).toBe(true);
    expect(text.event_id).toBeTruthy();
  }, 90_000);

  it('query_compliance returns regulation status', async () => {
    const result = await withMcpClient(async (c) => {
      return c.callTool({
        name: 'query_compliance',
        arguments: { agent_id: agentId, regulation: 'gdpr' },
      });
    });
    const text = JSON.parse(result.content[0].text);
    expect(text.regulation).toBe('gdpr');
    expect(text).toHaveProperty('gaps');
  }, 90_000);
}, 300_000);