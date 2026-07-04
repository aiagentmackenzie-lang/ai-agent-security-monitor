import { afterEach, beforeAll, afterAll } from 'vitest';
import { PostgreSqlContainer } from '@testcontainers/postgresql';
import { Pool } from 'pg';
import { initDb } from '../../src/db/init.js';
import { buildServer } from '../../src/api/server.js';
import { loadTestConfig } from '../../src/config.js';
import type { FastifyInstance } from 'fastify';

export interface IntegrationHarness {
  pool: Pool;
  fastify: FastifyInstance;
  baseUrl: string;
  close: () => Promise<void>;
  truncate: () => Promise<void>;
  headers: Record<string, string>;
}

let harness: IntegrationHarness | null = null;

/**
 * Boot a one-shot testcontainers Postgres + Fastify server (no rate limit,
 * dev mode, injected pool) shared across integration test files via
 * `getHarness()`. Tables are truncated between tests.
 */
export async function getHarness(): Promise<IntegrationHarness> {
  if (harness) return harness;

  const container = await new PostgreSqlContainer('postgres:16-alpine')
    .withDatabase('ai_agent_security')
    .withUsername('test')
    .withPassword('test')
    .start();

  const connectionString = `postgresql://${container.getUsername()}:${container.getPassword()}@${container.getHost()}:${container.getMappedPort(5432)}/${container.getDatabase()}`;
  const pool = new Pool({ connectionString });

  await initDb(connectionString);

  const config = loadTestConfig(connectionString, { devMode: true });
  const { fastify, close } = await buildServer({ config, pool, skipRateLimit: true });
  await fastify.ready();

  const baseUrl = `http://test.local`;
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };

  const truncate = async () => {
    await pool.query('TRUNCATE TABLE compliance_records, alerts, agent_events, policies, agents, access_logs RESTART IDENTITY CASCADE');
  };

  const fullClose = async () => {
    await close();
    await container.stop();
  };

  harness = { pool, fastify, baseUrl, close: fullClose, truncate, headers };
  return harness;
}

// Shared lifecycle so importing any integration test file sets up/tears down.
beforeAll(async () => {
  const h = await getHarness();
  await h.truncate();
}, 90_000);

afterEach(async () => {
  const h = await getHarness();
  await h.truncate();
});

afterAll(async () => {
  if (harness) {
    await harness.close();
    harness = null;
  }
}, 60_000);