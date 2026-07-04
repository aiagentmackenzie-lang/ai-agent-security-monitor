import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { PostgreSqlContainer } from '@testcontainers/postgresql';
import type { StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { Pool } from 'pg';
import { createHash } from 'crypto';
import { initDb } from '../src/db/init.js';
import { AgentDiscoveryService } from '../src/services/discovery.js';

let container: StartedPostgreSqlContainer;
let pool: Pool;

beforeAll(async () => {
  container = await new PostgreSqlContainer('postgres:16-alpine')
    .withDatabase('ai_agent_security').withUsername('test').withPassword('test').start();
  const cs = `postgresql://${container.getUsername()}:${container.getPassword()}@${container.getHost()}:${container.getMappedPort(5432)}/${container.getDatabase()}`;
  pool = new Pool({ connectionString: cs });
  await initDb(cs);
}, 120_000);

afterAll(async () => {
  if (pool) await pool.end();
  if (container) await container.stop();
}, 60_000);

async function truncate() {
  await pool.query('TRUNCATE compliance_records, alerts, agent_events, policies, agents, access_logs RESTART IDENTITY CASCADE');
}

describe('AgentDiscoveryService', () => {
  it('detectShadowAgents creates a shadow agent + alert for an unregistered key', async () => {
    await truncate();
    const svc = new AgentDiscoveryService(pool);
    // Load known keys (empty)
    await (svc as unknown as { loadKnownApiKeys: () => Promise<void> }).loadKnownApiKeys();
    await svc.detectShadowAgents([
      { api_key: 'sk-ghost-001', resource: '/api/secret', timestamp: new Date() },
    ]);
    const agents = await pool.query("SELECT name, type, metadata FROM agents WHERE name LIKE 'shadow_%'");
    expect(agents.rows.length).toBe(1);
    const alerts = await pool.query("SELECT type, severity FROM alerts WHERE type = 'shadow_agent_detected'");
    expect(alerts.rows[0].severity).toBe('high');
  });

  it('does not create a duplicate for an already-shadowed key', async () => {
    const svc = new AgentDiscoveryService(pool);
    await (svc as unknown as { loadKnownApiKeys: () => Promise<void> }).loadKnownApiKeys();
    await svc.detectShadowAgents([
      { api_key: 'sk-ghost-001', resource: '/api/secret2', timestamp: new Date() },
    ]);
    const agents = await pool.query("SELECT name FROM agents WHERE name LIKE 'shadow_%'");
    expect(agents.rows.length).toBe(1);
  });

  it('discoverOrphanedTokens returns keys not registered', async () => {
    const svc = new AgentDiscoveryService(pool);
    const orphaned = await svc.discoverOrphanedTokens(['sk-ghost-001', 'sk-totally-new-999']);
    // sk-ghost-001 is now registered (as a shadow agent with its hash), so only the new one is orphaned
    expect(orphaned).toEqual(['sk-totally-new-999']);
  });

  it('detectNewApiKeys scans ingested access logs for unknown hashes', async () => {
    await truncate();
    // Register one agent with a known key hash
    const knownHash = createHash('sha256').update('sk-known').digest('hex');
    await pool.query(
      `INSERT INTO agents (name, type, api_key_hash, metadata, active, quarantined) VALUES ($1, 'custom', $2, '{}', true, false)`,
      ['Known', knownHash]
    );
    // Ingest access logs: one known, one unknown
    await pool.query(
      `INSERT INTO access_logs (api_key_hash, key_prefix, resource, observed_at) VALUES ($1, $2, $3, NOW()), ($4, $5, $6, NOW())`,
      [knownHash, 'sk***', '/known', createHash('sha256').update('sk-unknown-1').digest('hex'), 'sk***', '/unknown']
    );

    const svc = new AgentDiscoveryService(pool);
    const discovered = await svc.detectNewApiKeys();
    expect(discovered.length).toBe(1);
    expect(discovered[0].shadow).toBe(true);
    expect(discovered[0].discovery_method).toBe('access_log_key_scan');
  });

  it('detectByBehavior flags custom agents matching a known baseline', async () => {
    await truncate();
    // Create a custom agent that emits 12 claude_code-style actions
    const a = await pool.query(
      `INSERT INTO agents (name, type, metadata, active, quarantined) VALUES ('Mystery', 'custom', '{}', true, false) RETURNING id`
    );
    const agentId = a.rows[0].id;
    for (const action of ['bash', 'read', 'write', 'edit', 'grep', 'glob', 'bash', 'read', 'write', 'edit', 'grep', 'glob']) {
      await pool.query(
        `INSERT INTO agent_events (agent_id, event_type, action, resource, result, details, previous_hash, hash) VALUES ($1, 'tool_call', $2, 'fs', 'success', '{}', NULL, $3)`,
        [agentId, action, createHash('sha256').update(action + Math.random()).digest('hex')]
      );
    }
    const svc = new AgentDiscoveryService(pool);
    const findings = await svc.detectByBehavior();
    const mine = findings.find(f => f.agent_id === agentId);
    expect(mine).toBeDefined();
    expect(mine!.inferred_type).toBe('claude_code');
    expect(mine!.confidence).toBeGreaterThanOrEqual(0.6);
  });

  it('detectByBehavior skips agents with too few events', async () => {
    await truncate();
    const a = await pool.query(
      `INSERT INTO agents (name, type, metadata, active, quarantined) VALUES ('Few', 'custom', '{}', true, false) RETURNING id`
    );
    await pool.query(
      `INSERT INTO agent_events (agent_id, event_type, action, resource, result, details, previous_hash, hash) VALUES ($1, 't', 'bash', 'fs', 'success', '{}', NULL, 'h1')`,
      [a.rows[0].id]
    );
    const svc = new AgentDiscoveryService(pool);
    const findings = await svc.detectByBehavior();
    expect(findings.find(f => f.agent_id === a.rows[0].id)).toBeUndefined();
  });
});