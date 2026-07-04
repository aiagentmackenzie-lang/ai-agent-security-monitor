import { describe, it, expect, beforeAll } from 'vitest';
import { getHarness } from './setup.js';

describe('Discovery: shadow-agent + behavior detection', () => {
  let h: Awaited<ReturnType<typeof getHarness>>;

  beforeAll(async () => { h = await getHarness(); });

  it('ingests access logs and scans for shadow agents', async () => {
    // Ingest logs with an unregistered key
    const ingest = await h.fastify.inject({
      method: 'POST', url: '/discovery/access-logs',
      payload: {
        access_logs: [
          { api_key: 'sk-agent-unregistered-001', resource: '/api/secret', timestamp: new Date().toISOString() },
          { api_key: 'sk-agent-unregistered-002', resource: '/api/finance', timestamp: new Date().toISOString() },
        ],
      },
    });
    expect(ingest.statusCode).toBe(200);
    expect(ingest.json().ingested).toBe(2);

    const scan = await h.fastify.inject({ method: 'POST', url: '/discovery/shadow-scan' });
    expect(scan.statusCode).toBe(200);
    const body = scan.json();
    expect(body.shadow_agents_detected).toBe(2);
    expect(body.discovered[0].key_prefix).toMatch(/^\w{2}\*\*\*$/);

    // A high-severity shadow_agent_detected alert should now exist
    const alerts = await h.fastify.inject({ method: 'GET', url: '/alerts?acknowledged=false' });
    const shadow = alerts.json().alerts.find((a: { type: string }) => a.type === 'shadow_agent_detected');
    expect(shadow).toBeDefined();
    expect(shadow.severity).toBe('high');

    // Re-running the scan must not create duplicates
    const scan2 = await h.fastify.inject({ method: 'POST', url: '/discovery/shadow-scan' });
    expect(scan2.json().shadow_agents_detected).toBe(0);
  });

  it('does not flag a registered key as shadow', async () => {
    // Register an agent with a hashed key
    const create = await h.fastify.inject({
      method: 'POST', url: '/agents',
      payload: { name: 'Registered Agent', type: 'custom', api_key_hash: require('crypto').createHash('sha256').update('sk-known-key-123').digest('hex') },
    });
    expect(create.statusCode).toBe(200);

    await h.fastify.inject({
      method: 'POST', url: '/discovery/access-logs',
      payload: { access_logs: [{ api_key: 'sk-known-key-123', resource: '/api/x', timestamp: new Date().toISOString() }] },
    });
    const scan = await h.fastify.inject({ method: 'POST', url: '/discovery/shadow-scan' });
    // No new shadow agent for the registered key
    expect(scan.json().shadow_agents_detected).toBe(0);
  });

  it('detects misregistered custom agents by behavior', async () => {
    // Create a 'custom' agent that behaves exactly like claude_code
    const create = await h.fastify.inject({
      method: 'POST', url: '/agents', payload: { name: 'Mystery Agent', type: 'custom' },
    });
    const agentId = create.json().agent.id;
    // Log 12 claude_code-style actions (bash/read/write/edit/grep/glob)
    for (const action of ['bash', 'read', 'write', 'edit', 'grep', 'glob', 'bash', 'read', 'write', 'edit', 'grep', 'glob']) {
      await h.fastify.inject({
        method: 'POST', url: `/agents/${agentId}/events`,
        payload: { agent_id: agentId, event_type: 'tool_call', action, resource: 'fs', result: 'success', details: {} },
      });
    }
    const res = await h.fastify.inject({ method: 'GET', url: '/discovery/behavior-scan' });
    expect(res.statusCode).toBe(200);
    const findings = res.json().behavior_findings;
    const mine = findings.find((f: { agent_id: string }) => f.agent_id === agentId);
    expect(mine).toBeDefined();
    expect(mine.inferred_type).toBe('claude_code');
    expect(mine.confidence).toBeGreaterThanOrEqual(0.6);
  });
});