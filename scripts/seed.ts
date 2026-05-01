import 'dotenv/config';
import pg from 'pg';

const { Pool } = pg;

async function seed() {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });

  console.log('Seeding demo data...\n');

  // Clear existing data (in correct order due to foreign keys)
  await pool.query('DELETE FROM compliance_records');
  await pool.query('DELETE FROM alerts');
  await pool.query('DELETE FROM agent_events');
  await pool.query('DELETE FROM policies');
  await pool.query('DELETE FROM agents');
  console.log('✓ Cleared existing data');

  // ── Agents ──
  const agents = [
    { name: 'Mackenzie-OpenClaw', type: 'openclaw', owner: 'raphael', metadata: { description: 'Primary AI agent assistant' } },
    { name: 'Claude-Code-Agent', type: 'claude_code', owner: 'engineering', metadata: { description: 'Code review and development agent' } },
    { name: 'Finance-Bot', type: 'langchain', owner: 'finance', metadata: { data_classification: 'financial_data', description: 'Financial data analysis agent' } },
    { name: 'HR-Assistant', type: 'crewai', owner: 'hr', metadata: { data_classification: 'pii', description: 'HR onboarding and data access agent' } },
    { name: 'Security-Scanner', type: 'custom', owner: 'security', metadata: { description: 'Automated vulnerability scanning agent' } },
  ];

  const agentIds: string[] = [];
  for (const agent of agents) {
    const result = await pool.query(
      `INSERT INTO agents (name, type, owner, metadata)
       VALUES ($1, $2, $3, $4)
       RETURNING id`,
      [agent.name, agent.type, agent.owner, JSON.stringify(agent.metadata)]
    );
    agentIds.push(result.rows[0].id);
    console.log(`✓ Agent: ${agent.name} (${agent.type})`);
  }

  // ── Policies ──
  const policies = [
    {
      name: 'Deny Data Deletion',
      description: 'No agent may delete data without explicit approval',
      rules: [{ action: 'data:delete:*', resource: '*', effect: 'deny' }],
      agent_ids: ['*'],
      active: true,
      default_effect: null,
    },
    {
      name: 'Finance Allowlist',
      description: 'Finance bot can only read approved financial resources',
      rules: [{ action: 'data:read:transactions', resource: '/api/finance/transactions', effect: 'permit' }],
      agent_ids: ['*'],
      active: true,
      default_effect: 'deny',
    },
    {
      name: 'Admin API Protection',
      description: 'Block all agents from admin API endpoints',
      rules: [{ action: 'api:*', resource: '/admin/*', effect: 'deny' }],
      agent_ids: ['*'],
      active: true,
      default_effect: null,
    },
    {
      name: 'PII Read Access',
      description: 'HR agents can read PII data for onboarding',
      rules: [
        { action: 'data:read:pii', resource: '/api/hr/*', effect: 'permit' },
      ],
      agent_ids: [agentIds[3]], // HR-Assistant
      active: true,
      default_effect: null,
    },
  ];

  for (const policy of policies) {
    await pool.query(
      `INSERT INTO policies (name, description, rules, agent_ids, active, default_effect)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [policy.name, policy.description, JSON.stringify(policy.rules), policy.agent_ids, policy.active, policy.default_effect]
    );
    console.log(`✓ Policy: ${policy.name}`);
  }

  // ── Events with hash chain ──
  const events = [
    { agent_idx: 0, event_type: 'tool_call', action: 'data:read:users', resource: '/api/users', result: 'success', details: { tool: 'user_lookup', response_time_ms: 120 } },
    { agent_idx: 0, event_type: 'api_call', action: 'data:read:products', resource: '/api/products', result: 'success', details: { endpoint: 'https://api.internal/products', response_time_ms: 85 } },
    { agent_idx: 1, event_type: 'tool_call', action: 'code:review', resource: '/repo/frontend/src/auth.ts', result: 'success', details: { language: 'typescript', issues_found: 2 } },
    { agent_idx: 2, event_type: 'data_access', action: 'data:read:transactions', resource: '/api/finance/transactions', result: 'success', details: { records_accessed: 150, data_classification: 'financial_data' } },
    { agent_idx: 3, event_type: 'data_access', action: 'data:read:pii', resource: '/api/hr/employees', result: 'success', details: { records_accessed: 5, data_classification: 'pii' } },
    { agent_idx: 4, event_type: 'security_scan', action: 'vuln:scan', resource: '/infrastructure/web-server', result: 'success', details: { vulnerabilities_found: 0, scan_duration_ms: 45000 } },
    { agent_idx: 0, event_type: 'tool_call', action: 'data:read:users', resource: '/api/users/123', result: 'denied', details: { reason: 'rate_limit_exceeded', attempts: 15 } },
  ];

  let previousHash: string | null = null;
  const { createHash } = await import('crypto');

  for (const event of events) {
    const agentId = agentIds[event.agent_idx];
    const eventData = `${agentId}-${event.event_type}-${event.action}-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const hash = createHash('sha256').update(previousHash ? `${previousHash}-${eventData}` : eventData).digest('hex');

    await pool.query(
      `INSERT INTO agent_events (agent_id, event_type, action, resource, result, details, previous_hash, hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [agentId, event.event_type, event.action, event.resource, event.result, JSON.stringify(event.details), previousHash, hash]
    );
    previousHash = hash;

    // Map compliance
    const regulations: Array<{ regulation: string; control_id: string }> = [];
    if (event.details.data_classification === 'financial_data') {
      regulations.push({ regulation: 'finra', control_id: 'FINRA-4511' });
    }
    if (event.details.data_classification === 'pii') {
      regulations.push({ regulation: 'gdpr', control_id: 'ART-22' });
    }
    if (event.event_type === 'tool_call' || event.event_type === 'api_call') {
      regulations.push({ regulation: 'ai_act', control_id: 'ART-12' });
    }

    for (const reg of regulations) {
      await pool.query(
        `INSERT INTO compliance_records (agent_id, regulation, control_id, evidence, status)
         VALUES ($1, $2, $3, $4, $5)`,
        [agentId, reg.regulation, reg.control_id, JSON.stringify({ event_type: event.event_type, action: event.action, resource: event.resource, mapped_at: new Date().toISOString() }), 'compliant']
      );
    }
    console.log(`✓ Event: ${event.event_type} → ${event.action} on ${event.resource} (${event.result})`);
  }

  // ── Alerts ──
  const alerts = [
    { agent_idx: 0, type: 'rate_limit', severity: 'medium', message: 'Agent Mackenzie-OpenClaw exceeded rate limit on user lookups', metadata: { attempts: 15, window_minutes: 5 } },
    { agent_idx: 4, type: 'scan_complete', severity: 'low', message: 'Security-Scanner completed vulnerability scan — 0 issues found', metadata: { scan_duration_ms: 45000 } },
  ];

  for (const alert of alerts) {
    await pool.query(
      `INSERT INTO alerts (agent_id, type, severity, message, metadata)
       VALUES ($1, $2, $3, $4, $5)`,
      [agentIds[alert.agent_idx], alert.type, alert.severity, alert.message, JSON.stringify(alert.metadata)]
    );
    console.log(`✓ Alert: [${alert.severity}] ${alert.type}`);
  }

  console.log('\n✅ Seed complete!');
  console.log(`   ${agents.length} agents, ${policies.length} policies, ${events.length} events, ${alerts.length} alerts`);

  await pool.end();
}

seed().catch((e) => {
  console.error('Seed failed:', e);
  process.exit(1);
});