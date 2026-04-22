import 'dotenv/config';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import { z } from 'zod';
import pg from 'pg';
import { mapEventToCompliance } from '../compliance/mapper.js';
import { matchPattern } from '../policy/engine.js';

const { Pool } = pg;

const AgentTypeEnum = z.enum(['langchain', 'crewai', 'claude_code', 'openclaw', 'openai_agents', 'custom']);
const RegulationEnum = z.enum(['gdpr', 'ai_act', 'ccpa', 'hipaa', 'finra']);

const CreateAgentSchema = z.object({
  name: z.string().min(1),
  type: AgentTypeEnum,
  api_key_hash: z.string().optional(),
  owner: z.string().optional(),
  metadata: z.record(z.unknown()).optional(),
});

const PolicyRuleSchema = z.object({
  action: z.string().min(1),
  resource: z.string().min(1),
  effect: z.enum(['permit', 'deny']),
  conditions: z.record(z.unknown()).optional(),
});

const CreatePolicySchema = z.object({
  name: z.string().min(1),
  description: z.string().optional(),
  rules: z.array(PolicyRuleSchema).min(1),
  agent_ids: z.array(z.string()).default(['*']),
  active: z.boolean().default(true),
});

const EvaluatePolicySchema = z.object({
  agent_id: z.string().min(1),
  action: z.string().min(1),
  resource: z.string().min(1),
  context: z.object({
    user: z.string().optional(),
    session_id: z.string().optional(),
    data_classification: z.string().optional(),
    timestamp: z.string().optional(),
  }).optional(),
});

const LogEventSchema = z.object({
  agent_id: z.string().min(1),
  event_type: z.string().min(1),
  action: z.string().optional(),
  resource: z.string().optional(),
  result: z.enum(['success', 'denied', 'error']),
  details: z.record(z.unknown()).optional(),
});

export async function buildServer() {
  const fastify = Fastify({
    logger: {
      level: process.env.LOG_LEVEL || 'info',
    },
  });

  await fastify.register(cors, { origin: true });
  await fastify.register(swagger, {
    openapi: {
      info: {
        title: 'AI Agent Security Monitor',
        version: '0.1.0',
      },
    },
  });
  await fastify.register(swaggerUi);

  const pool = new Pool({ connectionString: process.env.DATABASE_URL });

  fastify.get('/health', async () => ({ status: 'ok', timestamp: new Date().toISOString() }));

  fastify.get('/agents', async () => {
    const result = await pool.query('SELECT * FROM agents ORDER BY created_at DESC');
    return { agents: result.rows };
  });

  fastify.post('/agents', async (request) => {
    const data = CreateAgentSchema.parse(request.body);
    const result = await pool.query(
      `INSERT INTO agents (name, type, api_key_hash, owner, metadata)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [data.name, data.type, data.api_key_hash, data.owner, JSON.stringify(data.metadata || {})]
    );
    return { agent: result.rows[0] };
  });

  fastify.get('/agents/:id', async (request) => {
    const { id } = request.params as { id: string };
    const result = await pool.query('SELECT * FROM agents WHERE id = $1', [id]);
    if (result.rows.length === 0) {
      throw { statusCode: 404, message: 'Agent not found' };
    }
    return { agent: result.rows[0] };
  });

  fastify.patch('/agents/:id', async (request) => {
    const { id } = request.params as { id: string };
    const data = CreateAgentSchema.partial().parse(request.body);
    const updates: string[] = [];
    const values: unknown[] = [];
    let idx = 1;

    if (data.name !== undefined) { updates.push(`name = $${idx++}`); values.push(data.name); }
    if (data.type !== undefined) { updates.push(`type = $${idx++}`); values.push(data.type); }
    if (data.api_key_hash !== undefined) { updates.push(`api_key_hash = $${idx++}`); values.push(data.api_key_hash); }
    if (data.owner !== undefined) { updates.push(`owner = $${idx++}`); values.push(data.owner); }
    if (data.metadata !== undefined) { updates.push(`metadata = $${idx++}`); values.push(JSON.stringify(data.metadata)); }
    updates.push(`updated_at = NOW()`);
    values.push(id);

    const result = await pool.query(
      `UPDATE agents SET ${updates.join(', ')} WHERE id = $${idx} RETURNING *`,
      values
    );
    if (result.rows.length === 0) {
      throw { statusCode: 404, message: 'Agent not found' };
    }
    return { agent: result.rows[0] };
  });

  fastify.delete('/agents/:id', async (request) => {
    const { id } = request.params as { id: string };
    await pool.query('UPDATE agents SET active = false, updated_at = NOW() WHERE id = $1', [id]);
    return { success: true };
  });

  fastify.post('/agents/:id/quarantine', async (request) => {
    const { id } = request.params as { id: string };
    const result = await pool.query(
      `UPDATE agents SET quarantined = true, updated_at = NOW() WHERE id = $1 RETURNING *`,
      [id]
    );
    if (result.rows.length === 0) {
      throw { statusCode: 404, message: 'Agent not found' };
    }
    const alertResult = await pool.query(
      `INSERT INTO alerts (agent_id, type, severity, message, metadata)
       VALUES ($1, 'agent_quarantined', 'high', $2, $3) RETURNING *`,
      [id, `Agent ${result.rows[0].name} has been quarantined`, JSON.stringify({ agent_name: result.rows[0].name })]
    );
    return { agent: result.rows[0], alert: alertResult.rows[0] };
  });

  fastify.post('/agents/:id/unquarantine', async (request) => {
    const { id } = request.params as { id: string };
    const result = await pool.query(
      `UPDATE agents SET quarantined = false, updated_at = NOW() WHERE id = $1 RETURNING *`,
      [id]
    );
    if (result.rows.length === 0) {
      throw { statusCode: 404, message: 'Agent not found' };
    }
    return { agent: result.rows[0] };
  });

  fastify.post('/agents/:id/revoke', async (request) => {
    const { id } = request.params as { id: string };
    const result = await pool.query(
      `UPDATE agents SET active = false, quarantined = true, updated_at = NOW() WHERE id = $1 RETURNING *`,
      [id]
    );
    if (result.rows.length === 0) {
      throw { statusCode: 404, message: 'Agent not found' };
    }

    const lastEvent = await pool.query(
      'SELECT hash FROM agent_events WHERE agent_id = $1 ORDER BY created_at DESC LIMIT 1',
      [id]
    );
    const previousHash = lastEvent.rows[0]?.hash || null;

    const { createHash } = await import('crypto');
    const eventData = `${id}-revoked-${Date.now()}`;
    const hash = createHash('sha256').update(previousHash ? `${previousHash}-${eventData}` : eventData).digest('hex');

    await pool.query(
      `INSERT INTO agent_events (agent_id, event_type, action, resource, result, details, previous_hash, hash)
       VALUES ($1, 'revoked', 'revoke', 'agent', 'success', $2, $3, $4)`,
      [id, JSON.stringify({ reason: 'Agent access revoked', revoked_at: new Date().toISOString() }), previousHash, hash]
    );
    const alertResult = await pool.query(
      `INSERT INTO alerts (agent_id, type, severity, message, metadata)
       VALUES ($1, 'agent_revoked', 'critical', $2, $3) RETURNING *`,
      [id, `Agent ${result.rows[0].name} has been revoked`, JSON.stringify({ agent_name: result.rows[0].name })]
    );
    return { agent: result.rows[0], alert: alertResult.rows[0] };
  });

  fastify.get('/agents/:id/events', async (request) => {
    const { id } = request.params as { id: string };
    const result = await pool.query(
      `SELECT * FROM agent_events WHERE agent_id = $1 ORDER BY created_at DESC LIMIT 100`,
      [id]
    );
    return { events: result.rows };
  });

  fastify.post('/agents/:id/events', async (request) => {
    const data = LogEventSchema.parse(request.body);

    const lastEvent = await pool.query(
      'SELECT hash FROM agent_events WHERE agent_id = $1 ORDER BY created_at DESC LIMIT 1',
      [data.agent_id]
    );
    const previousHash = lastEvent.rows[0]?.hash || null;

    const { createHash: createHashFn } = await import('crypto');
    const eventData = `${data.agent_id}-${data.event_type}-${data.action || ''}-${Date.now()}`;
    const eventHash = createHashFn('sha256').update(previousHash ? `${previousHash}-${eventData}` : eventData).digest('hex');

    const result = await pool.query(
      `INSERT INTO agent_events (agent_id, event_type, action, resource, result, details, previous_hash, hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [data.agent_id, data.event_type, data.action, data.resource, data.result, JSON.stringify(data.details || {}), previousHash, eventHash]
    );

    const complianceRecords = mapEventToCompliance(
      data.agent_id,
      data.event_type,
      data.action,
      data.resource,
      data.details || {}
    );

    for (const record of complianceRecords) {
      await pool.query(
        `INSERT INTO compliance_records (agent_id, regulation, control_id, evidence, status)
         VALUES ($1, $2, $3, $4, $5)`,
        [record.agent_id, record.regulation, record.control_id, JSON.stringify(record.evidence), record.status]
      );
    }

    return { event: result.rows[0], compliance_records: complianceRecords };
  });

  fastify.get('/policies', async () => {
    const result = await pool.query('SELECT * FROM policies ORDER BY created_at DESC');
    return { policies: result.rows };
  });

  fastify.post('/policies', async (request) => {
    const data = CreatePolicySchema.parse(request.body);
    const result = await pool.query(
      `INSERT INTO policies (name, description, rules, agent_ids, active)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [data.name, data.description, JSON.stringify(data.rules), data.agent_ids, data.active]
    );
    return { policy: result.rows[0] };
  });

  fastify.get('/policies/:id', async (request) => {
    const { id } = request.params as { id: string };
    const result = await pool.query('SELECT * FROM policies WHERE id = $1', [id]);
    if (result.rows.length === 0) {
      throw { statusCode: 404, message: 'Policy not found' };
    }
    return { policy: result.rows[0] };
  });

  fastify.patch('/policies/:id', async (request) => {
    const { id } = request.params as { id: string };
    const data = CreatePolicySchema.partial().parse(request.body);
    const updates: string[] = [];
    const values: unknown[] = [];
    let idx = 1;

    if (data.name !== undefined) { updates.push(`name = $${idx++}`); values.push(data.name); }
    if (data.description !== undefined) { updates.push(`description = $${idx++}`); values.push(data.description); }
    if (data.rules !== undefined) { updates.push(`rules = $${idx++}`); values.push(JSON.stringify(data.rules)); }
    if (data.agent_ids !== undefined) { updates.push(`agent_ids = $${idx++}`); values.push(data.agent_ids); }
    if (data.active !== undefined) { updates.push(`active = $${idx++}`); values.push(data.active); }
    updates.push(`updated_at = NOW()`);
    values.push(id);

    const result = await pool.query(
      `UPDATE policies SET ${updates.join(', ')} WHERE id = $${idx} RETURNING *`,
      values
    );
    if (result.rows.length === 0) {
      throw { statusCode: 404, message: 'Policy not found' };
    }
    return { policy: result.rows[0] };
  });

  fastify.delete('/policies/:id', async (request) => {
    const { id } = request.params as { id: string };
    await pool.query('DELETE FROM policies WHERE id = $1', [id]);
    return { success: true };
  });

  fastify.post('/policy/evaluate', async (request) => {
    const data = EvaluatePolicySchema.parse(request.body);
    
    const agentResult = await pool.query('SELECT quarantined, active FROM agents WHERE id = $1', [data.agent_id]);
    if (agentResult.rows.length > 0 && (agentResult.rows[0].quarantined || !agentResult.rows[0].active)) {
      return {
        allowed: false,
        reason: 'Agent is quarantined or inactive',
        policy_id: undefined,
        certificate_id: undefined,
        agent_id: data.agent_id,
        action: data.action,
        resource: data.resource,
        evaluated_at: new Date().toISOString(),
      };
    }

    const result = await pool.query(
      `SELECT * FROM policies WHERE active = true AND ($1 = ANY(agent_ids) OR agent_ids = ARRAY['*']) ORDER BY priority DESC`,
      [data.agent_id]
    );
    const policies = result.rows;
    let allowed = true;
    let reason = 'Default allow - no matching policy found';
    let policy_id: string | undefined;

    for (const policy of policies) {
      const rules = policy.rules as z.infer<typeof PolicyRuleSchema>[];
      const match = rules.find(r => {
        const actionMatch = matchPattern(data.action, r.action);
        const resourceMatch = matchPattern(data.resource, r.resource);
        return actionMatch && resourceMatch;
      });
      if (match) {
        allowed = match.effect === 'permit';
        reason = match.effect === 'deny'
          ? `Denied by policy: ${policy.name}`
          : `Permitted by policy: ${policy.name}`;
        policy_id = policy.id;
        break;
      }
    }

    const certificate_id = `cert_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;

    return {
      allowed,
      reason,
      policy_id,
      certificate_id,
      agent_id: data.agent_id,
      action: data.action,
      resource: data.resource,
      evaluated_at: new Date().toISOString(),
    };
  });

  

  fastify.get('/compliance/:agent_id/:regulation', async (request) => {
    const { agent_id, regulation } = request.params as { agent_id: string; regulation: string };
    RegulationEnum.parse(regulation);

    const records = await pool.query(
      'SELECT * FROM compliance_records WHERE agent_id = $1 AND regulation = $2',
      [agent_id, regulation]
    );

    const lastAuditResult = await pool.query(
      'SELECT created_at FROM compliance_records WHERE agent_id = $1 AND regulation = $2 ORDER BY created_at DESC LIMIT 1',
      [agent_id, regulation]
    );

    const satisfied = records.rows.filter(r => r.status === 'compliant').map(r => r.control_id);
    const gaps = records.rows.filter(r => r.status !== 'compliant').map(r => r.control_id);

    return {
      agent_id,
      regulation,
      compliant: gaps.length === 0,
      controls_satisfied: satisfied,
      gaps,
      evidence_count: records.rows.length,
      last_audit_timestamp: lastAuditResult.rows[0]?.created_at || null,
    };
  });

  fastify.get('/compliance/reports/:agent_id', async (request) => {
    const { agent_id } = request.params as { agent_id: string };
    const { regulations } = request.query as { regulations?: string } || {};

    const agentResult = await pool.query('SELECT * FROM agents WHERE id = $1', [agent_id]);
    if (agentResult.rows.length === 0) {
      throw { statusCode: 404, message: 'Agent not found' };
    }

    const events = await pool.query(
      'SELECT * FROM agent_events WHERE agent_id = $1 ORDER BY created_at DESC',
      [agent_id]
    );

    const regulationsList = regulations ? regulations.split(',') : ['gdpr', 'ai_act', 'ccpa', 'hipaa', 'finra'];
    interface ComplianceRegResult {
      compliant: boolean;
      controls_satisfied: string[];
      gaps: string[];
      evidence_count: number;
      records: Array<Record<string, unknown>>;
    }
    const complianceByRegulation: Record<string, ComplianceRegResult> = {};

    for (const reg of regulationsList) {
      RegulationEnum.parse(reg);
      const records = await pool.query(
        'SELECT * FROM compliance_records WHERE agent_id = $1 AND regulation = $2',
        [agent_id, reg]
      );
      const satisfied = records.rows.filter(r => r.status === 'compliant').map(r => r.control_id);
      const gaps = records.rows.filter(r => r.status !== 'compliant').map(r => r.control_id);
      complianceByRegulation[reg] = {
        compliant: gaps.length === 0,
        controls_satisfied: satisfied,
        gaps,
        evidence_count: records.rows.length,
        records: records.rows,
      };
    }

    return {
      agent: agentResult.rows[0],
      report: {
        generated_at: new Date().toISOString(),
        events: events.rows,
        compliance: complianceByRegulation,
      },
    };
  });

  fastify.get('/compliance/export/:agent_id', async (request) => {
    const { agent_id } = request.params as { agent_id: string };
    const { page = '1', limit = '50' } = request.query as { page?: string; limit?: string };
    const pageNum = parseInt(page, 10);
    const limitNum = Math.min(parseInt(limit, 10), 100);
    const offset = (pageNum - 1) * limitNum;

    const agentResult = await pool.query('SELECT * FROM agents WHERE id = $1', [agent_id]);
    if (agentResult.rows.length === 0) {
      throw { statusCode: 404, message: 'Agent not found' };
    }

    const eventsResult = await pool.query(
      'SELECT * FROM agent_events WHERE agent_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3',
      [agent_id, limitNum, offset]
    );

    const totalResult = await pool.query(
      'SELECT COUNT(*) FROM agent_events WHERE agent_id = $1',
      [agent_id]
    );

    const certificates = await pool.query(
      `SELECT * FROM compliance_records WHERE agent_id = $1 ORDER BY created_at DESC`,
      [agent_id]
    );

    const chainResult = await pool.query(
      `SELECT hash, previous_hash FROM agent_events WHERE agent_id = $1 ORDER BY created_at ASC`,
      [agent_id]
    );

    return {
      agent: agentResult.rows[0],
      export: {
        generated_at: new Date().toISOString(),
        pagination: {
          page: pageNum,
          limit: limitNum,
          total: parseInt(totalResult.rows[0].count, 10),
          total_pages: Math.ceil(parseInt(totalResult.rows[0].count, 10) / limitNum),
        },
        events: eventsResult.rows,
        certificate_chain: certificates.rows.map(r => ({
          id: r.id,
          regulation: r.regulation,
          control_id: r.control_id,
          status: r.status,
          created_at: r.created_at,
        })),
        hash_chain: {
          verified: verifyHashChain(chainResult.rows),
          events: chainResult.rows,
        },
      },
    };
  });

  function verifyHashChain(events: { hash: string; previous_hash: string | null }[]): boolean {
    for (let i = 1; i < events.length; i++) {
      if (events[i].previous_hash !== events[i - 1].hash) {
        return false;
      }
    }
    return true;
  }

  fastify.get('/dashboard/summary', async () => {
    const agentStats = await pool.query(`
      SELECT
        COUNT(*) as total_agents,
        COUNT(*) FILTER (WHERE active = true) as active_agents,
        COUNT(*) FILTER (WHERE quarantined = true) as quarantined_agents,
        COUNT(*) FILTER (WHERE active = false) as inactive_agents
      FROM agents
    `);

    const eventStats = await pool.query(`
      SELECT
        COUNT(*) as total_events,
        COUNT(*) FILTER (WHERE result = 'denied') as denied_events,
        COUNT(*) FILTER (WHERE result = 'error') as error_events
      FROM agent_events
    `);

    const alertStats = await pool.query(`
      SELECT
        COUNT(*) as total_alerts,
        COUNT(*) FILTER (WHERE acknowledged = false) as unacknowledged_alerts,
        COUNT(*) FILTER (WHERE severity = 'critical') as critical_alerts
      FROM alerts
    `);

    const complianceStats = await pool.query(`
      SELECT
        regulation,
        COUNT(*) as total_records,
        COUNT(*) FILTER (WHERE status = 'compliant') as compliant_records,
        COUNT(*) FILTER (WHERE status != 'compliant') as gap_records
      FROM compliance_records
      GROUP BY regulation
    `);

    return {
      agents: {
        total: parseInt(agentStats.rows[0].total_agents, 10),
        active: parseInt(agentStats.rows[0].active_agents, 10),
        quarantined: parseInt(agentStats.rows[0].quarantined_agents, 10),
        inactive: parseInt(agentStats.rows[0].inactive_agents, 10),
      },
      events: {
        total: parseInt(eventStats.rows[0].total_events, 10),
        denied: parseInt(eventStats.rows[0].denied_events, 10),
        errors: parseInt(eventStats.rows[0].error_events, 10),
      },
      alerts: {
        total: parseInt(alertStats.rows[0].total_alerts, 10),
        unacknowledged: parseInt(alertStats.rows[0].unacknowledged_alerts, 10),
        critical: parseInt(alertStats.rows[0].critical_alerts, 10),
      },
      compliance: complianceStats.rows.reduce((acc, r) => {
        acc[r.regulation] = {
          total: parseInt(r.total_records, 10),
          compliant: parseInt(r.compliant_records, 10),
          gaps: parseInt(r.gap_records, 10),
        };
        return acc;
      }, {} as Record<string, { total: number; compliant: number; gaps: number }>),
      generated_at: new Date().toISOString(),
    };
  });

  fastify.get('/dashboard/events/timeline', async (request) => {
    const { agent_id, hours = '24' } = request.query as { agent_id?: string; hours?: string };
    const hoursNum = Math.min(parseInt(hours, 10), 168);
    const query = agent_id
      ? `SELECT * FROM agent_events WHERE agent_id = $1 AND created_at > NOW() - INTERVAL '${hoursNum} hours' ORDER BY created_at DESC`
      : `SELECT * FROM agent_events WHERE created_at > NOW() - INTERVAL '${hoursNum} hours' ORDER BY created_at DESC`;
    const params = agent_id ? [agent_id] : [];
    const result = await pool.query(query, params);

    return {
      timeline: result.rows,
      count: result.rows.length,
      hours_range: hoursNum,
    };
  });

  fastify.get('/dashboard/compliance/summary', async () => {
    const summary = await pool.query(`
      SELECT
        regulation,
        COUNT(*) as total_records,
        COUNT(*) FILTER (WHERE status = 'compliant') as compliant_records,
        COUNT(*) FILTER (WHERE status = 'pending') as pending_records,
        COUNT(*) FILTER (WHERE status = 'gap') as gap_records
      FROM compliance_records
      GROUP BY regulation
    `);

    const overallCompliance = await pool.query(`
      SELECT
        COUNT(*) as total,
        COUNT(*) FILTER (WHERE status = 'compliant') as compliant
      FROM compliance_records
    `);

    const complianceRate = overallCompliance.rows[0].total > 0
      ? (parseInt(overallCompliance.rows[0].compliant, 10) / parseInt(overallCompliance.rows[0].total, 10)) * 100
      : 0;

    return {
      by_regulation: summary.rows.map(r => ({
        regulation: r.regulation,
        total: parseInt(r.total_records, 10),
        compliant: parseInt(r.compliant_records, 10),
        pending: parseInt(r.pending_records, 10),
        gaps: parseInt(r.gap_records, 10),
      })),
      overall: {
        total_records: parseInt(overallCompliance.rows[0].total, 10),
        compliant_records: parseInt(overallCompliance.rows[0].compliant, 10),
        compliance_rate: Math.round(complianceRate * 100) / 100,
      },
      generated_at: new Date().toISOString(),
    };
  });

  fastify.get('/alerts', async (request) => {
    const { agent_id, acknowledged } = request.query as { agent_id?: string; acknowledged?: string };
    let query = 'SELECT * FROM alerts WHERE 1=1';
    const params: string[] = [];
    if (agent_id) { params.push(agent_id); query += ` AND agent_id = $${params.length}`; }
    if (acknowledged !== undefined) { params.push(acknowledged); query += ` AND acknowledged = $${params.length}`; }
    query += ' ORDER BY created_at DESC LIMIT 100';
    const result = await pool.query(query, params);
    return { alerts: result.rows };
  });

  fastify.post('/alerts/:id/acknowledge', async (request) => {
    const { id } = request.params as { id: string };
    const { acknowledged_by } = request.body as { acknowledged_by?: string } || {};
    const result = await pool.query(
      `UPDATE alerts SET acknowledged = true, acknowledged_by = $1, acknowledged_at = NOW() WHERE id = $2 RETURNING *`,
      [acknowledged_by, id]
    );
    if (result.rows.length === 0) {
      throw { statusCode: 404, message: 'Alert not found' };
    }
    return { alert: result.rows[0] };
  });

  await fastify.listen({ port: Number(process.env.PORT) || 8000, host: '0.0.0.0' });
  console.log(`AI Agent Security Monitor running on port ${process.env.PORT || 8000}`);

  return { fastify, pool };
}

buildServer().catch(console.error);
