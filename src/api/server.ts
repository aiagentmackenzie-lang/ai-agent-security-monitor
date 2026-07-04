import { fileURLToPath } from 'url';
import 'dotenv/config';
import Fastify, { FastifyRequest, FastifyReply } from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import { z } from 'zod';
import pg, { Pool } from 'pg';
import { randomUUID, createHash } from 'crypto';
import { mapEventToCompliance } from '../compliance/mapper.js';
import { matchPattern } from '../policy/engine.js';
import { redactEvent } from '../security/redaction.js';
import { detectAnomalies } from '../services/baseline.js';
import { SecurityScarletIntegration } from '../services/security-scarlet.js';
import { AgentDiscoveryService } from '../services/discovery.js';
import { loadConfig, type AppConfig } from '../config.js';
import { HttpError, errorHandler } from './errors.js';
import { dirname, join } from 'path';

const { Pool: PgPool } = pg;

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
  default_effect: z.enum(['deny']).optional(),
  priority: z.number().int().default(0),
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

const AccessLogSchema = z.object({
  api_key: z.string().min(1),
  resource: z.string().min(1),
  timestamp: z.string().datetime().optional(),
});

const IngestAccessLogsSchema = z.object({
  access_logs: z.array(AccessLogSchema).min(1),
});

export interface BuildServerOptions {
  config?: AppConfig;
  pool?: Pool;
  /** Skip rate-limit registration (tests that drive high request volume). */
  skipRateLimit?: boolean;
}

/**
 * Build the Fastify server WITHOUT listening. Safe to import in tests.
 *
 * Configuration and the DB pool are injectable so integration tests can point
 * at a testcontainers Postgres without env mutation.
 */
export async function buildServer(opts: BuildServerOptions = {}): Promise<{
  fastify: Fastify.FastifyInstance;
  pool: Pool;
  close: () => Promise<void>;
}> {
  const config = opts.config ?? loadConfig();
  const pool = opts.pool ?? new PgPool({ connectionString: config.databaseUrl });

  const fastify = Fastify({
    logger: { level: config.logLevel },
  });

  fastify.setErrorHandler(errorHandler);

  // CORS — explicit allowlist in production, open only in dev mode
  await fastify.register(cors, {
    origin: config.devMode && config.corsOrigins.length === 0 ? true : config.corsOrigins,
  });

  // Rate limiting — Redis-backed when available, in-memory otherwise
  if (!opts.skipRateLimit) {
    let redisStore: import('ioredis').default | undefined;
    if (config.redisUrl) {
      const ioredis = await import('ioredis');
      const RedisCtor = (ioredis as unknown as { default: new (url: string, opts?: Record<string, unknown>) => import('ioredis').default }).default;
      redisStore = new RedisCtor(config.redisUrl, { maxRetriesPerRequest: null });
    }
    await fastify.register(rateLimit, {
      max: config.rateLimitMax,
      timeWindow: config.rateLimitWindowMs,
      ...(redisStore ? { redis: redisStore } : {}),
      allowList: (req: FastifyRequest) => req.url === '/health',
    });
  }

  await fastify.register(swagger, {
    openapi: { info: { title: 'AI Agent Security Monitor', version: '0.1.0' } },
  });
  await fastify.register(swaggerUi, { routePrefix: '/documentation' });

  // Auth hook — required API key unless dev mode allows open access
  fastify.addHook('onRequest', async (request: FastifyRequest, reply: FastifyReply) => {
    if (!config.apiKey) return; // dev mode, no key configured
    const provided = request.headers['x-api-key'];
    if (provided !== config.apiKey) {
      throw HttpError.unauthorized('Unauthorized — invalid or missing X-API-Key header');
    }
    // reply unused on success
    void reply;
  });

  // Scarlet forwarding (opt-in). Fire-and-forget after a successful commit.
  const scarlet = config.scarletForwardEnabled && config.scarletApiUrl
    ? new SecurityScarletIntegration({
        apiUrl: config.scarletApiUrl,
        apiKey: config.scarletApiKey || '',
        eventBusUrl: config.scarletEventBusUrl || '',
      })
    : null;

  // ─── Health ───
  fastify.get('/health', async () => ({ status: 'ok', timestamp: new Date().toISOString() }));

  // ─── Agents ───
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
    if (result.rows.length === 0) throw HttpError.notFound('Agent not found');
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
    if (result.rows.length === 0) throw HttpError.notFound('Agent not found');
    return { agent: result.rows[0] };
  });

  fastify.delete('/agents/:id', async (request) => {
    const { id } = request.params as { id: string };
    const result = await pool.query(
      'UPDATE agents SET active = false, updated_at = NOW() WHERE id = $1 RETURNING id',
      [id]
    );
    if (result.rows.length === 0) throw HttpError.notFound('Agent not found');
    return { success: true };
  });

  fastify.post('/agents/:id/quarantine', async (request) => {
    const { id } = request.params as { id: string };
    const result = await pool.query(
      `UPDATE agents SET quarantined = true, updated_at = NOW() WHERE id = $1 RETURNING *`,
      [id]
    );
    if (result.rows.length === 0) throw HttpError.notFound('Agent not found');
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
    if (result.rows.length === 0) throw HttpError.notFound('Agent not found');
    return { agent: result.rows[0] };
  });

  fastify.post('/agents/:id/revoke', async (request) => {
    const { id } = request.params as { id: string };

    const client = await pool.connect();
    try {
      await client.query('BEGIN');

      const result = await client.query(
        `UPDATE agents SET active = false, quarantined = true, updated_at = NOW() WHERE id = $1 RETURNING *`,
        [id]
      );
      if (result.rows.length === 0) {
        await client.query('ROLLBACK');
        throw HttpError.notFound('Agent not found');
      }

      const lastEvent = await client.query(
        'SELECT hash FROM agent_events WHERE agent_id = $1 ORDER BY created_at DESC LIMIT 1',
        [id]
      );
      const previousHash = lastEvent.rows[0]?.hash || null;

      const eventData = JSON.stringify({
        agent_id: id,
        event_type: 'revoked',
        action: 'revoke',
        resource: 'agent',
        result: 'success',
        ts: Date.now(),
      });
      const hash = createHash('sha256')
        .update(previousHash ? `${previousHash}-${eventData}` : eventData)
        .digest('hex');

      await client.query(
        `INSERT INTO agent_events (agent_id, event_type, action, resource, result, details, previous_hash, hash)
         VALUES ($1, 'revoked', 'revoke', 'agent', 'success', $2, $3, $4)`,
        [id, JSON.stringify({ reason: 'Agent access revoked', revoked_at: new Date().toISOString() }), previousHash, hash]
      );

      const alertResult = await client.query(
        `INSERT INTO alerts (agent_id, type, severity, message, metadata)
         VALUES ($1, 'agent_revoked', 'critical', $2, $3) RETURNING *`,
        [id, `Agent ${result.rows[0].name} has been revoked`, JSON.stringify({ agent_name: result.rows[0].name })]
      );

      await client.query('COMMIT');
      return { agent: result.rows[0], alert: alertResult.rows[0] };
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
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
    const { id } = request.params as { id: string };
    const data = LogEventSchema.parse(request.body);

    const agentId = id;
    const client = await pool.connect();
    let committed: { event_id: string; agent_id: string; event_type: string; action: string | null; resource: string | null; result: string; details: Record<string, unknown>; created_at: Date; compliance_records: unknown[] } | null = null;

    try {
      await client.query('BEGIN');

      const agentCheck = await client.query('SELECT id FROM agents WHERE id = $1', [agentId]);
      if (agentCheck.rows.length === 0) {
        await client.query('ROLLBACK');
        throw HttpError.notFound('Agent not found');
      }

      const lastEvent = await client.query(
        'SELECT hash FROM agent_events WHERE agent_id = $1 ORDER BY created_at DESC LIMIT 1',
        [agentId]
      );
      const previousHash = lastEvent.rows[0]?.hash || null;

      const eventData = JSON.stringify({
        agent_id: agentId,
        event_type: data.event_type,
        action: data.action || '',
        resource: data.resource || '',
        result: data.result,
        details: data.details || {},
        ts: Date.now(),
      });
      const eventHash = createHash('sha256')
        .update(previousHash ? `${previousHash}-${eventData}` : eventData)
        .digest('hex');

      const redacted = redactEvent({
        event_type: data.event_type,
        action: data.action,
        resource: data.resource,
        result: data.result,
        details: data.details || {},
      });

      const result = await client.query(
        `INSERT INTO agent_events (agent_id, event_type, action, resource, result, details, previous_hash, hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING *`,
        [agentId, data.event_type, redacted.action, redacted.resource, data.result, JSON.stringify(redacted.details), previousHash, eventHash]
      );

      if (redacted.flags.length > 0) {
        const criticalFlags = redacted.flags.filter(f => f.severity === 'critical' || f.severity === 'high');
        if (criticalFlags.length > 0) {
          await client.query(
            `INSERT INTO alerts (agent_id, type, severity, message, metadata)
             VALUES ($1, 'sensitive_data_detected', $2, $3, $4)`,
            [
              agentId,
              criticalFlags.some(f => f.severity === 'critical') ? 'critical' : 'high',
              `Sensitive data detected in event: ${criticalFlags.map(f => f.pattern).join(', ')}`,
              JSON.stringify({ flags: redacted.flags, event_type: data.event_type }),
            ]
          );
        }
      }

      const complianceRecords = mapEventToCompliance(
        agentId,
        data.event_type,
        redacted.action,
        redacted.resource,
        redacted.details
      );

      for (const record of complianceRecords) {
        await client.query(
          `INSERT INTO compliance_records (agent_id, regulation, control_id, evidence, status)
           VALUES ($1, $2, $3, $4, $5)`,
          [record.agent_id, record.regulation, record.control_id, JSON.stringify(record.evidence), record.status]
        );
      }

      await client.query('COMMIT');
      committed = {
        event_id: result.rows[0].id,
        agent_id: agentId,
        event_type: data.event_type,
        action: redacted.action ?? null,
        resource: redacted.resource ?? null,
        result: data.result,
        details: redacted.details,
        created_at: result.rows[0].created_at,
        compliance_records: complianceRecords,
      };
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }

    // Fire-and-forget Scarlet forwarding (after commit, never blocks response)
    if (scarlet && committed) {
      scarlet.forwardEvent({
        agent_id: committed.agent_id,
        event_type: committed.event_type,
        action: committed.action ?? undefined,
        resource: committed.resource ?? undefined,
        result: committed.result,
        details: committed.details,
        created_at: committed.created_at,
      }).catch((e) => fastify.log.warn({ err: e }, 'Scarlet forward failed'));
    }

    return { event: { id: committed!.event_id }, compliance_records: committed!.compliance_records };
  });

  // ─── Agent anomaly detection (behavior baseline) ───
  fastify.get('/agents/:id/anomalies', async (request) => {
    const { id } = request.params as { id: string };
    const { window_hours = '24' } = request.query as { window_hours?: string };
    const hours = parseInt(window_hours, 10);
    if (isNaN(hours) || hours < 1) throw HttpError.badRequest('window_hours must be a positive integer');
    const clamped = Math.min(hours, 168);

    const agentRes = await pool.query('SELECT type FROM agents WHERE id = $1', [id]);
    if (agentRes.rows.length === 0) throw HttpError.notFound('Agent not found');

    const eventsRes = await pool.query(
      `SELECT action, resource, created_at FROM agent_events
       WHERE agent_id = $1 AND created_at > NOW() - INTERVAL '1 hour' * $2
       ORDER BY created_at ASC`,
      [id, clamped]
    );

    const anomalies = detectAnomalies(
      id,
      agentRes.rows[0].type,
      eventsRes.rows.map((r: { action: string; resource: string; created_at: Date }) => ({
        action: r.action || '',
        resource: r.resource || '',
        created_at: new Date(r.created_at),
      }))
    );

    return { agent_id: id, window_hours: clamped, event_count: eventsRes.rows.length, anomalies };
  });

  // ─── Policies ───
  fastify.get('/policies', async () => {
    const result = await pool.query('SELECT * FROM policies ORDER BY priority DESC, created_at DESC');
    return { policies: result.rows };
  });

  fastify.post('/policies', async (request) => {
    const data = CreatePolicySchema.parse(request.body);
    const result = await pool.query(
      `INSERT INTO policies (name, description, rules, agent_ids, active, default_effect, priority)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [data.name, data.description, JSON.stringify(data.rules), data.agent_ids, data.active, data.default_effect || null, data.priority]
    );
    return { policy: result.rows[0] };
  });

  fastify.get('/policies/:id', async (request) => {
    const { id } = request.params as { id: string };
    const result = await pool.query('SELECT * FROM policies WHERE id = $1', [id]);
    if (result.rows.length === 0) throw HttpError.notFound('Policy not found');
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
    if (data.default_effect !== undefined) { updates.push(`default_effect = $${idx++}`); values.push(data.default_effect); }
    if (data.priority !== undefined) { updates.push(`priority = $${idx++}`); values.push(data.priority); }
    updates.push(`updated_at = NOW()`);
    values.push(id);

    const result = await pool.query(
      `UPDATE policies SET ${updates.join(', ')} WHERE id = $${idx} RETURNING *`,
      values
    );
    if (result.rows.length === 0) throw HttpError.notFound('Policy not found');
    return { policy: result.rows[0] };
  });

  fastify.delete('/policies/:id', async (request) => {
    const { id } = request.params as { id: string };
    const result = await pool.query(
      'UPDATE policies SET active = false, updated_at = NOW() WHERE id = $1 RETURNING id',
      [id]
    );
    if (result.rows.length === 0) throw HttpError.notFound('Policy not found');
    return { success: true };
  });

  // ─── Policy Evaluation ───
  fastify.post('/policy/evaluate', async (request) => {
    const data = EvaluatePolicySchema.parse(request.body);

    const agentResult = await pool.query('SELECT quarantined, active FROM agents WHERE id = $1', [data.agent_id]);
    if (agentResult.rows.length > 0 && (agentResult.rows[0].quarantined || !agentResult.rows[0].active)) {
      return {
        allowed: false,
        reason: 'Agent is quarantined or inactive',
        policy_id: undefined,
        certificate_id: `cert_${randomUUID()}`,
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
    let reason = 'Default allow — no matching policy found';
    let policy_id: string | undefined;

    let allowlistPolicy: { id: string; name: string } | undefined;

    for (const policy of policies) {
      const rules = policy.rules as z.infer<typeof PolicyRuleSchema>[];
      for (const rule of rules) {
        const actionMatch = matchPattern(data.action, rule.action);
        const resourceMatch = matchPattern(data.resource, rule.resource);
        if (actionMatch && resourceMatch) {
          if (rule.conditions) {
            if (data.context) {
              let conditionsMet = true;
              for (const [field, expected] of Object.entries(rule.conditions)) {
                const actual = data.context[field as keyof typeof data.context];
                if (typeof expected === 'string') {
                  if (actual !== expected) { conditionsMet = false; break; }
                } else if (typeof expected === 'object' && expected !== null) {
                  const op = expected as Record<string, unknown>;
                  if ('eq' in op && actual !== op.eq) { conditionsMet = false; break; }
                  if ('neq' in op && actual === op.neq) { conditionsMet = false; break; }
                  if ('in' in op && Array.isArray(op.in) && !op.in.includes(actual)) { conditionsMet = false; break; }
                  if ('contains' in op && typeof actual === 'string' && !actual.includes(op.contains as string)) { conditionsMet = false; break; }
                }
              }
              if (!conditionsMet) continue;
            } else if (rule.effect === 'permit') {
              continue; // permit cannot be validated without context — skip (fail-closed)
            }
            // conditional deny with no context → falls through and fires (over-block)
          }

          allowed = rule.effect === 'permit';
          reason = rule.effect === 'deny'
            ? `Denied by policy: ${policy.name}`
            : `Permitted by policy: ${policy.name}`;
          policy_id = policy.id;
          break;
        }
      }
      if (policy_id) break;

      if (policy.default_effect === 'deny' && !allowlistPolicy) {
        allowlistPolicy = { id: policy.id, name: policy.name };
      }
    }

    if (!policy_id && allowlistPolicy) {
      allowed = false;
      reason = `Denied by default — allowlist policy '${allowlistPolicy.name}' has no matching permit rule`;
      policy_id = allowlistPolicy.id;
    }

    const certificate_id = `cert_${randomUUID()}`;

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

  // ─── Compliance ───
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
      compliant: gaps.length === 0 && satisfied.length > 0,
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
    if (agentResult.rows.length === 0) throw HttpError.notFound('Agent not found');

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
        compliant: gaps.length === 0 && satisfied.length > 0,
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

    if (isNaN(pageNum) || isNaN(limitNum) || pageNum < 1 || limitNum < 1) {
      throw HttpError.badRequest('Invalid pagination parameters');
    }

    const agentResult = await pool.query('SELECT * FROM agents WHERE id = $1', [agent_id]);
    if (agentResult.rows.length === 0) throw HttpError.notFound('Agent not found');

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

  // ─── Dashboard ───
  fastify.get('/dashboard/summary', async () => {
    const agentStats = await pool.query(`
      SELECT
        COUNT(*) as total_agents,
        COUNT(*) FILTER (WHERE active = true AND quarantined = false) as active_agents,
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
    const hoursNum = parseInt(hours, 10);
    if (isNaN(hoursNum) || hoursNum < 1) throw HttpError.badRequest('Invalid hours parameter — must be a positive integer');
    const clampedHours = Math.min(hoursNum, 168);

    let result;
    if (agent_id) {
      result = await pool.query(
        `SELECT * FROM agent_events WHERE agent_id = $1 AND created_at > NOW() - INTERVAL '1 hour' * $2 ORDER BY created_at DESC`,
        [agent_id, clampedHours]
      );
    } else {
      result = await pool.query(
        `SELECT * FROM agent_events WHERE created_at > NOW() - INTERVAL '1 hour' * $1 ORDER BY created_at DESC`,
        [clampedHours]
      );
    }

    return { timeline: result.rows, count: result.rows.length, hours_range: clampedHours };
  });

  fastify.get('/dashboard/compliance/summary', async () => {
    const summary = await pool.query(`
      SELECT
        regulation,
        COUNT(*) as total_records,
        COUNT(*) FILTER (WHERE status = 'compliant') as compliant_records,
        COUNT(*) FILTER (WHERE status = 'pending') as pending_records,
        COUNT(*) FILTER (WHERE status NOT IN ('compliant', 'pending')) as gap_records
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

  // ─── Alerts ───
  fastify.get('/alerts', async (request) => {
    const { agent_id, acknowledged } = request.query as { agent_id?: string; acknowledged?: string };
    const params: unknown[] = [];
    let query = 'SELECT * FROM alerts WHERE 1=1';
    if (agent_id) { params.push(agent_id); query += ` AND agent_id = $${params.length}`; }
    if (acknowledged !== undefined) {
      if (acknowledged !== 'true' && acknowledged !== 'false') {
        throw HttpError.badRequest("acknowledged must be 'true' or 'false'");
      }
      params.push(acknowledged === 'true'); query += ` AND acknowledged = $${params.length}`;
    }
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
    if (result.rows.length === 0) throw HttpError.notFound('Alert not found');
    return { alert: result.rows[0] };
  });

  // ─── Discovery (shadow agent detection) ───
  // Ingest raw API-gateway access logs for shadow-agent scanning.
  fastify.post('/discovery/access-logs', async (request) => {
    const data = IngestAccessLogsSchema.parse(request.body);
    const inserted: { count: number } = { count: 0 };
    const client = await pool.connect();
    try {
      for (const log of data.access_logs) {
        const ts = log.timestamp ? new Date(log.timestamp) : new Date();
        await client.query(
          `INSERT INTO access_logs (api_key_hash, key_prefix, resource, observed_at)
           VALUES ($1, $2, $3, $4)`,
          [
            createHash('sha256').update(log.api_key).digest('hex'),
            log.api_key.length >= 4 ? `${log.api_key.slice(0, 2)}***` : '***',
            log.resource,
            ts,
          ]
        );
        inserted.count++;
      }
    } finally {
      client.release();
    }
    return { ingested: inserted.count };
  });

  // Run a shadow-agent scan against ingested access logs.
  fastify.post('/discovery/shadow-scan', async () => {
    const logsRes = await pool.query(
      `SELECT api_key_hash, key_prefix, resource, observed_at FROM access_logs ORDER BY observed_at ASC`
    );

    // Reconstruct a synthetic api_key per row is impossible (we only store hashes),
    // so we scan by hash directly: any access-log hash not present in agents.api_key_hash
    // is a shadow key. This is the real, privacy-preserving implementation.
    const discovered: { key_prefix: string; resource: string; observed_at: Date }[] = [];
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      for (const row of logsRes.rows) {
        const known = await client.query(
          'SELECT id FROM agents WHERE api_key_hash = $1',
          [row.api_key_hash]
        );
        if (known.rows.length === 0) {
          // Avoid duplicate shadow agents for the same key hash
          const existing = await client.query(
            `SELECT a.id FROM agents a
             JOIN alerts al ON al.agent_id = a.id
             WHERE a.api_key_hash = $1 AND al.type = 'shadow_agent_detected'`,
            [row.api_key_hash]
          );
          if (existing.rows.length === 0) {
            const agentRes = await client.query(
              `INSERT INTO agents (name, type, api_key_hash, metadata, active, quarantined)
               VALUES ($1, 'custom', $2, $3, true, false) RETURNING id`,
              [
                `shadow_${row.key_prefix}`,
                row.api_key_hash,
                JSON.stringify({ discovered_at: row.observed_at.toISOString(), resource: row.resource, shadow: true }),
              ]
            );
            await client.query(
              `INSERT INTO alerts (agent_id, type, severity, message, metadata)
               VALUES ($1, 'shadow_agent_detected', 'high', $2, $3)`,
              [
                agentRes.rows[0].id,
                `Shadow agent detected accessing ${row.resource}`,
                JSON.stringify({ key_prefix: row.key_prefix, resource: row.resource, observed_at: row.observed_at.toISOString() }),
              ]
            );
            discovered.push({ key_prefix: row.key_prefix, resource: row.resource, observed_at: row.observed_at });
          }
        }
      }
      await client.query('COMMIT');
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
    return { shadow_agents_detected: discovered.length, discovered };
  });

  // Behavior-based discovery: flag agents registered as 'custom'/'unknown' whose
  // action-pattern distribution matches a known baseline agent type with high
  // confidence — a strong signal of a misregistered or shadow agent.
  fastify.get('/discovery/behavior-scan', async () => {
    const discovery = new AgentDiscoveryService(pool);
    const findings = await discovery.detectByBehavior();
    return { behavior_findings: findings };
  });

  // ─── Dashboard UI (Vite + React build served at /ui/) ───
  // Served via @fastify/static at the /ui/ prefix to avoid any conflict with
  // the /dashboard/* JSON API routes. The React app calls the API with
  // absolute paths (/dashboard/summary, /agents, /alerts, ...).
  const __dirname = dirname(fileURLToPath(import.meta.url));
  const uiDir = join(__dirname, '..', '..', 'ui', 'dist');
  try {
    const { default: fastifyStatic } = await import('@fastify/static');
    await fastify.register(fastifyStatic, {
      root: uiDir,
      prefix: '/ui/',
      decorateReply: false,
    });
  } catch {
    // ui/dist may not exist when the UI hasn't been built — skip silently.
  }
  // Backward-compatible redirect from the old dashboard HTML path.
  fastify.get('/dashboard/', async (_request, reply) => {
    reply.redirect('/ui/', 301);
  });
  fastify.get('/dashboard', async (_request, reply) => {
    reply.redirect('/ui/', 301);
  });
  fastify.get('/', async (_request, reply) => {
    reply.redirect('/ui/', 302);
  });

  const close = async () => {
    await fastify.close();
    await pool.end();
  };

  return { fastify, pool, close };
}

/**
 * Start the server (listen on a port). Only runs when this file is the entry
 * point — importing buildServer() in tests does NOT start a listener.
 */
export async function start(): Promise<void> {
  const config = loadConfig();
  const { fastify, close } = await buildServer({ config });

  const shutdown = async (signal: string) => {
    fastify.log.info(`${signal} received, shutting down…`);
    await close();
    process.exit(0);
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));

  await fastify.listen({ port: config.port, host: config.host });
  fastify.log.info(`AI Agent Security Monitor running on port ${config.port}`);
}

if (fileURLToPath(import.meta.url) === process.argv[1]) {
  start().catch((err) => {
    console.error('Failed to start:', err);
    process.exit(1);
  });
}