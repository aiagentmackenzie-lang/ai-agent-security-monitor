import pg, { Pool } from 'pg';
import { EventEmitter } from 'events';
import { createHash } from 'crypto';
import { fileURLToPath } from 'url';
import { DEFAULT_BASELINES } from '../services/baseline.js';

export interface DiscoveredAgent {
  name: string;
  type: string;
  owner?: string;
  metadata: Record<string, unknown>;
  shadow: boolean;
  discovery_method: string;
}

export interface BehaviorFinding {
  agent_id: string;
  agent_name: string;
  registered_type: string;
  inferred_type: string;
  confidence: number;
  evidence: { action_prefix: string; count: number; matches_baseline: boolean }[];
  description: string;
}

export interface DiscoveryConfig {
  pollIntervalMs: number;
  apiKeyPatterns: string[];
  /** Minimum fraction of an agent's events that must match a baseline type to infer it. */
  behaviorConfidenceThreshold: number;
  /** Minimum events before behavior inference is attempted. */
  minEventsForBehavior: number;
}

const DEFAULT_CONFIG: DiscoveryConfig = {
  pollIntervalMs: 60000,
  apiKeyPatterns: ['sk-agent-*', 'agt-*', 'crewai-*', 'langchain-*'],
  behaviorConfidenceThreshold: 0.6,
  minEventsForBehavior: 10,
};

/**
 * Agent discovery service — detects AI agents operating in the environment that
 * are not registered with the governance plane.
 *
 * Two real signals are implemented (no stubs):
 *
 *   1. detectNewApiKeys()  — scans the `access_logs` table (ingested from an API
 *      gateway) for API-key hashes that do not appear in `agents.api_key_hash`.
 *      Only SHA-256 hashes are ever persisted; raw keys never touch the DB.
 *
 *   2. detectByBehavior()  — analyses `agent_events` for agents registered as
 *      'custom' whose action-prefix distribution matches a known baseline agent
 *      type above a confidence threshold. A strong signal of a misregistered or
 *      shadow agent masquerading under a generic type.
 */
export class AgentDiscoveryService extends EventEmitter {
  private pool: Pool;
  private config: DiscoveryConfig;
  private intervalId: ReturnType<typeof setInterval> | null = null;
  private knownApiKeys: Set<string> = new Set();

  constructor(poolOrConnString: Pool | string, config: Partial<DiscoveryConfig> = {}) {
    super();
    if (typeof poolOrConnString === 'string') {
      const { Pool } = pg;
      this.pool = new Pool({ connectionString: poolOrConnString });
    } else {
      this.pool = poolOrConnString;
    }
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  async start(): Promise<void> {
    await this.loadKnownApiKeys();
    this.intervalId = setInterval(() => {
      this.scan().catch(err => this.emit('error', err));
    }, this.config.pollIntervalMs);
    this.emit('started');
  }

  stop(): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    this.emit('stopped');
  }

  private async loadKnownApiKeys(): Promise<void> {
    const result = await this.pool.query(
      'SELECT api_key_hash FROM agents WHERE api_key_hash IS NOT NULL'
    );
    this.knownApiKeys = new Set(result.rows.map(r => r.api_key_hash));
  }

  async scan(): Promise<DiscoveredAgent[]> {
    const discovered: DiscoveredAgent[] = [];
    const newApiKeys = await this.detectNewApiKeys();

    for (const agent of newApiKeys) {
      await this.registerDiscoveredAgent(agent);
      discovered.push(agent);
      this.emit('agent_discovered', agent);
    }

    return discovered;
  }

  /**
   * Detect shadow agents by scanning ingested access logs for API-key hashes
   * that are not present in the registered agent set. Raw API keys are never
   * stored — only their SHA-256 hash, and a 2-char + `***` prefix for triage.
   */
  async detectNewApiKeys(): Promise<DiscoveredAgent[]> {
    await this.loadKnownApiKeys();
    const logs = await this.pool.query(
      `SELECT api_key_hash, key_prefix, resource, MAX(observed_at) AS last_seen
       FROM access_logs
       GROUP BY api_key_hash, key_prefix, resource
       ORDER BY last_seen DESC`
    );

    const discovered: DiscoveredAgent[] = [];
    const seen = new Set<string>();

    for (const row of logs.rows) {
      if (this.knownApiKeys.has(row.api_key_hash)) continue;
      // Deduplicate by key hash across resources
      if (seen.has(row.api_key_hash)) continue;
      seen.add(row.api_key_hash);

      // Skip if a shadow agent already exists for this hash
      const existing = await this.pool.query(
        'SELECT id FROM agents WHERE api_key_hash = $1',
        [row.api_key_hash]
      );
      if (existing.rows.length > 0) continue;

      discovered.push({
        name: `shadow_${row.key_prefix}`,
        type: 'custom',
        owner: 'unknown',
        metadata: {
          discovered_at: row.last_seen.toISOString(),
          resource: row.resource,
          shadow: true,
          key_prefix: row.key_prefix,
        },
        shadow: true,
        discovery_method: 'access_log_key_scan',
      });
    }

    return discovered;
  }

  /**
   * Detect agents whose registered type is 'custom' but whose observed action
   * distribution matches a known baseline agent type above the confidence
   * threshold. Returns a finding per agent with the inferred type and evidence.
   *
   * This does not mutate state — callers (or an operator) decide whether to
   * reclassify, quarantine, or investigate. Findings are emitted as events.
   */
  async detectByBehavior(): Promise<BehaviorFinding[]> {
    const candidates = await this.pool.query(
      `SELECT a.id, a.name, a.type
       FROM agents a
       WHERE a.type = 'custom' AND a.active = true`
    );

    const findings: BehaviorFinding[] = [];

    for (const agent of candidates.rows) {
      const events = await this.pool.query(
        `SELECT action FROM agent_events WHERE agent_id = $1 AND action IS NOT NULL`,
        [agent.id]
      );
      if (events.rows.length < this.config.minEventsForBehavior) continue;

      const actionPrefixes = events.rows.map((r: { action: string }) => (r.action || '').split(':')[0]);
      const total = actionPrefixes.length;

      let best: { type: string; confidence: number; evidence: BehaviorFinding['evidence'] } | null = null;

      for (const baseline of DEFAULT_BASELINES) {
        const baselinePrefixes = new Set(baseline.action_patterns.map(p => p.split(':')[0]));
        const evidence: BehaviorFinding['evidence'] = [];
        let matched = 0;
        for (const prefix of new Set(actionPrefixes)) {
          const count = actionPrefixes.filter(p => p === prefix).length;
          const matches = baselinePrefixes.has(prefix);
          if (matches) matched += count;
          evidence.push({ action_prefix: prefix, count, matches_baseline: matches });
        }
        const confidence = matched / total;
        if (confidence >= this.config.behaviorConfidenceThreshold) {
          if (!best || confidence > best.confidence) {
            best = { type: baseline.agent_type, confidence, evidence };
          }
        }
      }

      if (best) {
        const finding: BehaviorFinding = {
          agent_id: agent.id,
          agent_name: agent.name,
          registered_type: agent.type,
          inferred_type: best.type,
          confidence: Math.round(best.confidence * 100) / 100,
          evidence: best.evidence,
          description: `Agent '${agent.name}' is registered as 'custom' but its action distribution matches the '${best.type}' baseline with ${Math.round(best.confidence * 100)}% confidence — likely misregistered or a shadow agent.`,
        };
        findings.push(finding);
        this.emit('behavior_finding', finding);
      }
    }

    return findings;
  }

  private async registerDiscoveredAgent(agent: DiscoveredAgent): Promise<void> {
    const result = await this.pool.query(
      `INSERT INTO agents (name, type, owner, metadata, active, quarantined)
       VALUES ($1, $2, $3, $4, true, false)
       RETURNING id`,
      [agent.name, agent.type, agent.owner || 'unknown', JSON.stringify(agent.metadata)]
    );

    await this.pool.query(
      `INSERT INTO alerts (agent_id, type, severity, message, metadata)
       VALUES ($1, 'shadow_agent_detected', 'high', $2, $3)`,
      [
        result.rows[0].id,
        `Discovered unregistered agent: ${agent.name}`,
        JSON.stringify({ discovery_method: agent.discovery_method, shadow: agent.shadow }),
      ]
    );
  }

  /**
   * Detect shadow agents from an in-memory list of raw access logs by matching
   * raw API keys against registered key hashes. Only a truncated prefix is
   * stored in alerts. The full key is never persisted.
   */
  async detectShadowAgents(accessLogs: Array<{ api_key: string; resource: string; timestamp: Date }>): Promise<void> {
    for (const log of accessLogs) {
      if (!this.isKnownApiKey(log.api_key)) {
        const hash = this.hashApiKey(log.api_key);
        const existing = await this.pool.query(
          'SELECT id FROM agents WHERE api_key_hash = $1',
          [hash]
        );

        if (existing.rows.length === 0) {
          const keyPrefix = log.api_key.length >= 4 ? `${log.api_key.slice(0, 2)}***` : '***';

          const agentResult = await this.pool.query(
            `INSERT INTO agents (name, type, api_key_hash, metadata, active, quarantined)
             VALUES ($1, 'custom', $2, $3, true, false)
             RETURNING id`,
            [
              `shadow_${keyPrefix}`,
              hash,
              JSON.stringify({ discovered_at: log.timestamp.toISOString(), resource: log.resource }),
            ]
          );

          await this.pool.query(
            `INSERT INTO alerts (agent_id, type, severity, message, metadata)
             VALUES ($1, 'shadow_agent_detected', 'high', $2, $3)`,
            [
              agentResult.rows[0].id,
              `Shadow agent detected accessing ${log.resource}`,
              JSON.stringify({ key_prefix: keyPrefix, resource: log.resource }),
            ]
          );
        }
      }
    }
  }

  private isKnownApiKey(apiKey: string): boolean {
    return this.knownApiKeys.has(this.hashApiKey(apiKey));
  }

  private hashApiKey(apiKey: string): string {
    return createHash('sha256').update(apiKey).digest('hex');
  }

  async discoverOrphanedTokens(activeKeys: string[]): Promise<string[]> {
    const orphaned: string[] = [];
    const result = await this.pool.query(
      'SELECT api_key_hash FROM agents WHERE api_key_hash IS NOT NULL'
    );
    const registeredKeys = new Set(result.rows.map(r => r.api_key_hash));

    for (const key of activeKeys) {
      const hash = this.hashApiKey(key);
      if (!registeredKeys.has(hash)) {
        orphaned.push(key);
      }
    }

    return orphaned;
  }
}

if (fileURLToPath(import.meta.url) === process.argv[1]) {
  const connectionString = process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/ai_agent_security';
  const service = new AgentDiscoveryService(connectionString);

  service.on('agent_discovered', (agent) => {
    console.log('Agent discovered:', agent);
  });
  service.on('behavior_finding', (f) => {
    console.log('Behavior finding:', f);
  });
  service.on('error', (err) => {
    console.error('Discovery error:', err);
  });

  service.start().then(() => {
    console.log('Agent discovery service started');
    setTimeout(() => service.stop(), 300000);
  });
}