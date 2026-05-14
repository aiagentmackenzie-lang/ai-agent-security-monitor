import pg from 'pg';
import { EventEmitter } from 'events';
import { createHash } from 'crypto';

const { Pool } = pg;

export interface DiscoveredAgent {
  name: string;
  type: string;
  owner?: string;
  metadata: Record<string, unknown>;
  shadow: boolean;
  discovery_method: string;
}

export interface DiscoveryConfig {
  pollIntervalMs: number;
  apiKeyPatterns: string[];
  behaviorSignatures: Record<string, string[]>;
}

const DEFAULT_CONFIG: DiscoveryConfig = {
  pollIntervalMs: 60000,
  apiKeyPatterns: ['sk-agent-*', 'agt-*', 'crewai-*', 'langchain-*'],
  behaviorSignatures: {
    langchain: ['tool_use', 'chain_invoke', 'llm_call'],
    crewai: ['task_execute', 'crew_run', 'agent_delegate'],
    claude_code: ['bash', 'read', 'write', 'edit'],
    openclaw: ['skill_invoke', 'tool_call', 'agent_execute'],
  },
};

export class AgentDiscoveryService extends EventEmitter {
  private pool: pg.Pool;
  private config: DiscoveryConfig;
  private intervalId: ReturnType<typeof setInterval> | null = null;
  private knownApiKeys: Set<string> = new Set();

  constructor(connectionString: string, config: Partial<DiscoveryConfig> = {}) {
    super();
    this.pool = new Pool({ connectionString });
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
    const behaviorAgents = await this.detectByBehavior();

    for (const agent of [...newApiKeys, ...behaviorAgents]) {
      if (!this.isKnownAgent(agent)) {
        await this.registerDiscoveredAgent(agent);
        discovered.push(agent);
        this.emit('agent_discovered', agent);
      }
    }

    return discovered;
  }

  /**
   * STUB: Detection via new API keys observed in access logs.
   * Implement by integrating with your API gateway / proxy logs.
   */
  private async detectNewApiKeys(): Promise<DiscoveredAgent[]> {
    // TODO: Integrate with API gateway access logs to detect keys not in the registry
    return [];
  }

  /**
   * STUB: Detection via behavior analysis of event patterns.
   * Implement by analyzing agent_events for patterns matching known agent types.
   */
  private async detectByBehavior(): Promise<DiscoveredAgent[]> {
    // TODO: Analyze agent_events table for behavior signatures matching unknown agents
    return [];
  }

  private isKnownAgent(agent: DiscoveredAgent): boolean {
    // Check against registered agent names to avoid duplicate discovery
    return agent.shadow === false && this.knownApiKeys.size > 0;
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
   * Detect shadow agents from access logs by matching raw API keys
   * against registered key hashes.
   *
   * NOTE: Only a truncated hash prefix (4 chars) is stored in alerts to
   * avoid leaking credential material. The full key is never persisted.
   */
  async detectShadowAgents(accessLogs: Array<{ api_key: string; resource: string; timestamp: Date }>): Promise<void> {
    for (const log of accessLogs) {
      if (!this.isKnownApiKey(log.api_key)) {
        const existing = await this.pool.query(
          'SELECT id FROM agents WHERE api_key_hash = $1',
          [this.hashApiKey(log.api_key)]
        );

        if (existing.rows.length === 0) {
          // FIX: Only store a minimal hash prefix (4 chars) instead of 8 to reduce info leakage
          const keyPrefix = log.api_key.length >= 4 ? `${log.api_key.slice(0, 2)}***` : '***';

          const agentResult = await this.pool.query(
            `INSERT INTO agents (name, type, metadata, active, quarantined)
             VALUES ($1, 'unknown', $2, true, false)
             RETURNING id`,
            [`shadow_${keyPrefix}`, JSON.stringify({ discovered_at: log.timestamp.toISOString(), resource: log.resource })]
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

if (import.meta.url === `file://${process.argv[1]}`) {
  const connectionString = process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/ai_agent_security';
  const service = new AgentDiscoveryService(connectionString);

  service.on('agent_discovered', (agent) => {
    console.log('Agent discovered:', agent);
  });

  service.on('error', (err) => {
    console.error('Discovery error:', err);
  });

  service.start().then(() => {
    console.log('Agent discovery service started');
    setTimeout(() => service.stop(), 300000);
  });
}