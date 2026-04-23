import { Pool } from 'pg';

export async function initDb(connectionString: string) {
  const pool = new Pool({ connectionString });

  await pool.query(`
    CREATE TABLE IF NOT EXISTS agents (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name VARCHAR(255) NOT NULL,
      type VARCHAR(100) NOT NULL,
      api_key_hash VARCHAR(255),
      owner VARCHAR(255),
      metadata JSONB DEFAULT '{}',
      active BOOLEAN DEFAULT true,
      quarantined BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS agent_events (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      agent_id UUID REFERENCES agents(id),
      event_type VARCHAR(100) NOT NULL,
      action VARCHAR(255),
      resource VARCHAR(255),
      result VARCHAR(50),
      details JSONB DEFAULT '{}',
      previous_hash VARCHAR(64),
      hash VARCHAR(64) NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS policies (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name VARCHAR(255) NOT NULL,
      description TEXT,
      rules JSONB NOT NULL DEFAULT '[]',
      agent_ids TEXT[] DEFAULT ARRAY['*'],
      active BOOLEAN DEFAULT true,
      default_effect VARCHAR(10), -- 'permit' or 'deny' — when 'deny', unmatched actions are blocked (allowlist mode)
      priority INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS compliance_records (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      agent_id UUID REFERENCES agents(id),
      regulation VARCHAR(100) NOT NULL,
      control_id VARCHAR(100),
      evidence JSONB DEFAULT '{}',
      status VARCHAR(50) DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS alerts (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      agent_id UUID REFERENCES agents(id),
      type VARCHAR(100) NOT NULL,
      severity VARCHAR(50) DEFAULT 'medium',
      message TEXT NOT NULL,
      acknowledged BOOLEAN DEFAULT false,
      acknowledged_by VARCHAR(255),
      acknowledged_at TIMESTAMP,
      metadata JSONB DEFAULT '{}',
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_agent_events_agent_id ON agent_events(agent_id);
    CREATE INDEX IF NOT EXISTS idx_agent_events_created_at ON agent_events(created_at);
    CREATE INDEX IF NOT EXISTS idx_compliance_records_agent_id ON compliance_records(agent_id);
    CREATE INDEX IF NOT EXISTS idx_policies_active ON policies(active);
    CREATE INDEX IF NOT EXISTS idx_alerts_agent_id ON alerts(agent_id);
    CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON alerts(acknowledged);
  `);

  console.log('Database initialized successfully');
  await pool.end();
}

if (import.meta.url === `file://${process.argv[1]}`) {
  initDb(process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/ai_agent_security')
    .then(() => process.exit(0))
    .catch((e) => { console.error(e); process.exit(1); });
}
