# AI Agent Security Monitor — Continue Prompt

## Project Location
`/Users/main/Security Apps/AI Agent Security Monitor/`

## Project Overview
Runtime access control and observability plane for AI agents. Supports LangChain, CrewAI, Claude Code, OpenClaw, OpenAI Agents, and custom agent types.

## Current Status
| Phase | Status |
|-------|--------|
| Phase 1: Foundation & Agent Visibility Layer | ✅ COMPLETE |
| Phase 2: Policy Enforcement Engine | ✅ COMPLETE |
| Phase 3: Compliance Evidence Collector | ⏳ NOT STARTED |
| Phase 4: Agent Discovery Scanner | ⏳ NOT STARTED |

---

## Quick Start (Run First Every Session)

```bash
cd "/Users/main/Security Apps/AI Agent Security Monitor"

# Start Docker PostgreSQL (if not running)
docker compose up -d postgres

# Verify Postgres is ready
docker exec aiagentsecuritymonitor-postgres-1 pg_isready -U postgres

# Run migrations (only if schema changed)
npm run db:migrate

# Start dev server
npm run dev

# Verify server is up
curl http://localhost:8000/health
```

**Expected response:** `{"status":"ok","timestamp":"..."}`

---

## Static Verification (Must Pass Before Declaring Any Work Done)

```bash
cd "/Users/main/Security Apps/AI Agent Security Monitor"
npm run typecheck   # Must show 0 errors
npm run lint         # Must show 0 errors
npm test            # Must show 12/12 passing
```

---

## What Was Built

### Core Architecture
- **Fastify API** running on port 8000 with 22+ endpoints
- **MCP Server** (stdio) with 5 tools integrated with the API
- **PostgreSQL** database with 5 tables
- **Redis** (available but not yet actively used)

### API Endpoints (22+)
| Category | Endpoints |
|----------|-----------|
| Agents | `GET /agents`, `POST /agents`, `GET /agents/:id`, `PATCH /agents/:id`, `DELETE /agents/:id`, `POST /agents/:id/quarantine`, `POST /agents/:id/unquarantine`, `POST /agents/:id/revoke`, `GET /agents/:id/events`, `POST /agents/:id/events` |
| Policies | `GET /policies`, `POST /policies`, `GET /policies/:id`, `PATCH /policies/:id`, `DELETE /policies/:id` |
| Policy Eval | `POST /policy/evaluate` |
| Compliance | `GET /compliance/:agent_id/:regulation` |
| Alerts | `GET /alerts`, `POST /alerts/:id/acknowledge` |
| Health | `GET /health` |

### MCP Tools (5)
1. `gate_action` — Bounded tier policy evaluation (returns allow/deny + certificate)
2. `enforced_tool_call` — Strong tier tool proxy (blocks denied calls, logs to audit)
3. `register_agent` — Register new agent via API
4. `log_event` — Log agent action to audit trail
5. `query_compliance` — Query compliance status by regulation

### Key Features Working
- Glob pattern matching in policy rules (e.g., `data/*` matches `data/file.txt`)
- Priority ordering in policy evaluation (higher priority = evaluated first)
- Quarantine/revoke auto-denies in policy evaluation
- Alerts auto-created on quarantine and revocation events
- Hash-chained audit events (on revoke)
- Agent types: `langchain`, `crewai`, `claude_code`, `openclaw`, `openai_agents`, `custom`

---

## Database Schema (PostgreSQL)

### Table: `agents`
```sql
id UUID PRIMARY KEY, name VARCHAR, type VARCHAR, api_key_hash VARCHAR,
owner VARCHAR, metadata JSONB, active BOOLEAN, quarantined BOOLEAN,
created_at TIMESTAMP, updated_at TIMESTAMP
```

### Table: `agent_events`
```sql
id UUID PRIMARY KEY, agent_id UUID REFERENCES agents(id),
event_type VARCHAR, action VARCHAR, resource VARCHAR, result VARCHAR,
details JSONB, previous_hash VARCHAR(64), hash VARCHAR(64), created_at TIMESTAMP
```

### Table: `policies`
```sql
id UUID PRIMARY KEY, name VARCHAR, description TEXT,
rules JSONB NOT NULL, agent_ids TEXT[], active BOOLEAN, priority INTEGER,
created_at TIMESTAMP, updated_at TIMESTAMP
```

### Table: `compliance_records`
```sql
id UUID PRIMARY KEY, agent_id UUID REFERENCES agents(id),
regulation VARCHAR, control_id VARCHAR, evidence JSONB,
status VARCHAR, created_at TIMESTAMP
```

### Table: `alerts`
```sql
id UUID PRIMARY KEY, agent_id UUID REFERENCES agents(id),
type VARCHAR, severity VARCHAR, message TEXT,
acknowledged BOOLEAN, acknowledged_by VARCHAR, acknowledged_at TIMESTAMP,
metadata JSONB, created_at TIMESTAMP
```

---

## Phase 3: Compliance Evidence Collector

**Goal**: Map agent actions to regulations, auto-generate reports, cryptographic proof

### Chunk 3.1: Compliance Evidence Mapping
- Map each agent event to applicable regulations
- Store evidence in `compliance_records` table
- Track which controls are satisfied per agent

### Chunk 3.2: Compliance Status API
- `GET /compliance/:agent_id/:regulation` — already exists
- Return: `compliant`, `controls_satisfied`, `gaps`, `evidence_count`

### Chunk 3.3: Compliance Report Generation
- `GET /compliance/reports/:agent_id` — generate full report
- Include: all events, policy evaluations, compliance mappings
- Export as JSON structure

### Chunk 3.4: Cryptographic Audit Trail
- Implement hash-chaining on `agent_events`
- Each event hash includes previous event hash
- Tampering detection: if chain breaks, audit fails
- **NOTE**: Hash-chaining already partially exists (on revoke events)

### Chunk 3.5: ai-compliance-engine Integration
- Connect to existing `ai-compliance-engine` for framework controls
- Map platform events → compliance framework requirements

### Chunk 3.6: Report Export
- `GET /compliance/export/:agent_id` — export as JSON
- Support pagination for large event sets
- Include certificate chain for verification

---

## Important Implementation Notes

### Dotenv Required
The API server **requires** `import 'dotenv/config'` at the top of `src/api/server.ts` to load environment variables from `.env` file. Without it, `DATABASE_URL` is undefined and causes `SASL: SCRAM-SERVER-FIRST-MESSAGE: client password must be a string` errors.

### Policy Evaluation Logic
Located in `POST /policy/evaluate` in `src/api/server.ts`:
- Checks if agent is quarantined or inactive first (blocks if true)
- Queries policies ordered by priority DESC
- Uses glob pattern matching via `matchPattern()` function
- Returns `{ allowed, reason, certificate_id, policy_id, agent_id, action, resource, evaluated_at }`

### MCP Server
Located in `src/mcp/server.ts`:
- Runs on stdio
- Connects to API at `http://localhost:8000` (configurable via `API_BASE_URL`)
- All tools call the API endpoints

### Compliance Mapper
Located in `src/compliance/mapper.ts`:
- Defines requirements for: `gdpr`, `ai_act`, `ccpa`, `hipaa`, `finra`
- `getComplianceStatus()` function checks records against requirements

---

## File Structure
```
AI Agent Security Monitor/
├── src/
│   ├── api/server.ts       # Fastify API (import 'dotenv/config' first!)
│   ├── mcp/server.ts       # MCP server with 5 tools
│   ├── policy/engine.ts    # Policy evaluation logic
│   ├── compliance/mapper.ts # Regulation mappings
│   ├── agents/registry.ts  # Agent factory functions
│   ├── db/init.ts          # Database schema
│   └── types.ts           # TypeScript interfaces
├── scripts/
│   └── migrate.ts          # Database migrations
├── tests/
│   └── policy.test.ts      # 12 unit tests
├── docker-compose.yml      # PostgreSQL + Redis
├── IMPLEMENTATION_PLAN.md  # Full 4-phase plan (READ THIS)
├── SESSION_SUMMARY.md      # Current session state
├── CONTINUE_PROMPT.md       # This file
└── .env                    # DATABASE_URL=postgresql://...
```

---

## Critical Rules
1. **Always run static verification** (`npm run typecheck`, `npm run lint`, `npm test`) before declaring work done
2. **Always verify runtime** after starting server: `curl http://localhost:8000/health`
3. **Read IMPLEMENTATION_PLAN.md** for full Phase 3 chunk details before implementing
4. **Keep .env file** — contains `DATABASE_URL` pointing to Docker PostgreSQL

---

## Next Step
Start Phase 3, Chunk 3.1: Compliance Evidence Mapping. Read Section "Phase 3" in `IMPLEMENTATION_PLAN.md` for full details on each chunk before implementing. Begin by understanding the current compliance mapper in `src/compliance/mapper.ts` and how agent events should map to compliance records.