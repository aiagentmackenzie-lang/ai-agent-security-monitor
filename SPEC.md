# AI Agent Security Monitor — Specification

## 1. Overview

**Project Name**: AI Agent Security Monitor  
**Category**: AI Agent Governance & Runtime Security Platform  
**Core Function**: Runtime access control and observability plane for every AI agent operating against an organization's data — authorized or not, owned by IT or not, known to security or not.

---

## 2. Problem Statement

Every company now has AI agents operating against their data:

- Claude Code on employee laptops
- OpenClaw agents running in any environment
- Custom agents built by engineering teams
- ChatGPT integrations in sales workflows
- AI assistants in finance departments
- Third-party agents connected to company APIs

**No one knows which agents exist, what they have access to, or what they're doing with that access.**

This platform solves that.

---

## 3. Core Capabilities (Three Layers)

### 3.1 Discovery — Find every agent
Continuously discover every AI agent with access to company systems:
- Agents running on employee devices
- Agents in the cloud
- Third-party agents connected to APIs
- Shadow agents nobody told IT about

### 3.2 Observability — Track what they do
Track every agent action in real-time:
- Which tools each agent calls
- What data it accesses
- What it sends to external APIs
- What comes back

### 3.3 Control — Enforce policy
Enforce rules at the agent level:
- Revoke access when an employee leaves
- Block an agent from calling a sensitive API
- Quarantine agents exhibiting anomalous behavior
- Generate compliance evidence automatically

---

## 4. Technical Architecture

### 4.1 System Components

```
┌─────────────────────────────────────────────────────────────┐
│                   AI Agent Security Monitor                  │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐│
│  │   MCP        │     │   Policy     │     │   Agent      ││
│  │   Security   │────►│   Engine     │────►│   Registry   ││
│  │   Server     │     │              │     │   (DB)       ││
│  │   (Proxy)    │     │  - Z3        │     │              ││
│  │              │     │  - Cedar     │     │  - Identity  ││
│  │  - gate_     │     │  - Rules     │     │  - API keys  ││
│  │    action    │     │              │     │  - Sessions  ││
│  │  - enforced  │     └──────────────┘     └──────────────┘│
│  │    tool_call │              │                    │       │
│  └──────────────┘              │                    │       │
│         │                      │                    │       │
│         ▼                      ▼                    │       │
│  ┌──────────────┐     ┌──────────────┐            │       │
│  │  Decision     │     │  Audit       │◄───────────┘       │
│  │  Certificate │     │  Trail       │                    │
│  │  Store       │     │  (Hash-      │                    │
│  │              │     │  Chained)    │                    │
│  └──────────────┘     └──────────────┘                    │
│                               │                             │
│                               ▼                             │
│                      ┌──────────────┐                      │
│                      │ Compliance   │                      │
│                      │ Evidence     │                      │
│                      │ Collector    │                      │
│                      └──────────────┘                      │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 MCP Security Server

The MCP server acts as a **non-bypassable proxy** between AI agents and the tools/data they access.

#### Tools Exposed

| Tool | Type | Description |
|------|------|-------------|
| `gate_action` | Destructive | Pre-execution policy check + signed certificate |
| `register_agent` | Destructive | Register a new agent in the system |
| `log_event` | Destructive | Log an agent action event |
| `query_compliance` | Read | Query compliance evidence |

#### Enforcement Tiers

1. **Strong** — MCP server as tool proxy. Agents call tools through MCP server, which checks policy and signs before allowing execution.

2. **Bounded** — Pre-execution gates check policy and sign the decision before the agent acts.

3. **Detectable** — Every action gets a hash-chained audit entry. If logs are tampered with, the chain breaks.

### 4.3 Policy Engine

- **Pattern Matching**: Glob-style patterns (`data:delete:*`, `/admin/*`)
- **Cedar-inspired JSON policies**: Human-readable rule format
- **Z3 Integration** (future): Formal verification for complex multi-step plans
- **Default**: Allow by default, deny by exception

### 4.4 Agent Registry

Stores:
- Agent identity (ID, name, type)
- API key hashes for identification
- Owner/creator
- Metadata (version, capabilities, last seen)
- Active/inactive status

### 4.5 Audit Trail

- Append-only event log
- Hash-chained entries (detect tampering)
- Includes: agent_id, action, resource, result, timestamp, context

### 4.6 Compliance Evidence Collector

Maps agent actions to regulatory requirements:

| Regulation | Key Requirement | Control |
|------------|-----------------|---------|
| GDPR Art. 22 | Automated decisions affecting individuals | Document & explain |
| AI Act Art. 12 | System operations documentation | Maintain logs |
| CCPA | Consumer data access | Document & revocable |
| HIPAA | PHI access logging | Monitored & logged |
| FINRA | AI-assisted financial services | Audit trails |

---

## 5. Data Model

### 5.1 Database Schema

```sql
-- Agents table
CREATE TABLE agents (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  type VARCHAR(100) NOT NULL,  -- langchain, crewai, claude_code, openclaw, openai_agents, custom
  api_key_hash VARCHAR(255),
  owner VARCHAR(255),
  metadata JSONB DEFAULT '{}',
  active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Agent events (audit trail)
CREATE TABLE agent_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id UUID REFERENCES agents(id),
  event_type VARCHAR(100) NOT NULL,
  action VARCHAR(255),
  resource VARCHAR(255),
  result VARCHAR(50),  -- success, denied, error
  details JSONB DEFAULT '{}',
  created_at TIMESTAMP DEFAULT NOW()
);

-- Policies
CREATE TABLE policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  description TEXT,
  rules JSONB NOT NULL DEFAULT '[]',
  agent_ids TEXT[] DEFAULT ARRAY['*'],
  active BOOLEAN DEFAULT true,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- Compliance records
CREATE TABLE compliance_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_id UUID REFERENCES agents(id),
  regulation VARCHAR(100) NOT NULL,
  control_id VARCHAR(100),
  evidence JSONB DEFAULT '{}',
  status VARCHAR(50) DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT NOW()
);
```

---

## 6. API Endpoints

### 6.1 Agent Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/agents` | List all registered agents |
| POST | `/agents` | Register a new agent |
| GET | `/agents/:id` | Get agent details |
| PATCH | `/agents/:id` | Update agent |
| DELETE | `/agents/:id` | Deactivate agent |
| GET | `/agents/:id/events` | Get agent's event history |

### 6.2 Policy Management

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/policies` | List all policies |
| POST | `/policies` | Create a policy |
| POST | `/policy/evaluate` | Evaluate an action against policies |
| PATCH | `/policies/:id` | Update a policy |
| DELETE | `/policies/:id` | Delete a policy |

### 6.3 Compliance

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/compliance/:agent_id/:regulation` | Get compliance status |
| GET | `/compliance/reports/:agent_id` | Generate compliance report |

### 6.4 MCP Server Tools (via stdio)

| Tool | Description |
|------|-------------|
| `gate_action` | Evaluate policy before execution |
| `register_agent` | Register a new agent |
| `log_event` | Log an audit event |
| `query_compliance` | Check compliance status |

---

## 7. Build Phases

### Phase 1: Agent Visibility Layer (Now)
- [x] Agent registry (PostgreSQL)
- [x] Basic audit event logging
- [x] MCP server with `gate_action`, `register_agent`, `log_event`
- [x] Simple policy evaluation (pattern matching)
- [ ] Agent inventory dashboard
- [ ] Integration with SecurityScarletAI for anomaly detection

### Phase 2: Policy Enforcement Engine (6 months)
- [ ] Policy engine with allow/deny rules per agent, data source, tool
- [ ] Automatic agent quarantine on threat detection
- [ ] Access revocation tied to HR/IT lifecycle events
- [ ] Alerting and incident creation

### Phase 3: Compliance Evidence Collector (12 months)
- [ ] Map agent interactions to GDPR/AI Act/CCPA controls
- [ ] Auto-generate compliance reports
- [ ] Cryptographic proof of data access
- [ ] Integration with ai-compliance-engine

### Phase 4: Agent Discovery Scanner (18 months)
- [ ] Proactive scanning for unknown agents
- [ ] API key and OAuth token discovery
- [ ] Shadow agent alerting

---

## 8. Tech Stack

| Layer | Technology |
|-------|------------|
| Runtime | Node.js 20+ LTS |
| Language | TypeScript |
| API Framework | Fastify |
| Database | PostgreSQL 16+ |
| Queue | BullMQ |
| Cache | Redis |
| MCP SDK | @modelcontextprotocol/sdk |
| Policy Engine | Cedar-inspired JSON + Z3 (future) |
| Cryptography | Ed25519, ML-DSA-65 (future) |
| Container | Docker + Docker Compose |
| Testing | Vitest |

---

## 9. Integration Points

### 9.1 With Existing SecurityScarletAI Infrastructure

The platform integrates with existing components:

| Component | Integration Point |
|-----------|-----------------|
| unified-monitor | Agent event bus |
| SecurityScarletAI | Anomaly detection |
| ai-compliance-engine | Compliance mapping |
| threat-intelligence-platform | Threat intel cross-reference |

### 9.2 MCP Ecosystem

Works with any MCP-compatible agent. **OpenClaw is a principal integration target:**

- **OpenClaw** — Primary integration. OpenClaw agents running in any environment connect via MCP to receive policy decisions, log events, and query compliance status
- Claude Desktop
- Claude Code
- Cursor
- VS Code Copilot
- Custom agents via MCP SDK

#### OpenClaw Integration Architecture

```
OpenClaw Agent
      │
      │ MCP (stdio)
      ▼
┌──────────────────┐
│ AI Agent Security │
│ Monitor MCP Server │
│                    │
│ gate_action        │──► Policy Engine ──► Decision Certificate
│ register_agent     │──► Agent Registry
│ log_event         │──► Audit Trail
│ query_compliance  │──► Compliance Evidence
└──────────────────┘
```

OpenClaw agents register on startup, gate every sensitive action through the policy engine, and log all tool calls to the audit trail. Compliance queries return evidence mapped to GDPR/AI Act/CCPA/HIPAA/FINRA controls.

---

## 10. Security Considerations

- API keys are hashed before storage
- Audit log is append-only with hash chaining
- MCP server runs as a local proxy (no remote code execution)
- All inputs validated with Zod schemas
- Secrets managed via environment variables

---

## 11. Future Enhancements

- **Quantum-safe signatures**: ML-DSA-65 (FIPS 204) for decision certificates
- **Formal verification**: Z3 theorem prover for multi-step plan verification
- **Cross-customer threat intelligence**: Shared behavioral patterns
- **Predictive access risk scoring**: ML-based anomaly detection

---

*Document Version: 0.1.0*  
*Created: April 2026*  
*Classification: Internal*
