# AI Agent Security Monitor

[![Node.js](https://img.shields.io/badge/node-20%2B-green?logo=node.js)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/typescript-5.0-blue?logo=typescript)](https://www.typescriptlang.org/)
[![Fastify](https://img.shields.io/badge/framework-Fastify-009688?logo=fastapi)](https://fastify.dev/)
[![Tests](https://img.shields.io/badge/tests-80%20passing-brightgreen)](./tests)
[![OWASP Agentic](https://img.shields.io/badge/OWASP-Agentic%20Top%2010%202026-purple)](https://genai.owasp.org/)
[![License](https://img.shields.io/badge/license-ISC-green)](./LICENSE)

**Runtime access control and observability plane for every AI agent operating against your organization's data — authorized or not, owned by IT or not, known to security or not.**

## What Is This?

Every company now has AI agents operating against their data. OpenClaw agents on servers. Claude Code on laptops. Custom agents in engineering. ChatGPT in sales. AI assistants in finance. Third-party agents connected to APIs.

**No one knows which agents exist, what they have access to, or what they're doing with that access.**

This platform solves that at three layers:

1. **Discovery** — Find every AI agent with access to your systems
2. **Observability** — Track what every agent does in real-time
3. **Control** — Enforce policy and generate compliance evidence

## Features

| Feature | Description |
|---------|-------------|
| 🔍 Agent Discovery | Detect shadow AI agents via API key scanning and behavior signatures |
| 📊 Policy Engine | Deny-by-default and allowlist modes with wildcard pattern matching |
| 🔒 Sensitive Data Redaction | Auto-redact 18+ secret types (API keys, tokens, PII) before persistence |
| ⛓️ Hash-Chained Audit Trail | Tamper-evident event log with SHA-256 chain verification |
| 🏥 Agent Quarantine | Instantly isolate rogue agents with one API call |
| 📋 Compliance Mapping | Auto-map agent actions to GDPR, AI Act, CCPA, HIPAA, FINRA |
| 🚨 Alert System | Severity-graded alerts for policy violations and sensitive data detection |
| 📡 Behavior Baselines | Anomaly detection for frequency spikes, off-hours activity, unusual actions |
| 📄 Compliance Export | Generate paginated evidence with hash chain verification for auditors |
| 🤖 MCP Integration | Act as a non-bypassable proxy gate for OpenClaw / Claude Code agents |

## Quick Start

### Prerequisites

- Node.js 20+
- Docker & Docker Compose (Colima / Docker Desktop)

### Installation

```bash
# Clone and install
git clone https://github.com/aiagentmackenzie-lang/ai-agent-security-monitor.git
cd ai-agent-security-monitor
npm install

# Copy environment template
cp .env.example .env

# Start infrastructure (PostgreSQL + Redis)
docker compose up -d

# Run database migrations
npm run db:migrate

# (Optional) Seed demo data
npm run db:seed

# Start the API server with hot reload
npm run dev
```

Server runs on `http://localhost:8000`. Swagger UI at `/documentation`.

### Development

```bash
npm run dev          # Start with hot reload
npm test             # Run 80 tests
npm run test:coverage # Coverage report
npm run typecheck    # TypeScript check
npm run lint         # ESLint
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  AI Agent Security Monitor                   │
├─────────────────────────────────────────────────────────────┤
│  MCP Security Server (Proxy/Gate)                           │
│  └── gate_action, register_agent, log_event, query_compliance │
│                           │                                  │
│  Policy Engine ────────────┼────────────────────────────────│
│  └── Deny-by-exception     │                                 │
│  └── Allowlist mode        │                                 │
│  └── Wildcard patterns     │                                 │
│                           ▼                                  │
│  Agent Registry ───────────┼────────────────────────────────│
│  └── Identity mapping      │                                 │
│  └── API key hashing       │                                 │
│  └── Quarantine / Revoke   │                                 │
│                           ▼                                  │
│  Sensitive Data Redaction  │                                 │
│  └── 18+ secret patterns   │                                 │
│  └── Severity flagging     │                                 │
│                           ▼                                  │
│  Audit Trail (Hash-Chained) │                                │
│  └── SHA-256 chain         │                                 │
│  └── Tamper evidence       │                                 │
│                           ▼                                  │
│  Compliance Evidence Collector │                              │
│  └── GDPR, AI Act, CCPA, HIPAA, FINRA                       │
│                           ▼                                  │
│  Behavior Baselines        │                                 │
│  └── Frequency anomaly     │                                 │
│  └── Off-hours detection   │                                 │
│  └── Unusual action flags  │                                 │
└─────────────────────────────────────────────────────────────┘
```

## API Endpoints

### Agents
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/agents` | List all registered agents |
| `POST` | `/agents` | Register a new agent |
| `GET` | `/agents/:id` | Get agent details |
| `PATCH` | `/agents/:id` | Update agent |
| `DELETE` | `/agents/:id` | Soft-delete agent |
| `POST` | `/agents/:id/quarantine` | Quarantine an agent |
| `POST` | `/agents/:id/unquarantine` | Release from quarantine |
| `POST` | `/agents/:id/revoke` | Revoke all agent access |
| `GET` | `/agents/:id/events` | Get agent event history |
| `POST` | `/agents/:id/events` | Log an agent event (with redaction + compliance) |

### Policies
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/policies` | List all policies |
| `POST` | `/policies` | Create a policy |
| `GET` | `/policies/:id` | Get policy details |
| `PATCH` | `/policies/:id` | Update policy |
| `DELETE` | `/policies/:id` | Delete a policy |
| `POST` | `/policy/evaluate` | Evaluate action against all active policies |

### Compliance
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/compliance/:agent_id/:regulation` | Check agent compliance status |
| `GET` | `/compliance/export/:agent_id` | Export paginated compliance evidence with hash chain |

### Dashboard
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/dashboard/summary` | Agent, event, alert, and compliance stats |
| `GET` | `/dashboard/events/timeline` | Event timeline (filterable by agent, hours) |
| `GET` | `/dashboard/compliance/summary` | Compliance breakdown by regulation |

### Alerts
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/alerts` | List alerts (filterable by agent, acknowledged) |
| `POST` | `/alerts/:id/acknowledge` | Acknowledge an alert |

## Sensitive Data Redaction

Automatically detects and redacts **18+ secret patterns** before persistence:

| Pattern | Severity | Example |
|---------|----------|---------|
| AWS Access Key | Critical | `AKIA...` → `[AWS_ACCESS_KEY]` |
| OpenAI API Key | Critical | `sk-abc...` → `[OPENAI_API_KEY]` |
| Anthropic API Key | Critical | `sk-ant-...` → `[ANTHROPIC_API_KEY]` |
| GitHub Token | Critical | `ghp_...` → `[GITHUB_TOKEN]` |
| Bearer Token | Critical | `Bearer eyJ...` → `Bearer [BEARER_TOKEN]` |
| DB Connection String | Critical | `postgresql://user:pass@...` → redacted |
| Private Key | Critical | `-----BEGIN RSA PRIVATE KEY-----` → `[PRIVATE_KEY_REDACTED]` |
| JWT Token | High | `eyJhbG...` → `[JWT_TOKEN]` |
| Slack Token | High | `xoxb-...` → `[SLACK_TOKEN]` |
| Stripe Key | Critical | `sk_live_...` → `[STRIPE_KEY]` |
| Email Address | Medium | `user@company.com` → `[EMAIL_REDACTED]` |
| Credit Card | Critical | `4111-1111-...` → `[CC_REDACTED]` |
| Private IP | Low | `192.168.x.x` → `[PRIVATE_IP]` |

Critical and high-severity redactions automatically generate alerts.

## Compliance Mapping

Agent events are auto-mapped to regulatory controls:

| Regulation | Control | Trigger |
|------------|---------|---------|
| GDPR Art. 22 | Automated decisions | `decision:*`, `classify:*`, `score:*` actions |
| AI Act Art. 12 | System operations | All agent events (wildcard) |
| CCPA Sec. 1798 | Consumer data access | `data:read:*`, `data:access:*` + consumer_data |
| HIPAA PHI-LOG | PHI access logging | `data:read:*`, `api:call:*` + phi data |
| FINRA 4511 | Financial audit trails | `trade:*`, `execute:*` + financial_data |

## MCP Server

The MCP server acts as a non-bypassable proxy for AI agents. It exposes tools for:

| Tool | Description |
|------|-------------|
| `gate_action` | Evaluate policy decision before execution |
| `register_agent` | Register a new AI agent |
| `log_event` | Log an agent action event |
| `query_compliance` | Query compliance evidence |

### Connecting OpenClaw or Claude Code

Add to your MCP configuration (`~/.claude/mcp.json` for OpenClaw or Claude Code):

```json
{
  "mcpServers": {
    "ai-agent-security-monitor": {
      "command": "npx",
      "args": ["tsx", "src/mcp/server.ts"]
    }
  }
}
```

## Tech Stack

| Layer | Technology |
|-------|------------|
| Runtime | Node.js 20+ |
| Language | TypeScript |
| API | Fastify |
| Database | PostgreSQL 16+ |
| Queue | BullMQ / Redis |
| MCP | @modelcontextprotocol/sdk |
| Container | Docker Compose |
| Testing | Vitest (80 tests) |

## Project Structure

```
ai-agent-security-monitor/
├── src/
│   ├── api/              # Fastify API server + Swagger
│   ├── mcp/              # MCP security server
│   ├── policy/           # Policy evaluation engine
│   ├── agents/           # Agent registry
│   ├── compliance/       # Compliance mapping (GDPR, AI Act, CCPA, HIPAA, FINRA)
│   ├── security/         # Sensitive data redaction (18+ patterns)
│   ├── services/         # Discovery, behavior baselines, security scarlet
│   └── db/               # Database initialization
├── scripts/              # Migration + seed scripts
├── tests/                # 80 tests across 5 files
│   ├── policy.test.ts
│   ├── redaction.test.ts
│   ├── compliance.test.ts
│   ├── baseline.test.ts
│   └── registry.test.ts
├── docker-compose.yml
└── package.json
```

## License

ISC