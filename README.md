# AI Agent Security Monitor

[![Node.js](https://img.shields.io/badge/node-20%2B-green?logo=node.js)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/typescript-5.0-blue?logo=typescript)](https://www.typescriptlang.org/)
[![Fastify](https://img.shields.io/badge/framework-Fastify-009688?logo=fastapi)](https://fastify.dev/)
[![Tests](https://img.shields.io/badge/tests-86%20passing-brightgreen)](./tests)
[![OWASP Agentic](https://img.shields.io/badge/OWASP-Agentic%20Top%2010%202026-purple)](https://genai.owasp.org/)
[![License](https://img.shields.io/badge/license-ISC-green)](./LICENSE)

**Runtime access control and observability plane for every AI agent operating against your organization's data — authorized or not, owned by IT or not, known to security or not.**

## What Is This?

Every company now has AI agents operating against their data. OpenClaw agents on servers. Claude Code on laptops. Custom agents in engineering. ChatGPT in sales. AI assistants in finance. Third-party agents connected to APIs.

**No one knows which agents exist, what they have access to, or what they're doing with that access.**

This platform solves that at three layers:

1. **Observability** — Track what every agent does in real-time with tamper-evident audit logs
2. **Control** — Enforce policy (deny-by-default and allowlist modes) with signed certificates
3. **Compliance** — Auto-map agent actions to GDPR, AI Act, CCPA, HIPAA, FINRA controls

> **Note:** Agent Discovery (shadow AI detection) is architecturally present but core detection methods are stubs awaiting integration with your API gateway or access logs. See `src/services/discovery.ts`.

## Features

| Feature | Description |
|---------|-------------|
| 🔒 Policy Engine | Deny-by-default and allowlist modes with wildcard pattern matching and conditions |
| 🔐 Sensitive Data Redaction | Auto-redact 17 secret types (API keys, tokens, PII) before persistence |
| ⛓️ Hash-Chained Audit Trail | SHA-256 chained event log with field-level integrity and tamper verification |
| 🏥 Agent Quarantine & Revocation | Instantly isolate or revoke rogue agents with one API call |
| 📋 Compliance Mapping | Auto-map agent actions to GDPR, AI Act, CCPA, HIPAA, FINRA (status: pending until verified) |
| 🚨 Alert System | Severity-graded alerts for policy violations and sensitive data detection |
| 📡 Behavior Baselines | Anomaly detection for frequency spikes, off-hours activity, unusual actions |
| 📄 Compliance Export | Generate paginated evidence with hash chain verification for auditors |
| 🤖 MCP Integration | Act as a policy gate for OpenClaw / Claude Code agents via MCP |
| 🔑 API Key Authentication | Optional `X-API-Key` header authentication for all endpoints (production recommended) |

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

### Authentication

Set the `API_KEY` environment variable to enable authentication on all endpoints:

```bash
# In .env or environment
API_KEY=your-secure-api-key-here
```

When `API_KEY` is set, all requests must include the `X-API-Key` header. Without it, all endpoints are open (suitable for local development only).

### Development

```bash
npm run dev          # Start with hot reload
npm test             # Run 86 tests
npm run test:coverage # Coverage report
npm run typecheck    # TypeScript check
npm run lint         # ESLint
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  AI Agent Security Monitor                   │
├─────────────────────────────────────────────────────────────┤
│  API (Fastify) ─────── Swagger UI / JSON ──────────────── │
│  └── Auth middleware (X-API-Key when configured)            │
│                           │                                  │
│  MCP Security Server ────┤                                  │
│  └── gate_action          │                                  │
│  └── evaluate_tool_call   │  (policy evaluation only,       │
│  └── register_agent       │   does NOT proxy/execute tools)│
│  └── log_event            │                                  │
│  └── query_compliance     │                                  │
│                           ▼                                  │
│  Policy Engine ───────────┼────────────────────────────────│
│  └── Deny-by-exception   │                                  │
│  └── Allowlist mode       │                                  │
│  └── Wildcard patterns    │                                  │
│  └── Condition evaluation │                                  │
│                           ▼                                  │
│  Sensitive Data Redaction │                                  │
│  └── 17 secret patterns   │                                  │
│  └── Severity flagging     │                                  │
│                           ▼                                  │
│  Audit Trail (Hash-Chained)│                                │
│  └── SHA-256 chain (all fields)                             │
│  └── Tamper evidence       │                                │
│                           ▼                                  │
│  Compliance Evidence Collector │                              │
│  └── GDPR, AI Act, CCPA, HIPAA, FINRA (pending status)     │
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
| `DELETE` | `/agents/:id` | Soft-delete agent (returns 404 if not found) |
| `POST` | `/agents/:id/quarantine` | Quarantine an agent |
| `POST` | `/agents/:id/unquarantine` | Release from quarantine |
| `POST` | `/agents/:id/revoke` | Revoke all agent access (transactional) |
| `GET` | `/agents/:id/events` | Get agent event history |
| `POST` | `/agents/:id/events` | Log an agent event (uses URL `:id`, with redaction + compliance) |

### Policies
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/policies` | List all policies (ordered by priority) |
| `POST` | `/policies` | Create a policy (supports `priority` and `default_effect`) |
| `GET` | `/policies/:id` | Get policy details |
| `PATCH` | `/policies/:id` | Update policy |
| `DELETE` | `/policies/:id` | Soft-delete policy (sets `active = false`) |

### Policy Evaluation
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/policy/evaluate` | Evaluate action against all active policies (supports conditions) |

### Compliance
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/compliance/:agent_id/:regulation` | Check agent compliance status |
| `GET` | `/compliance/reports/:agent_id` | Generate full compliance report |
| `GET` | `/compliance/export/:agent_id` | Export paginated evidence with hash chain verification |

### Dashboard
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/dashboard/summary` | Agent, event, alert, and compliance stats |
| `GET` | `/dashboard/events/timeline` | Event timeline (parameterized query, validated input) |
| `GET` | `/dashboard/compliance/summary` | Compliance breakdown by regulation |

### Alerts
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/alerts` | List alerts (filterable by agent, acknowledged) |
| `POST` | `/alerts/:id/acknowledge` | Acknowledge an alert |

## Sensitive Data Redaction

Automatically detects and redacts **17 secret patterns** before persistence:

| Pattern | Severity | Example |
|---------|----------|---------|
| AWS Access Key | Critical | `AKIA...` → `[AWS_ACCESS_KEY]` |
| AWS Secret Key (context-aware) | Critical | Only flagged near AWS context |
| OpenAI API Key | Critical | `sk-abc...` → `[OPENAI_API_KEY]` |
| Anthropic API Key | Critical | `sk-ant-...` → `[ANTHROPIC_API_KEY]` |
| GitHub Token | Critical | `ghp_...` → `[GITHUB_TOKEN]` |
| Bearer Token | Critical | `Bearer eyJ...` → `Bearer [BEARER_TOKEN]` |
| DB Connection String | Critical | `postgresql://user:pass@...` → redacted |
| Private Key | Critical | `-----BEGIN RSA PRIVATE KEY-----` → `[PRIVATE_KEY_REDACTED]` |
| JWT Token | High | `eyJhbG...` → `[JWT_TOKEN]` |
| Slack Token | High | `xoxb-...` → `[SLACK_TOKEN]` |
| Discord Token | High | `MN...27` → `[DISCORD_TOKEN]` |
| GCP Service Account | High | `...@...iam.gserviceaccount.com` → `[GCP_SERVICE_ACCOUNT]` |
| GCP API Key | High | `AIza...` → `[GCP_API_KEY]` |
| Gemini API Key | High | `AIzaSy...` → `[GEMINI_API_KEY]` |
| Stripe Key | Critical | `sk_live_...` → `[STRIPE_KEY]` |
| Email Address | Medium | `user@company.com` → `[EMAIL_REDACTED]` |
| Credit Card | Critical | `4111-1111-...` → `[CC_REDACTED]` |
| Private IP | Low | `192.168.x.x` → `[PRIVATE_IP]` |

**Note:** The old over-broad AWS secret key regex (which matched any 40-char base64 string) has been replaced with a context-aware pattern that only flags AWS secrets near AKIA access keys.

Critical and high-severity redactions automatically generate alerts.

## Compliance Mapping

Agent events are auto-mapped to regulatory controls with `pending` status (not auto-compliant):

| Regulation | Control | Trigger |
|------------|---------|---------|
| GDPR Art. 22 | Automated decisions | `decision:*`, `classify:*`, `score:*` actions |
| AI Act Art. 12 | System operations | All agent events (wildcard) |
| CCPA Sec. 1798 | Consumer data access | `data:read:*`, `data:access:*` + consumer_data |
| HIPAA PHI-LOG | PHI access logging | `data:read:*`, `api:call:*` + phi data |
| FINRA 4511 | Financial audit trails | `trade:*`, `execute:*` + financial_data |

## Policy Engine

### Condition Rules

Policies now support optional `conditions` for context-aware evaluation:

```json
{
  "action": "data:read",
  "resource": "*",
  "effect": "deny",
  "conditions": {
    "data_classification": "confidential"
  }
}
```

Supported condition operators: `eq` (exact match), `neq` (not equal), `in` (list membership), `contains` (substring).

## MCP Server

The MCP server provides policy evaluation and audit logging. It does **not** proxy or execute tool calls — it returns a permission decision that the calling agent must respect.

| Tool | Description |
|------|-------------|
| `gate_action` | Evaluate policy decision before execution |
| `evaluate_tool_call` | Evaluate policy for a tool call (returns decision only, does NOT execute) |
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
      "args": ["tsx", "src/mcp/server.ts"],
      "env": {
        "API_BASE_URL": "http://localhost:8000",
        "API_KEY": "your-api-key-here"
      }
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
| MCP | @modelcontextprotocol/sdk |
| Container | Docker Compose |
| Testing | Vitest (86 tests) |

## Project Structure

```
ai-agent-security-monitor/
├── src/
│   ├── api/              # Fastify API server + Swagger
│   ├── mcp/              # MCP security server
│   ├── policy/           # Policy evaluation engine (with conditions)
│   ├── agents/           # Agent registry
│   ├── compliance/       # Compliance mapping (GDPR, AI Act, CCPA, HIPAA, FINRA)
│   ├── security/         # Sensitive data redaction (17 patterns)
│   ├── services/         # Discovery (stubs), behavior baselines, scarlet integration
│   ├── types.ts          # Canonical type definitions
│   └── db/               # Database initialization
├── scripts/              # Migration + seed scripts
├── sdk/                  # Client SDK (Node.js)
├── tests/                # 86 tests across 5 files
│   ├── policy.test.ts
│   ├── redaction.test.ts
│   ├── compliance.test.ts
│   ├── baseline.test.ts
│   └── registry.test.ts
├── docker-compose.yml
└── package.json
```

## Security Considerations

- **Authentication**: Set `API_KEY` env var to enable auth on all endpoints. Without it, the API is open (dev mode only).
- **CORS**: Configurable via `CORS_ORIGINS` env var (comma-separated). Defaults to `true` (all origins) for development.
- **Event logging**: Agent ID is taken from the URL path (`:id`), not the request body, to prevent ID spoofing.
- **Hash chain**: Event hashes include all fields (agent_id, event_type, action, resource, result, details, timestamp).
- **Certificates**: Policy evaluation certificates use `crypto.randomUUID()` (CSPRNG), not `Math.random()`.
- **Redaction**: The AWS secret key regex now requires proximity to an AKIA access key to avoid false positives.

## License

ISC