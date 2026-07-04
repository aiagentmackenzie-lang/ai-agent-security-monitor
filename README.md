# AI Agent Security Monitor

[![Node.js](https://img.shields.io/badge/node-20%2B-green?logo=node.js)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/typescript-5.0-blue?logo=typescript)](https://www.typescriptlang.org/)
[![Fastify](https://img.shields.io/badge/framework-Fastify-009688?logo=fastapi)](https://fastify.dev/)
[![Tests](https://img.shields.io/badge/tests-154%20passing-brightgreen)](./tests)
[![Coverage](https://img.shields.io/badge/coverage-82%25-brightgreen)](./vitest.config.ts)
[![CI](https://img.shields.io/badge/CI-github%20actions-blue)](./.github/workflows/ci.yml)
[![OWASP Agentic](https://img.shields.io/badge/OWASP-Agentic%20Top%2010%202026-purple)](https://genai.owasp.org/)
[![License](https://img.shields.io/badge/license-ISC-green)](./LICENSE)

**Runtime access control and observability plane for every AI agent operating against your organization's data — authorized or not, owned by IT or not, known to security or not.**

> **Pairs with [NeuralGuard-AI-Firewall](../NeuralGuard-AI-Firewall/) (S-tier, Production)**
> — NeuralGuard is the **input** firewall (prompt-injection defense at the LLM
> boundary). This project is the **runtime** plane (policy gate + tamper-evident
> audit + compliance + shadow-agent discovery). Together they form a complete
> AI agent security stack. See [`threat-model.md`](./threat-model.md) for the
> OWASP Agentic Top 10 (2026) control mapping.

## What Is This?

Every company now has AI agents operating against their data — OpenClaw on
servers, Claude Code on laptops, custom agents in engineering, ChatGPT in
sales, third-party agents connected to APIs. **No one knows which agents exist,
what they have access to, or what they're doing with that access.**

This platform solves that at three layers:

1. **Control** — Enforce deny/permit policy with signed certificates before any
   agent action or tool call. Allowlist (`default_effect: deny`) mode is
   fail-closed.
2. **Observability** — Tamper-evident (SHA-256 chained) audit trail with
   automatic sensitive-data redaction before persistence.
3. **Compliance** — Auto-map agent actions to GDPR, AI Act, CCPA, HIPAA, FINRA
   controls, plus shadow-agent discovery (access-log key scan + behavior
   inference — no stubs).

## Features

| Feature | Description |
|---------|-------------|
| 🔒 Policy Engine | Deny-by-default + allowlist modes, wildcard matching, context conditions, **fail-closed** on conditional permits with no context |
| 🔐 Sensitive Data Redaction | 17 secret patterns (cloud/AI keys, tokens, PII) redacted **before** persistence; critical/high → alerts |
| ⛓️ Hash-Chained Audit Trail | SHA-256 chain over all event fields; `/compliance/export` verifies integrity |
| 🏥 Quarantine & Revocation | One-call quarantine (blocks gate) + transactional revoke (chain event + critical alert) |
| 📋 Compliance Mapping | GDPR Art-22, AI Act Art-12, CCPA, HIPAA, FINRA — always `pending` until verified |
| 🚨 Alert System | Severity-graded alerts; acknowledge workflow |
| 📡 Behavior Baselines | Frequency spikes, off-hours, unusual actions, new resource access — exposed at `/agents/:id/anomalies` |
| 🔍 Shadow-Agent Discovery | Access-log key scan (hash-based, privacy-preserving) + behavior-scan (misregistered-type inference) — **no stubs** |
| 🤖 MCP Integration | `gate_action`, `evaluate_tool_call` (decision-only, never executes), `register_agent`, `log_event`, `query_compliance` |
| 🔑 API Key Auth + Rate Limiting | `X-API-Key` auth + Redis-backed rate limiting (`@fastify/rate-limit`) |
| 📊 Dashboard UI | Single-page dashboard served at `/dashboard/` (agents, alerts, compliance, live stats) |
| 📡 SIEM Forwarding | Optional fire-and-forget forwarding to SecurityScarletAI (`SCARLET_FORWARD_ENABLED=true`) |

## Quick Start

### Prerequisites

- Node.js 20+
- Docker & Docker Compose (Colima / Docker Desktop)

### One-command smoke test

```bash
npm run smoke    # boots the full stack, runs the entire governance loop, exits 0 on success
```

### Manual

```bash
cp .env.example .env          # set DATABASE_URL, DEV_MODE=true for local dev
docker compose up -d          # postgres + redis + API (built from source)
npm install
npm run db:migrate            # create tables
npm run db:seed               # optional: demo data
npm run dev                   # API on :8000 (hot reload)
```

- Dashboard UI: `http://localhost:8000/dashboard/`
- Swagger: `http://localhost:8000/documentation`
- Health: `http://localhost:8000/health`

### Configuration & security posture

The server **refuses to start** unless either `DEV_MODE=true` (local dev) **or**
both `API_KEY` and `CORS_ORIGINS` are set. A governance product must not ship
open by default.

| Env var | Required in prod | Purpose |
|:---|:---:|:---|
| `DATABASE_URL` | ✅ | Postgres connection string |
| `API_KEY` | ✅ | `X-API-Key` auth on all endpoints |
| `CORS_ORIGINS` | ✅ | Comma-separated origin allowlist |
| `DEV_MODE` | — | `true` bypasses the auth/CORS gate (local only) |
| `REDIS_URL` | — | Enables shared rate limiting across workers |
| `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW_MS` | — | Rate-limit tuning (default 300 / 60s) |
| `SCARLET_FORWARD_ENABLED` + `SCARLET_API_URL` + `SCARLET_API_KEY` | — | SIEM forwarding |
| `PORT` / `HOST` / `LOG_LEVEL` | — | Network + log tuning |

See [`SECURITY.md`](./SECURITY.md) for the full security policy and
[`runbook.md`](./runbook.md) for deploy, rotation, and incident-response
procedures.

## Development

```bash
npm run dev            # API with hot reload
npm test               # 154 tests (unit + integration)
npm run test:coverage  # coverage report (70% gate)
npm run typecheck      # TypeScript check
npm run lint           # ESLint
npm run build          # compile to dist/
npm run build:sdk      # build the SDK
```

Integration tests use **testcontainers** (real Postgres in Docker) — no
external services required. Set `DOCKER_HOST` if using Colima.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  AI Agent Security Monitor                   │
├─────────────────────────────────────────────────────────────┤
│  API (Fastify) ─── Swagger UI / Dashboard UI ─────────────  │
│  └── Auth (X-API-Key) + Rate limit (Redis)                   │
│                           │                                  │
│  MCP Security Server ────┤                                  │
│  └── gate_action / evaluate_tool_call (decision-only)       │
│  └── register_agent / log_event / query_compliance          │
│                           ▼                                  │
│  Policy Engine ───────────┼────────────────────────────────│
│  └── Deny / allowlist (fail-closed) + wildcard + conditions │
│                           ▼                                  │
│  Sensitive Data Redaction (17 patterns) → Audit chain       │
│  └── SHA-256 hash chain (all fields, tamper-evident)        │
│                           ▼                                  │
│  Compliance Mapper (GDPR/AI Act/CCPA/HIPAA/FINRA)           │
│  Behavior Baselines · Shadow-Agent Discovery                │
│                           ▼                                  │
│  (opt-in) SecurityScarletAI SIEM forwarding                 │
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
| `DELETE` | `/agents/:id` | Soft-delete agent (404 if not found) |
| `POST` | `/agents/:id/quarantine` | Quarantine an agent + high alert |
| `POST` | `/agents/:id/unquarantine` | Release from quarantine |
| `POST` | `/agents/:id/revoke` | Transactional revoke + critical alert + chain event |
| `GET` | `/agents/:id/events` | Get agent event history |
| `POST` | `/agents/:id/events` | Log an event (redaction + compliance + chain) |
| `GET` | `/agents/:id/anomalies` | Behavior-baseline anomaly detection |

### Policies
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/policies` | List policies (priority order) |
| `POST` | `/policies` | Create policy (supports `priority`, `default_effect`) |
| `GET` / `PATCH` / `DELETE` | `/policies/:id` | Read / update / soft-delete |

### Policy Evaluation
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/policy/evaluate` | Evaluate action against active policies (supports conditions) |

### Compliance
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/compliance/:agent_id/:regulation` | Compliance status for one regulation |
| `GET` | `/compliance/reports/:agent_id` | Full multi-regulation report |
| `GET` | `/compliance/export/:agent_id` | Paginated evidence + hash-chain verification |

### Discovery
| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/discovery/access-logs` | Ingest API-gateway access logs (hashed) |
| `POST` | `/discovery/shadow-scan` | Detect shadow agents from ingested logs |
| `GET` | `/discovery/behavior-scan` | Infer misregistered agent types from behavior |

### Dashboard
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/dashboard/` | Single-page dashboard UI |
| `GET` | `/dashboard/summary` | Agent, event, alert, compliance stats |
| `GET` | `/dashboard/events/timeline` | Event timeline (parameterized, validated) |
| `GET` | `/dashboard/compliance/summary` | Compliance breakdown by regulation |

### Alerts
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/alerts` | List alerts (filterable by agent, acknowledged) |
| `POST` | `/alerts/:id/acknowledge` | Acknowledge an alert |

## Sensitive Data Redaction

17 patterns, ordered by specificity, severity-graded, redacted before
persistence: AWS/GCP/Gemini keys, OpenAI/Anthropic/GitHub/Stripe/Slack/Discord
tokens, Bearer/Basic auth, DB connection strings, JWTs, private keys, credit
cards, emails, private IPs. Critical/high findings auto-create alerts. The AWS
secret-key regex is context-aware (only flagged near an AKIA prefix) to avoid
false positives.

## Compliance Mapping

| Regulation | Control | Trigger |
|------------|---------|---------|
| GDPR Art. 22 | Automated decisions | `decision:*`, `classify:*`, `score:*` |
| AI Act Art. 12 | System operations | All agent events (wildcard) |
| CCPA Sec. 1798 | Consumer data access | `data:read:*` + consumer_data |
| HIPAA PHI-LOG | PHI access logging | `data:read:*`, `api:call:*` + phi |
| FINRA 4511 | Financial audit trails | `trade:*`, `execute:*` + financial_data |

## Policy Engine

### Condition Rules (fail-closed)

```json
{
  "action": "data:read", "resource": "*", "effect": "permit",
  "conditions": { "data_classification": "confidential" }
}
```

Operators: `eq`, `neq`, `in`, `contains` (or a bare string for exact match).

**Fail-closed semantics:**
- A conditional **permit** with no request context is **skipped** → falls
  through to allowlist `default-deny`.
- A conditional **deny** with no request context still **fires** (over-block
  rather than under-block).

## MCP Server

Decision-only — never proxies or executes tools. The calling agent must respect
the decision; denials are logged as `tool_denied` events.

| Tool | Description |
|------|-------------|
| `gate_action` | Evaluate policy decision before execution (returns signed certificate) |
| `evaluate_tool_call` | Evaluate policy for a tool call (decision only; logs denials) |
| `register_agent` | Register a new agent |
| `log_event` | Log an agent action event |
| `query_compliance` | Query compliance evidence |

### Connecting OpenClaw or Claude Code

```json
{
  "mcpServers": {
    "ai-agent-security-monitor": {
      "command": "npx",
      "args": ["tsx", "src/mcp/server.ts"],
      "env": { "API_BASE_URL": "http://localhost:8000", "API_KEY": "your-key" }
    }
  }
}
```

## Tech Stack

| Layer | Technology |
|-------|------------|
| Runtime | Node.js 20+ |
| Language | TypeScript (strict) |
| API | Fastify 5 + Swagger + rate-limit |
| Database | PostgreSQL 16+ |
| Cache/limiter | Redis 7 (optional) |
| MCP | @modelcontextprotocol/sdk |
| Container | Docker Compose (multi-stage, non-root) |
| Testing | Vitest + testcontainers (154 tests, 82% coverage) |
| CI | GitHub Actions |

## Project Structure

```
ai-agent-security-monitor/
├── src/
│   ├── api/              # Fastify server (testable build), errors, config
│   ├── mcp/              # MCP server (handlers exported for unit testing)
│   ├── policy/           # Policy engine (wildcard + conditions + fail-closed)
│   ├── agents/           # Agent/event factories
│   ├── compliance/       # GDPR/AI Act/CCPA/HIPAA/FINRA mapper
│   ├── security/         # 17-pattern redaction engine
│   ├── services/         # Discovery (real), baselines, SecurityScarlet forwarding
│   ├── config.ts         # Zod-validated config + security gate
│   ├── types.ts          # Canonical types
│   └── db/               # Schema init (agents, events, policies, compliance, alerts, access_logs)
├── dashboard/            # Single-page dashboard UI
├── scripts/              # migrate, seed, smoke_test
├── sdk/                  # Node SDK (camelCase mapping)
├── tests/                # unit + integration (testcontainers) + mcp + sdk
├── Dockerfile            # multi-stage, non-root
├── docker-compose.yml    # postgres + redis + api
├── vitest.config.ts      # 70% coverage gate
├── .github/workflows/    # CI
├── SECURITY.md · runbook.md · threat-model.md
└── package.json
```

## Security Considerations

- **Fail-closed config**: refuses to start without `API_KEY`+`CORS_ORIGINS` unless `DEV_MODE=true`.
- **Auth**: `X-API-Key` on all endpoints when `API_KEY` is set.
- **Rate limiting**: Redis-backed (`@fastify/rate-limit`); `/health` allow-listed.
- **Audit chain**: SHA-256 over all event fields + timestamp; tamper detection via `/compliance/export`.
- **Redaction**: 17 patterns, applied before persistence; raw secrets never reach the DB.
- **Privacy-preserving discovery**: only SHA-256 hashes + 2-char prefix of API keys stored.
- **Parameterised queries** everywhere; pagination/filter inputs validated.
- **Non-root container**; healthcheck; graceful shutdown.

## License

ISC