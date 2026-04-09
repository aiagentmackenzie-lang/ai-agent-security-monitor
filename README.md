# AI Agent Security Monitor

**Runtime access control and observability plane for every AI agent operating against your organization's data — authorized or not, owned by IT or not, known to security or not.**

## What Is This?

Every company now has AI agents operating against their data. OpenClaw agents on servers. Claude Code on laptops. Custom agents in engineering. ChatGPT in sales. AI assistants in finance. Third-party agents connected to APIs.

**No one knows which agents exist, what they have access to, or what they're doing with that access.**

This platform solves that at three layers:

1. **Discovery** — Find every AI agent with access to your systems
2. **Observability** — Track what every agent does in real-time
3. **Control** — Enforce policy and generate compliance evidence

## Quick Start

### Prerequisites

- Node.js 20+
- Docker & Docker Compose
- PostgreSQL 16+ (or use Docker)

### Installation

```bash
# Clone and install dependencies
cd "AI Agent Security Monitor"
npm install

# Copy environment template
cp .env.example .env

# Start infrastructure (PostgreSQL + Redis)
docker compose up -d

# Run database migrations
npm run db:migrate
```

### Development

```bash
# Start the API server with hot reload
npm run dev

# Run tests
npm test

# Type check
npm run typecheck
```

### Production

```bash
# Build
npm run build

# Start
npm start
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
│  └── Pattern matching      │                                 │
│  └── Deny by exception     │                                 │
│                           ▼                                  │
│  Agent Registry ───────────┼────────────────────────────────│
│  └── Identity mapping      │                                 │
│  └── API key hashing       │                                 │
│                           ▼                                  │
│  Audit Trail (Hash-Chained) │                                │
│                           ▼                                  │
│  Compliance Evidence Collector │                              │
│  └── GDPR, AI Act, CCPA, HIPAA, FINRA                        │
└─────────────────────────────────────────────────────────────┘
```

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

OpenClaw agents automatically register on startup and gate all sensitive actions through the policy engine.

## API Endpoints

### Agents
- `GET /agents` — List all registered agents
- `POST /agents` — Register a new agent
- `GET /agents/:id/events` — Get agent's event history

### Policy
- `POST /policy/evaluate` — Evaluate an action against policies

### Compliance
- `GET /compliance/:agent_id/:regulation` — Check compliance status

## Tech Stack

| Layer | Technology |
|-------|------------|
| Runtime | Node.js 20+ |
| Language | TypeScript |
| API | Fastify |
| Database | PostgreSQL 16+ |
| Queue | BullMQ |
| MCP | @modelcontextprotocol/sdk |
| Container | Docker Compose |

## Project Structure

```
ai-agent-security-monitor/
├── src/
│   ├── api/           # Fastify API server
│   ├── mcp/           # MCP security server
│   ├── policy/        # Policy evaluation engine
│   ├── agents/        # Agent registry
│   ├── compliance/    # Compliance mapping
│   └── db/            # Database initialization
├── scripts/           # Migration scripts
├── tests/             # Test suite
├── docker-compose.yml
├── package.json
└── SPEC.md            # Full specification
```

## Compliance Support

Maps agent actions to regulatory requirements:

| Regulation | Key Requirement |
|------------|-----------------|
| GDPR Art. 22 | Automated decisions must be documented |
| AI Act Art. 12 | System operations must be logged |
| CCPA | Consumer data access must be documented |
| HIPAA | PHI access must be logged |
| FINRA | Financial AI requires audit trails |

## License

ISC
