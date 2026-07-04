# Security Policy

## Supported versions

| Version | Supported |
|:---|:---|
| `main` (latest) | ✅ |
| `lift/agent-monitor-production` | ✅ (active development) |
| Older tags | ❌ |

## Reporting a vulnerability

Email the maintainer directly. Do **not** open a public issue for security
vulnerabilities. Include:

- Reproduction steps (minimal)
- Affected component (API, MCP server, SDK, redaction engine, etc.)
- Impact and any exploited primitives
- Suggested fix (optional)

You will receive an acknowledgement within 72 hours. A fix and disclosure
timeline will be coordinated with you.

## Security posture

This is a **governance product** — it must not be the weak link. The following
are enforced in code, not just documented:

- **Fail-closed configuration.** The server refuses to start unless either
  `DEV_MODE=true` (local dev only) or both `API_KEY` and `CORS_ORIGINS` are set.
  An open governance API in production is a configuration error, not a default.
- **API-key auth** on every endpoint when `API_KEY` is set (hook runs `onRequest`).
- **Rate limiting** on all endpoints (Redis-backed when `REDIS_URL` is set,
  in-memory otherwise). `/health` is allow-listed.
- **Tamper-evident audit trail.** Every `agent_event` is SHA-256 chained
  (`previous_hash` → `hash`) including all event fields + a timestamp. The
  `/compliance/export/:agent_id` endpoint verifies the chain and reports
  `verified: false` on any mutation.
- **Secret redaction before persistence.** 17 patterns (cloud keys, AI-provider
  keys, tokens, PII, connection strings) are redacted in `event.details` before
  the row is written. Critical/high redactions auto-create alerts. Raw secrets
  never reach the database.
- **Privacy-preserving discovery.** Shadow-agent detection stores only SHA-256
  hashes of API keys plus a 2-char + `***` prefix for triage. Raw keys are
  never persisted.
- **Fail-closed policy semantics.** A conditional `permit` rule with no request
  context is skipped (falls through to allowlist `default-deny`). A conditional
  `deny` with no context still fires (over-block rather than under-block).
- **Parameterised queries everywhere.** No string-interpolated SQL. Pagination
  and filter inputs are validated.
- **Non-root container.** The Dockerfile runs the API as an unprivileged user.

## Operational hardening checklist (production deploy)

1. Set `API_KEY` to a high-entropy value; never commit it.
2. Set `CORS_ORIGINS` to your exact UI origin(s).
3. Set `REDIS_URL` so rate limiting is shared across workers.
4. Run behind TLS-terminating reverse proxy (nginx/Caddy/ALB).
5. Use a managed Postgres with TLS; rotate the `DATABASE_URL` password.
6. Restrict network egress — the only outbound calls are optional
   SecurityScarletAI forwarding (opt-in via `SCARLET_API_URL`).
7. Back up Postgres regularly; the audit trail is your evidence of record.
8. Periodically run `/compliance/export/:agent_id` and confirm
   `hash_chain.verified === true` for every agent.

## Secret handling in this repo

- `.env` is gitignored. `.env.example` contains only non-secret placeholders.
- No real credentials are committed. Test fixtures use clearly-fake keys
  (`AKIAIOSFODNN7EXAMPLE`, `sk-test-123`, etc.).
- If a secret is accidentally committed, rotate it immediately — do not rely on
  history rewriting alone.