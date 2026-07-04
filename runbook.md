# Runbook — AI Agent Security Monitor

Operational procedures for deploy, rotation, incident response, and audit
verification.

## 1. Local development

```bash
cp .env.example .env          # set DATABASE_URL, DEV_MODE=true
docker compose up -d postgres redis
npm install
npm run db:migrate            # create tables
npm run db:seed               # optional: demo data
npm run dev                   # API on :8000, hot reload
```

Open `http://localhost:8000/dashboard` for the UI and
`http://localhost:8000/documentation` for Swagger.

## 2. Production deploy (docker compose)

```bash
export API_KEY=$(openssl rand -hex 32)
export CORS_ORIGINS=https://governance.yourcorp.com
export DATABASE_URL=postgresql://user:pass@db:5432/ai_agent_security
export REDIS_URL=redis://redis:6379
docker compose up -d --build
```

The `api` service waits for healthy `postgres` + `redis` before starting, runs
migrations are run via `npm run db:migrate` (run once after first boot, or wire
into an init container). Health: `GET /health`.

**Do NOT set `DEV_MODE=true` in production.** Without it, the server enforces
`API_KEY` + `CORS_ORIGINS`.

## 3. Rotation procedures

### Rotate the API key
1. Pick a new key: `openssl rand -hex 32`.
2. Update `API_KEY` in the environment of the API service **and** all MCP
   clients / SDK consumers (`X-API-Key` header).
3. Restart the API service and clients. There is ~0 downtime — requests during
   the window with the old key return `401`.

### Rotate the DB password
1. Create a new DB role/password.
2. Update `DATABASE_URL`; restart the API.
3. Drop the old role after confirming no connections use it.

## 4. Incident response — rogue agent

**Scenario:** an agent is observed acting outside policy or exfiltrating data.

1. **Quarantine immediately** (blocks all future policy evaluations):
   ```bash
   curl -X POST -H "X-API-Key: $API_KEY" \
     http://localhost:8000/agents/<AGENT_ID>/quarantine
   ```
   This sets `quarantined=true` and raises a `high` alert.
2. **Revoke** if the agent must be fully killed (transactional: deactivates,
   quarantines, appends a `revoked` event to the audit chain, raises a
   `critical` alert):
   ```bash
   curl -X POST -H "X-API-Key: $API_KEY" \
     http://localhost:8000/agents/<AGENT_ID>/revoke
   ```
3. **Pull the evidence export** for the incident timeline:
   ```bash
   curl -H "X-API-Key: $API_KEY" \
     http://localhost:8000/compliance/export/<AGENT_ID>?limit=100
   ```
   Confirm `hash_chain.verified === true` — if `false`, the chain has been
   tampered with (escalate to security team).
4. **Acknowledge the alerts** with the responder's name:
   ```bash
   curl -X POST -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
     -d '{"acknowledged_by":"raphael"}' \
     http://localhost:8000/alerts/<ALERT_ID>/acknowledge
   ```

## 5. Shadow-agent detection

Two real heuristics, no stubs:

- **Access-log key scan.** Ingest API-gateway access logs, then scan:
  ```bash
  curl -X POST -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
    -d '{"access_logs":[{"api_key":"sk-...","resource":"/api/x","timestamp":"2026-07-04T12:00:00Z"}]}' \
    http://localhost:8000/discovery/access-logs
  curl -X POST -H "X-API-Key: $API_KEY" \
    http://localhost:8000/discovery/shadow-scan
  ```
  Any key hash not present in `agents.api_key_hash` is recorded as a shadow
  agent with a `high` alert. Raw keys are never stored — only SHA-256 hashes.

- **Behavior scan.** Flags agents registered as `custom` whose action
  distribution matches a known baseline type above 60% confidence:
  ```bash
  curl -H "X-API-Key: $API_KEY" http://localhost:8000/discovery/behavior-scan
  ```

## 6. Audit-chain verification

```bash
curl -H "X-API-Key: $API_KEY" \
  http://localhost:8000/compliance/export/<AGENT_ID> | jq '.export.hash_chain.verified'
```

A `false` result means at least one event's `previous_hash` does not match the
prior event's `hash` — investigate as a potential integrity incident.

## 7. SecurityScarletAI forwarding (optional)

Wire agent events into your SIEM by enabling forwarding:

```
SCARLET_FORWARD_ENABLED=true
SCARLET_API_URL=https://scarlet.yourcorp.com
SCARLET_API_KEY=<key>
```

Forwarding is fire-and-forget after the event commit — it never blocks the API
response or breaks the audit chain on failure (errors are logged at `warn`).

## 8. Backups

- Back up the Postgres volume on your regular DB schedule.
- The `agent_events` table is the evidence of record — treat it as immutable.
  Never run `UPDATE`/`DELETE` against it in normal operation; the chain
  verification will catch any such mutation.

## 9. Observability

- Logs: pino JSON to stdout. Set `LOG_LEVEL=debug` for verbose output.
- Metrics: health endpoint + dashboard summary. Wire Prometheus to scrape
  `/dashboard/summary` or extend with a `/metrics` endpoint (roadmap).
- Rate-limit hits return `429`.