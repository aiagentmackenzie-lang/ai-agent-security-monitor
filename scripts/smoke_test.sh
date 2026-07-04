#!/usr/bin/env bash
# End-to-end smoke test for AI Agent Security Monitor.
# Boots the full stack (postgres + redis + API), runs migrations + seed, then
# exercises the complete governance loop. Exits 0 only if every assertion passes.
set -euo pipefail

API="http://127.0.0.1:8000"
DB_URL="postgresql://postgres:postgres@127.0.0.1:5433/ai_agent_security"
PASS=0
FAIL=0

c() { printf '\033[1;36m▶\033[0m %s\n' "$1"; }
ok() { printf '  \033[1;32m✓\033[0m %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf '  \033[1;31m✗\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
die() { printf '\033[1;31mFATAL:\033[0m %s\n' "$1"; exit 1; }

jq_present() { command -v jq >/dev/null 2>&1; }

require() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }
require curl; require docker

# ── Boot stack ──
c "Starting docker compose stack"
docker compose down --remove-orphans >/dev/null 2>&1 || true
docker compose up -d --build
trap 'docker compose down >/dev/null 2>&1 || true' EXIT

c "Waiting for API health"
healthy=0
for i in $(seq 1 30); do
  if curl -sf "$API/health" >/dev/null 2>&1; then healthy=1; break; fi
  sleep 2
done
[ "$healthy" = "1" ] && ok "API healthy" || die "API never became healthy"

# ── Migrate + seed ──
c "Running migrations + seed"
DATABASE_URL="$DB_URL" npm run db:migrate >/dev/null 2>&1 || die "migrate failed"
DATABASE_URL="$DB_URL" npm run db:seed >/dev/null 2>&1 || die "seed failed"
ok "migrations + seed applied"

H='-H Content-Type:application/json'

# ── Register an agent ──
c "Registering an agent"
AGENT_RESP=$(curl -sf -X POST "$API/agents" $H -d '{"name":"Smoke Agent","type":"openclaw","owner":"raphael"}')
AGENT_ID=$(echo "$AGENT_RESP" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
[ -n "$AGENT_ID" ] && ok "agent registered: $AGENT_ID" || die "no agent id"

# ── Create a deny policy ──
c "Creating a deny policy"
curl -sf -X POST "$API/policies" $H -d '{"name":"Deny Dangerous","rules":[{"action":"tool:dangerous","resource":"*","effect":"deny"}],"agent_ids":["*"],"priority":100}' >/dev/null
ok "deny policy created"

c "Creating a permit policy for the safe action"
curl -sf -X POST "$API/policies" $H -d '{"name":"Permit Safe Read","rules":[{"action":"data:read:safe","resource":"/safe","effect":"permit"}],"agent_ids":["*"],"priority":50,"default_effect":"deny"}' >/dev/null
ok "permit policy created"

# ── Gate: dangerous action must be denied ──
c "Gating a dangerous action (expect deny)"
DEC=$(curl -sf -X POST "$API/policy/evaluate" $H -d "{\"agent_id\":\"$AGENT_ID\",\"action\":\"tool:dangerous\",\"resource\":\"/fs\"}")
if echo "$DEC" | grep -q '"allowed":false'; then ok "dangerous action denied"; else bad "dangerous action NOT denied"; fi
if echo "$DEC" | grep -q '"certificate_id":"cert_'; then ok "certificate issued"; else bad "no certificate"; fi

# ── Gate: safe action must be allowed ──
c "Gating a safe action (expect allow)"
DEC2=$(curl -sf -X POST "$API/policy/evaluate" $H -d "{\"agent_id\":\"$AGENT_ID\",\"action\":\"data:read:safe\",\"resource\":\"/safe\"}")
if echo "$DEC2" | grep -q '"allowed":true'; then ok "safe action allowed"; else bad "safe action denied"; fi

# ── Log an event with an AWS key → redaction + critical alert ──
c "Logging an event with a leaked AWS key (expect redaction + alert)"
curl -sf -X POST "$API/agents/$AGENT_ID/events" $H -d "{\"agent_id\":\"$AGENT_ID\",\"event_type\":\"tool_call\",\"action\":\"tool:config\",\"resource\":\"/config\",\"result\":\"success\",\"details\":{\"env\":\"AKIAIOSFODNN7EXAMPLE leaked\"}}" >/dev/null

EVENTS=$(curl -sf "$API/agents/$AGENT_ID/events")
if echo "$EVENTS" | grep -q 'AWS_ACCESS_KEY'; then ok "AWS key redacted in stored event"; else bad "AWS key NOT redacted"; fi
if echo "$EVENTS" | grep -q 'AKIAIOSFODNN7EXAMPLE'; then bad "raw AWS key leaked to DB"; else ok "no raw key in DB"; fi

ALERTS=$(curl -sf "$API/alerts?acknowledged=false")
if echo "$ALERTS" | grep -q 'sensitive_data_detected'; then ok "sensitive-data alert raised"; else bad "no sensitive-data alert"; fi
if echo "$ALERTS" | grep -q '"severity":"critical"'; then ok "alert severity critical"; else bad "alert not critical"; fi

# ── Compliance mapping ──
c "Checking compliance mapping for a PII event"
curl -sf -X POST "$API/agents/$AGENT_ID/events" $H -d "{\"agent_id\":\"$AGENT_ID\",\"event_type\":\"data_access\",\"action\":\"classify:pii\",\"resource\":\"/hr\",\"result\":\"success\",\"details\":{\"data_type\":\"pii\"}}" >/dev/null
COMP=$(curl -sf "$API/compliance/$AGENT_ID/gdpr")
if echo "$COMP" | grep -q 'ART-22'; then ok "GDPR Art-22 mapped"; else bad "GDPR not mapped"; fi

# ── Hash-chain verification ──
c "Verifying the audit hash chain"
EXPORT=$(curl -sf "$API/compliance/export/$AGENT_ID")
if echo "$EXPORT" | grep -q '"verified":true'; then ok "hash chain verified"; else bad "hash chain broken"; fi

# ── Quarantine ──
c "Quarantining the agent"
Q=$(curl -sf -X POST "$API/agents/$AGENT_ID/quarantine")
if echo "$Q" | grep -q '"quarantined":true'; then ok "agent quarantined"; else bad "quarantine failed"; fi
if echo "$Q" | grep -q 'agent_quarantined'; then ok "quarantine alert created"; else bad "no quarantine alert"; fi
# Quarantined agent must now be denied at the gate
DEC3=$(curl -sf -X POST "$API/policy/evaluate" $H -d "{\"agent_id\":\"$AGENT_ID\",\"action\":\"data:read:anything\",\"resource\":\"/x\"}")
if echo "$DEC3" | grep -q 'quarantined'; then ok "quarantined agent denied at gate"; else bad "quarantined agent not denied"; fi

# ── Shadow-agent discovery ──
c "Shadow-agent discovery"
curl -sf -X POST "$API/discovery/access-logs" $H -d '{"access_logs":[{"api_key":"sk-ghost-smoke-001","resource":"/api/secret","timestamp":"2026-07-04T12:00:00Z"}]}' >/dev/null
SHADOW=$(curl -sf -X POST "$API/discovery/shadow-scan")
if echo "$SHADOW" | grep -q '"shadow_agents_detected":1'; then ok "shadow agent detected"; else bad "shadow agent NOT detected"; fi

# ── Dashboard summary ──
c "Dashboard summary"
SUM=$(curl -sf "$API/dashboard/summary")
if echo "$SUM" | grep -q '"agents"'; then ok "dashboard summary returned"; else bad "dashboard summary failed"; fi

# ── Dashboard UI loads ──
c "Dashboard UI (Vite+React)"
if curl -sf "$API/ui/" | grep -q 'root'; then ok "dashboard UI served at /ui/"; else bad "dashboard UI missing at /ui/"; fi
if curl -s -o /dev/null -w '%{http_code}' "$API/dashboard/" | grep -q '301'; then ok "old /dashboard/ redirects to /ui/"; else bad "old /dashboard/ does not redirect"; fi

# ── MCP server boots ──
c "MCP server process"
if API_BASE_URL="$API" API_KEY="" timeout 5 npx tsx src/mcp/server.ts 2>&1 | grep -q 'running on stdio'; then ok "MCP server starts"; else
  # fallback: non-timeout envs
  if API_BASE_URL="$API" API_KEY="" bash -c 'npx tsx src/mcp/server.ts 2>&1 & PID=$!; sleep 3; kill $PID 2>/dev/null; wait $PID 2>/dev/null' | grep -q 'running on stdio'; then ok "MCP server starts"; else bad "MCP server did not start"; fi
fi

# ── Result ──
echo ""
if [ "$FAIL" = "0" ]; then
  printf '\033[1;32m✅ ALL %d SMOKE CHECKS PASSED\033[0m\n' "$PASS"
  exit 0
else
  printf '\033[1;31m❌ %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
  exit 1
fi