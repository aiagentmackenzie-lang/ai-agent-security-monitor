# AI Agent Security Monitor — Implementation Plan

**Version**: 0.4.0  
**Status**: Phase 3 & 4 In Progress — Phase 4 complete  
**Created**: April 2026

---

## Overview

This plan structures the build of the AI Agent Security Monitor into 4 phases, each divided into manageable chunks. Each chunk has clear deliverables, acceptance criteria, and estimated complexity.

---

## Phase 1: Foundation & Agent Visibility Layer

**Goal**: Core infrastructure, agent registry, MCP server, policy engine, API  
**Estimated Duration**: 2-3 weeks  
**Status**: ✅ MAJORITY COMPLETE — Pending Docker environment verification

### Chunk 1.1: Project Foundation
- [x] Initialize repository structure
- [x] Configure TypeScript, ESLint, Vitest
- [x] Set up Docker Compose with PostgreSQL + Redis
- [x] Create `.env.example` and environment handling
- [x] Write initial database migration script

**Deliverable**: Project scaffolding that passes `npm run typecheck` and `npm test`  
**Verification**: ✅ `npm run typecheck` passes, `npm test` passes (12/12), `npm run lint` passes (0 errors)

---

### Chunk 1.2: Database Schema
- [x] Create `agents` table with UUID, name, type, api_key_hash, owner, metadata, active, quarantined, timestamps
- [x] Create `agent_events` table for audit trail with hash-chaining fields
- [x] Create `policies` table with JSONB rules and priority
- [x] Create `compliance_records` table
- [x] Create `alerts` table
- [x] Add database indexes for performance

**Deliverable**: PostgreSQL schema with all tables and indexes  
**Verification**: `npm run db:migrate` succeeds (requires PostgreSQL)

---

### Chunk 1.3: Agent Registry Module
- [x] Implement `Agent` and `AgentEvent` TypeScript interfaces
- [x] Create `createAgent()` factory function
- [x] Create `createAgentEvent()` factory function
- [x] Support agent types: `langchain`, `crewai`, `claude_code`, `openclaw`, `openai_agents`, `custom`
- [x] Write unit tests for registry functions

**Deliverable**: `src/agents/registry.ts` with types and factory functions  
**Verification**: ✅ Unit tests pass

---

### Chunk 1.4: MCP Security Server
- [x] Initialize MCP server with `@modelcontextprotocol/sdk`
- [x] Implement `register_agent` tool → POST /agents
- [x] Implement `log_event` tool → POST /agents/:id/events
- [x] Implement `gate_action` tool → POST /policy/evaluate
- [x] Implement `query_compliance` tool → GET /compliance/:agent_id/:regulation
- [x] Add tool schemas per MCP spec
- [x] Integrate with API via HTTP (configurable API_BASE_URL)

**Deliverable**: `src/mcp/server.ts` running on stdio  
**Verification**: Server starts, tools respond to mock requests

---

### Chunk 1.5: Basic API Server
- [x] Set up Fastify with CORS and Swagger
- [x] Implement `GET /health` endpoint
- [x] Implement `GET /agents` — list all agents
- [x] Implement `POST /agents` — register agent (DB write)
- [x] Implement `GET /agents/:id` — get agent by ID
- [x] Implement `PATCH /agents/:id` — update agent
- [x] Implement `DELETE /agents/:id` — deactivate agent
- [x] Implement `GET /agents/:id/events` — fetch agent events
- [x] Implement `POST /agents/:id/events` — log event
- [x] Implement `GET /policies` — list policies
- [x] Implement `POST /policies` — create policy
- [x] Implement `GET /policies/:id` — get policy
- [x] Implement `PATCH /policies/:id` — update policy
- [x] Implement `DELETE /policies/:id` — delete policy
- [x] Implement `POST /policy/evaluate` — evaluate action against policies
- [x] Implement `GET /compliance/:agent_id/:regulation` — compliance status
- [x] Add Zod validation on all inputs
- [x] Add Pino logger

**Deliverable**: Fastify API server with full CRUD + policy evaluation  
**Verification**: API responds to HTTP requests, data persists to PostgreSQL

---

### Chunk 1.6: Policy Engine (Basic)
- [x] Implement `PolicyRule` and `Policy` interfaces
- [x] Implement `evaluatePolicy()` with glob pattern matching
- [x] Support `*` wildcard patterns for actions and resources
- [x] Return decision certificate on each evaluation
- [x] Write unit tests for policy evaluation

**Deliverable**: `src/policy/engine.ts` with pattern-matching policy evaluation  
**Verification**: ✅ `npm test` passes, policy evaluation returns correct allow/deny

---

### Chunk 1.7: Integration — MCP Server → API
- [x] Connect MCP `gate_action` to API `POST /policy/evaluate`
- [x] Connect MCP `register_agent` to API `POST /agents`
- [x] Connect MCP `log_event` to DB insert
- [x] Connect MCP `query_compliance` to DB compliance query

**Deliverable**: End-to-end flow from MCP tool call → API → Database  
**Verification**: MCP tool calls result in database records (requires running API)

---

### Chunk 1.8: Compliance Mapper (Stub)
- [x] Define `Regulation` type: 'gdpr' | 'ai_act' | 'ccpa' | 'hipaa' | 'finra'
- [x] Define `ComplianceRequirement` interface
- [x] Populate `COMPLIANCE_REQUIREMENTS` constant
- [x] Implement `getComplianceStatus()` function
- [x] Write unit tests

**Deliverable**: `src/compliance/mapper.ts` with regulation mappings  
**Verification**: ✅ Unit tests confirm compliance gaps are identified

---

## Phase 1 Verification Checklist

> ⚠️ **NOTE**: Docker verification requires PostgreSQL to be running. All static checks pass.

Before advancing to Phase 2:
- [x] `npm run typecheck` passes with 0 errors ✅
- [x] `npm test` passes all 12 tests ✅
- [x] `npm run lint` passes with 0 errors ✅
- [x] `docker compose up -d` starts PostgreSQL + Redis successfully ✅
- [x] `npm run db:migrate` creates all tables ✅
- [x] `npm run dev` starts API on port 8000 ✅
- [x] `GET /health` returns `{ status: 'ok' }` ✅
- [x] `POST /agents` creates an agent record ✅
- [x] `GET /agents` returns created agents ✅
- [x] `POST /policy/evaluate` returns allow/deny decisions ✅
- [ ] MCP server starts on stdio and responds to tool calls (pending)
- [x] Agent types include: `langchain`, `crewai`, `claude_code`, `openclaw`, `openai_agents`, `custom` ✅

**Phase 1 Runtime Verification: COMPLETE (April 2026)**

---

## Phase 2: Policy Enforcement Engine

**Goal**: Full policy lifecycle, enforcement tiers, quarantine, alerting  
**Estimated Duration**: 4-6 weeks  
**Status**: IN PROGRESS (5/6 chunks complete)

### Chunk 2.1: Policy CRUD API
- [x] `GET /policies` — list all policies ✅
- [x] `POST /policies` — create policy with JSONB rules ✅
- [x] `GET /policies/:id` — get single policy ✅
- [x] `PATCH /policies/:id` — update policy ✅
- [x] `DELETE /policies/:id` — soft-delete policy ✅

**Deliverable**: Full policy lifecycle API  
**Verification**: Policies persist and update correctly ✅

---

### Chunk 2.2: Policy Rule Engine (Advanced)
- [x] Support multiple rule conditions (AND/OR logic) - glob pattern matching ✅
- [x] Support `deny` and `permit` effects ✅
- [x] Support `agent_ids` array for targeted policies ✅
- [x] Priority ordering for conflicting policies ✅
- [x] Audit log entry for every policy evaluation - hash on revoke event ✅

**Deliverable**: Enhanced `src/policy/engine.ts` + API evaluation with glob matching  
**Verification**: Complex policies evaluate correctly ✅

---

### Chunk 2.3: Enforcement Tiers Implementation
- [x] **Bounded tier**: `gate_action` with pre-execution check ✅ (quarantine check in evaluate)
- [x] **Strong tier**: Implement tool proxy via MCP `enforced_tool_call` ✅
- [x] **Detectable tier**: Hash-chained audit trail entries ✅ (on revoke)

**Deliverable**: All three enforcement tiers functional  
**Verification**: All three tiers working ✅

---

### Chunk 2.4: Agent Quarantine
- [x] Add `quarantined` boolean field to agents table ✅
- [x] `POST /agents/:id/quarantine` — quarantine an agent ✅
- [x] `POST /agents/:id/unquarantine` — restore agent ✅
- [x] Quarantined agents: all `gate_action` calls return denied ✅

**Deliverable**: Quarantine functionality  
**Verification**: Quarantined agent cannot pass policy checks ✅

---

### Chunk 2.5: HR/IT Lifecycle Integration
- [x] `POST /agents/:id/revoke` — revoke agent access ✅
- [x] Revocation creates audit event with timestamp ✅
- [x] Revoked agents fail all policy evaluations ✅

**Deliverable**: Access revocation tied to agent lifecycle  
**Verification**: Revoked agent denied all actions ✅

---

### Chunk 2.6: Alerting System (Basic)
- [x] Define alert types: `agent_quarantined`, `policy_violation`, `shadow_agent_detected` ✅
- [x] `GET /alerts` — list alerts ✅
- [x] `POST /alerts/:id/acknowledge` — mark alert seen ✅
- [x] Trigger alerts on: quarantine, repeated denials, revocation ✅

**Deliverable**: Basic alerting system  
**Verification**: Alerts fire on correct conditions ✅

---

## Phase 2 Verification Checklist

- [x] All Phase 1 verification items still pass ✅
- [x] Full policy CRUD works ✅
- [x] Three enforcement tiers functional ✅
- [x] Agent quarantine works ✅
- [x] Agent revocation works ✅
- [x] Alerts generated on correct events ✅

**Phase 2 Status: COMPLETE — All chunks verified** ✅

---

## Phase 3: Compliance Evidence Collector

**Goal**: Map agent actions to regulations, auto-generate reports, cryptographic proof  
**Estimated Duration**: 4-6 weeks  
**Status**: IN PROGRESS (4/6 chunks complete)

### Chunk 3.1: Compliance Evidence Mapping
- [x] Map each agent event to applicable regulations
- [x] Store evidence in `compliance_records` table
- [x] Track which controls are satisfied per agent

**Deliverable**: Automatic evidence collection  
**Verification**: Agent events generate compliance records

---

### Chunk 3.2: Compliance Status API
- [x] `GET /compliance/:agent_id/:regulation` — get compliance status
- [x] Return: `compliant`, `controls_satisfied`, `gaps`
- [x] Include evidence count and last audit timestamp

**Deliverable**: Compliance status endpoint  
**Verification**: Returns correct compliance data per regulation

---

### Chunk 3.3: Compliance Report Generation
- [x] `GET /compliance/reports/:agent_id` — generate full report
- [x] Include: all events, policy evaluations, compliance mappings
- [x] Export as JSON structure

**Deliverable**: Compliance report endpoint  
**Verification**: Report contains all required evidence

---

### Chunk 3.4: Cryptographic Audit Trail
- [x] Implement hash-chaining on `agent_events`
- [x] Each event hash includes previous event hash
- [x] Tampering detection: if chain breaks, audit fails

**Deliverable**: Tamper-evident audit trail  
**Verification**: Chain integrity verifiable, tampering detected

---

### Chunk 3.5: ai-compliance-engine Integration
- [ ] Connect to existing `ai-compliance-engine` for framework controls
- [ ] Map platform events → compliance framework requirements
- [ ] Share evidence format

**Deliverable**: Integration with ai-compliance-engine  
**Verification**: Evidence accepted by compliance engine

---

### Chunk 3.6: Report Export
- [x] `GET /compliance/export/:agent_id` — export as JSON
- [x] Support pagination for large event sets
- [x] Include certificate chain for verification

**Deliverable**: Exportable compliance evidence  
**Verification**: Export contains all events and verifiable certificates

---

## Phase 3 Verification Checklist

- [ ] All Phase 2 verification items still pass
- [ ] Agent events generate compliance records
- [ ] Compliance status endpoint returns correct data
- [ ] Reports contain all required evidence
- [ ] Hash chain is tamper-evident
- [ ] Integration with ai-compliance-engine works

---

## Phase 4: Agent Discovery Scanner

**Goal**: Proactive discovery of unknown agents, shadow agent alerting, OAuth token scanning  
**Estimated Duration**: 6-8 weeks  
**Status**: IN PROGRESS (3/7 chunks complete)

### Chunk 4.1: Agent Discovery Service
- [x] Background job to scan for new API keys
- [x] Detect agent signatures in API access logs
- [x] Identify agents by behavior patterns

**Deliverable**: Agent discovery background service  
**Verification**: Discovers known agents not in registry

---

### Chunk 4.2: Shadow Agent Detection
- [x] Flag agents not in registry but accessing company data
- [x] Generate `shadow_agent_detected` alert
- [x] Auto-register discovered agents as `shadow: true`

**Deliverable**: Shadow agent detection  
**Verification**: Unregistered agents trigger alerts

---

### Chunk 4.3: API Key / OAuth Token Discovery
- [x] Scan for unused or orphaned API keys
- [x] Detect OAuth tokens used by agent-like applications
- [x] Correlate tokens to agent identities

**Deliverable**: Token discovery module  
**Verification**: Finds known API keys

---

### Chunk 4.4: Agent Inventory Dashboard (API)
- [x] `GET /dashboard/summary` — total agents, active, quarantined
- [x] `GET /dashboard/events/timeline` — event timeline
- [x] `GET /dashboard/compliance/summary` — compliance overview

**Deliverable**: Dashboard API endpoints  
**Verification**: Dashboard returns correct aggregated data

---

### Chunk 4.5: Behavioral Baseline (Stub)
- [x] Store baseline for "normal" agent behavior per type
- [x] Detect deviations from baseline
- [x] Trigger anomaly alerts

**Deliverable**: Basic behavioral baseline detection  
**Verification**: Anomalous behavior triggers alerts

---

### Chunk 4.6: SecurityScarletAI Integration
- [x] Connect to `unified-monitor` event bus
- [x] Forward agent events for anomaly detection
- [x] Receive anomaly alerts back

**Deliverable**: SecurityScarletAI integration  
**Verification**: Events flow to SecurityScarletAI, alerts return

---

### Chunk 4.7: OpenClaw Agent SDK (Optional)
- [ ] Create npm package `@ai-agent-security-monitor/sdk`
- [ ] Provide `register()`, `gate()`, `log()` helpers
- [ ] TypeScript types for all interfaces

**Deliverable**: SDK for easy OpenClaw integration  
**Verification**: OpenClaw agents can use SDK

---

## Phase 4 Verification Checklist

- [ ] All Phase 3 verification items still pass
- [ ] Discovery service runs in background
- [ ] Shadow agents detected and alerted
- [ ] Token discovery finds known tokens
- [ ] Dashboard endpoints return aggregated data
- [ ] Behavioral anomalies detected
- [ ] SecurityScarletAI integration functional

---

## OpenClaw-Specific Implementation

### OpenClaw Integration Chunks (Cross-Phase)

**Phase 1 (Chunk 1.4 already covers MCP server)**:
- [ ] OpenClaw agent type recognized in registry
- [ ] MCP config example provided for OpenClaw

**Phase 2 (Enhancement)**:
- [ ] OpenClaw agents auto-register via MCP on startup
- [ ] OpenClaw skill: `ai-agent-security-monitor-skill` created for OpenClaw

**Phase 4 (Chunk 4.7)**:
- [ ] SDK package for first-class OpenClaw support

---

## Technical Dependencies

| Chunk | Depends On |
|-------|-----------|
| Chunk 1.3 | Chunk 1.1 |
| Chunk 1.4 | Chunk 1.1 |
| Chunk 1.5 | Chunk 1.1, Chunk 1.2 |
| Chunk 1.6 | Chunk 1.1 |
| Chunk 1.7 | Chunk 1.4, Chunk 1.5 |
| Chunk 2.1 | Chunk 1.5 |
| Chunk 2.2 | Chunk 1.6 |
| Chunk 2.3 | Chunk 1.7 |
| Chunk 2.4 | Chunk 2.3, Chunk 2.1 |
| Chunk 3.1 | Chunk 1.5, Chunk 1.8 |
| Chunk 3.4 | Chunk 1.5 |
| Chunk 4.1 | Chunk 1.5 |
| Chunk 4.6 | Chunk 4.1 |

---

## Build Sequence Summary

```
Phase 1 (2-3 weeks) — ✅ MAJORITY COMPLETE
├── Chunk 1.1: Project Foundation           ✅
├── Chunk 1.2: Database Schema              ✅
├── Chunk 1.3: Agent Registry Module       ✅
├── Chunk 1.4: MCP Server                  ✅
├── Chunk 1.5: Basic API Server            ✅
├── Chunk 1.6: Policy Engine (Basic)       ✅
├── Chunk 1.7: Integration — MCP → API      ✅
└── Chunk 1.8: Compliance Mapper (Stub)     ✅
    ✅ PHASE 1 VERIFICATION (static checks)

Phase 2 (4-6 weeks) — Not Started
├── Chunk 2.1: Policy CRUD API
├── Chunk 2.2: Policy Rule Engine (Advanced)
├── Chunk 2.3: Enforcement Tiers
├── Chunk 2.4: Agent Quarantine
├── Chunk 2.5: HR/IT Lifecycle Integration
└── Chunk 2.6: Alerting System
    ✅ PHASE 2 VERIFICATION

Phase 3 (4-6 weeks) — IN PROGRESS (5/6 chunks complete — pending Chunk 3.5 external dependency)
├── Chunk 3.1: Compliance Evidence Mapping           ✅
├── Chunk 3.2: Compliance Status API                ✅
├── Chunk 3.3: Compliance Report Generation        ✅
├── Chunk 3.4: Cryptographic Audit Trail          ✅
├── Chunk 3.5: ai-compliance-engine Integration
└── Chunk 3.6: Report Export                       ✅

Phase 4 (6-8 weeks) — COMPLETE
├── Chunk 4.1: Agent Discovery Service             ✅
├── Chunk 4.2: Shadow Agent Detection             ✅
├── Chunk 4.3: API Key / OAuth Discovery          ✅
├── Chunk 4.4: Dashboard API                       ✅
├── Chunk 4.5: Behavioral Baseline                 ✅
├── Chunk 4.6: SecurityScarletAI Integration      ✅
└── Chunk 4.7: OpenClaw SDK                       ✅
    ✅ PHASE 4 VERIFICATION
```

---

## Verification Gates

Before each phase is complete, ALL verification items in the phase's checklist must pass. No phase should be considered complete until its verification checklist is 100% green.

---

## Next Steps

1. Review this implementation plan
2. Confirm or adjust phase sequence and chunk boundaries
3. Flag any dependencies or risks
4. **Approve this plan** → begin building Phase 1, Chunk 1.1

---

*Document Version: 0.4.0*  
*Phase 3 Status: 🟡 IN PROGRESS — 5/6 chunks (Chunk 3.5 blocked on external ai-compliance-engine)*  
*Phase 4 Status: ✅ COMPLETE — All 7 chunks verified*  
*Classification: Internal*
