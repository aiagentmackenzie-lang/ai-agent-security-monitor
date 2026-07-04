# Threat Model — AI Agent Security Monitor

Mapping the platform's controls to the **OWASP Agentic Top 10 (2026)** and the
current agent-runtime attack surface. This document is the interview/client
differentiator: it shows the controls are anchored to a recognised framework,
not invented.

## Scope

The platform is a **runtime governance and observability plane** for AI agents
that call tools and access data. It sits between agent frameworks (LangChain,
CrewAI, Claude Code, OpenClaw, OpenAI Agents) and the resources they touch. It
does **not** host agents or execute tools — it gates and records.

## Assets

- **Audit trail** (`agent_events`) — tamper-evident evidence of record.
- **Policy store** — defines what agents may do.
- **Agent registry** — identity + quarantine/revoke state.
- **Compliance records** — regulatory evidence.

## OWASP Agentic Top 10 (2026) — control mapping

| # | Agentic risk | How this platform mitigates |
|:---:|:---|:---|
| A1 | **Excessive agency / unauthorized tool execution** | `gate_action` + `evaluate_tool_call` enforce deny/permit policy with signed certificates before any tool runs. Allowlist (`default_effect: deny`) blocks unmatched actions. Quarantined/inactive agents are denied at the gate. |
| A2 | **Sensitive data exposure in logs/outputs** | 17-pattern redaction engine strips keys/tokens/PII from `event.details` **before** persistence. Critical/high findings auto-create alerts. |
| A3 | **Unregistered / shadow agents** | Two real discovery heuristics: access-log key-scan (hash-based, privacy-preserving) and behavior-scan (misregistered-type detection). Shadow agents get `high` alerts. |
| A4 | **Lack of auditability** | SHA-256 hash-chained event log with all fields + timestamp. `/compliance/export` verifies the chain. Tamper turns `verified` to `false`. |
| A5 | **Insecure agent-to-agent / agent-to-tool boundaries** | MCP `evaluate_tool_call` is **decision-only** — it never proxies the tool. The calling agent must respect the decision; denials are logged as `tool_denied` events. |
| A6 | **Prompt-injection-driven policy bypass** | Policy conditions can require `data_classification` / `user` / `session_id` context. Permit rules with conditions but no context fail closed (skipped → default-deny). |
| A7 | **Non-compliant automated decisions** | Auto-mapping to GDPR Art-22, AI Act Art-12, CCPA, HIPAA, FINRA with `pending` status (never auto-compliant). Evidence is collected per event. |
| A8 | **Supply-chain / credential leakage via agents** | Redaction catches provider keys (OpenAI, Anthropic, GCP, Gemini, GitHub, Stripe, Slack) in agent outputs before they're stored or forwarded. |
| A9 | **Loss of agent control (rogue agent)** | One-call quarantine (blocks gate) and revoke (transactional: deactivate + quarantine + chain event + critical alert). |
| A10 | **Unbounded agent activity (volume/frequency abuse)** | Redis-backed rate limiting on the API; behavior baselines detect frequency spikes, off-hours activity, unusual actions, and new resource access. |

## Trust boundaries

```
[Agent framework] --(gate_action/evaluate_tool_call)--> [Policy Engine] --> decision
        |                       |
        |                  (log_event)
        v                       v
   tool execution          [Redaction] --> [Audit chain] --> [Compliance mapper]
                                                                |
                                                  (opt-in) --> [SecurityScarletAI SIEM]
```

- **Boundary 1 — agent → gate:** untrusted. The agent may send any action/resource/context. Policy is evaluated server-side; the agent cannot influence the decision beyond the inputs, which are matched against signed rules.
- **Boundary 2 — event → persistence:** untrusted input redacted before trust. The chain hash is computed server-side from canonicalised fields.
- **Boundary 3 — API → SIEM:** optional, fire-and-forget. SIEM compromise cannot affect the audit chain.

## Assumptions & limits (honest)

- The platform **cannot enforce** a decision on an agent that ignores it. The
  MCP `evaluate_tool_call` returns a decision; a malicious agent that bypasses
  the MCP gate and calls the tool directly is only caught **after the fact**
  via logged events, anomaly detection, and shadow discovery. Full
  in-band enforcement requires the tool layer to require a valid certificate
  (roadmap: certificate-verifying tool proxy).
- Policy context (e.g. `data_classification`) is provided by the caller. The
  platform does not independently classify data — it enforces on the
  classification it is given. Operators must ensure classification is set
  upstream.
- Behavior discovery requires ≥10 events per agent before inference.
- The audit chain proves **integrity**, not **authenticity of the submitter** —
  if a registered agent's credentials are compromised, events appear valid.
  Pair with quarantine/revoke on anomaly.

## Roadmap (not in this build)

- Certificate-verifying tool proxy (in-band enforcement).
- JWT/OIDC for operator auth (currently single shared `API_KEY`).
- Per-tenant policy namespaces.
- SBOM + cosign image signing.