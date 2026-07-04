# @ai-agent-security-monitor/sdk

TypeScript SDK for integrating AI agents with the **AI Agent Security Monitor**
governance API. Maps the API's snake_case contract to idiomatic camelCase.

## Install (local / pack)

```bash
# From the repo root:
npm run build:sdk            # builds sdk/dist
cd sdk && npm pack           # produces ai-agent-security-monitor-sdk-0.1.0.tgz
```

Then in a consumer project:

```bash
npm install ./ai-agent-security-monitor-sdk-0.1.0.tgz
```

## Usage

```ts
import { createAgentClient } from '@ai-agent-security-monitor/sdk';

const client = createAgentClient({
  baseUrl: 'http://localhost:8000',
  apiKey: process.env.AGENT_MONITOR_API_KEY!, // required when API_KEY is set server-side
});

// Register an agent (apiKey is SHA-256 hashed before sending)
const { id } = await client.register({
  name: 'My Agent',
  type: 'openclaw',
  owner: 'engineering',
  apiKey: 'sk-agent-xxx',
});

// Gate an action before executing it
const decision = await client.gate({
  agentId: id,
  action: 'data:read:users',
  resource: '/api/users',
  context: { user: 'alice', sessionId: 's1', dataClassification: 'confidential' },
});
if (!decision.allowed) {
  throw new Error(`Blocked by governance: ${decision.reason}`);
}

// Log what actually happened (auto-redacted server-side)
await client.log({
  agentId: id,
  eventType: 'tool_call',
  action: 'data:read:users',
  resource: '/api/users',
  result: 'success',
});
```

## Convenience functions

`register`, `gate`, and `log` are also exported as standalone functions that
accept an optional `{ baseUrl, apiKey }` second argument — handy for one-off
calls without constructing a client.

## API surface

| Method | Description |
|:---|:---|
| `client.register(agent)` | Register an agent; hashes `apiKey` if provided |
| `client.gate(request)` | Evaluate policy; returns `{ allowed, reason, certificateId, policyId, ... }` |
| `client.log(event)` | Append a redacted, hash-chained event to the audit trail |

## Contract notes

- The server API uses **snake_case**; the SDK maps to **camelCase** for you.
- `gate()` returns a signed `certificateId` — keep it as evidence of the
  decision if you need to prove the action was authorised.