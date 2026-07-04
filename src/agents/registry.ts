import { randomUUID } from 'crypto';
import type { Agent, AgentType, AgentEvent } from '../types.js';

export type { Agent, AgentType, AgentEvent };

/**
 * In-memory factory helpers for constructing Agent and AgentEvent objects.
 *
 * NOTE: These produce `agt_<short>` string IDs for test/illustration use. The
 * live API does NOT use these — the database generates UUIDs for persisted
 * agents (see `src/db/init.ts`). Do not persist the `agt_` IDs against the
 * UUID-typed `agent_id` foreign key.
 */
export function createAgent(data: Partial<Agent> & { name?: string }): Agent {
  const now = new Date();
  return {
    id: data.id || `agt_${randomUUID().slice(0, 8)}`,
    name: data.name || 'Unknown Agent',
    type: data.type || 'custom',
    api_key_hash: data.api_key_hash,
    owner: data.owner,
    metadata: data.metadata || {},
    active: data.active !== false,
    quarantined: data.quarantined ?? false,
    created_at: data.created_at || now,
    updated_at: data.updated_at || now,
  };
}

export function createAgentEvent(data: Partial<AgentEvent> & { agent_id: string; event_type: string; result: 'success' | 'denied' | 'error' }): AgentEvent {
  return {
    id: data.id || `evt_${randomUUID().slice(0, 8)}`,
    agent_id: data.agent_id,
    event_type: data.event_type,
    action: data.action,
    resource: data.resource,
    result: data.result,
    details: data.details || {},
    previous_hash: data.previous_hash ?? null,
    hash: data.hash ?? '',
    created_at: data.created_at || new Date(),
  };
}