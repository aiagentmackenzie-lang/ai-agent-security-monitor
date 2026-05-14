import { randomUUID } from 'crypto';
import type { Agent, AgentType } from '../types.js';

export type { Agent, AgentType };

export interface AgentEvent {
  id: string;
  agent_id: string;
  event_type: string;
  action?: string;
  resource?: string;
  result: 'success' | 'denied' | 'error';
  details: Record<string, unknown>;
  previous_hash?: string | null;
  hash: string;
  created_at: Date;
}

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