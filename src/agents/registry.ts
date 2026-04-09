import { randomUUID } from 'crypto';

export type AgentType = 'langchain' | 'crewai' | 'claude_code' | 'openclaw' | 'openai_agents' | 'custom';

export interface Agent {
  id: string;
  name: string;
  type: AgentType;
  api_key_hash?: string;
  owner?: string;
  metadata: Record<string, unknown>;
  active: boolean;
  created_at: Date;
  updated_at: Date;
}

export interface AgentEvent {
  id: string;
  agent_id: string;
  event_type: string;
  action?: string;
  resource?: string;
  result: 'success' | 'denied' | 'error';
  details: Record<string, unknown>;
  created_at: Date;
}

export function createAgent(data: Partial<Agent>): Agent {
  const now = new Date();
  return {
    id: data.id || `agt_${randomUUID().slice(0, 8)}`,
    name: data.name || 'Unknown Agent',
    type: data.type || 'custom',
    api_key_hash: data.api_key_hash,
    owner: data.owner,
    metadata: data.metadata || {},
    active: data.active !== false,
    created_at: data.created_at || now,
    updated_at: data.updated_at || now,
  };
}

export function createAgentEvent(data: Partial<AgentEvent>): AgentEvent {
  return {
    id: data.id || `evt_${randomUUID().slice(0, 8)}`,
    agent_id: data.agent_id || '',
    event_type: data.event_type || 'unknown',
    action: data.action,
    resource: data.resource,
    result: data.result || 'success',
    details: data.details || {},
    created_at: data.created_at || new Date(),
  };
}
