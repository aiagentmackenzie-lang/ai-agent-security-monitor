export type AgentType = 'langchain' | 'crewai' | 'claude_code' | 'openclaw' | 'openai_agents' | 'custom';

export interface AgentRegistration {
  name: string;
  type: AgentType;
  owner?: string;
  apiKey?: string;
  metadata?: Record<string, unknown>;
}

export interface GateRequest {
  agentId: string;
  action: string;
  resource: string;
  context?: {
    user?: string;
    sessionId?: string;
    dataClassification?: string;
  };
}

export interface GateResponse {
  allowed: boolean;
  reason: string;
  certificateId?: string;
  policyId?: string;
  evaluatedAt?: string;
  agentId: string;
  action: string;
  resource: string;
}

export interface EventLog {
  agentId: string;
  eventType: string;
  action?: string;
  resource?: string;
  result: 'success' | 'denied' | 'error';
  details?: Record<string, unknown>;
}

export interface SecurityMonitorClient {
  register(agent: AgentRegistration): Promise<{ id: string }>;
  gate(request: GateRequest): Promise<GateResponse>;
  log(event: EventLog): Promise<{ id: string }>;
}

async function hashKey(key: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(key);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Map SDK camelCase keys to API snake_case keys for context objects.
 */
function mapContext(context?: GateRequest['context']): Record<string, string | undefined> | undefined {
  if (!context) return undefined;
  return {
    user: context.user,
    session_id: context.sessionId,
    data_classification: context.dataClassification,
  };
}

function createClient(baseUrl: string, apiKey?: string): SecurityMonitorClient {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (apiKey) {
    headers['X-API-Key'] = apiKey;
  }

  return {
    register: async function(agent: AgentRegistration): Promise<{ id: string }> {
      const response = await fetch(`${baseUrl}/agents`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          name: agent.name,
          type: agent.type,
          owner: agent.owner,
          api_key_hash: agent.apiKey ? await hashKey(agent.apiKey) : undefined,
          metadata: agent.metadata || {},
        }),
      });
      if (!response.ok) throw new Error(`Registration failed: ${response.statusText}`);
      const data = await response.json() as { agent: { id: string } };
      return { id: data.agent.id };
    },

    gate: async function(request: GateRequest): Promise<GateResponse> {
      const response = await fetch(`${baseUrl}/policy/evaluate`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          agent_id: request.agentId,
          action: request.action,
          resource: request.resource,
          context: mapContext(request.context),
        }),
      });
      if (!response.ok) throw new Error(`Gate check failed: ${response.statusText}`);
      const apiData = await response.json() as {
        allowed: boolean;
        reason: string;
        policy_id?: string;
        certificate_id?: string;
        evaluated_at?: string;
        agent_id: string;
        action: string;
        resource: string;
      };

      return {
        allowed: apiData.allowed,
        reason: apiData.reason,
        policyId: apiData.policy_id,
        certificateId: apiData.certificate_id,
        evaluatedAt: apiData.evaluated_at,
        agentId: apiData.agent_id,
        action: apiData.action,
        resource: apiData.resource,
      };
    },

    log: async function(event: EventLog): Promise<{ id: string }> {
      const response = await fetch(`${baseUrl}/agents/${event.agentId}/events`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          agent_id: event.agentId,
          event_type: event.eventType,
          action: event.action,
          resource: event.resource,
          result: event.result,
          details: event.details || {},
        }),
      });
      if (!response.ok) throw new Error(`Event log failed: ${response.statusText}`);
      const data = await response.json() as { event: { id: string } };
      return { id: data.event.id };
    },
  };
}

export function createAgentClient(options: {
  baseUrl?: string;
  apiKey?: string;
}): SecurityMonitorClient {
  return createClient(options.baseUrl || 'http://localhost:8000', options.apiKey);
}

export async function register(
  agent: AgentRegistration,
  options?: { baseUrl?: string; apiKey?: string }
): Promise<{ id: string }> {
  return createAgentClient(options || {}).register(agent);
}

export async function gate(
  request: GateRequest,
  options?: { baseUrl?: string; apiKey?: string }
): Promise<GateResponse> {
  return createAgentClient(options || {}).gate(request);
}

export async function log(
  event: EventLog,
  options?: { baseUrl?: string; apiKey?: string }
): Promise<{ id: string }> {
  return createAgentClient(options || {}).log(event);
}