// Thin API client. All paths are absolute so the built bundle works behind any
// reverse proxy that fronts the Fastify API.

export interface Agent {
  id: string; name: string; type: string; owner?: string;
  active: boolean; quarantined: boolean; metadata: Record<string, unknown>;
  created_at: string;
}

export interface AlertRow {
  id: string; agent_id: string; type: string; severity: 'low' | 'medium' | 'high' | 'critical';
  message: string; acknowledged: boolean; created_at: string;
}

export interface PolicyRow {
  id: string; name: string; description?: string; rules: unknown[];
  agent_ids: string[]; active: boolean; default_effect?: string; priority: number;
}

export interface Summary {
  agents: { total: number; active: number; quarantined: number; inactive: number };
  events: { total: number; denied: number; errors: number };
  alerts: { total: number; unacknowledged: number; critical: number };
  compliance: Record<string, { total: number; compliant: number; gaps: number }>;
  generated_at: string;
}

export interface ComplianceSummary {
  by_regulation: Array<{ regulation: string; total: number; compliant: number; pending: number; gaps: number }>;
  overall: { total_records: number; compliant_records: number; compliance_rate: number };
}

export interface BehaviorFinding {
  agent_id: string; agent_name: string; registered_type: string;
  inferred_type: string; confidence: number; description: string;
}

export interface ShadowResult {
  shadow_agents_detected: number;
  discovered: Array<{ key_prefix: string; resource: string; observed_at: string }>;
}

async function getJSON<T>(path: string): Promise<T | null> {
  try {
    const r = await fetch(path);
    if (!r.ok) return null;
    return (await r.json()) as T;
  } catch {
    return null;
  }
}

export const api = {
  summary: () => getJSON<Summary>('/dashboard/summary'),
  complianceSummary: () => getJSON<ComplianceSummary>('/dashboard/compliance/summary'),
  agents: () => getJSON<{ agents: Agent[] }>('/agents'),
  alerts: () => getJSON<{ alerts: AlertRow[] }>('/alerts?acknowledged=false'),
  policies: () => getJSON<{ policies: PolicyRow[] }>('/policies'),
  behaviorScan: () => getJSON<{ behavior_findings: BehaviorFinding[] }>('/discovery/behavior-scan'),
  health: () => getJSON<{ status: string }>('/health'),
  acknowledge: async (id: string, by: string) => {
    await fetch(`/alerts/${id}/acknowledge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ acknowledged_by: by }),
    });
  },
};