/**
 * Canonical type definitions for AI Agent Security Monitor.
 * All other modules must import from this file — no duplicate definitions.
 */

export type AgentType = 'langchain' | 'crewai' | 'claude_code' | 'openclaw' | 'openai_agents' | 'custom';

export type EventResult = 'success' | 'denied' | 'error';

export type Regulation = 'gdpr' | 'ai_act' | 'ccpa' | 'hipaa' | 'finra';

export interface Agent {
  id: string;
  name: string;
  type: AgentType;
  api_key_hash?: string;
  owner?: string;
  metadata: Record<string, unknown>;
  active: boolean;
  quarantined: boolean;
  created_at: Date;
  updated_at: Date;
}

export interface AgentEvent {
  id: string;
  agent_id: string;
  event_type: string;
  action?: string;
  resource?: string;
  result: EventResult;
  details: Record<string, unknown>;
  previous_hash?: string | null;
  hash: string;
  created_at: Date;
}

export interface PolicyRule {
  action: string;
  resource: string;
  effect: 'permit' | 'deny';
  conditions?: Record<string, unknown>;
}

export interface Policy {
  id: string;
  name: string;
  description?: string;
  rules: PolicyRule[];
  agent_ids: string[];
  active: boolean;
  /** When 'deny', unmatched actions are blocked (allowlist mode). When absent, unmatched actions are allowed (denylist mode). */
  default_effect?: 'deny';
  priority: number;
  created_at: Date;
  updated_at: Date;
}

export interface ComplianceRecord {
  id: string;
  agent_id: string;
  regulation: Regulation;
  control_id: string;
  evidence: Record<string, unknown>;
  status: 'pending' | 'compliant' | 'non_compliant';
  created_at: Date;
}

export interface PolicyEvaluationRequest {
  agent_id: string;
  action: string;
  resource: string;
  context?: {
    user?: string;
    session_id?: string;
    data_classification?: string;
    timestamp?: string;
  };
}

export interface PolicyEvaluationResult {
  allowed: boolean;
  reason: string;
  policy_id?: string;
  certificate_id?: string;
  evaluated_at: string;
}

export interface ComplianceStatus {
  compliant: boolean;
  controls_satisfied: string[];
  gaps: string[];
}

export interface Alert {
  id: string;
  agent_id: string;
  type: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  acknowledged: boolean;
  acknowledged_by?: string;
  acknowledged_at?: Date;
  metadata: Record<string, unknown>;
  created_at: Date;
}