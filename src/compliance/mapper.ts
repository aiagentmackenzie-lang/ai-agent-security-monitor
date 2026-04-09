export type Regulation = 'gdpr' | 'ai_act' | 'ccpa' | 'hipaa' | 'finra';

export interface ComplianceRequirement {
  regulation: Regulation;
  control_id: string;
  description: string;
  data_types?: string[];
  agent_actions?: string[];
}

export const COMPLIANCE_REQUIREMENTS: ComplianceRequirement[] = [
  {
    regulation: 'gdpr',
    control_id: 'ART-22',
    description: 'Automated decision-making affecting individuals must be documented and explainable',
    data_types: ['pii', 'personal_data'],
    agent_actions: ['decision:*', 'classify:*', 'score:*'],
  },
  {
    regulation: 'ai_act',
    control_id: 'ART-12',
    description: 'Operators of AI systems must maintain documentation of system operations',
    data_types: ['*'],
    agent_actions: ['*'],
  },
  {
    regulation: 'ccpa',
    control_id: 'SEC-1798',
    description: 'Consumer data access must be documented and revocable',
    data_types: ['consumer_data', 'pii'],
    agent_actions: ['data:read:*', 'data:access:*'],
  },
  {
    regulation: 'hipaa',
    control_id: 'PHI-LOG',
    description: 'PHI access must be logged and monitored',
    data_types: ['phi', 'health_data'],
    agent_actions: ['data:read:*', 'api:call:*'],
  },
  {
    regulation: 'finra',
    control_id: 'FINRA-4511',
    description: 'AI-assisted financial services require audit trails',
    data_types: ['financial_data'],
    agent_actions: ['trade:*', 'execute:*', 'analyze:*'],
  },
];

export interface ComplianceRecord {
  agent_id: string;
  regulation: Regulation;
  control_id: string;
  evidence: Record<string, unknown>;
  status: 'compliant' | 'pending' | 'gap';
}

export function mapEventToCompliance(
  agentId: string,
  eventType: string,
  action: string | undefined,
  resource: string | undefined,
  details: Record<string, unknown>
): ComplianceRecord[] {
  const records: ComplianceRecord[] = [];

  for (const req of COMPLIANCE_REQUIREMENTS) {
    const actionMatches = matchGlobPattern(action || '', req.agent_actions || []);
    const resourceMatches = matchDataType(details, req.data_types || []);

    if (actionMatches || resourceMatches) {
      records.push({
        agent_id: agentId,
        regulation: req.regulation,
        control_id: req.control_id,
        evidence: {
          event_type: eventType,
          action,
          resource,
          details,
          mapped_at: new Date().toISOString(),
        },
        status: 'compliant',
      });
    }
  }

  return records;
}

function matchGlobPattern(action: string, patterns: string[]): boolean {
  for (const pattern of patterns) {
    if (pattern === '*') return true;
    if (pattern.includes('*')) {
      const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
      if (regex.test(action)) return true;
    } else if (pattern === action) {
      return true;
    }
  }
  return false;
}

function matchDataType(details: Record<string, unknown>, dataTypes: string[]): boolean {
  const dataType = details.data_type as string || details.dataClassification as string;
  if (!dataType) return false;
  for (const dt of dataTypes) {
    if (dt === '*') return true;
    if (dt === dataType) return true;
    if (dataType.includes(dt)) return true;
  }
  return false;
}

export function getComplianceStatus(
  regulation: Regulation,
  agent_metadata: Record<string, unknown>
): { compliant: boolean; controls_satisfied: string[]; gaps: string[] } {
  const requirements = COMPLIANCE_REQUIREMENTS.filter(r => r.regulation === regulation);
  const controls_satisfied: string[] = [];
  const gaps: string[] = [];

  for (const req of requirements) {
    const complianceData = agent_metadata.compliance as Record<string, boolean> | undefined;
    if (complianceData?.[req.control_id]) {
      controls_satisfied.push(req.control_id);
    } else {
      gaps.push(req.control_id);
    }
  }

  return {
    compliant: gaps.length === 0,
    controls_satisfied,
    gaps,
  };
}
