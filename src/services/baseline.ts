export interface BehaviorBaseline {
  agent_type: string;
  action_patterns: string[];
  event_frequency: number;
  typical_hours: string[];
  resource_access_patterns: string[];
}

export interface BehaviorAnomaly {
  agent_id: string;
  anomaly_type: 'frequency_spike' | 'unusual_action' | 'off_hours_activity' | 'new_resource_access';
  severity: 'low' | 'medium' | 'high';
  description: string;
  detected_at: Date;
}

export interface BaselineConfig {
  min_events_for_baseline: number;
  frequency_threshold_stddev: number;
  off_hours_start: number;
  off_hours_end: number;
}

const DEFAULT_BASELINE_CONFIG: BaselineConfig = {
  min_events_for_baseline: 50,
  frequency_threshold_stddev: 2,
  off_hours_start: 22,
  off_hours_end: 6,
};

export const DEFAULT_BASELINES: BehaviorBaseline[] = [
  {
    agent_type: 'langchain',
    action_patterns: ['tool_use', 'chain_invoke', 'llm_call', 'retrieval_query'],
    event_frequency: 100,
    typical_hours: ['9-17'],
    resource_access_patterns: ['vector_db', 'api:*'],
  },
  {
    agent_type: 'crewai',
    action_patterns: ['task_execute', 'crew_run', 'agent_delegate', 'task_complete'],
    event_frequency: 50,
    typical_hours: ['8-18'],
    resource_access_patterns: ['task_queue', 'api:*', 'file_processor'],
  },
  {
    agent_type: 'claude_code',
    action_patterns: ['bash', 'read', 'write', 'edit', 'grep', 'glob'],
    event_frequency: 200,
    typical_hours: ['9-22'],
    resource_access_patterns: ['filesystem:*', 'git', 'process'],
  },
  {
    agent_type: 'openclaw',
    action_patterns: ['skill_invoke', 'tool_call', 'agent_execute', 'mcp_call'],
    event_frequency: 150,
    typical_hours: ['6-22'],
    resource_access_patterns: ['skill:*', 'tool:*', 'mcp:*'],
  },
];

export function detectAnomalies(
  agentId: string,
  agentType: string,
  recentEvents: Array<{ action: string; created_at: Date; resource: string }>,
  baselines: BehaviorBaseline[] = DEFAULT_BASELINES,
  config: Partial<BaselineConfig> = {}
): BehaviorAnomaly[] {
  const anomalies: BehaviorAnomaly[] = [];
  const cfg = { ...DEFAULT_BASELINE_CONFIG, ...config };

  const baseline = baselines.find(b => b.agent_type === agentType);
  if (!baseline) return anomalies;

  const frequencyAnomaly = checkFrequencyAnomaly(recentEvents, baseline, cfg);
  if (frequencyAnomaly) anomalies.push(frequencyAnomaly);

  const actionAnomaly = checkUnusualActions(recentEvents, baseline);
  if (actionAnomaly) anomalies.push(actionAnomaly);

  const offHoursAnomaly = checkOffHoursActivity(recentEvents, baseline, cfg);
  if (offHoursAnomaly) anomalies.push(offHoursAnomaly);

  const resourceAnomaly = checkNewResourceAccess(recentEvents, baseline);
  if (resourceAnomaly) anomalies.push(resourceAnomaly);

  return anomalies;
}

function checkFrequencyAnomaly(
  events: Array<{ action: string; created_at: Date; resource: string }>,
  baseline: BehaviorBaseline,
  config: BaselineConfig
): BehaviorAnomaly | null {
  const hourEvents = events.filter(e => {
    const hour = e.created_at.getHours();
    return hour >= 9 && hour <= 17;
  });

  const avgEventsPerHour = hourEvents.length / 24;
  const expectedRate = baseline.event_frequency / 24;

  if (avgEventsPerHour > expectedRate * (1 + config.frequency_threshold_stddev)) {
    return {
      agent_id: '',
      anomaly_type: 'frequency_spike',
      severity: 'high',
      description: `Event frequency ${avgEventsPerHour.toFixed(1)}/hr exceeds baseline ${expectedRate.toFixed(1)}/hr by ${config.frequency_threshold_stddev} stddev`,
      detected_at: new Date(),
    };
  }

  return null;
}

function checkUnusualActions(
  events: Array<{ action: string; created_at: Date; resource: string }>,
  baseline: BehaviorBaseline
): BehaviorAnomaly | null {
  const unusualActions = events.filter(e => {
    const normalizedAction = e.action.split(':')[0];
    return !baseline.action_patterns.some(p => p.startsWith(normalizedAction));
  });

  if (unusualActions.length > events.length * 0.3) {
    return {
      agent_id: '',
      anomaly_type: 'unusual_action',
      severity: 'medium',
      description: `Agent performing ${unusualActions.length} unusual actions not in baseline pattern`,
      detected_at: new Date(),
    };
  }

  return null;
}

function checkOffHoursActivity(
  events: Array<{ action: string; created_at: Date; resource: string }>,
  baseline: BehaviorBaseline,
  config: BaselineConfig
): BehaviorAnomaly | null {
  const offHoursEvents = events.filter(e => {
    const hour = e.created_at.getHours();
    return hour >= config.off_hours_start || hour < config.off_hours_end;
  });

  if (offHoursEvents.length > baseline.event_frequency * 0.1) {
    return {
      agent_id: '',
      anomaly_type: 'off_hours_activity',
      severity: 'low',
      description: `${offHoursEvents.length} events detected outside typical business hours`,
      detected_at: new Date(),
    };
  }

  return null;
}

function checkNewResourceAccess(
  events: Array<{ action: string; created_at: Date; resource: string }>,
  baseline: BehaviorBaseline
): BehaviorAnomaly | null {
  const newResources = events.filter(e => {
    return !baseline.resource_access_patterns.some(p => {
      if (p === '*') return true;
      return e.resource.startsWith(p.replace('*', ''));
    });
  });

  if (newResources.length > 5) {
    return {
      agent_id: '',
      anomaly_type: 'new_resource_access',
      severity: 'medium',
      description: `Agent accessing ${newResources.length} new resource types not in baseline`,
      detected_at: new Date(),
    };
  }

  return null;
}

export function getBaselineForType(
  agentType: string,
  baselines: BehaviorBaseline[] = DEFAULT_BASELINES
): BehaviorBaseline | undefined {
  return baselines.find(b => b.agent_type === agentType);
}
