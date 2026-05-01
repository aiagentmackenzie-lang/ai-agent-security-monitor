import { describe, it, expect } from 'vitest';
import {
  detectAnomalies,
  getBaselineForType,
  DEFAULT_BASELINES,
  type BehaviorBaseline,
  type BaselineConfig,
} from '../src/services/baseline.js';

describe('Baseline - Default Baselines', () => {
  it('should have baselines for all supported agent types', () => {
    const types = DEFAULT_BASELINES.map(b => b.agent_type);
    expect(types).toContain('langchain');
    expect(types).toContain('crewai');
    expect(types).toContain('claude_code');
    expect(types).toContain('openclaw');
    expect(types.length).toBe(4);
  });

  it('should have action patterns for each baseline', () => {
    for (const baseline of DEFAULT_BASELINES) {
      expect(baseline.action_patterns.length).toBeGreaterThan(0);
      expect(baseline.event_frequency).toBeGreaterThan(0);
      expect(baseline.typical_hours.length).toBeGreaterThan(0);
      expect(baseline.resource_access_patterns.length).toBeGreaterThan(0);
    }
  });

  it('should get baseline by agent type', () => {
    const openclaw = getBaselineForType('openclaw');
    expect(openclaw).toBeDefined();
    expect(openclaw!.agent_type).toBe('openclaw');
    expect(openclaw!.action_patterns).toContain('skill_invoke');
  });

  it('should return undefined for unknown agent type', () => {
    const result = getBaselineForType('unknown_type');
    expect(result).toBeUndefined();
  });
});

describe('Baseline - Frequency Anomaly Detection', () => {
  const baseline: BehaviorBaseline = {
    agent_type: 'test',
    action_patterns: ['data:read', 'data:write'],
    event_frequency: 100,
    typical_hours: ['9-17'],
    resource_access_patterns: ['/api/*'],
  };

  it('should detect frequency spikes', () => {
    // All events within business hours (9-17) — 5000 events in a 1-hour window
    const noon = new Date();
    noon.setHours(12, 0, 0, 0);
    const events = Array.from({ length: 5000 }, (_, i) => ({
      action: 'data:read',
      created_at: new Date(noon.getTime() - i * 60000), // 1 min apart
      resource: '/api/data',
    }));

    // With freq_threshold_stddev=2 and baseline frequency=100,
    // expected rate = 100/24 ≈ 4.17/hr, threshold = 4.17 * 3 ≈ 12.5/hr
    // 5000 events over ~83 hrs but only ~32hrs in 9-17 range
    // avgEventsPerHour = 32/24 ≈ 208/hr — far exceeds 12.5
    const anomalies = detectAnomalies('agt_test', 'test', events, [baseline]);
    const freqAnomaly = anomalies.find(a => a.anomaly_type === 'frequency_spike');
    expect(freqAnomaly).toBeDefined();
    expect(freqAnomaly!.severity).toBe('high');
  });

  it('should not flag normal frequency', () => {
    const now = new Date();
    now.setHours(12, 0, 0, 0);
    const events = Array.from({ length: 10 }, (_, i) => ({
      action: 'data:read',
      created_at: new Date(now.getTime() - i * 3600000),
      resource: '/api/data',
    }));

    const anomalies = detectAnomalies('agt_test', 'test', events, [baseline]);
    expect(anomalies.find(a => a.anomaly_type === 'frequency_spike')).toBeUndefined();
  });
});

describe('Baseline - Unusual Action Detection', () => {
  const baseline: BehaviorBaseline = {
    agent_type: 'openclaw',
    action_patterns: ['skill_invoke', 'tool_call', 'agent_execute', 'mcp_call'],
    event_frequency: 150,
    typical_hours: ['6-22'],
    resource_access_patterns: ['skill:*', 'tool:*', 'mcp:*'],
  };

  it('should detect unusual actions exceeding 30% threshold', () => {
    const now = new Date();
    now.setHours(12);
    const events = Array.from({ length: 20 }, (_, i) => ({
      action: i < 7 ? 'skill_invoke' : 'admin:delete:users',
      created_at: new Date(now.getTime() - i * 3600000),
      resource: '/api/users',
    }));

    const anomalies = detectAnomalies('agt_test', 'openclaw', events, [baseline]);
    const actionAnomaly = anomalies.find(a => a.anomaly_type === 'unusual_action');
    expect(actionAnomaly).toBeDefined();
    expect(actionAnomaly!.severity).toBe('medium');
  });

  it('should not flag normal actions', () => {
    const now = new Date();
    now.setHours(12);
    const events = Array.from({ length: 10 }, (_, i) => ({
      action: 'skill_invoke',
      created_at: new Date(now.getTime() - i * 3600000),
      resource: '/skill/search',
    }));

    const anomalies = detectAnomalies('agt_test', 'openclaw', events, [baseline]);
    expect(anomalies.find(a => a.anomaly_type === 'unusual_action')).toBeUndefined();
  });
});

describe('Baseline - Off-Hours Activity', () => {
  const baseline: BehaviorBaseline = {
    agent_type: 'crewai',
    action_patterns: ['task_execute', 'crew_run'],
    event_frequency: 50,
    typical_hours: ['8-18'],
    resource_access_patterns: ['task_queue', 'api:*'],
  };

  it('should detect off-hours activity', () => {
    const midnight = new Date();
    midnight.setHours(0, 0, 0, 0);
    const events = Array.from({ length: 10 }, (_, i) => ({
      action: 'task_execute',
      created_at: new Date(midnight.getTime() + i * 60000),
      resource: '/task/queue',
    }));

    const config: Partial<BaselineConfig> = {
      off_hours_start: 22,
      off_hours_end: 6,
      min_events_for_baseline: 5,
      frequency_threshold_stddev: 2,
    };

    const anomalies = detectAnomalies('agt_test', 'crewai', events, [baseline], config);
    const offHours = anomalies.find(a => a.anomaly_type === 'off_hours_activity');
    expect(offHours).toBeDefined();
    expect(offHours!.severity).toBe('low');
  });
});

describe('Baseline - New Resource Access', () => {
  const baseline: BehaviorBaseline = {
    agent_type: 'langchain',
    action_patterns: ['tool_use', 'chain_invoke', 'llm_call'],
    event_frequency: 100,
    typical_hours: ['9-17'],
    resource_access_patterns: ['vector_db', 'api:*'],
  };

  it('should detect new resource access patterns', () => {
    const now = new Date();
    now.setHours(12);
    const events = Array.from({ length: 8 }, (_, i) => ({
      action: 'tool_use',
      created_at: new Date(now.getTime() - i * 3600000),
      resource: `/admin/secret-${i}`,
    }));

    const anomalies = detectAnomalies('agt_test', 'langchain', events, [baseline]);
    const resourceAnomaly = anomalies.find(a => a.anomaly_type === 'new_resource_access');
    expect(resourceAnomaly).toBeDefined();
  });

  it('should not flag baseline resource access', () => {
    const now = new Date();
    now.setHours(12);
    const events = Array.from({ length: 5 }, (_, i) => ({
      action: 'tool_use',
      created_at: new Date(now.getTime() - i * 3600000),
      resource: `/api/data-${i}`,
    }));

    const anomalies = detectAnomalies('agt_test', 'langchain', events, [baseline]);
    expect(anomalies.find(a => a.anomaly_type === 'new_resource_access')).toBeUndefined();
  });
});

describe('Baseline - Unknown Agent Type', () => {
  it('should return no anomalies for unknown agent type', () => {
    const now = new Date();
    const events = Array.from({ length: 100 }, (_, i) => ({
      action: 'unknown_action',
      created_at: new Date(now.getTime() - i * 60000),
      resource: '/unknown/path',
    }));

    const anomalies = detectAnomalies('agt_test', 'unknown_type', events);
    expect(anomalies).toEqual([]);
  });
});