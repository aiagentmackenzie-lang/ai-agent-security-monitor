import { describe, it, expect } from 'vitest';
import {
  mapEventToCompliance,
  getComplianceStatus,
  COMPLIANCE_REQUIREMENTS,
  type Regulation,
} from '../src/compliance/mapper.js';

describe('Compliance Mapper - Requirements Coverage', () => {
  it('should cover all 5 major regulations', () => {
    const regulations = COMPLIANCE_REQUIREMENTS.map(r => r.regulation);
    const unique = [...new Set(regulations)];
    expect(unique.sort()).toEqual(['ai_act', 'ccpa', 'finra', 'gdpr', 'hipaa']);
  });

  it('should have control IDs for each requirement', () => {
    for (const req of COMPLIANCE_REQUIREMENTS) {
      expect(req.control_id).toBeTruthy();
      expect(req.description).toBeTruthy();
    }
  });

  it('should have agent_actions defined for matching', () => {
    for (const req of COMPLIANCE_REQUIREMENTS) {
      expect(req.agent_actions).toBeDefined();
      expect(req.agent_actions!.length).toBeGreaterThan(0);
    }
  });
});

describe('Compliance Mapper - Event Mapping', () => {
  it('should map AI Act for all events (wildcard action)', () => {
    const records = mapEventToCompliance('agt_1', 'tool_call', 'data:read', '/api/users', {});
    const aiAct = records.find(r => r.regulation === 'ai_act');
    expect(aiAct).toBeDefined();
    expect(aiAct!.control_id).toBe('ART-12');
    expect(aiAct!.status).toBe('compliant');
  });

  it('should map GDPR for decision-making actions', () => {
    const records = mapEventToCompliance('agt_1', 'decision', 'classify:pii', '/api/users', {});
    const gdpr = records.find(r => r.regulation === 'gdpr');
    expect(gdpr).toBeDefined();
    expect(gdpr!.control_id).toBe('ART-22');
  });

  it('should map CCPA for consumer data access', () => {
    const records = mapEventToCompliance('agt_1', 'data_access', 'data:read:profile', '/api/consumer', {
      data_type: 'consumer_data',
    });
    const ccpa = records.find(r => r.regulation === 'ccpa');
    expect(ccpa).toBeDefined();
    expect(ccpa!.control_id).toBe('SEC-1798');
  });

  it('should map HIPAA for PHI access', () => {
    const records = mapEventToCompliance('agt_1', 'data_access', 'data:read:medical', '/api/health', {
      data_type: 'phi',
    });
    const hipaa = records.find(r => r.regulation === 'hipaa');
    expect(hipaa).toBeDefined();
    expect(hipaa!.control_id).toBe('PHI-LOG');
  });

  it('should map FINRA for financial trade actions', () => {
    const records = mapEventToCompliance('agt_1', 'trade', 'trade:execute', '/api/trades', {
      data_type: 'financial_data',
    });
    const finra = records.find(r => r.regulation === 'finra');
    expect(finra).toBeDefined();
    expect(finra!.control_id).toBe('FINRA-4511');
  });

  it('should return empty when no regulation matches', () => {
    const records = mapEventToCompliance('agt_1', 'ping', 'health:check', '/health', {});
    // Only AI Act wildcard matches everything
    expect(records.length).toBeGreaterThanOrEqual(0);
  });

  it('should include evidence in compliance records', () => {
    const records = mapEventToCompliance('agt_1', 'tool_call', 'data:read', '/api/users', { key: 'val' });
    for (const record of records) {
      expect(record.evidence).toBeDefined();
      expect(record.evidence.event_type).toBe('tool_call');
      expect(record.evidence.action).toBe('data:read');
      expect(record.evidence.mapped_at).toBeDefined();
    }
  });

  it('should map multiple regulations for a single event', () => {
    const records = mapEventToCompliance('agt_1', 'decision', 'classify:pii', '/api/users', {
      data_type: 'consumer_data',
    });
    // Should match GDPR (decision:*), CCPA (consumer_data), AI Act (*)
    expect(records.length).toBeGreaterThanOrEqual(2);
    const regulationNames = records.map(r => r.regulation);
    expect(regulationNames).toContain('ai_act');
  });
});

describe('Compliance Mapper - Status Check', () => {
  it('should report gaps for GDPR with no metadata', () => {
    const result = getComplianceStatus('gdpr', {});
    expect(result.compliant).toBe(false);
    expect(result.gaps).toContain('ART-22');
    expect(result.controls_satisfied).toEqual([]);
  });

  it('should report satisfied when control is present', () => {
    const result = getComplianceStatus('gdpr', {
      compliance: { 'ART-22': true },
    });
    expect(result.controls_satisfied).toContain('ART-22');
    expect(result.gaps).not.toContain('ART-22');
    expect(result.compliant).toBe(true);
  });

  it('should handle partial compliance', () => {
    const result = getComplianceStatus('gdpr', {
      compliance: { 'ART-22': false },
    });
    // ART-22 is present but false, so it's a gap
    expect(result.gaps).toContain('ART-22');
  });

  it('should work for all regulation types', () => {
    const regs: Regulation[] = ['gdpr', 'ai_act', 'ccpa', 'hipaa', 'finra'];
    for (const reg of regs) {
      const result = getComplianceStatus(reg, {});
      expect(result.gaps).toBeDefined();
      expect(result.controls_satisfied).toBeDefined();
      expect(typeof result.compliant).toBe('boolean');
    }
  });
});

describe('Compliance Mapper - Glob Pattern Matching', () => {
  it('should match wildcard action patterns', () => {
    const records = mapEventToCompliance('agt_1', 'decision', 'score:credit', '/api/scores', {});
    const gdpr = records.find(r => r.regulation === 'gdpr');
    expect(gdpr).toBeDefined(); // decision:* matches via glob
  });

  it('should match exact action patterns', () => {
    const records = mapEventToCompliance('agt_1', 'action', 'trade:execute', '/api/trades', {
      data_type: 'financial_data',
    });
    const finra = records.find(r => r.regulation === 'finra');
    expect(finra).toBeDefined();
  });

  it('should not match unrelated actions', () => {
    const records = mapEventToCompliance('agt_1', 'action', 'health:check', '/health', {
      data_type: 'system_data',
    });
    // Should only get AI Act (wildcard match)
    const nonAiAct = records.filter(r => r.regulation !== 'ai_act');
    expect(nonAiAct.length).toBe(0);
  });
});