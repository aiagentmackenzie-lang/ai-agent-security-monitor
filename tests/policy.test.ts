import { describe, it, expect } from 'vitest';
import { createAgent, createAgentEvent } from '../src/agents/registry.js';
import { evaluatePolicy } from '../src/policy/engine.js';
import { getComplianceStatus, COMPLIANCE_REQUIREMENTS } from '../src/compliance/mapper.js';

describe('Agent Registry', () => {
  it('should create an agent with defaults', () => {
    const agent = createAgent({ name: 'Test Agent', type: 'openclaw' });
    expect(agent.id).toMatch(/^agt_/);
    expect(agent.name).toBe('Test Agent');
    expect(agent.type).toBe('openclaw');
    expect(agent.active).toBe(true);
    expect(agent.quarantined).toBeUndefined();
  });

  it('should create an agent event', () => {
    const event = createAgentEvent({
      agent_id: 'test-agent-id',
      event_type: 'tool_call',
      action: 'data:read',
      resource: '/api/users',
      result: 'success',
    });
    expect(event.id).toMatch(/^evt_/);
    expect(event.agent_id).toBe('test-agent-id');
    expect(event.result).toBe('success');
  });
});

describe('Policy Engine', () => {
  it('should deny deletion actions', () => {
    const result = evaluatePolicy(
      { agent_id: 'agt_123', action: 'data:delete:users', resource: '/db/users' },
      [
        {
          id: 'pol_001',
          name: 'Deny Data Deletion',
          rules: [
            { action: 'data:delete:*', resource: '*', effect: 'deny' as const },
          ],
          agent_ids: ['*'],
          active: true,
        },
      ]
    );
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('Deny Data Deletion');
  });

  it('should allow non-restricted actions by default', () => {
    const result = evaluatePolicy(
      { agent_id: 'agt_789', action: 'data:read:products', resource: '/api/products' },
      [
        {
          id: 'pol_001',
          name: 'Deny Data Deletion',
          rules: [
            { action: 'data:delete:*', resource: '*', effect: 'deny' as const },
          ],
          agent_ids: ['*'],
          active: true,
        },
      ]
    );
    expect(result.allowed).toBe(true);
    expect(result.reason).toContain('Default allow');
  });

  it('should deny admin API access', () => {
    const result = evaluatePolicy(
      { agent_id: 'agt_456', action: 'api:write', resource: '/admin/users' },
      [
        {
          id: 'pol_002',
          name: 'Admin Protection',
          rules: [
            { action: 'api:*', resource: '/admin/*', effect: 'deny' as const },
          ],
          agent_ids: ['*'],
          active: true,
        },
      ]
    );
    expect(result.allowed).toBe(false);
  });

  it('should generate a certificate for policy decisions', () => {
    const result = evaluatePolicy(
      { agent_id: 'agt_123', action: 'data:delete:users', resource: '/db/users' },
      [
        {
          id: 'pol_001',
          name: 'Deny Data Deletion',
          rules: [
            { action: 'data:delete:*', resource: '*', effect: 'deny' as const },
          ],
          agent_ids: ['*'],
          active: true,
        },
      ]
    );
    expect(result.certificate_id).toBeDefined();
    expect(result.policy_id).toBe('pol_001');
    expect(result.evaluated_at).toBeDefined();
  });

  it('should apply wildcard patterns correctly', () => {
    const result = evaluatePolicy(
      { agent_id: 'agt_any', action: 'data:delete:anything', resource: '/any/path' },
      [
        {
          id: 'pol_001',
          name: 'Block all deletes',
          rules: [
            { action: 'data:delete:*', resource: '*', effect: 'deny' as const },
          ],
          agent_ids: ['*'],
          active: true,
        },
      ]
    );
    expect(result.allowed).toBe(false);
  });
});

describe('Compliance Mapper', () => {
  it('should have requirements for all major regulations', () => {
    expect(COMPLIANCE_REQUIREMENTS.length).toBeGreaterThan(0);
    const regulations = COMPLIANCE_REQUIREMENTS.map(r => r.regulation);
    expect(regulations).toContain('gdpr');
    expect(regulations).toContain('ai_act');
    expect(regulations).toContain('ccpa');
    expect(regulations).toContain('hipaa');
    expect(regulations).toContain('finra');
  });

  it('should identify GDPR compliance gaps when no metadata', () => {
    const result = getComplianceStatus('gdpr', {});
    expect(result.compliant).toBe(false);
    expect(result.gaps).toContain('ART-22');
  });

  it('should identify compliance satisfied when control is in metadata', () => {
    const result = getComplianceStatus('gdpr', {
      compliance: { 'ART-22': true },
    });
    expect(result.controls_satisfied).toContain('ART-22');
    expect(result.gaps).not.toContain('ART-22');
  });

  it('should check all supported regulations', () => {
    const regs = ['gdpr', 'ai_act', 'ccpa', 'hipaa', 'finra'] as const;
    for (const reg of regs) {
      const result = getComplianceStatus(reg, {});
      expect(result.gaps).toBeDefined();
      expect(result.controls_satisfied).toBeDefined();
    }
  });
});

describe('Type exports', () => {
  it('should export valid AgentTypes including openclaw', async () => {
    const { createAgent } = await import('../src/agents/registry.js');
    const agent = createAgent({ name: 'Test', type: 'openclaw' });
    expect(agent.type).toBe('openclaw');
    const agent2 = createAgent({ name: 'Test2', type: 'claude_code' });
    expect(agent2.type).toBe('claude_code');
  });
});
