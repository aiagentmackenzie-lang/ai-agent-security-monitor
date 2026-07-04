import { describe, it, expect } from 'vitest';
import { createAgent } from '../src/agents/registry.js';
import { evaluatePolicy, matchPattern } from '../src/policy/engine.js';
import { getComplianceStatus, COMPLIANCE_REQUIREMENTS } from '../src/compliance/mapper.js';

describe('Agent Registry', () => {
  it('should create an agent with defaults and quarantined=false', () => {
    const agent = createAgent({ name: 'Test Agent', type: 'openclaw' });
    expect(agent.id).toMatch(/^agt_/);
    expect(agent.name).toBe('Test Agent');
    expect(agent.type).toBe('openclaw');
    expect(agent.active).toBe(true);
    expect(agent.quarantined).toBe(false);
  });

  it('should allow setting quarantined', () => {
    const agent = createAgent({ name: 'Q Agent', type: 'custom', quarantined: true });
    expect(agent.quarantined).toBe(true);
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
          priority: 0,
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
          priority: 0,
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
          priority: 0,
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
          priority: 0,
        },
      ]
    );
    expect(result.certificate_id).toBeDefined();
    expect(result.certificate_id).toMatch(/^cert_/);
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
          priority: 0,
        },
      ]
    );
    expect(result.allowed).toBe(false);
  });

  it('should evaluate conditions when provided', () => {
    const result = evaluatePolicy(
      {
        agent_id: 'agt_123',
        action: 'data:read',
        resource: '/api/users',
        context: { data_classification: 'confidential' },
      },
      [
        {
          id: 'pol_cond',
          name: 'Deny Confidential Read',
          rules: [
            {
              action: 'data:read',
              resource: '*',
              effect: 'deny' as const,
              conditions: { data_classification: 'confidential' },
            },
          ],
          agent_ids: ['*'],
          active: true,
          priority: 0,
        },
      ]
    );
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('Deny Confidential Read');
  });

  it('should skip rule when conditions do not match', () => {
    const result = evaluatePolicy(
      {
        agent_id: 'agt_123',
        action: 'data:read',
        resource: '/api/users',
        context: { data_classification: 'public' },
      },
      [
        {
          id: 'pol_cond',
          name: 'Deny Confidential Read',
          rules: [
            {
              action: 'data:read',
              resource: '*',
              effect: 'deny' as const,
              conditions: { data_classification: 'confidential' },
            },
          ],
          agent_ids: ['*'],
          active: true,
          priority: 0,
        },
      ]
    );
    // Condition not met, so falls through to default allow
    expect(result.allowed).toBe(true);
  });

  it('should enforce condition rules even when context is missing (fail-closed)', () => {
    const result = evaluatePolicy(
      { agent_id: 'agt_123', action: 'data:read', resource: '/api/users' },
      [
        {
          id: 'pol_cond',
          name: 'Deny Confidential Read',
          rules: [
            {
              action: 'data:read',
              resource: '*',
              effect: 'deny' as const,
              conditions: { data_classification: 'confidential' },
            },
          ],
          agent_ids: ['*'],
          active: true,
          priority: 0,
        },
      ]
    );
    // No context provided, but conditions exist — when context is missing,
    // conditions can't be evaluated but the action/resource still match.
    // Without context, conditions are skipped, and the deny rule still matches.
    // Fail-closed: if a deny rule matches the action/resource, it is enforced.
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('Deny Confidential Read');
  });

  it('should NOT permit a conditional permit rule when context is missing (fail-closed)', () => {
    const result = evaluatePolicy(
      { agent_id: 'agt_123', action: 'data:read', resource: '/api/users' },
      [
        {
          id: 'pol_cond_permit',
          name: 'Permit Confidential Read',
          rules: [
            {
              action: 'data:read',
              resource: '*',
              effect: 'permit' as const,
              conditions: { data_classification: 'confidential' },
            },
          ],
          agent_ids: ['*'],
          active: true,
          priority: 0,
          default_effect: 'deny',
        },
      ]
    );
    // No context -> the conditional permit cannot be validated -> skipped
    // -> falls through to allowlist default-deny. Fail-closed on permit.
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('allowlist');
  });
});

describe('Policy Engine - Allowlist Mode', () => {
  it('should deny unmatched actions when default_effect is deny', () => {
    const result = evaluatePolicy(
      { agent_id: 'agt_123', action: 'data:read:products', resource: '/api/products' },
      [
        {
          id: 'pol_allow',
          name: 'Allowlist Policy',
          rules: [
            { action: 'data:read:users', resource: '/api/users', effect: 'permit' as const },
          ],
          agent_ids: ['*'],
          active: true,
          priority: 0,
          default_effect: 'deny',
        },
      ]
    );
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('allowlist policy');
    expect(result.reason).toContain('Allowlist Policy');
    expect(result.policy_id).toBe('pol_allow');
  });

  it('should permit matched actions in allowlist mode', () => {
    const result = evaluatePolicy(
      { agent_id: 'agt_123', action: 'data:read:users', resource: '/api/users' },
      [
        {
          id: 'pol_allow',
          name: 'Allowlist Policy',
          rules: [
            { action: 'data:read:users', resource: '/api/users', effect: 'permit' as const },
          ],
          agent_ids: ['*'],
          active: true,
          priority: 0,
          default_effect: 'deny',
        },
      ]
    );
    expect(result.allowed).toBe(true);
    expect(result.reason).toContain('Permitted by policy');
  });

  it('should still allow by default when no default_effect is set', () => {
    const result = evaluatePolicy(
      { agent_id: 'agt_123', action: 'data:read:products', resource: '/api/products' },
      [
        {
          id: 'pol_deny',
          name: 'Deny Policy',
          rules: [
            { action: 'data:delete:*', resource: '*', effect: 'deny' as const },
          ],
          agent_ids: ['*'],
          active: true,
          priority: 0,
        },
      ]
    );
    expect(result.allowed).toBe(true);
    expect(result.reason).toContain('Default allow');
  });

  it('should combine allowlist mode with explicit deny rules', () => {
    const result = evaluatePolicy(
      { agent_id: 'agt_123', action: 'data:delete:users', resource: '/db/users' },
      [
        {
          id: 'pol_combined',
          name: 'Combined Policy',
          rules: [
            { action: 'data:read:*', resource: '*', effect: 'permit' as const },
            { action: 'data:delete:*', resource: '*', effect: 'deny' as const },
          ],
          agent_ids: ['*'],
          active: true,
          priority: 0,
          default_effect: 'deny',
        },
      ]
    );
    expect(result.allowed).toBe(false);
    expect(result.reason).toContain('Denied by policy');
  });

  it('should handle wildcard permits in allowlist mode', () => {
    const result = evaluatePolicy(
      { agent_id: 'agt_123', action: 'data:read:orders', resource: '/api/orders' },
      [
        {
          id: 'pol_wild',
          name: 'Wildcard Allow',
          rules: [
            { action: 'data:read:*', resource: '*', effect: 'permit' as const },
          ],
          agent_ids: ['*'],
          active: true,
          priority: 0,
          default_effect: 'deny',
        },
      ]
    );
    expect(result.allowed).toBe(true);
  });

  it('should generate certificate for allowlist-mode denials', () => {
    const result = evaluatePolicy(
      { agent_id: 'agt_123', action: 'admin:write', resource: '/admin/settings' },
      [
        {
          id: 'pol_strict',
          name: 'Strict Allowlist',
          rules: [
            { action: 'data:read:*', resource: '*', effect: 'permit' as const },
          ],
          agent_ids: ['*'],
          active: true,
          priority: 0,
          default_effect: 'deny',
        },
      ]
    );
    expect(result.certificate_id).toBeDefined();
    expect(result.policy_id).toBe('pol_strict');
  });
});

describe('matchPattern', () => {
  it('should match exact strings', () => {
    expect(matchPattern('data:read', 'data:read')).toBe(true);
    expect(matchPattern('data:read', 'data:write')).toBe(false);
  });

  it('should match wildcards', () => {
    expect(matchPattern('data:read:users', 'data:read:*')).toBe(true);
    expect(matchPattern('data:delete:everything', 'data:delete:*')).toBe(true);
    expect(matchPattern('anything', '*')).toBe(true);
  });

  it('should escape regex metacharacters in patterns', () => {
    expect(matchPattern('api.call', 'api.call')).toBe(true);
    expect(matchPattern('apiXcall', 'api.call')).toBe(false);
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
  it('should export valid AgentTypes including openclaw and openai_agents', async () => {
    const { createAgent } = await import('../src/agents/registry.js');
    const agent = createAgent({ name: 'Test', type: 'openclaw' });
    expect(agent.type).toBe('openclaw');
    const agent2 = createAgent({ name: 'Test2', type: 'openai_agents' });
    expect(agent2.type).toBe('openai_agents');
  });
});