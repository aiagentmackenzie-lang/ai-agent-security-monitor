import { describe, it, expect } from 'vitest';
import { createAgent } from '../src/agents/registry.js';

describe('Agent Registry - createAgent', () => {
  it('should create an agent with defaults', () => {
    const agent = createAgent({ name: 'Test Agent', type: 'openclaw' });
    expect(agent.id).toMatch(/^agt_/);
    expect(agent.name).toBe('Test Agent');
    expect(agent.type).toBe('openclaw');
    expect(agent.active).toBe(true);
    expect(agent.quarantined).toBe(false);
    expect(agent.metadata).toEqual({});
    expect(agent.created_at).toBeInstanceOf(Date);
    expect(agent.updated_at).toBeInstanceOf(Date);
  });

  it('should create agents for all supported types', () => {
    const types = ['langchain', 'crewai', 'claude_code', 'openclaw', 'openai_agents', 'custom'] as const;
    for (const type of types) {
      const agent = createAgent({ name: `${type} Agent`, type });
      expect(agent.type).toBe(type);
      expect(agent.active).toBe(true);
    }
  });

  it('should default to custom type when not specified', () => {
    const agent = createAgent({ name: 'Unknown', type: 'custom' });
    expect(agent.type).toBe('custom');
  });

  it('should accept optional fields', () => {
    const agent = createAgent({
      name: 'Full Agent',
      type: 'langchain',
      owner: 'engineering',
      api_key_hash: 'abc123',
      metadata: { region: 'us-east' },
    });
    expect(agent.owner).toBe('engineering');
    expect(agent.api_key_hash).toBe('abc123');
    expect(agent.metadata).toEqual({ region: 'us-east' });
  });

  it('should generate unique IDs for each agent', () => {
    const agent1 = createAgent({ name: 'A1', type: 'openclaw' });
    const agent2 = createAgent({ name: 'A2', type: 'openclaw' });
    expect(agent1.id).not.toBe(agent2.id);
  });

  it('should create agent as active by default', () => {
    const agent = createAgent({ name: 'Test', type: 'crewai' });
    expect(agent.active).toBe(true);
    expect(agent.quarantined).toBe(false);
  });

  it('should respect explicit active=false', () => {
    const agent = createAgent({ name: 'Inactive', type: 'custom', active: false });
    expect(agent.active).toBe(false);
  });

  it('should allow setting quarantined flag', () => {
    const agent = createAgent({ name: 'Quarantined', type: 'custom', quarantined: true });
    expect(agent.quarantined).toBe(true);
  });
});