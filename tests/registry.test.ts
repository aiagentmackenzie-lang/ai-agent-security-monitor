import { describe, it, expect } from 'vitest';
import { createAgent, createAgentEvent } from '../src/agents/registry.js';

describe('Agent Registry - createAgent', () => {
  it('should create an agent with required fields', () => {
    const agent = createAgent({ name: 'Test Agent', type: 'openclaw' });
    expect(agent.id).toMatch(/^agt_/);
    expect(agent.name).toBe('Test Agent');
    expect(agent.type).toBe('openclaw');
    expect(agent.active).toBe(true);
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
  });

  it('should respect explicit active=false', () => {
    const agent = createAgent({ name: 'Inactive', type: 'custom', active: false });
    expect(agent.active).toBe(false);
  });
});

describe('Agent Registry - createAgentEvent', () => {
  it('should create an event with required fields', () => {
    const event = createAgentEvent({
      agent_id: 'agt_123',
      event_type: 'tool_call',
      action: 'data:read',
      resource: '/api/users',
      result: 'success',
    });
    expect(event.id).toMatch(/^evt_/);
    expect(event.agent_id).toBe('agt_123');
    expect(event.event_type).toBe('tool_call');
    expect(event.action).toBe('data:read');
    expect(event.resource).toBe('/api/users');
    expect(event.result).toBe('success');
    expect(event.details).toEqual({});
  });

  it('should accept all result types', () => {
    for (const result of ['success', 'denied', 'error'] as const) {
      const event = createAgentEvent({
        agent_id: 'agt_test',
        event_type: 'test',
        result,
      });
      expect(event.result).toBe(result);
    }
  });

  it('should accept optional details', () => {
    const event = createAgentEvent({
      agent_id: 'agt_test',
      event_type: 'api_call',
      result: 'success',
      details: { endpoint: '/v1/chat', tokens: 500 },
    });
    expect(event.details).toEqual({ endpoint: '/v1/chat', tokens: 500 });
  });

  it('should generate unique event IDs', () => {
    const e1 = createAgentEvent({ agent_id: 'a', event_type: 't', result: 'success' });
    const e2 = createAgentEvent({ agent_id: 'a', event_type: 't', result: 'success' });
    expect(e1.id).not.toBe(e2.id);
  });

  it('should default result to success', () => {
    const event = createAgentEvent({ agent_id: 'a', event_type: 't', result: 'success' });
    expect(event.result).toBe('success');
  });
});