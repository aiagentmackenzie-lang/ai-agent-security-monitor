import { describe, it, expect } from 'vitest';
import {
  redactString,
  redactObject,
  redactEvent,
  REDACTION_PATTERNS,
} from '../src/security/redaction.js';

describe('Redaction - String Patterns', () => {
  it('should redact OpenAI API keys', () => {
    const { result, flags } = redactString('Using key sk-abc123def456ghi789jkl012mno345pqr');
    expect(result).toContain('[OPENAI_API_KEY]');
    expect(result).not.toContain('sk-abc123');
    expect(flags.length).toBeGreaterThan(0);
    expect(flags[0].pattern).toBe('openai_short_key');
    expect(flags[0].severity).toBe('critical');
  });

  it('should redact Anthropic API keys', () => {
    const { result, flags } = redactString('Key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGH');
    expect(result).toContain('[ANTHROPIC_API_KEY]');
    expect(result).not.toContain('sk-ant-');
    expect(flags[0].severity).toBe('critical');
  });

  it('should redact AWS access keys', () => {
    const { result, flags } = redactString('AWS key: AKIAIOSFODNN7EXAMPLE');
    expect(result).toContain('[AWS_ACCESS_KEY]');
    expect(result).not.toContain('AKIAIOSFODNN7');
    expect(flags[0].severity).toBe('critical');
  });

  it('should redact GitHub tokens', () => {
    const { result } = redactString('Token: ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD');
    expect(result).toContain('[GITHUB_TOKEN]');
    expect(result).not.toContain('ghp_');
  });

  it('should redact Bearer tokens', () => {
    const { result } = redactString('Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 payload sig');
    expect(result).toContain('[BEARER_TOKEN]');
  });

  it('should redact database connection strings', () => {
    const { result } = redactString('DB=postgresql://admin:secretpass@db.host:5432/mydb');
    expect(result).toContain('[USER]:[PASSWORD]');
    expect(result).not.toContain('secretpass');
  });

  it('should redact private keys', () => {
    const { result } = redactString(
      'Key: -----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----'
    );
    expect(result).toContain('[PRIVATE_KEY_REDACTED]');
    expect(result).not.toContain('MIIEpAIBAAKCAQEA');
  });

  it('should redact email addresses', () => {
    const { result } = redactString('User email: john.doe@example.com contacted support');
    expect(result).toContain('[EMAIL_REDACTED]');
    expect(result).not.toContain('john.doe@example.com');
  });

  it('should redact credit card numbers', () => {
    const { result } = redactString('Card: 4111-1111-1111-1111 charged');
    expect(result).toContain('[CC_REDACTED]');
  });

  it('should redact Slack tokens', () => {
    const { result } = redactString('Token: xoxb-FAKEFAKEFAKE-FAKEFAKEFAKEFA-FAKEFAKEFAKEFAKEFAKEFAKE');
    expect(result).toContain('[SLACK_TOKEN]');
  });

  it('should leave clean strings unchanged', () => {
    const { result, flags } = redactString('data:read:users /api/v1/products');
    expect(result).toBe('data:read:users /api/v1/products');
    expect(flags.length).toBe(0);
  });

  it('should redact private IP addresses', () => {
    const { result } = redactString('Connected to 192.168.1.100 via 10.0.0.1');
    expect(result).toContain('[PRIVATE_IP]');
    expect(result).not.toContain('192.168.1.100');
  });
});

describe('Redaction - Object Recursion', () => {
  it('should redact nested object values', () => {
    const { redacted, flags } = redactObject({
      tool_name: 'openai',
      api_key: 'sk-abc123def456ghi789jkl012mno345pqr',
      nested: {
        user_email: 'user@company.com',
        deep: {
          token: 'ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD',
        },
      },
    });

    expect(redacted.api_key).toBe('[OPENAI_API_KEY]');
    expect(redacted.nested.user_email).toBe('[EMAIL_REDACTED]');
    expect(redacted.nested.deep.token).toBe('[GITHUB_TOKEN]');
    expect(flags.length).toBe(3);
  });

  it('should redact values in arrays', () => {
    const { redacted, flags } = redactObject({
      recipients: ['alice@test.com', 'bob@test.com'],
      safe_data: ['hello', 'world'],
    });

    expect(redacted.recipients[0]).toBe('[EMAIL_REDACTED]');
    expect(redacted.recipients[1]).toBe('[EMAIL_REDACTED]');
    expect(redacted.safe_data[0]).toBe('hello');
    expect(flags.length).toBe(2);
  });

  it('should preserve non-string values', () => {
    const { redacted } = redactObject({
      count: 42,
      active: true,
      ratio: 3.14,
      empty: null,
    });

    expect(redacted.count).toBe(42);
    expect(redacted.active).toBe(true);
    expect(redacted.ratio).toBe(3.14);
    expect(redacted.empty).toBe(null);
  });
});

describe('Redaction - Event Integration', () => {
  it('should redact all fields in an agent event', () => {
    const result = redactEvent({
      event_type: 'tool_call',
      action: 'api:call:openai',
      resource: 'sk-abc123def456ghi789jkl012mno345pqr',
      result: 'success',
      details: {
        endpoint: 'https://api.openai.com/v1/chat',
        api_key: 'sk-abc123def456ghi789jkl012mno345pqr',
        user: 'admin@company.com',
        response: 'Generated text output',
      },
    });

    expect(result.action).toBe('api:call:openai'); // clean, no redaction needed
    expect(result.resource).toBe('[OPENAI_API_KEY]'); // key in resource field
    expect(result.details.api_key).toBe('[OPENAI_API_KEY]');
    expect(result.details.user).toBe('[EMAIL_REDACTED]');
    expect(result.details.endpoint).toBe('https://api.openai.com/v1/chat');
    expect(result.flags.length).toBeGreaterThanOrEqual(3);
  });

  it('should flag critical severity for API keys', () => {
    const result = redactEvent({
      event_type: 'tool_call',
      action: 'data:read',
      resource: '/api/users',
      result: 'success',
      details: {
        key: 'sk-abc123def456ghi789jkl012mno345pqr',
      },
    });

    const criticalFlags = result.flags.filter(f => f.severity === 'critical');
    expect(criticalFlags.length).toBeGreaterThan(0);
  });

  it('should handle events with no sensitive data', () => {
    const result = redactEvent({
      event_type: 'tool_call',
      action: 'data:read:products',
      resource: '/api/v1/products',
      result: 'success',
      details: {
        items_returned: 42,
        query_time_ms: 150,
      },
    });

    expect(result.action).toBe('data:read:products');
    expect(result.resource).toBe('/api/v1/products');
    expect(result.details.items_returned).toBe(42);
    expect(result.flags.length).toBe(0);
  });
});

describe('Redaction - Pattern Coverage', () => {
  it('should have patterns for all major secret categories', () => {
    const patternNames = REDACTION_PATTERNS.map(p => p.name);
    expect(patternNames).toContain('aws_access_key');
    expect(patternNames).toContain('openai_api_key');
    expect(patternNames).toContain('anthropic_api_key');
    expect(patternNames).toContain('github_token');
    expect(patternNames).toContain('bearer_token');
    expect(patternNames).toContain('db_connection_string');
    expect(patternNames).toContain('private_key');
    expect(patternNames).toContain('jwt_token');
    expect(patternNames).toContain('email_address');
    expect(patternNames).toContain('credit_card');
    expect(patternNames).toContain('slack_token');
  });

  it('should have severity levels for all patterns', () => {
    for (const pattern of REDACTION_PATTERNS) {
      expect(['low', 'medium', 'high', 'critical']).toContain(pattern.severity);
    }
  });
});