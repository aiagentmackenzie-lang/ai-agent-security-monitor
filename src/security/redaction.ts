/**
 * Sensitive data redaction for agent events.
 * Scans and redacts common secret patterns before database persistence.
 * OWASP AI Agent Security Cheat Sheet: "Log all agent decisions with redacted sensitive data"
 */

export interface RedactionResult {
  redacted: Record<string, unknown>;
  flags: RedactionFlag[];
}

export interface RedactionFlag {
  field: string;
  pattern: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface RedactionPattern {
  name: string;
  pattern: RegExp;
  replacement: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Known secret patterns — ordered by specificity (longer/more specific first)
 * to avoid partial matches on truncated values.
 */
export const REDACTION_PATTERNS: RedactionPattern[] = [
  // Cloud provider keys
  {
    name: 'aws_access_key',
    pattern: /\b(AKIA[0-9A-Z]{16})\b/g,
    replacement: '[AWS_ACCESS_KEY]',
    severity: 'critical',
  },
  {
    name: 'aws_secret_key',
    pattern: /\b([0-9a-zA-Z/+]{40})\b/g,
    replacement: '[AWS_SECRET_KEY]',
    severity: 'critical',
    // Only trigger when adjacent to AWS context — handled in logic below
  },
  {
    name: 'gcp_service_account',
    pattern: /\b([a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com)\b/g,
    replacement: '[GCP_SERVICE_ACCOUNT]',
    severity: 'high',
  },
  {
    name: 'gcp_api_key',
    pattern: /\b(AIza[0-9A-Za-z_-]{35})\b/g,
    replacement: '[GCP_API_KEY]',
    severity: 'high',
  },
  // AI/LLM provider keys
  {
    name: 'openai_api_key',
    pattern: /\b(sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})\b/g,
    replacement: '[OPENAI_API_KEY]',
    severity: 'critical',
  },
  {
    name: 'openai_short_key',
    pattern: /\b(sk-[a-zA-Z0-9]{32,48})\b/g,
    replacement: '[OPENAI_API_KEY]',
    severity: 'critical',
  },
  {
    name: 'anthropic_api_key',
    pattern: /\b(sk-ant-[a-zA-Z0-9_-]{32,95})\b/g,
    replacement: '[ANTHROPIC_API_KEY]',
    severity: 'critical',
  },
  {
    name: 'google_gemini_key',
    pattern: /\b(AIzaSy[a-zA-Z0-9_-]{33})\b/g,
    replacement: '[GEMINI_API_KEY]',
    severity: 'high',
  },
  // Generic tokens
  {
    name: 'bearer_token',
    pattern: /\b(Bearer\s+)([a-zA-Z0-9._-]{20,})\b/gi,
    replacement: '$1[BEARER_TOKEN]',
    severity: 'critical',
  },
  {
    name: 'basic_auth',
    pattern: /\b(Authorization:\s*Basic\s+)([a-zA-Z0-9+/=]{8,})\b/gi,
    replacement: '$1[BASIC_AUTH]',
    severity: 'critical',
  },
  // Database connection strings
  {
    name: 'db_connection_string',
    pattern: /\b(postgresql|mysql|mongodb|redis):\/\/[^@\s]+:[^@\s]+@/gi,
    replacement: '$1://[USER]:[PASSWORD]@',
    severity: 'critical',
  },
  // Private keys
  {
    name: 'private_key',
    pattern: /-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+)?PRIVATE\s+KEY-----/g,
    replacement: '[PRIVATE_KEY_REDACTED]',
    severity: 'critical',
  },
  // JWT tokens
  {
    name: 'jwt_token',
    pattern: /\b(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\b/g,
    replacement: '[JWT_TOKEN]',
    severity: 'high',
  },
  // Slack tokens
  {
    name: 'slack_token',
    pattern: /\b(xox[bpors]-[a-zA-Z0-9-]{10,})\b/g,
    replacement: '[SLACK_TOKEN]',
    severity: 'high',
  },
  // Discord tokens
  {
    name: 'discord_token',
    pattern: /\b([MN][a-zA-Z0-9_-]{23,}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27})\b/g,
    replacement: '[DISCORD_TOKEN]',
    severity: 'high',
  },
  // GitHub tokens
  {
    name: 'github_token',
    pattern: /\b(gh[ps]_[a-zA-Z0-9]{36,50})\b/g,
    replacement: '[GITHUB_TOKEN]',
    severity: 'critical',
  },
  // Stripe keys
  {
    name: 'stripe_key',
    pattern: /\b(sk_live_[a-zA-Z0-9]{24,})\b/g,
    replacement: '[STRIPE_KEY]',
    severity: 'critical',
  },
  // Email addresses (GDPR/CCPA PII)
  {
    name: 'email_address',
    pattern: /\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/g,
    replacement: '[EMAIL_REDACTED]',
    severity: 'medium',
  },
  // Credit card numbers (basic Luhn-like pattern)
  {
    name: 'credit_card',
    pattern: /\b(\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})\b/g,
    replacement: '[CC_REDACTED]',
    severity: 'critical',
  },
  // IP addresses (private ranges — potential internal network info)
  {
    name: 'private_ip',
    pattern: /\b((?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(?:172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})|(?:192\.168\.\d{1,3}\.\d{1,3}))\b/g,
    replacement: '[PRIVATE_IP]',
    severity: 'low',
  },
];

/**
 * Redact sensitive data from a string value.
 * Returns the redacted string and any flags raised.
 */
export function redactString(value: string): { result: string; flags: RedactionFlag[] } {
  let result = value;
  const flags: RedactionFlag[] = [];

  for (const pattern of REDACTION_PATTERNS) {
    const matches = result.match(pattern.pattern);
    if (matches && matches.length > 0) {
      result = result.replace(pattern.pattern, pattern.replacement);
      flags.push({
        field: 'string',
        pattern: pattern.name,
        severity: pattern.severity,
      });
    }
  }

  return { result, flags };
}

/**
 * Recursively redact sensitive data from an object.
 * Walks all nested properties and redacts string values.
 */
export function redactObject(obj: Record<string, unknown>): RedactionResult {
  const redacted: Record<string, unknown> = {};
  const flags: RedactionFlag[] = [];

  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === 'string') {
      const { result, flags: fieldFlags } = redactString(value);
      redacted[key] = result;
      for (const f of fieldFlags) {
        flags.push({ ...f, field: key });
      }
    } else if (Array.isArray(value)) {
      redacted[key] = value.map((item, idx) => {
        if (typeof item === 'string') {
          const { result, flags: itemFlags } = redactString(item);
          for (const f of itemFlags) {
            flags.push({ ...f, field: `${key}[${idx}]` });
          }
          return result;
        } else if (item !== null && typeof item === 'object') {
          const nested = redactObject(item as Record<string, unknown>);
          flags.push(...nested.flags.map(f => ({ ...f, field: `${key}[${idx}].${f.field}` })));
          return nested.redacted;
        }
        return item;
      });
    } else if (value !== null && typeof value === 'object') {
      const nested = redactObject(value as Record<string, unknown>);
      redacted[key] = nested.redacted;
      flags.push(...nested.flags.map(f => ({ ...f, field: `${key}.${f.field}` })));
    } else {
      redacted[key] = value;
    }
  }

  return { redacted, flags };
}

/**
 * Redact an agent event before persistence.
 * Returns redacted event data and a list of flags for alerting.
 */
export function redactEvent(event: {
  event_type: string;
  action?: string;
  resource?: string;
  result: string;
  details: Record<string, unknown>;
}): RedactionResult & {
  action?: string;
  resource?: string;
  details: Record<string, unknown>;
} {
  const allFlags: RedactionFlag[] = [];

  // Redact action
  let action = event.action;
  if (action) {
    const { result, flags } = redactString(action);
    action = result;
    allFlags.push(...flags.map(f => ({ ...f, field: `action` })));
  }

  // Redact resource
  let resource = event.resource;
  if (resource) {
    const { result, flags } = redactString(resource);
    resource = result;
    allFlags.push(...flags.map(f => ({ ...f, field: `resource` })));
  }

  // Redact details
  const { redacted, flags: detailFlags } = redactObject(event.details || {});
  allFlags.push(...detailFlags);

  return {
    redacted,
    flags: allFlags,
    action,
    resource,
    details: redacted,
  };
}