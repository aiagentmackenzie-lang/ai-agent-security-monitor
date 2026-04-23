export interface PolicyRule {
  action: string;
  resource: string;
  effect: 'permit' | 'deny';
  conditions?: Record<string, unknown>;
}

export interface Policy {
  id: string;
  name: string;
  description?: string;
  rules: PolicyRule[];
  agent_ids: string[];
  active: boolean;
  /** When 'deny', unmatched actions are blocked (allowlist mode). When 'permit' or unset, unmatched actions are allowed (denylist mode — current default). */
  default_effect?: 'permit' | 'deny';
}

export interface PolicyEvaluationRequest {
  agent_id: string;
  action: string;
  resource: string;
  context?: {
    user?: string;
    session_id?: string;
    data_classification?: string;
    timestamp?: string;
  };
}

export interface PolicyEvaluationResult {
  allowed: boolean;
  reason: string;
  policy_id?: string;
  certificate_id?: string;
  evaluated_at: string;
}

export function evaluatePolicy(
  request: PolicyEvaluationRequest,
  policies: Policy[]
): PolicyEvaluationResult {
  const applicable = policies.filter(
    p => p.active && (p.agent_ids.includes('*') || p.agent_ids.includes(request.agent_id))
  );

  // Track which allowlist policies evaluated (for default_effect logic)
  let allowlistPolicy: Policy | undefined;

  for (const policy of applicable) {
    for (const rule of policy.rules) {
      const actionMatch = matchPattern(request.action, rule.action);
      const resourceMatch = matchPattern(request.resource, rule.resource);

      if (actionMatch && resourceMatch) {
        return {
          allowed: rule.effect === 'permit',
          reason: rule.effect === 'deny' ? `Denied by policy: ${policy.name}` : `Permitted by policy: ${policy.name}`,
          policy_id: policy.id,
          certificate_id: `cert_${Date.now()}_${Math.random().toString(36).slice(2)}`,
          evaluated_at: new Date().toISOString(),
        };
      }
    }

    // Track the first allowlist policy we encounter
    if (policy.default_effect === 'deny' && !allowlistPolicy) {
      allowlistPolicy = policy;
    }
  }

  // If any applicable policy uses allowlist mode (default_effect='deny'),
  // unmatched actions are denied by that policy
  if (allowlistPolicy) {
    return {
      allowed: false,
      reason: `Denied by default — allowlist policy '${allowlistPolicy.name}' has no matching permit rule`,
      policy_id: allowlistPolicy.id,
      certificate_id: `cert_${Date.now()}_${Math.random().toString(36).slice(2)}`,
      evaluated_at: new Date().toISOString(),
    };
  }

  return {
    allowed: true,
    reason: 'Default allow - no matching policy found',
    evaluated_at: new Date().toISOString(),
  };
}

export function matchPattern(value: string, pattern: string): boolean {
  if (pattern === '*') return true;
  if (pattern.includes('*')) {
    // Escape regex metacharacters except *, then replace * with .*
    const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
    const regex = new RegExp('^' + escaped + '$');
    return regex.test(value);
  }
  return value === pattern;
}
