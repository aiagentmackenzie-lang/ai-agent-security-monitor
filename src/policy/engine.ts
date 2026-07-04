import { randomUUID } from 'crypto';
import type { PolicyRule, Policy, PolicyEvaluationRequest, PolicyEvaluationResult } from '../types.js';

export type { PolicyRule, Policy, PolicyEvaluationRequest, PolicyEvaluationResult };

/**
 * Evaluate simple conditions against request context.
 * Supported condition operators:
 *   - { field: "value" }           → exact string match
 *   - { field: { eq: "value" } }   → exact match
 *   - { field: { neq: "value" } }  → not-equal
 *   - { field: { in: ["a","b"] } } → value in list
 *   - { field: { contains: "x" } }→ string contains
 *
 * All conditions within a rule must pass (AND logic).
 */
function evaluateConditions(
  conditions: Record<string, unknown>,
  context: NonNullable<PolicyEvaluationRequest['context']>
): boolean {
  for (const [field, expected] of Object.entries(conditions)) {
    const actual = context[field as keyof typeof context];

    // Exact value match
    if (typeof expected === 'string') {
      if (actual !== expected) return false;
      continue;
    }

    // Object operator match
    if (typeof expected === 'object' && expected !== null) {
      const op = expected as Record<string, unknown>;

      if ('eq' in op && actual !== op.eq) return false;
      if ('neq' in op && actual === op.neq) return false;
      if ('in' in op && Array.isArray(op.in) && !op.in.includes(actual)) return false;
      if ('contains' in op && typeof actual === 'string' && !actual.includes(op.contains as string)) return false;
      continue;
    }

    return false; // unsupported condition value type
  }

  return true;
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
        // Evaluate conditions if present.
        // Production fail-closed semantics:
        //   - A conditional DENY with no context still fires (over-block rather
        //     than under-block — safer for a governance product).
        //   - A conditional PERMIT with no context does NOT fire (falls through
        //     to default-deny in allowlist mode) — fail-closed on permit.
        if (rule.conditions) {
          if (request.context) {
            if (!evaluateConditions(rule.conditions, request.context)) {
              continue; // conditions not met — skip this rule
            }
          } else if (rule.effect === 'permit') {
            continue; // permit rule cannot be validated without context — skip
          }
          // deny rule with conditions but no context → falls through and fires
        }

        return {
          allowed: rule.effect === 'permit',
          reason: rule.effect === 'deny' ? `Denied by policy: ${policy.name}` : `Permitted by policy: ${policy.name}`,
          policy_id: policy.id,
          certificate_id: `cert_${randomUUID()}`,
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
      certificate_id: `cert_${randomUUID()}`,
      evaluated_at: new Date().toISOString(),
    };
  }

  return {
    allowed: true,
    reason: 'Default allow — no matching policy found',
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