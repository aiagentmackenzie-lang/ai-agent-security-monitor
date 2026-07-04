import { z } from 'zod';

/**
 * Centralised, validated configuration for the AI Agent Security Monitor.
 *
 * Every module reads from this object — no direct `process.env` access outside
 * `loadConfig()`. This makes the server testable (inject a config) and prevents
 * silent misconfiguration.
 *
 * Security posture:
 *   - If neither `DEV_MODE=true` nor `API_KEY` is set, the server refuses to
 *     start. A governance product must not ship open by default.
 *   - CORS origins must be an explicit allowlist unless `DEV_MODE` is set.
 */

const ConfigSchema = z.object({
  nodeEnv: z.enum(['production', 'test', 'development']).default('development'),
  devMode: z.boolean().default(false),
  port: z.number().int().positive().default(8000),
  host: z.string().default('0.0.0.0'),
  logLevel: z.string().default('info'),

  databaseUrl: z.string().min(1, { message: 'DATABASE_URL is required' }),

  // Auth
  apiKey: z.string().optional(),
  apiKeyHashAlgorithm: z.string().default('sha256'),

  // CORS
  corsOrigins: z.array(z.string()).default([]),

  // Rate limiting (Redis-backed when redisUrl is set; in-memory otherwise)
  redisUrl: z.string().optional(),
  rateLimitMax: z.number().int().positive().default(300),
  rateLimitWindowMs: z.number().int().positive().default(60_000),

  // SecurityScarletAI forwarding (opt-in)
  scarletApiUrl: z.string().optional(),
  scarletApiKey: z.string().optional(),
  scarletEventBusUrl: z.string().optional(),
  scarletForwardEnabled: z.boolean().default(false),

  // Discovery
  discoveryPollIntervalMs: z.number().int().positive().default(60_000),
});

export type AppConfig = z.infer<typeof ConfigSchema>;

function parseCors(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw.split(',').map(s => s.trim()).filter(Boolean);
}

/**
 * Load and validate configuration from the environment.
 *
 * @param env override source (defaults to process.env) — used by tests.
 * @param overrides explicit overrides that win over env — used by tests.
 */
export function loadConfig(
  env: Record<string, string | undefined> = process.env,
  overrides: Partial<AppConfig> = {}
): AppConfig {
  const raw: Record<string, unknown> = {
    nodeEnv: env.NODE_ENV ?? 'development',
    devMode: (env.DEV_MODE ?? '').toLowerCase() === 'true',
    port: env.PORT ? Number(env.PORT) : undefined,
    host: env.HOST,
    logLevel: env.LOG_LEVEL,
    databaseUrl: env.DATABASE_URL,
    apiKey: env.API_KEY,
    corsOrigins: parseCors(env.CORS_ORIGINS),
    redisUrl: env.REDIS_URL,
    rateLimitMax: env.RATE_LIMIT_MAX ? Number(env.RATE_LIMIT_MAX) : undefined,
    rateLimitWindowMs: env.RATE_LIMIT_WINDOW_MS ? Number(env.RATE_LIMIT_WINDOW_MS) : undefined,
    scarletApiUrl: env.SCARLET_API_URL,
    scarletApiKey: env.SCARLET_API_KEY,
    scarletEventBusUrl: env.SCARLET_EVENT_BUS_URL,
    scarletForwardEnabled: (env.SCARLET_FORWARD_ENABLED ?? '').toLowerCase() === 'true',
    discoveryPollIntervalMs: env.DISCOVERY_POLL_INTERVAL_MS ? Number(env.DISCOVERY_POLL_INTERVAL_MS) : undefined,
  };

  // Strip undefined so Zod defaults apply
  for (const k of Object.keys(raw)) {
    if (raw[k] === undefined) delete raw[k];
  }

  const parsed = ConfigSchema.parse({ ...raw, ...overrides });

  // Security gate: refuse to start open in non-dev mode
  if (!parsed.devMode && !parsed.apiKey) {
    throw new ConfigError(
      'Refusing to start: no API_KEY set and DEV_MODE is not true. ' +
        'Set API_KEY to lock down the API, or set DEV_MODE=true for local development only.'
    );
  }
  if (!parsed.devMode && parsed.corsOrigins.length === 0) {
    throw new ConfigError(
      'Refusing to start: CORS_ORIGINS is not set and DEV_MODE is not true. ' +
        'Set CORS_ORIGINS to a comma-separated allowlist, or set DEV_MODE=true for local development only.'
    );
  }

  return parsed;
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

/**
 * Load config for tests where the security gate should be bypassed.
 * Forces devMode=true so tests can run without API_KEY/CORS.
 */
export function loadTestConfig(databaseUrl: string, overrides: Partial<AppConfig> = {}): AppConfig {
  return loadConfig(
    { DATABASE_URL: databaseUrl, DEV_MODE: 'true', NODE_ENV: 'test', LOG_LEVEL: 'silent' },
    { devMode: true, logLevel: 'silent', ...overrides }
  );
}