import { describe, it, expect } from 'vitest';
import { loadConfig, loadTestConfig, ConfigError } from '../src/config.js';

describe('Config security gate', () => {
  it('refuses to start without API_KEY or DEV_MODE', () => {
    expect(() => loadConfig({ DATABASE_URL: 'postgres://x' })).toThrow(ConfigError);
  });

  it('refuses without CORS_ORIGINS in production mode', () => {
    expect(() => loadConfig({ DATABASE_URL: 'postgres://x', API_KEY: 'k' })).toThrow(ConfigError);
  });

  it('starts in dev mode without API_KEY or CORS', () => {
    const cfg = loadConfig({ DATABASE_URL: 'postgres://x', DEV_MODE: 'true' });
    expect(cfg.devMode).toBe(true);
    expect(cfg.apiKey).toBeUndefined();
  });

  it('starts in production mode with API_KEY + CORS', () => {
    const cfg = loadConfig({ DATABASE_URL: 'postgres://x', API_KEY: 'secret', CORS_ORIGINS: 'https://app.example.com' });
    expect(cfg.apiKey).toBe('secret');
    expect(cfg.corsOrigins).toEqual(['https://app.example.com']);
  });

  it('parses multiple CORS origins', () => {
    const cfg = loadConfig({ DATABASE_URL: 'postgres://x', API_KEY: 'k', CORS_ORIGINS: 'https://a.com,https://b.com' });
    expect(cfg.corsOrigins).toEqual(['https://a.com', 'https://b.com']);
  });

  it('requires DATABASE_URL', () => {
    expect(() => loadConfig({ DEV_MODE: 'true' })).toThrow();
  });

  it('loadTestConfig bypasses the gate', () => {
    const cfg = loadTestConfig('postgres://x');
    expect(cfg.devMode).toBe(true);
    expect(cfg.nodeEnv).toBe('test');
  });

  it('applies defaults', () => {
    const cfg = loadTestConfig('postgres://x');
    expect(cfg.port).toBe(8000);
    expect(cfg.rateLimitMax).toBe(300);
    expect(cfg.discoveryPollIntervalMs).toBe(60_000);
  });
});