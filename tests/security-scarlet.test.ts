import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import Fastify from 'fastify';
import { SecurityScarletIntegration } from '../src/services/security-scarlet.js';

let capture: Fastify.FastifyInstance;
let received: { body: unknown; auth: string | undefined } | null = null;
let baseUrl: string;

beforeAll(async () => {
  capture = Fastify({ logger: false });
  capture.post('/events', async (req, reply) => {
    received = { body: req.body, auth: (req.headers as Record<string, string>)['authorization'] };
    return reply.code(200).send({ ok: true });
  });
  capture.get('/health', async (_req, reply) => reply.code(200).send({ ok: true }));
  capture.get('/anomalies', async (_req, reply) => reply.code(200).send({ anomalies: [{ id: 'a1', severity: 'high', type: 't', description: 'd', detected_at: new Date().toISOString(), agent_id: 'agt_1' }] }));
  await capture.listen({ port: 0, host: '127.0.0.1' });
  const a = capture.server.address();
  const port = typeof a === 'object' && a ? a.port : 8000;
  baseUrl = `http://127.0.0.1:${port}`;
});

afterAll(async () => { await capture.close(); });

describe('SecurityScarletIntegration', () => {
  it('forwards an event with the bearer API key', async () => {
    received = null;
    const integ = new SecurityScarletIntegration({ apiUrl: baseUrl, apiKey: 'secret', eventBusUrl: '', pollIntervalMs: 1000 });
    const ok = await integ.forwardEvent({
      agent_id: 'agt_1', event_type: 'tool_call', action: 'a', resource: 'r',
      result: 'success', details: { x: 1 }, created_at: new Date(),
    });
    expect(ok).toBe(true);
    expect(received).not.toBeNull();
    expect(received!.auth).toBe('Bearer secret');
    expect((received!.body as { agent_id: string }).agent_id).toBe('agt_1');
  });

  it('returns false when the upstream is unreachable', async () => {
    const integ = new SecurityScarletIntegration({ apiUrl: 'http://127.0.0.1:1', apiKey: '', eventBusUrl: '', pollIntervalMs: 1000 });
    const ok = await integ.forwardEvent({
      agent_id: 'a', event_type: 'e', result: 'success', details: {}, created_at: new Date(),
    });
    expect(ok).toBe(false);
  });

  it('checkConnection reports health', async () => {
    const integ = new SecurityScarletIntegration({ apiUrl: baseUrl, apiKey: '', eventBusUrl: '', pollIntervalMs: 1000 });
    expect(await integ.checkConnection()).toBe(true);
  });

  it('fetchAnomalies returns parsed anomalies', async () => {
    const integ = new SecurityScarletIntegration({ apiUrl: baseUrl, apiKey: '', eventBusUrl: '', pollIntervalMs: 1000 });
    const anomalies = await integ.fetchAnomalies();
    expect(anomalies.length).toBe(1);
    expect(anomalies[0].id).toBe('a1');
  });

  it('anomaly polling emits events', async () => {
    const integ = new SecurityScarletIntegration({ apiUrl: baseUrl, apiKey: '', eventBusUrl: '', pollIntervalMs: 50 });
    const seen = new Promise<void>((resolve) => integ.on('anomaly', () => resolve()));
    integ.startAnomalyPolling();
    await seen;
    integ.stopAnomalyPolling();
  });
});