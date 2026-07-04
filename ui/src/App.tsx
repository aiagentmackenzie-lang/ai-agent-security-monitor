import { useEffect, useState, useCallback } from 'react';
import { api, type Agent, type AlertRow, type PolicyRow, type Summary, type ComplianceSummary, type BehaviorFinding } from './api.js';

type Tab = 'overview' | 'agents' | 'alerts' | 'policies' | 'discovery';

export function App() {
  const [tab, setTab] = useState<Tab>('overview');
  const [summary, setSummary] = useState<Summary | null>(null);
  const [health, setHealth] = useState<boolean | null>(null);
  const [lastRefresh, setLastRefresh] = useState<Date>(new Date());

  const refresh = useCallback(async () => {
    const [s, h] = await Promise.all([api.summary(), api.health()]);
    setSummary(s);
    setHealth(h?.status === 'ok');
    setLastRefresh(new Date());
  }, []);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 15000);
    return () => clearInterval(id);
  }, [refresh]);

  return (
    <div className="app">
      <header>
        <h1>AI Agent Security <span className="accent">Monitor</span></h1>
        <div className="right">
          <span><span className={`health-dot ${health === null ? '' : health ? 'ok' : 'bad'}`} /> {health === null ? '…' : health ? 'API healthy' : 'API down'}</span>
          <span>↻ {lastRefresh.toLocaleTimeString()}</span>
          <a href="/documentation" target="_blank" rel="noreferrer">API docs</a>
          <button className="btn" onClick={refresh}>Refresh</button>
        </div>
      </header>

      <main>
        <div className="tabs">
          {(['overview', 'agents', 'alerts', 'policies', 'discovery'] as Tab[]).map(t => (
            <button key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>
              {t.charAt(0).toUpperCase() + t.slice(1)}
            </button>
          ))}
        </div>

        {tab === 'overview' && <Overview summary={summary} />}
        {tab === 'agents' && <AgentsTab />}
        {tab === 'alerts' && <AlertsTab />}
        {tab === 'policies' && <PoliciesTab />}
        {tab === 'discovery' && <DiscoveryTab />}
      </main>

      <div className="footer">
        AI Agent Security Monitor · OWASP Agentic Top 10 2026 · tamper-evident audit trail ·{' '}
        <a href="https://github.com/aiagentmackenzie-lang/ai-agent-security-monitor" target="_blank" rel="noreferrer">repo</a>
      </div>
    </div>
  );
}

function Overview({ summary }: { summary: Summary | null }) {
  const [comp, setComp] = useState<ComplianceSummary | null>(null);
  useEffect(() => { api.complianceSummary().then(setComp); }, []);

  if (!summary) return <div className="empty"><span className="spinner" /> Loading summary…</div>;

  const cards = [
    { label: 'Total Agents', value: summary.agents.total, sub: `${summary.agents.active} active` },
    { label: 'Quarantined', value: summary.agents.quarantined, cls: summary.agents.quarantined ? 'danger' : 'ok' },
    { label: 'Total Events', value: summary.events.total, sub: `${summary.events.denied} denied` },
    { label: 'Denied Events', value: summary.events.denied, cls: summary.events.denied ? 'warn' : 'ok' },
    { label: 'Critical Alerts', value: summary.alerts.critical, cls: summary.alerts.critical ? 'danger' : 'ok' },
    { label: 'Unack. Alerts', value: summary.alerts.unacknowledged, cls: summary.alerts.unacknowledged ? 'warn' : 'ok' },
  ];

  return (
    <>
      <div className="grid">
        {cards.map(c => (
          <div className="card" key={c.label}>
            <div className="label">{c.label}</div>
            <div className={`value ${c.cls || ''}`}>{c.value}</div>
            {c.sub && <div className="sub">{c.sub}</div>}
          </div>
        ))}
      </div>

      <section>
        <h2>Compliance by regulation {comp && <span className="count">overall {comp.overall.compliance_rate}%</span>}</h2>
        {!comp ? <div className="empty">Loading…</div> : comp.by_regulation.length === 0 ? <div className="empty">No compliance records yet</div> : (
          comp.by_regulation.map(r => {
            const rate = r.total > 0 ? (r.compliant / r.total) * 100 : 0;
            const cls = rate >= 80 ? '' : rate >= 50 ? 'warn' : 'bad';
            return (
              <div className="bar-row" key={r.regulation}>
                <div className="name">{r.regulation}</div>
                <div className="bar-track"><div className={`bar-fill ${cls}`} style={{ width: `${rate}%` }} /></div>
                <div className="pct">{Math.round(rate)}%</div>
                <div className="muted" style={{ width: 120, fontSize: 12 }}>
                  {r.compliant}/{r.total} · {r.gaps} gaps
                </div>
              </div>
            );
          })
        )}
      </section>
    </>
  );
}

function sevBadge(s: string) {
  const map: Record<string, string> = { critical: 'crit', high: 'high', medium: 'med', low: 'low' };
  return <span className={`badge ${map[s] || 'low'}`}>{s}</span>;
}

function AgentsTab() {
  const [agents, setAgents] = useState<Agent[] | null>(null);
  useEffect(() => { api.agents().then(r => setAgents(r?.agents ?? [])); }, []);
  return (
    <section>
      <h2>Agents {agents && <span className="count">{agents.length}</span>}</h2>
      {!agents ? <div className="empty">Loading…</div> : agents.length === 0 ? <div className="empty">No agents registered</div> : (
        <table>
          <thead><tr><th>Name</th><th>Type</th><th>Owner</th><th>Status</th><th>ID</th></tr></thead>
          <tbody>
            {agents.map(a => (
              <tr key={a.id}>
                <td>{a.name}</td>
                <td>{a.type}</td>
                <td>{a.owner || '—'}</td>
                <td>{a.quarantined ? <>{sevBadge('high')} quarantined</> : a.active ? <span className="badge ok">active</span> : <span className="badge low">inactive</span>}</td>
                <td className="mono">{a.id}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function AlertsTab() {
  const [alerts, setAlerts] = useState<AlertRow[] | null>(null);
  const load = useCallback(() => { api.alerts().then(r => setAlerts(r?.alerts ?? [])); }, []);
  useEffect(() => { load(); }, [load]);

  const ack = async (id: string) => { await api.acknowledge(id, 'ui-operator'); load(); };

  return (
    <section>
      <h2>Unacknowledged alerts {alerts && <span className="count">{alerts.length}</span>}</h2>
      {!alerts ? <div className="empty">Loading…</div> : alerts.length === 0 ? <div className="empty">No unacknowledged alerts 🎉</div> : (
        <table>
          <thead><tr><th>Severity</th><th>Type</th><th>Message</th><th>Agent</th><th>Time</th><th></th></tr></thead>
          <tbody>
            {alerts.map(a => (
              <tr key={a.id}>
                <td>{sevBadge(a.severity)}</td>
                <td>{a.type}</td>
                <td>{a.message}</td>
                <td className="mono">{a.agent_id?.slice(0, 8)}</td>
                <td className="mono">{new Date(a.created_at).toLocaleString()}</td>
                <td><button className="btn small" onClick={() => ack(a.id)}>Ack</button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function PoliciesTab() {
  const [policies, setPolicies] = useState<PolicyRow[] | null>(null);
  useEffect(() => { api.policies().then(r => setPolicies(r?.policies ?? [])); }, []);
  return (
    <section>
      <h2>Policies {policies && <span className="count">{policies.length}</span>}</h2>
      {!policies ? <div className="empty">Loading…</div> : policies.length === 0 ? <div className="empty">No policies defined</div> : (
        <table>
          <thead><tr><th>Name</th><th>Priority</th><th>Mode</th><th>Rules</th><th>Scope</th><th>Status</th></tr></thead>
          <tbody>
            {policies.map(p => (
              <tr key={p.id}>
                <td>{p.name}<div className="muted" style={{ fontSize: 11 }}>{p.description}</div></td>
                <td>{p.priority}</td>
                <td>{p.default_effect === 'deny' ? <span className="badge info">allowlist</span> : <span className="badge low">denylist</span>}</td>
                <td>{(p.rules as Array<{ effect: string }>).length}</td>
                <td className="mono">{(p.agent_ids || []).join(', ')}</td>
                <td>{p.active ? <span className="badge ok">active</span> : <span className="badge low">inactive</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function DiscoveryTab() {
  const [findings, setFindings] = useState<BehaviorFinding[] | null>(null);
  const [scan, setScan] = useState<'idle' | 'running' | 'done'>('idle');
  const run = async () => {
    setScan('running');
    const r = await api.behaviorScan();
    setFindings(r?.behavior_findings ?? []);
    setScan('done');
  };
  useEffect(() => { run(); }, []);
  return (
    <section>
      <h2>Behavior discovery — misregistered agent inference {findings && <span className="count">{findings.length} findings</span>}</h2>
      <div style={{ padding: '12px 18px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 12, alignItems: 'center' }}>
        <button className="btn" onClick={run} disabled={scan === 'running'}>{scan === 'running' ? 'Scanning…' : 'Re-run scan'}</button>
        <span className="muted">Flags agents registered as 'custom' whose action distribution matches a known baseline type above 60% confidence.</span>
      </div>
      {!findings ? <div className="empty">Scanning…</div> : findings.length === 0 ? <div className="empty">No misregistered agents detected</div> : (
        <table>
          <thead><tr><th>Agent</th><th>Registered</th><th>Inferred</th><th>Confidence</th><th>Description</th></tr></thead>
          <tbody>
            {findings.map(f => (
              <tr key={f.agent_id}>
                <td>{f.agent_name}<div className="mono" style={{ fontSize: 11 }}>{f.agent_id.slice(0, 8)}</div></td>
                <td><span className="badge low">{f.registered_type}</span></td>
                <td><span className="badge high">{f.inferred_type}</span></td>
                <td>{Math.round(f.confidence * 100)}%</td>
                <td className="muted">{f.description}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}