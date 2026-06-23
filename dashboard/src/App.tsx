import { useState, useEffect, useCallback } from 'react';
import {
  Play, Pause, Square, RotateCcw, FileText, Shield, Zap, Clock,
  Activity, Globe, Server, AlertTriangle, Radio, Cpu, GitBranch, Image
} from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import {
  Scan, Finding, TelemetryEvent, listScans, startScan, pauseScan,
  resumeScan, stopScan, scheduleScan, generateReport, connectTelemetry,
  listWorkers, killWorker, restartWorker, getCrawlTree, getGraph, login
} from './api';
import { FindingsPanel, FindingDetail, CrawlTreeView, GraphView, WorkerMap, PortHeatmap } from './components/Panels';
import { OnboardingWizard, QuickHuntBar } from './components/Onboarding';

const SEV_COLORS: Record<string, string> = {
  critical: '#ff0055', high: '#ff6644', medium: '#ffaa00', low: '#88cc00', info: '#00f0ff'
};

const THEMES = {
  cyberpunk: { bg: '#0a0a12', accent: '#00f0ff', purple: '#7b2fff' },
  blood: { bg: '#120a0a', accent: '#ff0055', purple: '#ff4444' },
  matrix: { bg: '#0a120a', accent: '#00ff88', purple: '#00cc66' },
};

type Tab = 'dashboard' | 'findings' | 'graph' | 'crawl' | 'workers' | 'evidence' | 'screenshots';

export default function App() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [activeScan, setActiveScan] = useState<Scan | null>(null);
  const [target, setTarget] = useState('');
  const [telemetry, setTelemetry] = useState<TelemetryEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState<Tab>('dashboard');
  const [theme, setTheme] = useState<keyof typeof THEMES>('cyberpunk');
  const [workers, setWorkers] = useState<Record<string, unknown>[]>([]);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [crawlTree, setCrawlTree] = useState<Record<string, unknown>>({});
  const [graph, setGraph] = useState<{ nodes: unknown[]; edges: unknown[] } | undefined>();
  const [loggedIn, setLoggedIn] = useState(!!localStorage.getItem('snapescape_token'));
  const [showOnboarding, setShowOnboarding] = useState(!localStorage.getItem('snapescape_onboarded'));

  const refresh = useCallback(async () => {
    try {
      const data = await listScans();
      setScans(data);
      if (activeScan) {
        const u = data.find((s: Scan) => s.id === activeScan.id);
        if (u) setActiveScan(u);
      }
      setWorkers(await listWorkers());
    } catch { /* auth */ }
  }, [activeScan]);

  useEffect(() => {
    if (!loggedIn) return;
    refresh();
    const ws = connectTelemetry((e) => {
      setTelemetry(p => [e, ...p].slice(0, 200));
      if (e.worker_id) setWorkers(w => [{ worker_id: e.worker_id, status: 'active', ...e }, ...w].slice(0, 20));
      refresh();
    });
    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    return () => ws.close();
  }, [loggedIn]);

  useEffect(() => {
    if (!activeScan || tab !== 'crawl') return;
    getCrawlTree(activeScan.id).then(setCrawlTree).catch(() => {});
  }, [activeScan, tab]);

  useEffect(() => {
    if (!activeScan || tab !== 'graph') return;
    getGraph(activeScan.id).then(setGraph).catch(() => {});
  }, [activeScan, tab]);

  const handleLogin = async () => {
    await login('snape', 'snapescape');
    setLoggedIn(true);
  };

  const handleQuickHunt = async (t: string, profile: string) => {
    setLoading(true);
    try {
      const API = import.meta.env.VITE_API_URL || 'http://localhost:8000';
      const token = localStorage.getItem('snapescape_token');
      const res = await fetch(`${API}/api/quick-scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
        body: JSON.stringify({ target: t, profile }),
      });
      const result = await res.json();
      await refresh();
      const scans = await listScans();
      const scan = scans.find((s: Scan) => s.id === result.scan_id);
      if (scan) setActiveScan(scan);
      if (result.findings > 0) setTab('findings');
    } finally { setLoading(false); }
  };

  const handleCreateAndStart = async () => {
    if (!target.trim()) return;
    await handleQuickHunt(target.trim(), 'standard');
    setTarget('');
  };

  const handleAction = async (action: string) => {
    if (!activeScan) return;
    setLoading(true);
    try {
      const ops: Record<string, () => Promise<Scan>> = {
        start: () => startScan(activeScan.id),
        pause: () => pauseScan(activeScan.id),
        resume: () => resumeScan(activeScan.id),
        stop: () => stopScan(activeScan.id),
      };
      if (action === 'report') { await generateReport(activeScan.id); }
      else if (action === 'schedule') { await scheduleScan(activeScan.id, '0 */6 * * *'); }
      else if (ops[action]) setActiveScan(await ops[action]());
      await refresh();
    } finally { setLoading(false); }
  };

  if (!loggedIn) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', flexDirection: 'column', gap: 24, padding: 20 }}>
        <img src="/branding/logo.png" alt="SnapeScape" style={{ width: 220, filter: 'drop-shadow(0 0 24px rgba(0,240,255,0.4))' }} onError={(e) => { (e.target as HTMLImageElement).style.display = 'none'; }} />
        <Shield size={48} color="#00f0ff" style={{ display: 'none' }} />
        <h1 style={{ fontFamily: 'Orbitron', color: '#00f0ff', fontSize: 32 }} className="glow-text">SnapeScape</h1>
        <p style={{ color: '#888', maxWidth: 420, textAlign: 'center', lineHeight: 1.6, fontSize: 13, letterSpacing: 1 }}>
          THE WORLD'S ATTACK SURFACE INTELLIGENCE PLATFORM
        </p>
        <button onClick={handleLogin} style={{
          padding: '16px 40px', background: 'linear-gradient(135deg,#00f0ff33,#7b2fff33)',
          border: '1px solid #00f0ff', color: '#00f0ff', borderRadius: 12, cursor: 'pointer',
          fontFamily: 'Orbitron', fontSize: 16, fontWeight: 700,
        }}>
          Enter Command Center
        </button>
        <p style={{ color: '#555', fontSize: 12 }}>Default: snape / snapescape</p>
      </div>
    );
  }

  const t = THEMES[theme];
  const sevData = activeScan?.findings?.reduce((a: {name:string;value:number}[], f) => {
    const e = a.find(x => x.name === f.severity);
    if (e) e.value++; else a.push({ name: f.severity, value: 1 });
    return a;
  }, []) || [];

  const tabs: { id: Tab; label: string; icon: React.ReactNode }[] = [
    { id: 'dashboard', label: 'Dashboard', icon: <Activity size={14} /> },
    { id: 'findings', label: 'Findings', icon: <AlertTriangle size={14} /> },
    { id: 'graph', label: 'Attack Graph', icon: <GitBranch size={14} /> },
    { id: 'crawl', label: 'Crawl Tree', icon: <Globe size={14} /> },
    { id: 'workers', label: 'Workers', icon: <Cpu size={14} /> },
    { id: 'evidence', label: 'Evidence', icon: <FileText size={14} /> },
    { id: 'screenshots', label: 'Screenshots', icon: <Image size={14} /> },
  ];

  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: t.bg }}>
      <aside className="glass" style={{ width: 220, padding: 16, display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 24 }}>
          <img src="/branding/logo.png" alt="SnapeScape" style={{ width: 40, height: 40, objectFit: 'contain' }} onError={(e) => { (e.target as HTMLImageElement).src = ''; (e.target as HTMLImageElement).style.display = 'none'; }} />
          <Shield size={24} color={t.accent} />
          <div>
            <div style={{ fontFamily: 'Orbitron', color: t.accent, fontSize: 16 }}>SnapeScape</div>
            <div style={{ fontSize: 9, color: '#666' }}>v1.0 — Pr0Fessor_SnApe</div>
          </div>
        </div>
        {tabs.map(tb => (
          <div key={tb.id} onClick={() => setTab(tb.id)} style={{
            padding: '9px 12px', borderRadius: 8, cursor: 'pointer', fontSize: 13, marginBottom: 2,
            display: 'flex', gap: 8, alignItems: 'center',
            background: tab === tb.id ? `${t.accent}18` : 'transparent',
            color: tab === tb.id ? t.accent : '#888',
          }}>{tb.icon} {tb.label}</div>
        ))}
        <div style={{ marginTop: 'auto', paddingTop: 16 }}>
          <div style={{ fontSize: 11, color: '#666', marginBottom: 6 }}>Theme</div>
          {Object.keys(THEMES).map(th => (
            <button key={th} onClick={() => setTheme(th as keyof typeof THEMES)} style={{
              fontSize: 10, marginRight: 4, padding: '3px 8px', borderRadius: 4, cursor: 'pointer',
              border: `1px solid ${theme === th ? t.accent : '#333'}`, background: 'transparent', color: theme === th ? t.accent : '#666',
            }}>{th}</button>
          ))}
          <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginTop: 12 }}>
            <Radio size={10} color={connected ? '#00ff88' : '#ff0055'} />
            <span style={{ fontSize: 11, color: connected ? '#00ff88' : '#ff0055' }}>{connected ? 'Live' : 'Offline'}</span>
          </div>
        </div>
      </aside>

      <main style={{ flex: 1, padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
        {showOnboarding && <OnboardingWizard onComplete={() => setShowOnboarding(false)} />}
        <QuickHuntBar onScan={handleQuickHunt} loading={loading} />
        <header className="glass" style={{ padding: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
          <h1 style={{ fontFamily: 'Orbitron', fontSize: 20, color: t.accent }}>Attack Surface Command</h1>
          <div style={{ display: 'flex', gap: 8 }}>
            <input value={target} onChange={e => setTarget(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleCreateAndStart()}
              placeholder="target.com" style={{ background: '#0006', border: `1px solid ${t.accent}33`, borderRadius: 8, padding: '8px 14px', color: '#fff', width: 260, fontFamily: 'JetBrains Mono' }} />
            <button onClick={handleCreateAndStart} disabled={loading} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '8px 16px', background: `${t.accent}22`, border: `1px solid ${t.accent}`, color: t.accent, borderRadius: 8, cursor: 'pointer' }}>
              <Zap size={14} /> Launch
            </button>
          </div>
        </header>

        {activeScan && (
          <div className="glass" style={{ padding: '10px 16px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8 }}>
            <span style={{ fontFamily: 'JetBrains Mono', fontSize: 12, color: t.accent }}>{activeScan.target} | {activeScan.status} | {activeScan.phase} | {activeScan.progress.toFixed(0)}%</span>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {[{ a: 'start', i: Play, l: 'Start' }, { a: 'pause', i: Pause, l: 'Pause' }, { a: 'resume', i: RotateCcw, l: 'Resume' },
                { a: 'stop', i: Square, l: 'Stop', c: '#ff0055' }, { a: 'schedule', i: Clock, l: 'Schedule' },
                { a: 'report', i: FileText, l: 'Report', c: t.purple }].map(({ a, i: Icon, l, c }) => (
                <button key={a} onClick={() => handleAction(a)} style={{ display: 'flex', alignItems: 'center', gap: 4, padding: '5px 10px', background: 'transparent', border: `1px solid ${c || t.accent}44`, color: c || t.accent, borderRadius: 6, cursor: 'pointer', fontSize: 11 }}>
                  <Icon size={12} /> {l}
                </button>
              ))}
            </div>
          </div>
        )}

        {tab === 'dashboard' && (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 12 }}>
              {[{ i: Globe, l: 'Running', v: scans.filter(s => s.status === 'running').length, c: t.accent },
                { i: Server, l: 'Scans', v: scans.length, c: t.purple },
                { i: AlertTriangle, l: 'Findings', v: activeScan?.findings?.length || 0, c: '#ff0055' },
                { i: Activity, l: 'Progress', v: `${(activeScan?.progress || 0).toFixed(0)}%`, c: '#00ff88' }].map((s, i) => (
                <div key={i} className="glass" style={{ padding: 16 }}>
                  <s.i size={18} color={s.c} />
                  <div style={{ fontSize: 26, fontWeight: 700, fontFamily: 'Orbitron', color: s.c }}>{s.v}</div>
                  <div style={{ fontSize: 11, color: '#888' }}>{s.l}</div>
                </div>
              ))}
            </div>
            <div style={{ display: 'flex', gap: 16 }}>
              <div className="glass" style={{ flex: 2, padding: 16 }}>
                <h3 style={{ fontSize: 13, color: '#888', marginBottom: 12, fontFamily: 'Orbitron' }}>Scan Progress</h3>
                <ResponsiveContainer width="100%" height={180}>
                  <AreaChart data={Array.from({ length: 20 }, (_, i) => ({ t: `${i}s`, p: Math.min(activeScan?.progress || 0, (i + 1) * 5) }))}>
                    <Area type="monotone" dataKey="p" stroke={t.accent} fill={`${t.accent}33`} />
                    <XAxis dataKey="t" stroke="#444" fontSize={10} /><YAxis stroke="#444" fontSize={10} domain={[0, 100]} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
              <div className="glass" style={{ flex: 1, padding: 16 }}>
                <h3 style={{ fontSize: 13, color: '#888', marginBottom: 12, fontFamily: 'Orbitron' }}>Severity</h3>
                <ResponsiveContainer width="100%" height={180}>
                  <PieChart><Pie data={sevData.length ? sevData : [{ name: 'none', value: 1 }]} dataKey="value" innerRadius={40} outerRadius={65} stroke="none">
                    {(sevData.length ? sevData : [{ name: 'none', value: 1 }]).map((e, i) => <Cell key={i} fill={SEV_COLORS[e.name] || '#333'} />)}
                  </Pie></PieChart>
                </ResponsiveContainer>
              </div>
            </div>
            <div className="glass" style={{ padding: 16 }}>
              <h3 style={{ fontSize: 13, color: '#888', marginBottom: 12, fontFamily: 'Orbitron' }}>Port Heatmap</h3>
              <PortHeatmap assets={activeScan?.assets || []} />
            </div>
            <div className="glass" style={{ padding: 16, maxHeight: 200, overflow: 'auto' }}>
              <h3 style={{ fontSize: 13, color: '#888', marginBottom: 8, fontFamily: 'Orbitron' }}>Live Telemetry</h3>
              {telemetry.slice(0, 30).map((ev, i) => (
                <div key={i} style={{ fontSize: 11, fontFamily: 'JetBrains Mono', color: '#888', padding: '2px 0' }}>
                  <span style={{ color: t.purple }}>[{ev.event}]</span> {ev.phase} {ev.progress !== undefined && <span style={{ color: '#00ff88' }}>{ev.progress.toFixed(0)}%</span>}
                </div>
              ))}
            </div>
          </>
        )}

        {tab === 'findings' && (
          <div className="glass" style={{ padding: 16 }}>
            <FindingsPanel scan={activeScan} onSelect={setSelectedFinding} />
            <FindingDetail finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
          </div>
        )}
        {tab === 'graph' && <div className="glass" style={{ padding: 16 }}><GraphView graph={graph || activeScan?.graph} /></div>}
        {tab === 'crawl' && <div className="glass" style={{ padding: 16 }}><CrawlTreeView tree={crawlTree} /></div>}
        {tab === 'workers' && (
          <div className="glass" style={{ padding: 16 }}>
            <WorkerMap workers={workers} />
            <div style={{ marginTop: 12, display: 'flex', gap: 8 }}>
              {workers.slice(0, 5).map((w, i) => (
                <div key={i} style={{ display: 'flex', gap: 6 }}>
                  <button onClick={() => killWorker(String((w as {worker_id?: string}).worker_id || i))} style={{ fontSize: 11, padding: '4px 10px', background: '#ff005522', border: '1px solid #ff0055', color: '#ff0055', borderRadius: 4, cursor: 'pointer' }}>Kill</button>
                  <button onClick={() => restartWorker(String((w as {worker_id?: string}).worker_id || i))} style={{ fontSize: 11, padding: '4px 10px', background: '#00ff8822', border: '1px solid #00ff88', color: '#00ff88', borderRadius: 4, cursor: 'pointer' }}>Restart</button>
                </div>
              ))}
            </div>
          </div>
        )}
        {tab === 'evidence' && (
          <div className="glass" style={{ padding: 16, fontFamily: 'JetBrains Mono', fontSize: 12 }}>
            {activeScan?.findings?.map(f => (
              <div key={f.id} style={{ marginBottom: 12, padding: 12, background: '#0004', borderRadius: 8 }}>
                <div style={{ color: t.accent }}>{f.title}</div>
                <pre style={{ color: '#888', marginTop: 8 }}>{JSON.stringify(f.evidence, null, 2)}</pre>
              </div>
            )) || <div style={{ color: '#555' }}>No evidence</div>}
          </div>
        )}
        {tab === 'screenshots' && (
          <div className="glass" style={{ padding: 16, color: '#888' }}>
            Screenshots captured by Playwright/Puppeteer engines appear here after browser analysis phase.
          </div>
        )}

        <div className="glass" style={{ padding: 16 }}>
          <h3 style={{ fontSize: 13, color: '#888', marginBottom: 8, fontFamily: 'Orbitron' }}>Scan History</h3>
          {scans.map(s => (
            <div key={s.id} onClick={() => setActiveScan(s)} style={{
              display: 'flex', justifyContent: 'space-between', padding: '8px 12px', cursor: 'pointer', borderRadius: 8, marginBottom: 4,
              border: `1px solid ${activeScan?.id === s.id ? t.accent : 'transparent'}`,
            }}>
              <span>{s.target}</span>
              <span style={{ fontSize: 11, color: s.status === 'running' ? '#00ff88' : '#888' }}>{s.status}</span>
            </div>
          ))}
        </div>
      </main>
    </div>
  );
}
