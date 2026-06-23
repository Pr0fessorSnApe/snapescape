import { useState } from 'react';
import { Scan, Finding, explainFinding, validateFinding, replayRequest } from '../api';

export function FindingsPanel({ scan, onSelect }: { scan: Scan | null; onSelect: (f: Finding) => void }) {
  const confirmed = scan?.findings?.filter(f => f.validated === true) || [];
  if (!confirmed.length) return <div style={{ color: '#555', padding: 16 }}>No confirmed findings — unvalidated detections are filtered to prevent false positives</div>;
  return (
    <div>
      <div style={{ fontSize: 11, color: '#00ff88', marginBottom: 8, fontFamily: 'JetBrains Mono' }}>
        ✓ {confirmed.length} confirmed finding(s) — zero false positive filter active
      </div>
      {confirmed.map(f => (
        <div key={f.id} style={rowStyle} onClick={() => onSelect(f)}>
          <span style={{ color: sevColor(f.severity), fontWeight: 600 }}>[{f.severity.toUpperCase()}]</span>
          <span style={{ marginLeft: 8 }}>{f.title}</span>
          <span style={{ float: 'right', color: '#888', fontSize: 11 }}>{(f.confidence * 100).toFixed(0)}%</span>
        </div>
      ))}
    </div>
  );
}

export function FindingDetail({ finding, onClose }: { finding: Finding | null; onClose: () => void }) {
  const [ai, setAi] = useState<Record<string, unknown> | null>(null);
  const [replay, setReplay] = useState<Record<string, unknown> | null>(null);
  if (!finding) return null;
  return (
    <div className="glass" style={{ padding: 20, marginTop: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
        <h3 style={{ color: '#00f0ff' }}>{finding.title}</h3>
        <button onClick={onClose} style={btnStyle}>Close</button>
      </div>
      <p style={{ fontSize: 13, color: '#aaa' }}>{finding.url}</p>
      <div style={{ display: 'flex', gap: 8, marginTop: 12 }}>
        <button style={btnStyle} onClick={async () => setAi(await explainFinding(finding))}>AI Explain</button>
        <button style={btnStyle} onClick={async () => validateFinding(finding)}>Validate</button>
        <button style={btnStyle} onClick={async () => setReplay(await replayRequest('GET', finding.url))}>Replay Request</button>
      </div>
      {ai && <pre style={preStyle}>{JSON.stringify(ai, null, 2)}</pre>}
      {replay && <pre style={preStyle}>{JSON.stringify(replay, null, 2)}</pre>}
      <pre style={preStyle}>{JSON.stringify(finding.evidence, null, 2)}</pre>
    </div>
  );
}

export function CrawlTreeView({ tree }: { tree: Record<string, unknown> }) {
  const entries = Object.entries(tree);
  if (!entries.length) return <div style={{ color: '#555' }}>No crawl data</div>;
  return (
    <div style={{ fontFamily: 'JetBrains Mono', fontSize: 12 }}>
      {entries.map(([url, data]) => (
        <div key={url} style={{ padding: '4px 0', borderLeft: '2px solid #7b2fff', paddingLeft: 12, marginBottom: 4 }}>
          <div style={{ color: '#00f0ff' }}>{url}</div>
          <div style={{ color: '#666' }}>{JSON.stringify(data)}</div>
        </div>
      ))}
    </div>
  );
}

export function GraphView({ graph }: { graph?: { nodes: unknown[]; edges: unknown[] } }) {
  if (!graph?.nodes?.length) return <div style={{ color: '#555' }}>Graph will render after scan</div>;
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
      {graph.nodes.slice(0, 30).map((n: unknown, i) => (
        <div key={i} className="glass" style={{ padding: '8px 12px', fontSize: 11, fontFamily: 'JetBrains Mono' }}>
          {JSON.stringify(n).slice(0, 80)}
        </div>
      ))}
      <div style={{ width: '100%', color: '#888', fontSize: 12, marginTop: 8 }}>
        {graph.nodes.length} nodes, {graph.edges.length} edges
      </div>
    </div>
  );
}

export function WorkerMap({ workers }: { workers: Record<string, unknown>[] }) {
  if (!workers.length) return <div style={{ color: '#555' }}>No workers connected</div>;
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 12 }}>
      {workers.map((w, i) => (
        <div key={i} className="glass" style={{ padding: 16, borderColor: '#00ff8844' }}>
          <div style={{ color: '#00ff88', fontFamily: 'Orbitron' }}>Worker {(w as {worker_id?: string}).worker_id || i}</div>
          <div style={{ fontSize: 12, color: '#888' }}>{(w as {status?: string}).status || 'active'}</div>
        </div>
      ))}
    </div>
  );
}

export function PortHeatmap({ assets }: { assets: unknown[] }) {
  const ports = (assets as {asset_type?: string; value?: string}[]).filter(a => a.asset_type === 'port');
  const common = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017];
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 6 }}>
      {common.map(p => {
        const open = ports.some(a => a.value?.endsWith(`:${p}`));
        return (
          <div key={p} style={{
            padding: 12, textAlign: 'center', borderRadius: 8,
            background: open ? 'rgba(255,0,85,0.2)' : 'rgba(255,255,255,0.03)',
            border: `1px solid ${open ? '#ff0055' : '#333'}`,
            color: open ? '#ff0055' : '#555',
          }}>{p}</div>
        );
      })}
    </div>
  );
}

const sevColor = (s: string) => ({ critical: '#ff0055', high: '#ff6644', medium: '#ffaa00', low: '#88cc00', info: '#00f0ff' }[s] || '#888');
const rowStyle: React.CSSProperties = { padding: '10px 12px', cursor: 'pointer', borderBottom: '1px solid rgba(255,255,255,0.05)', fontSize: 13 };
const btnStyle: React.CSSProperties = { background: 'transparent', border: '1px solid #00f0ff44', color: '#00f0ff', padding: '6px 12px', borderRadius: 6, cursor: 'pointer', fontSize: 12 };
const preStyle: React.CSSProperties = { background: '#111', padding: 12, borderRadius: 8, fontSize: 11, marginTop: 12, overflow: 'auto', maxHeight: 200 };
