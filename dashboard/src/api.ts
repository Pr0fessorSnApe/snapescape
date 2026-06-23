const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
const WS_URL = API_URL.replace('http', 'ws');

let authToken: string | null = localStorage.getItem('snapescape_token');

export function setToken(token: string) {
  authToken = token;
  localStorage.setItem('snapescape_token', token);
}

function headers(): Record<string, string> {
  const h: Record<string, string> = { 'Content-Type': 'application/json' };
  if (authToken) h['Authorization'] = `Bearer ${authToken}`;
  return h;
}

async function api(path: string, options: RequestInit = {}) {
  const res = await fetch(`${API_URL}${path}`, { ...options, headers: { ...headers(), ...options.headers as Record<string, string> } });
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}

export interface Scan {
  id: string; target: string; status: string; phase: string;
  progress: number; created_at: string; assets: unknown[];
  findings: Finding[]; crawl_tree?: Record<string, unknown>;
  graph?: { nodes: unknown[]; edges: unknown[] };
}

export interface Finding {
  id: string; title: string; severity: string; confidence: number;
  vuln_type: string; url: string; evidence?: Record<string, unknown>;
  mitre_attack?: string; validated?: boolean;
}

export interface TelemetryEvent {
  scan_id?: string; event?: string; phase?: string; progress?: number;
  worker_id?: string; message?: string;
}

export const login = (u: string, p: string) =>
  fetch(`${API_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username: u, password: p }),
  }).then(r => r.json()).then(d => { setToken(d.access_token); return d; });

export const createScan = (target: string) => api('/api/scans', { method: 'POST', body: JSON.stringify({ target }) });
export const listScans = () => api('/api/scans');
export const getScan = (id: string) => api(`/api/scans/${id}`);
export const startScan = (id: string) => api(`/api/scans/${id}/start`, { method: 'POST' });
export const pauseScan = (id: string) => api(`/api/scans/${id}/pause`, { method: 'POST' });
export const resumeScan = (id: string) => api(`/api/scans/${id}/resume`, { method: 'POST' });
export const stopScan = (id: string) => api(`/api/scans/${id}/stop`, { method: 'POST' });
export const scheduleScan = (id: string, cron: string) => api(`/api/scans/${id}/schedule`, { method: 'POST', body: JSON.stringify({ cron }) });
export const generateReport = (id: string) => api(`/api/scans/${id}/report`, { method: 'POST' });
export const getGraph = (id: string) => api(`/api/scans/${id}/graph`);
export const getCrawlTree = (id: string) => api(`/api/scans/${id}/crawl-tree`);
export const getEvidence = (id: string) => api(`/api/scans/${id}/evidence`);
export const listWorkers = () => api('/api/workers');
export const killWorker = (id: string) => api(`/api/workers/${id}/kill`, { method: 'POST' });
export const restartWorker = (id: string) => api(`/api/workers/${id}/restart`, { method: 'POST' });
export const explainFinding = (finding: Finding) => api('/api/ai/explain', { method: 'POST', body: JSON.stringify(finding) });
export const validateFinding = (finding: Finding) => api('/api/validate', { method: 'POST', body: JSON.stringify({ finding }) });
export const replayRequest = (method: string, url: string, hdrs: Record<string, string> = {}) =>
  api('/api/replay', { method: 'POST', body: JSON.stringify({ method, url, headers: hdrs }) });

export const quickScan = (target: string, profile = 'standard') =>
  api('/api/quick-scan', { method: 'POST', body: JSON.stringify({ target, profile }) });

export const getPlatformInfo = () => api('/api/info');

export function connectTelemetry(onEvent: (e: TelemetryEvent) => void): WebSocket {
  const ws = new WebSocket(`${WS_URL}/ws/telemetry`);
  ws.onmessage = (msg) => { try { onEvent(JSON.parse(msg.data)); } catch {} };
  return ws;
}
