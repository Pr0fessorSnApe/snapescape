export class SnapescapeClient {
  private baseUrl: string;
  private token: string | null = null;

  constructor(baseUrl = 'http://localhost:8000') {
    this.baseUrl = baseUrl.replace(/\/$/, '');
  }

  async login(username: string, password: string): Promise<string> {
    const body = new URLSearchParams({ username, password });
    const res = await fetch(`${this.baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    const data = await res.json();
    this.token = data.access_token;
    return this.token!;
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.token) h['Authorization'] = `Bearer ${this.token}`;
    return h;
  }

  async createScan(target: string) {
    const res = await fetch(`${this.baseUrl}/api/scans`, {
      method: 'POST', headers: this.headers(), body: JSON.stringify({ target }),
    });
    return res.json();
  }

  async startScan(scanId: string) {
    const res = await fetch(`${this.baseUrl}/api/scans/${scanId}/start`, {
      method: 'POST', headers: this.headers(),
    });
    return res.json();
  }

  async getScan(scanId: string) {
    const res = await fetch(`${this.baseUrl}/api/scans/${scanId}`, { headers: this.headers() });
    return res.json();
  }

  async generateReport(scanId: string) {
    const res = await fetch(`${this.baseUrl}/api/scans/${scanId}/report`, {
      method: 'POST', headers: this.headers(),
    });
    return res.json();
  }

  connectTelemetry(onEvent: (data: unknown) => void): WebSocket {
    const ws = new WebSocket(this.baseUrl.replace('http', 'ws') + '/ws/telemetry');
    ws.onmessage = (m) => onEvent(JSON.parse(m.data));
    return ws;
  }
}
