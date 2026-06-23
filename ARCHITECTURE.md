# SNAPESCAPE Architecture

## Design Principles

1. **Native implementations** — No shell-out to external scanners
2. **Multi-engine validation** — Consensus before reporting findings
3. **Zero false positive philosophy** — Verify before alert
4. **Horizontal scalability** — Stateless workers, shared queue
5. **Language-optimized** — Right tool for each workload

## Technology Mapping

| Component | Language | Rationale |
|-----------|----------|-----------|
| DNS engine | Rust | Async I/O, memory safety, hickory-dns |
| HTTP prober | Rust | tokio + hyper, massive concurrency |
| Port scanner | Rust/C | Raw socket performance |
| Worker pipeline | Go | Goroutines, distributed nodes |
| API gateway | Python | FastAPI, AI/ML ecosystem |
| AI orchestration | Python | LLM integration, triage |
| Browser automation | Playwright (Node) | JS rendering, screenshots |
| Parsers | Zig (future) | Zero-copy binary parsing |
| Fuzzing modules | Nim (future) | Lightweight stealth payloads |
| Dashboard | React/TypeScript | Real-time UI, WebGL graphs |

## Data Flow

```
Target Input
    │
    ▼
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Scheduler  │────▶│  Task Queue  │────▶│ Go Workers  │
└─────────────┘     └──────────────┘     └──────┬──────┘
                                                 │
                    ┌────────────────────────────┼────────────────────────────┐
                    ▼                            ▼                            ▼
              ┌──────────┐              ┌──────────────┐            ┌─────────────┐
              │ DNS Enum │              │ HTTP Probe   │            │ Browser     │
              └────┬─────┘              └──────┬───────┘            └──────┬──────┘
                   │                           │                           │
                   └───────────────────────────┼───────────────────────────┘
                                               ▼
                                    ┌─────────────────────┐
                                    │  Asset Correlation  │
                                    │  Graph Engine       │
                                    └──────────┬──────────┘
                                               ▼
                                    ┌─────────────────────┐
                                    │ Validation Engine   │
                                    │ (multi-stage)       │
                                    └──────────┬──────────┘
                                               ▼
                                    ┌─────────────────────┐
                                    │ Findings Store      │
                                    │ + Report Generator  │
                                    └─────────────────────┘
```

## IPC & Communication

- **REST API** — CRUD, scan control, auth
- **WebSocket** — Real-time telemetry stream
- **Redis Streams** — Task queue between API and workers
- **gRPC** (proto defined) — Worker ↔ Rust engine binary protocol

## Database Schema

### PostgreSQL (relational)
- `users`, `workspaces`, `teams`, `scans`, `assets`, `findings`, `evidence`, `reports`, `audit_logs`

### Redis (cache + queue)
- Task streams, session cache, rate limits, live telemetry pub/sub

## Security Boundaries

```
┌─────────────────────────────────────┐
│  Public: Dashboard (auth required)  │
├─────────────────────────────────────┤
│  API Gateway: RBAC, rate limit      │
├─────────────────────────────────────┤
│  Worker Sandbox: scoped network     │
├─────────────────────────────────────┤
│  Vault: AES-256 encrypted keys      │
└─────────────────────────────────────┘
```

## Scalability

- Workers scale horizontally via `docker compose scale worker=N`
- Rust engines compiled as shared library + standalone binaries
- Connection pooling, bounded concurrency per target
- Circuit breakers on failing hosts

## False Positive Elimination

```
Detection → Differential Check → Protocol Validation → Browser Verify → AI Triage → Report
     │              │                    │                  │              │
   Stage 1        Stage 2              Stage 3            Stage 4        Stage 5
```

Each finding requires `confidence_score >= 0.85` and at least 2 validation stages.
