"""SNAPESCAPE FastAPI — complete API gateway."""

from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Any

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from snapescape_api.orchestrator import ScanOrchestrator
from snapescape_api.ai_engine import AIEngine
from snapescape_api.report_engine import ReportEngine
from snapescape_api.validation_engine import ValidationEngine
from snapescape_api.vault import get_vault, VaultError
from snapescape_api.auth import (
    authenticate_user, create_access_token, get_current_user, require_role,
    Token, User,
)
from snapescape_api.plugin_sdk import PluginSDK
from snapescape_api.graph_engine import GraphEngine

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("snapescape.api")

orchestrator = ScanOrchestrator()
ai_engine = AIEngine()
report_engine = ReportEngine()
validator = ValidationEngine()
plugin_sdk = PluginSDK()
graph_engine = GraphEngine()
ws_clients: list[WebSocket] = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    await orchestrator.connect()

    async def broadcast(event: dict):
        dead = []
        for ws in ws_clients:
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        for ws in dead:
            ws_clients.remove(ws)

    orchestrator.on_telemetry(broadcast)
    logger.info("SNAPESCAPE API v1.0 — All systems online")
    yield
    await orchestrator.disconnect()
    await validator.close()


app = FastAPI(title="SNAPESCAPE API", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


class ScanCreate(BaseModel):
    target: str = Field(..., min_length=1)
    workspace_id: str | None = None
    profile: str = Field(default="standard", pattern="^(quick|standard|deep)$")


class QuickScan(BaseModel):
    target: str = Field(..., min_length=1, examples=["example.com"])
    profile: str = Field(default="standard", pattern="^(quick|standard|deep)$")


class ScheduleScan(BaseModel):
    cron: str = "0 */6 * * *"


class VaultKeySet(BaseModel):
    provider: str
    key_name: str = "api_key"
    value: str


class ReplayRequest(BaseModel):
    method: str = "GET"
    url: str
    headers: dict[str, str] = {}
    body: str | None = None


class ValidateFinding(BaseModel):
    finding: dict[str, Any]


# --- Auth ---

@app.post("/api/auth/login", response_model=Token)
async def login(form: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form.username, form.password)
    if not user:
        raise HTTPException(401, "Invalid credentials")
    token = create_access_token({"sub": user["username"], "role": user["role"]})
    return Token(access_token=token, token_type="bearer", role=user["role"])


@app.get("/api/auth/me", response_model=User)
async def me(user: User = Depends(get_current_user)):
    return user


# --- Health ---

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "snapescape", "version": "1.0.0", "engines": "all"}


@app.get("/api/info")
async def platform_info():
    """Platform info for onboarding UI."""
    from snapescape_api.engines.registry import SCAN_PROFILES
    return {
        "name": "SNAPESCAPE",
        "version": "1.0.0",
        "creator": "Pr0Fessor_SnApe",
        "profiles": {
            k: {"phases": len(v), "description": {
                "quick": "Fast recon — 2 min, best for first look",
                "standard": "Balanced scan — recommended for bug bounty",
                "deep": "Full arsenal — all engines, maximum coverage",
            }[k]} for k in SCAN_PROFILES
        },
        "default_login": {"username": "snape", "hint": "See README for default dev credentials"},
    }


@app.post("/api/quick-scan")
async def quick_scan(body: QuickScan, user: User = Depends(get_current_user)):
    """One-click scan: create, run, validate, report — returns summary."""
    import uuid
    from snapescape_api.engines.registry import run_full_pipeline

    scan_id = str(uuid.uuid4())
    scan = await orchestrator.create_scan(body.target)
    scan_id = scan["id"]
    scan["status"] = "running"

    result = await run_full_pipeline(body.target, scan_id, profile=body.profile)
    validated = await validator.validate_batch(result.get("findings", []))
    scan["assets"] = result.get("assets", [])
    scan["findings"] = validated
    scan["status"] = "complete"
    scan["progress"] = 100.0
    orchestrator._scans[scan_id] = scan

    paths = report_engine.generate(scan, validated, scan["assets"])
    top = sorted(validated, key=lambda x: x.get("confidence", 0), reverse=True)[:10]

    return {
        "scan_id": scan_id,
        "target": body.target,
        "profile": body.profile,
        "assets": len(scan["assets"]),
        "findings": len(validated),
        "raw_detections": len(result.get("findings", [])),
        "filtered_false_positives": len(result.get("findings", [])) - len(validated),
        "top_findings": top,
        "report_path": paths.get("html"),
        "reports": paths,
    }


# --- Scans ---

@app.post("/api/scans")
async def create_scan(body: ScanCreate, user: User = Depends(get_current_user)):
    return await orchestrator.create_scan(body.target, body.workspace_id)


@app.get("/api/scans")
async def list_scans(user: User = Depends(get_current_user)):
    return await orchestrator.list_scans()


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str, user: User = Depends(get_current_user)):
    try:
        return await orchestrator.get_scan(scan_id)
    except KeyError:
        raise HTTPException(404, "Scan not found")


@app.post("/api/scans/{scan_id}/start")
async def start_scan(scan_id: str, user: User = Depends(require_role("analyst"))):
    try:
        return await orchestrator.start_scan(scan_id)
    except KeyError:
        raise HTTPException(404, "Scan not found")


@app.post("/api/scans/{scan_id}/pause")
async def pause_scan(scan_id: str, user: User = Depends(require_role("analyst"))):
    try:
        return await orchestrator.pause_scan(scan_id)
    except KeyError:
        raise HTTPException(404)


@app.post("/api/scans/{scan_id}/resume")
async def resume_scan(scan_id: str, user: User = Depends(require_role("analyst"))):
    try:
        return await orchestrator.resume_scan(scan_id)
    except KeyError:
        raise HTTPException(404)


@app.post("/api/scans/{scan_id}/stop")
async def stop_scan(scan_id: str, user: User = Depends(require_role("analyst"))):
    try:
        return await orchestrator.stop_scan(scan_id)
    except KeyError:
        raise HTTPException(404)


@app.post("/api/scans/{scan_id}/schedule")
async def schedule_scan(scan_id: str, body: ScheduleScan, user: User = Depends(require_role("admin"))):
    try:
        return await orchestrator.schedule_scan(scan_id, body.cron)
    except KeyError:
        raise HTTPException(404)


@app.post("/api/scans/{scan_id}/report")
async def generate_report(scan_id: str, user: User = Depends(get_current_user)):
    try:
        scan = await orchestrator.get_scan(scan_id)
    except KeyError:
        raise HTTPException(404)
    findings = await ai_engine.prioritize(scan.get("findings", []))
    paths = report_engine.generate(scan, findings, scan.get("assets", []))
    return {"scan_id": scan_id, "reports": paths}


@app.get("/api/scans/{scan_id}/graph")
async def get_graph(scan_id: str, user: User = Depends(get_current_user)):
    try:
        scan = await orchestrator.get_scan(scan_id)
    except KeyError:
        raise HTTPException(404)
    return scan.get("graph") or graph_engine.build_from_scan(scan_id, scan.get("assets", []), scan.get("findings", []))


@app.get("/api/scans/{scan_id}/crawl-tree")
async def get_crawl_tree(scan_id: str, user: User = Depends(get_current_user)):
    try:
        scan = await orchestrator.get_scan(scan_id)
    except KeyError:
        raise HTTPException(404)
    return scan.get("crawl_tree", {})


@app.get("/api/scans/{scan_id}/evidence")
async def get_evidence(scan_id: str, user: User = Depends(get_current_user)):
    try:
        scan = await orchestrator.get_scan(scan_id)
    except KeyError:
        raise HTTPException(404)
    return scan.get("evidence", []) or [{"finding_id": f["id"], "data": f.get("evidence")} for f in scan.get("findings", [])]


# --- Workers ---

@app.get("/api/workers")
async def list_workers(user: User = Depends(get_current_user)):
    return orchestrator.list_workers()


@app.post("/api/workers/{worker_id}/kill")
async def kill_worker(worker_id: str, user: User = Depends(require_role("admin"))):
    return await orchestrator.kill_worker(worker_id)


@app.post("/api/workers/{worker_id}/restart")
async def restart_worker(worker_id: str, user: User = Depends(require_role("admin"))):
    return await orchestrator.restart_worker(worker_id)


# --- AI ---

@app.post("/api/ai/explain")
async def ai_explain(finding: dict[str, Any], user: User = Depends(get_current_user)):
    return await ai_engine.explain_vulnerability(finding)


@app.post("/api/ai/triage")
async def ai_triage(findings: list[dict[str, Any]], user: User = Depends(get_current_user)):
    return await ai_engine.prioritize(findings)


@app.post("/api/ai/mutate-payload")
async def ai_mutate(payload: str, vuln_type: str = "xss", user: User = Depends(require_role("analyst"))):
    return {"mutations": await ai_engine.mutate_payload(payload, vuln_type)}


@app.post("/api/ai/profile")
async def ai_profile(target: str, assets: list[dict] = [], user: User = Depends(get_current_user)):
    return await ai_engine.profile_target(target, assets)


# --- Validation ---

@app.post("/api/validate")
async def validate_finding(body: ValidateFinding, user: User = Depends(require_role("analyst"))):
    return await validator.validate_finding(body.finding)


# --- Replay ---

@app.post("/api/replay")
async def replay_request(body: ReplayRequest, user: User = Depends(require_role("analyst"))):
    async with httpx.AsyncClient(verify=False, timeout=15.0) as client:
        resp = await client.request(body.method, body.url, headers=body.headers, content=body.body)
        return {
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.text[:10000],
        }


# --- Vault ---

@app.get("/api/vault/providers")
async def vault_providers(user: User = Depends(require_role("admin"))):
    try:
        vault = get_vault()
        return {"providers": vault.list_providers(), "validation": vault.validate_providers()}
    except VaultError as e:
        raise HTTPException(500, str(e))


@app.post("/api/vault/keys")
async def vault_set_key(body: VaultKeySet, user: User = Depends(require_role("admin"))):
    try:
        get_vault().set_key(body.provider, body.key_name, body.value)
        return {"status": "ok", "provider": body.provider}
    except VaultError as e:
        raise HTTPException(500, str(e))


# --- Plugins ---

@app.get("/api/plugins")
async def list_plugins(user: User = Depends(get_current_user)):
    return {"plugins": plugin_sdk.list_plugins()}


@app.post("/api/plugins/{name}/run")
async def run_plugin(name: str, target: str, scan_id: str, user: User = Depends(require_role("analyst"))):
    return await plugin_sdk.execute(name, target, scan_id)


@app.get("/api/plugins/sdk-template")
async def plugin_template(user: User = Depends(get_current_user)):
    return {"template": plugin_sdk.get_sdk_template()}


# --- WebSocket ---

@app.websocket("/ws/telemetry")
async def ws_telemetry(websocket: WebSocket):
    await websocket.accept()
    ws_clients.append(websocket)
    try:
        await websocket.send_json({"event": "connected", "message": "SNAPESCAPE telemetry active"})
        while True:
            data = await websocket.receive_text()
            msg = json.loads(data)
            if msg.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in ws_clients:
            ws_clients.remove(websocket)


def main():
    import uvicorn
    uvicorn.run("snapescape_api.main:app", host="0.0.0.0", port=8000, reload=True)


if __name__ == "__main__":
    main()
