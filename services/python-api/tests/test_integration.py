"""Integration tests for SNAPESCAPE full pipeline."""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from snapescape_api.main import app


@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        # Login
        resp = await c.post("/api/auth/login", data={"username": "snape", "password": "snapescape"})
        token = resp.json()["access_token"]
        c.headers["Authorization"] = f"Bearer {token}"
        yield c


@pytest.mark.asyncio
async def test_full_scan_lifecycle(client):
    create = await client.post("/api/scans", json={"target": "example.com"})
    assert create.status_code == 200
    scan_id = create.json()["id"]

    start = await client.post(f"/api/scans/{scan_id}/start")
    assert start.status_code == 200

    get = await client.get(f"/api/scans/{scan_id}")
    assert get.status_code == 200

    schedule = await client.post(f"/api/scans/{scan_id}/schedule", json={"cron": "0 */6 * * *"})
    assert schedule.status_code == 200


@pytest.mark.asyncio
async def test_ai_and_validation(client):
    finding = {
        "id": "test", "title": "Test", "severity": "high",
        "vuln_type": "cors", "url": "https://example.com", "confidence": 0.9,
        "evidence": {},
    }
    explain = await client.post("/api/ai/explain", json=finding)
    assert explain.status_code == 200

    validate = await client.post("/api/validate", json={"finding": finding})
    assert validate.status_code == 200


@pytest.mark.asyncio
async def test_workers_and_plugins(client):
    workers = await client.get("/api/workers")
    assert workers.status_code == 200

    plugins = await client.get("/api/plugins")
    assert plugins.status_code == 200

    template = await client.get("/api/plugins/sdk-template")
    assert template.status_code == 200
    assert "run(target" in template.json()["template"]


@pytest.mark.asyncio
async def test_replay(client):
    resp = await client.post("/api/replay", json={
        "method": "GET", "url": "https://example.com", "headers": {},
    })
    assert resp.status_code == 200
    assert "status" in resp.json()
