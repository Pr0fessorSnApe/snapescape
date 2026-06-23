"""SNAPESCAPE API tests."""

import pytest
from fastapi.testclient import TestClient
from snapescape_api.main import app

client = TestClient(app)


def _auth_headers() -> dict[str, str]:
    resp = client.post(
        "/api/auth/login",
        data={"username": "snape", "password": "snapescape"},
    )
    assert resp.status_code == 200, resp.text
    token = resp.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_health():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["service"] == "snapescape"


def test_create_scan():
    resp = client.post(
        "/api/scans",
        json={"target": "example.com"},
        headers=_auth_headers(),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["target"] == "example.com"
    assert "id" in data


def test_list_scans():
    resp = client.get("/api/scans", headers=_auth_headers())
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_scan_lifecycle():
    headers = _auth_headers()
    create = client.post("/api/scans", json={"target": "test.example.com"}, headers=headers).json()
    scan_id = create["id"]

    start = client.post(f"/api/scans/{scan_id}/start", headers=headers)
    assert start.status_code == 200
    assert start.json()["status"] == "running"

    pause = client.post(f"/api/scans/{scan_id}/pause", headers=headers)
    assert pause.status_code == 200
    assert pause.json()["status"] == "paused"

    resume = client.post(f"/api/scans/{scan_id}/resume", headers=headers)
    assert resume.status_code == 200

    stop = client.post(f"/api/scans/{scan_id}/stop", headers=headers)
    assert stop.status_code == 200
    assert stop.json()["status"] == "stopped"
