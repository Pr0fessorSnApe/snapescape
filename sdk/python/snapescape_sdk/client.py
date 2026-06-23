"""SNAPESCAPE Python SDK — Created By: Pr0Fessor_SnApe"""

from __future__ import annotations

import httpx
from typing import Any


class SnapescapeClient:
    def __init__(self, base_url: str = "http://localhost:8000", token: str | None = None):
        self.base_url = base_url.rstrip("/")
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(base_url=self.base_url, headers=headers, timeout=30.0)

    def login(self, username: str, password: str) -> str:
        resp = self._client.post("/api/auth/login", data={"username": username, "password": password})
        resp.raise_for_status()
        token = resp.json()["access_token"]
        self._client.headers["Authorization"] = f"Bearer {token}"
        return token

    def create_scan(self, target: str) -> dict[str, Any]:
        return self._client.post("/api/scans", json={"target": target}).json()

    def start_scan(self, scan_id: str) -> dict[str, Any]:
        return self._client.post(f"/api/scans/{scan_id}/start").json()

    def get_scan(self, scan_id: str) -> dict[str, Any]:
        return self._client.get(f"/api/scans/{scan_id}").json()

    def list_scans(self) -> list[dict]:
        return self._client.get("/api/scans").json()

    def generate_report(self, scan_id: str) -> dict[str, Any]:
        return self._client.post(f"/api/scans/{scan_id}/report").json()

    def explain_finding(self, finding: dict) -> dict[str, Any]:
        return self._client.post("/api/ai/explain", json=finding).json()

    def get_graph(self, scan_id: str) -> dict[str, Any]:
        return self._client.get(f"/api/scans/{scan_id}/graph").json()

    def replay_request(self, method: str, url: str, headers: dict | None = None) -> dict:
        return self._client.post("/api/replay", json={
            "method": method, "url": url, "headers": headers or {},
        }).json()

    def close(self):
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
