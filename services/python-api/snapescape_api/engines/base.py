"""Base engine utilities."""

from __future__ import annotations

import re
import uuid
from typing import Any

import httpx

USER_AGENT = "SNAPESCAPE/1.0 (Authorized Security Scanner)"


def new_finding(
    scan_id: str,
    title: str,
    severity: str,
    vuln_type: str,
    url: str,
    evidence: dict[str, Any],
    confidence: float = 0.9,
    cwe: str | None = None,
    owasp: str | None = None,
    mitre: str | None = None,
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "scan_id": scan_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "vuln_type": vuln_type,
        "url": url,
        "evidence": evidence,
        "cwe": cwe,
        "owasp": owasp,
        "mitre_attack": mitre,
        "validated": False,
        "validation_stages": [],
    }


class BaseEngine:
    def __init__(self):
        self.client = httpx.AsyncClient(
            timeout=15.0,
            verify=False,
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT},
        )

    async def close(self):
        await self.client.aclose()

    @staticmethod
    def extract_params(url: str) -> list[str]:
        if "?" not in url:
            return []
        qs = url.split("?", 1)[1]
        return [p.split("=")[0] for p in qs.split("&") if "=" in p]
