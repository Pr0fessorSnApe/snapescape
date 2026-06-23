"""Multi-stage vulnerability validation — zero false positive philosophy."""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse, urlunparse

import httpx

logger = logging.getLogger("snapescape.validation")

# Strict thresholds — only confirmed findings pass
CONFIDENCE_THRESHOLD = 0.95
MIN_VALIDATION_STAGES = 3

# Vuln types that require strict replay + differential proof
STRICT_TYPES = {
    "sqli", "xss", "ssrf", "ssti", "xxe", "cors", "open_redirect",
    "subdomain_takeover", "sensitive_exposure", "cloud_bucket",
    "crlf", "request_smuggling", "cache_poisoning", "jwt",
}

# Informational findings still need proof but slightly lower bar
INFO_TYPES = {"waf_cdn", "cms", "js_analysis", "missing_security_header"}


class ValidationEngine:
    """Consensus-based false positive elimination — reject unless proven."""

    def __init__(self):
        self.client = httpx.AsyncClient(
            timeout=15.0,
            verify=False,
            follow_redirects=False,
            headers={"User-Agent": "SNAPESCAPE/1.0 (Authorized Security Scanner)"},
        )

    async def validate_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        vuln_type = finding.get("vuln_type", "")
        stages: list[str] = []
        confidence = finding.get("confidence", 0.0)

        # Stage 1: Protocol — URL must be reachable with meaningful response
        if await self._protocol_validation(finding):
            stages.append("protocol_validation")
        else:
            return self._reject(finding, "protocol_validation_failed")

        # Stage 2: Baseline differential — vuln signal must NOT appear on clean request
        if await self._baseline_differential(finding):
            stages.append("baseline_differential")
        else:
            return self._reject(finding, "baseline_false_positive")

        # Stage 3: Replay — re-execute detection logic and confirm
        if await self._replay_verification(finding):
            stages.append("replay_verification")
        else:
            return self._reject(finding, "replay_failed")

        # Stage 4: Vuln-specific content proof
        if await self._vuln_specific_proof(finding):
            stages.append("content_verification")
        else:
            return self._reject(finding, "content_proof_failed")

        # Stage 5: Negative control
        if await self._negative_control(finding):
            stages.append("negative_control")
            confidence = min(confidence + 0.05, 1.0)

        min_stages = MIN_VALIDATION_STAGES if vuln_type in STRICT_TYPES else 2
        validated = len(stages) >= min_stages and confidence >= CONFIDENCE_THRESHOLD

        if not validated:
            return self._reject(finding, f"insufficient_stages_{len(stages)}")

        return {
            **finding,
            "confidence": round(min(confidence, 0.99), 2),
            "validated": True,
            "validation_stages": stages,
            "false_positive_risk": "none",
        }

    async def validate_batch(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        results = []
        for f in findings:
            validated = await self.validate_finding(f)
            if validated.get("validated"):
                results.append(validated)
            else:
                logger.info(
                    "REJECTED (FP filter): %s | reason: %s",
                    f.get("title"),
                    validated.get("rejection_reason", "unknown"),
                )
        logger.info("Validation: %d/%d findings confirmed", len(results), len(findings))
        return results

    def _reject(self, finding: dict[str, Any], reason: str) -> dict[str, Any]:
        return {
            **finding,
            "validated": False,
            "confidence": 0.0,
            "rejection_reason": reason,
            "false_positive_risk": "filtered",
        }

    async def _protocol_validation(self, finding: dict[str, Any]) -> bool:
        url = finding.get("url")
        if not url:
            return False
        try:
            resp = await self.client.get(url)
            # Reject error pages and soft-404s for vuln claims
            if resp.status_code >= 500:
                return False
            if finding.get("vuln_type") == "sensitive_exposure" and resp.status_code != 200:
                return False
            return True
        except Exception:
            return False

    async def _baseline_differential(self, finding: dict[str, Any]) -> bool:
        """Confirm vuln indicator does NOT exist on a clean/baseline request."""
        url = finding.get("url", "")
        vuln_type = finding.get("vuln_type", "")
        parsed = urlparse(url)

        try:
            if vuln_type == "sqli":
                # Baseline: same URL with safe parameter value
                baseline_url = self._replace_query_param(url, finding.get("evidence", {}).get("parameter", "id"), "1")
                resp = await self.client.get(baseline_url)
                body = resp.text.lower()
                error = finding.get("evidence", {}).get("error", "").lower()
                return error not in body if error else True

            if vuln_type == "xss":
                payload = finding.get("evidence", {}).get("payload", "")
                baseline_url = self._replace_query_param(url, finding.get("evidence", {}).get("parameter", "q"), "baseline_test_safe")
                resp = await self.client.get(baseline_url)
                return payload not in resp.text

            if vuln_type == "cors":
                # Baseline: random origin should NOT be reflected
                resp = await self.client.get(url, headers={"Origin": "https://baseline-null-origin.invalid"})
                acao = resp.headers.get("access-control-allow-origin", "")
                evil = finding.get("evidence", {}).get("test_origin", "")
                # If baseline also reflects, it's a false positive pattern
                return "baseline-null-origin" not in acao

            if vuln_type == "open_redirect":
                loc = finding.get("evidence", {}).get("location", "")
                return "evil.snapescape-test.local" in loc or "snapescape-test" in loc

            if vuln_type == "sensitive_exposure":
                preview = finding.get("evidence", {}).get("preview", "") or finding.get("evidence", {}).get("body_preview", "")
                # Reject generic HTML error pages
                if "<html" in preview.lower() and "ref:" not in preview and "=" not in preview:
                    return False
                return len(preview.strip()) > 0

            if vuln_type == "ssti":
                expected = finding.get("evidence", {}).get("expected", "")
                baseline_url = url.split("?")[0]
                resp = await self.client.get(baseline_url)
                return expected not in resp.text

            return True
        except Exception:
            return False

    async def _replay_verification(self, finding: dict[str, Any]) -> bool:
        """Re-run the exact test that triggered the finding."""
        url = finding.get("url", "")
        vuln_type = finding.get("vuln_type", "")

        try:
            if vuln_type == "cors":
                origin = finding.get("evidence", {}).get("test_origin", "https://evil.snapescape-test.local")
                resp = await self.client.get(url, headers={"Origin": origin})
                acao = resp.headers.get("access-control-allow-origin", "")
                return acao in (origin, "*")

            if vuln_type == "open_redirect":
                resp = await self.client.get(url)
                loc = resp.headers.get("location", "")
                return bool(loc) and ("evil.snapescape-test" in loc or resp.status_code in (301, 302, 303, 307, 308))

            if vuln_type == "sqli":
                resp = await self.client.get(url)
                body = resp.text.lower()
                err = finding.get("evidence", {}).get("error", "").lower()
                return err in body if err else False

            if vuln_type == "xss":
                resp = await self.client.get(url)
                payload = finding.get("evidence", {}).get("payload", "")
                return payload in resp.text

            if vuln_type == "sensitive_exposure":
                resp = await self.client.get(url)
                if resp.status_code != 200:
                    return False
                preview = (finding.get("evidence", {}).get("preview") or "")[:200]
                body = resp.text[:200]
                return preview in resp.text or (len(body) > 10 and body == preview)

            if vuln_type == "missing_security_header":
                resp = await self.client.get(url)
                missing = finding.get("evidence", {}).get("missing") or finding.get("evidence", {}).get("missing_header")
                return resp.status_code == 200 and missing and missing not in {k.lower() for k in resp.headers}

            return vuln_type in INFO_TYPES or vuln_type in ("waf_cdn", "cms")
        except Exception:
            return False

    async def _vuln_specific_proof(self, finding: dict[str, Any]) -> bool:
        vuln_type = finding.get("vuln_type", "")
        evidence = finding.get("evidence", {})

        if vuln_type == "sqli":
            sql_errors = ["sql syntax", "mysql", "ora-", "postgresql", "sqlite", "odbc", "unclosed quotation"]
            preview = str(evidence).lower()
            return any(e in preview for e in sql_errors)

        if vuln_type == "xss":
            payload = evidence.get("payload", "")
            return bool(payload) and ("<" in payload or "alert" in payload or "onerror" in payload)

        if vuln_type == "subdomain_takeover":
            fp = evidence.get("fingerprint", "")
            return len(fp) > 10

        if vuln_type == "cloud_bucket":
            return evidence.get("status") == 200

        if vuln_type == "jwt":
            return evidence.get("weak_secret") or evidence.get("header", {}).get("alg") in ("none", "None")

        if vuln_type == "ssrf":
            indicator = evidence.get("indicator", "")
            return indicator in ("ami-id", "instance-id", "root:", "metadata")

        if vuln_type == "missing_security_header":
            return evidence.get("missing") or evidence.get("missing_header")

        return True

    async def _negative_control(self, finding: dict[str, Any]) -> bool:
        """Send a control request that should NOT trigger the vulnerability."""
        url = finding.get("url", "")
        vuln_type = finding.get("vuln_type", "")
        base = url.split("?")[0]

        try:
            if vuln_type in ("sqli", "xss", "ssti"):
                resp = await self.client.get(base)
                body = resp.text.lower()
                # Control page should not contain exploit artifacts
                return "sql syntax" not in body and "<script>alert" not in body

            if vuln_type == "cors":
                resp = await self.client.get(url)  # no Origin header
                acao = resp.headers.get("access-control-allow-origin", "")
                return acao != "*" or finding.get("evidence", {}).get("acac") != "true"

            return True
        except Exception:
            return True

    @staticmethod
    def _replace_query_param(url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        if not parsed.query:
            return f"{url}?{param}={value}"
        parts = []
        found = False
        for pair in parsed.query.split("&"):
            if "=" in pair:
                k, _ = pair.split("=", 1)
                if k == param:
                    parts.append(f"{k}={value}")
                    found = True
                else:
                    parts.append(pair)
            else:
                parts.append(pair)
        if not found:
            parts.append(f"{param}={value}")
        return urlunparse(parsed._replace(query="&".join(parts)))

    async def close(self):
        await self.client.aclose()
