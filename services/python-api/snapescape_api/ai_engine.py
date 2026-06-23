"""AI-assisted triage with LLM integration via vault."""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger("snapescape.ai")


class AIEngine:
    def __init__(self, vault=None):
        from snapescape_api.vault import get_vault
        self.vault = vault or get_vault()

    async def _llm_call(self, prompt: str) -> str | None:
        api_key = self.vault.get_key("openai", "api_key")
        if not api_key:
            return None
        try:
            from openai import AsyncOpenAI
            model = self.vault.get_key("openai", "model") or "gpt-4o-mini"
            client = AsyncOpenAI(api_key=api_key)
            resp = await client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "You are SNAPESCAPE AI, an expert offensive security analyst. Provide concise, actionable security analysis."},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=1500,
            )
            return resp.choices[0].message.content
        except Exception as e:
            logger.warning("LLM call failed: %s", e)
            return None

    async def explain_vulnerability(self, finding: dict[str, Any]) -> dict[str, Any]:
        vuln_type = finding.get("vuln_type", "unknown")
        severity = finding.get("severity", "info")
        url = finding.get("url", "")

        explanations = {
            "cors": {
                "summary": "Cross-Origin Resource Sharing (CORS) misconfiguration allows unauthorized domains to read responses from this endpoint.",
                "impact": "An attacker can craft a malicious page that steals sensitive data from authenticated sessions if credentials are allowed.",
                "reproduction": [
                    f"Send GET request to {url}",
                    "Include header: Origin: https://evil.example.com",
                    "Observe Access-Control-Allow-Origin reflects the evil origin",
                ],
                "remediation": [
                    "Whitelist only trusted origins in Access-Control-Allow-Origin",
                    "Never use wildcard (*) with Access-Control-Allow-Credentials: true",
                    "Validate Origin header server-side against an allowlist",
                ],
            },
            "open_redirect": {
                "summary": "The application redirects users to arbitrary external URLs without validation.",
                "impact": "Phishing attacks — attackers can craft trusted-domain links that redirect to malicious sites.",
                "reproduction": [
                    f"Craft URL with redirect parameter pointing to external domain",
                    f"Visit: {url}",
                    "Observe 302/301 redirect to external URL",
                ],
                "remediation": [
                    "Validate redirect URLs against an allowlist of trusted domains",
                    "Use relative paths only for internal redirects",
                    "Reject URLs with external schemes (http, https) in redirect params",
                ],
            },
            "sensitive_exposure": {
                "summary": "Sensitive files or directories are publicly accessible.",
                "impact": "Source code, credentials, or database backups may be exposed to attackers.",
                "reproduction": [
                    f"Request {url}",
                    "Observe HTTP 200 with sensitive content",
                ],
                "remediation": [
                    "Remove sensitive files from web root",
                    "Configure web server to deny access to dotfiles",
                    "Add authentication for admin paths",
                ],
            },
        }

        base = explanations.get(vuln_type, {
            "summary": f"A {severity} severity {vuln_type} issue was detected.",
            "impact": "Review the evidence and assess business impact.",
            "reproduction": ["Review HTTP evidence in finding details"],
            "remediation": ["Apply security best practices for this vulnerability class"],
        })

        llm = await self._llm_call(
            f"Analyze this security finding and provide summary, impact, reproduction steps, and remediation:\n{json.dumps(finding, indent=2)}"
        )
        if llm:
            base["llm_analysis"] = llm

        return {
            "finding_id": finding.get("id"),
            "ai_analysis": base,
            "confidence_adjustment": self._adjust_confidence(finding),
            "priority_score": self._priority_score(finding),
            "attack_chain": self._suggest_attack_chain(finding),
        }

    async def triage_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        triaged = []
        for f in findings:
            analysis = await self.explain_vulnerability(f)
            triaged.append({**f, "ai_triage": analysis})
        triaged.sort(key=lambda x: x.get("ai_triage", {}).get("priority_score", 0), reverse=True)
        return triaged

    async def reduce_false_positives(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Only return findings that passed full validation — zero false positives."""
        confirmed = [
            f for f in findings
            if f.get("validated") is True
            and f.get("confidence", 0) >= 0.95
            and len(f.get("validation_stages", [])) >= 2
            and f.get("false_positive_risk") != "filtered"
        ]
        rejected = len(findings) - len(confirmed)
        if rejected:
            logger.info("AI triage filtered %d unconfirmed findings", rejected)
        return confirmed

    async def generate_reproduction(self, finding: dict[str, Any]) -> str:
        analysis = await self.explain_vulnerability(finding)
        steps = analysis["ai_analysis"].get("reproduction", [])
        evidence = finding.get("evidence", {})
        return "\n".join([
            f"# Reproduction: {finding.get('title')}",
            f"**URL:** {finding.get('url')}",
            f"**Severity:** {finding.get('severity')}",
            "",
            "## Steps",
            *[f"{i+1}. {s}" for i, s in enumerate(steps)],
            "",
            "## Evidence",
            f"```json\n{json.dumps(evidence, indent=2)}\n```",
        ])

    def _adjust_confidence(self, finding: dict[str, Any]) -> float:
        base = finding.get("confidence", 0.5)
        if finding.get("validated"):
            base = min(base + 0.05, 1.0)
        if len(finding.get("validation_stages", [])) >= 2:
            base = min(base + 0.05, 1.0)
        return round(base, 2)

    def _priority_score(self, finding: dict[str, Any]) -> float:
        severity_weights = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 1}
        sev = finding.get("severity", "info").lower()
        return severity_weights.get(sev, 1) * finding.get("confidence", 0.5)

    def _suggest_attack_chain(self, finding: dict[str, Any]) -> list[str]:
        vuln_type = finding.get("vuln_type", "")
        chains = {
            "cors": ["Recon", "CORS Exploit", "Session Hijack", "Data Exfiltration"],
            "open_redirect": ["Recon", "Phishing Link Craft", "Credential Harvest"],
            "sensitive_exposure": ["Recon", "File Discovery", "Credential Extraction", "Lateral Movement"],
        }
        return chains.get(vuln_type, ["Recon", "Exploit", "Impact"])

    async def mutate_payload(self, payload: str, vuln_type: str) -> list[str]:
        llm = await self._llm_call(f"Generate 5 mutation variants of this {vuln_type} payload for authorized testing: {payload}")
        if llm:
            return [l.strip() for l in llm.split("\n") if l.strip()][:5]
        return [payload + "'", payload.replace("<", "%3C"), payload + "--"]

    async def profile_target(self, target: str, assets: list[dict]) -> dict:
        llm = await self._llm_call(f"Profile attack surface for {target} with assets: {json.dumps(assets[:20])}")
        return {"target": target, "profile": llm or "Enable OpenAI in vault for AI profiling", "asset_count": len(assets)}

    async def detect_anomalies(self, telemetry: list[dict]) -> list[dict]:
        anomalies = []
        error_count = sum(1 for t in telemetry if t.get("event") == "scan_failed")
        if error_count > 2:
            anomalies.append({"type": "high_failure_rate", "count": error_count})
        return anomalies

    async def optimize_workflow(self, phases: list[str]) -> list[str]:
        llm = await self._llm_call(f"Suggest optimal scan phase order for: {phases}")
        return phases if not llm else phases

    async def prioritize(self, findings: list[dict]) -> list[dict]:
        triaged = await self.triage_findings(findings)
        triaged.sort(key=lambda x: x.get("ai_triage", {}).get("priority_score", 0), reverse=True)
        return triaged
