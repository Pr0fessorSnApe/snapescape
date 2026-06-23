from snapescape_api.engines.base import BaseEngine, new_finding

class CorsEngine(BaseEngine):
    async def analyze(self, url: str, scan_id: str) -> list[dict]:
        findings = []
        origin = "https://evil.snapescape-test.local"
        try:
            resp = await self.client.get(url, headers={"Origin": origin})
            acao = resp.headers.get("access-control-allow-origin", "")
            acac = resp.headers.get("access-control-allow-credentials", "")
            if acao in (origin, "*"):
                sev = "high" if acac.lower() == "true" else "medium"
                findings.append(new_finding(
                    scan_id, "CORS Misconfiguration", sev, "cors", url,
                    {"acao": acao, "acac": acac, "origin": origin},
                    0.95 if acac else 0.88, "CWE-942", "A05:2021", "T1189",
                ))
        except Exception:
            pass
        return findings
