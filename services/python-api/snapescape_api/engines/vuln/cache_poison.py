from snapescape_api.engines.base import BaseEngine, new_finding
import uuid

class CachePoisonEngine(BaseEngine):
    async def analyze(self, url: str, scan_id: str) -> list[dict]:
        findings = []
        poison = f"snapescape-{uuid.uuid4().hex[:8]}"
        try:
            resp = await self.client.get(url, headers={"X-Forwarded-Host": poison, "X-Original-URL": "/cachetest"})
            cache_status = resp.headers.get("x-cache", resp.headers.get("cf-cache-status", ""))
            if poison in resp.text or "HIT" in cache_status.upper():
                findings.append(new_finding(
                    scan_id, "Web Cache Poisoning Indicator", "high", "cache_poisoning", url,
                    {"poison_key": poison, "cache_status": cache_status},
                    0.88, "CWE-349", "A05:2021", "T1190",
                ))
        except Exception:
            pass
        return findings
