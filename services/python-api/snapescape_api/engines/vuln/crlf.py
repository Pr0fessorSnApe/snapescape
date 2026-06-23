from snapescape_api.engines.base import BaseEngine, new_finding

class CrlfEngine(BaseEngine):
    async def analyze(self, url: str, scan_id: str) -> list[dict]:
        findings = []
        payloads = ["%0d%0aSet-Cookie:crlf=injection", "%0aX-Injected: snapescape"]
        for payload in payloads:
            test = f"{url}{'&' if '?' in url else '?'}{payload}"
            try:
                resp = await self.client.get(test)
                if "crlf=injection" in str(resp.headers) or "X-Injected" in str(resp.headers):
                    findings.append(new_finding(
                        scan_id, "CRLF Injection", "high", "crlf", test,
                        {"payload": payload, "headers": dict(resp.headers)},
                        0.92, "CWE-93", "A03:2021", "T1190",
                    ))
            except Exception:
                pass
        return findings
