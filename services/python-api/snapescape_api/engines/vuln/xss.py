from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
from snapescape_api.engines.base import BaseEngine, new_finding

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "'-alert(1)-'",
    "<svg/onload=alert(1)>",
    "javascript:alert(1)",
]


class XssEngine(BaseEngine):
    async def analyze(self, url: str, scan_id: str) -> list[dict]:
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            return findings
        for param in list(params.keys())[:5]:
            for payload in XSS_PAYLOADS:
                test_params = {k: v[:] for k, v in params.items()}
                test_params[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                try:
                    resp = await self.client.get(test_url)
                    if payload in resp.text or payload.replace("'", "&#39;") in resp.text:
                        findings.append(new_finding(
                            scan_id, "Reflected XSS", "high", "xss", test_url,
                            {"parameter": param, "payload": payload},
                            0.91, "CWE-79", "A03:2021", "T1189",
                        ))
                        return findings
                except Exception:
                    pass
        return findings
