from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
from snapescape_api.engines.base import BaseEngine, new_finding

SSRF_PARAMS = ["url", "uri", "path", "dest", "redirect", "next", "data", "reference", "site", "html", "feed"]
SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:80/",
    "http://[::1]/",
    "http://localhost/",
]


class SsrfEngine(BaseEngine):
    async def analyze(self, url: str, scan_id: str) -> list[dict]:
        findings = []
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = parse_qs(parsed.query)
        test_params = list(params.keys()) if params else SSRF_PARAMS
        for param in test_params[:8]:
            for payload in SSRF_PAYLOADS:
                test_url = f"{base}?{urlencode({param: payload})}"
                try:
                    resp = await self.client.get(test_url, timeout=8.0)
                    body = resp.text[:3000]
                    indicators = ["ami-id", "instance-id", "root:", "localhost", "metadata"]
                    for ind in indicators:
                        if ind in body.lower():
                            findings.append(new_finding(
                                scan_id, "Server-Side Request Forgery", "critical", "ssrf", test_url,
                                {"parameter": param, "payload": payload, "indicator": ind},
                                0.93, "CWE-918", "A10:2021", "T1190",
                            ))
                            return findings
                except Exception:
                    pass
        return findings
