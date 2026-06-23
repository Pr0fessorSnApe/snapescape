from snapescape_api.engines.base import BaseEngine, new_finding

class RedirectEngine(BaseEngine):
    async def analyze(self, url: str, scan_id: str) -> list[dict]:
        findings = []
        params = ["url", "redirect", "next", "return", "returnUrl", "dest", "destination", "redir", "continue"]
        payload = "https://evil.snapescape-test.local"
        base = url.split("?")[0]
        for param in params:
            test = f"{base}?{param}={payload}"
            try:
                resp = await self.client.get(test)
                loc = resp.headers.get("location", "")
                if "evil.snapescape-test.local" in loc:
                    findings.append(new_finding(
                        scan_id, "Open Redirect", "medium", "open_redirect", test,
                        {"parameter": param, "location": loc},
                        0.91, "CWE-601", "A01:2021", "T1566",
                    ))
            except Exception:
                pass
        return findings
