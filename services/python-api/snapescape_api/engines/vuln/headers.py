from snapescape_api.engines.base import BaseEngine, new_finding

REQUIRED = [
    ("strict-transport-security", "Missing HSTS", "medium"),
    ("x-content-type-options", "Missing X-Content-Type-Options", "low"),
    ("x-frame-options", "Missing X-Frame-Options", "low"),
    ("content-security-policy", "Missing CSP", "medium"),
    ("permissions-policy", "Missing Permissions-Policy", "low"),
]


class HeadersEngine(BaseEngine):
    async def analyze(self, url: str, scan_id: str) -> list[dict]:
        findings = []
        try:
            resp = await self.client.get(url)
            if resp.status_code != 200:
                return findings  # No header findings on error pages — prevents false positives
            for header, title, sev in REQUIRED:
                if header not in {k.lower() for k in resp.headers.keys()}:
                    findings.append(new_finding(
                        scan_id, title, sev, "missing_security_header", url,
                        {"missing": header},
                        0.90, "CWE-693", "A05:2021", "T1592",
                    ))
        except Exception:
            pass
        return findings
