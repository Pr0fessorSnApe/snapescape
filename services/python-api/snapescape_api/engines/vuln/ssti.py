from snapescape_api.engines.base import BaseEngine, new_finding

SSTI_PAYLOADS = [
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("{{config}}", "config"),
    ("{{self}}", "self"),
]


class SstiEngine(BaseEngine):
    async def analyze(self, url: str, scan_id: str) -> list[dict]:
        findings = []
        for payload, expected in SSTI_PAYLOADS:
            test_url = url if "?" in url else f"{url}?name={payload}"
            if "?" in url:
                test_url = f"{url}&tpl={payload}"
            try:
                resp = await self.client.get(test_url)
                if expected in resp.text:
                    findings.append(new_finding(
                        scan_id, "Server-Side Template Injection", "critical", "ssti", test_url,
                        {"payload": payload, "expected": expected},
                        0.95, "CWE-1336", "A03:2021", "T1190",
                    ))
                    return findings
            except Exception:
                pass
        return findings
