from snapescape_api.engines.base import BaseEngine, new_finding

class SmugglingEngine(BaseEngine):
    async def analyze(self, url: str, scan_id: str) -> list[dict]:
        findings = []
        smuggle = (
            "POST / HTTP/1.1\r\nHost: {}\r\nContent-Length: 6\r\n"
            "Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
        )
        try:
            from urllib.parse import urlparse
            host = urlparse(url).netloc
            # Detect via differential response on conflicting headers
            resp = await self.client.post(
                url,
                headers={
                    "Transfer-Encoding": "chunked",
                    "Content-Length": "4",
                },
                content=b"test",
            )
            te = resp.headers.get("transfer-encoding", "")
            if resp.status_code in (400, 501, 502) and "chunk" in str(resp.text).lower():
                findings.append(new_finding(
                    scan_id, "HTTP Request Smuggling Indicator", "high", "request_smuggling", url,
                    {"status": resp.status_code, "te_header": te},
                    0.87, "CWE-444", "A05:2021", "T1190",
                ))
        except Exception:
            pass
        return findings
