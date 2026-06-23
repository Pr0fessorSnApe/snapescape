from snapescape_api.engines.base import BaseEngine, new_finding

WAF_SIGNATURES = {
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "incapsula": "Imperva",
    "sucuri": "Sucuri",
    "aws": "AWS WAF",
    "f5": "F5 BIG-IP",
    "barracuda": "Barracuda",
}

CDN_HEADERS = ["cf-ray", "x-cdn", "x-cache", "via", "x-served-by", "x-amz-cf-id"]


class WafCdnEngine(BaseEngine):
    async def analyze(self, url: str, scan_id: str) -> list[dict]:
        findings = []
        try:
            resp = await self.client.get(url)
            headers_str = str(resp.headers).lower()
            detected = []
            for sig, name in WAF_SIGNATURES.items():
                if sig in headers_str or sig in resp.text[:500].lower():
                    detected.append(name)
            for h in CDN_HEADERS:
                if h in resp.headers:
                    detected.append(f"CDN ({h})")
            if detected:
                findings.append(new_finding(
                    scan_id, "WAF/CDN Detected", "info", "waf_cdn", url,
                    {"detected": list(set(detected)), "headers": dict(resp.headers)},
                    0.99, None, None, "T1590",
                ))
        except Exception:
            pass
        return findings
