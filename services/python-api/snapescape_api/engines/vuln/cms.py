from snapescape_api.engines.base import BaseEngine, new_finding

CMS_SIGNATURES = {
    "wp-content": ("WordPress", ["/wp-login.php", "/wp-json/wp/v2/users", "/xmlrpc.php"]),
    "/drupal": ("Drupal", ["/user/login", "/CHANGELOG.txt"]),
    "Joomla": ("Joomla", ["/administrator/", "/README.txt"]),
    "Magento": ("Magento", ["/admin", "/magento_version"]),
}


class CmsEngine(BaseEngine):
    async def analyze(self, url: str, scan_id: str) -> list[dict]:
        findings = []
        try:
            resp = await self.client.get(url)
            body = resp.text
            from urllib.parse import urlparse
            base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            for sig, (cms, paths) in CMS_SIGNATURES.items():
                if sig.lower() in body.lower():
                    findings.append(new_finding(
                        scan_id, f"{cms} Detected", "info", "cms", url,
                        {"cms": cms, "signature": sig},
                        0.99, None, None, "T1590",
                    ))
                    for path in paths:
                        ep = base + path
                        r = await self.client.get(ep)
                        if r.status_code == 200:
                            sev = "medium" if "login" in path or "admin" in path else "low"
                            findings.append(new_finding(
                                scan_id, f"{cms} Endpoint Exposed: {path}", sev, "cms", ep,
                                {"status": r.status_code},
                                0.91, "CWE-200", "A05:2021", "T1590",
                            ))
        except Exception:
            pass
        return findings
