import re
from snapescape_api.engines.base import BaseEngine, new_finding

SECRET_PATTERNS = [
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key", "critical"),
    (r'(?:api[_-]?key|apikey)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{16,}', "API Key", "high"),
    (r'-----BEGIN (?:RSA )?PRIVATE KEY-----', "Private Key", "critical"),
    (r'ghp_[A-Za-z0-9]{36}', "GitHub Token", "critical"),
    (r'xox[baprs]-[A-Za-z0-9\-]+', "Slack Token", "high"),
    (r'sk_live_[A-Za-z0-9]{24,}', "Stripe Live Key", "critical"),
]

XSS_SINKS = ["innerHTML", "document.write", "eval(", "setTimeout(", "setInterval(", "Function("]


class JsAnalyzer(BaseEngine):
    async def analyze(self, url: str, scan_id: str) -> list[dict]:
        findings = []
        try:
            resp = await self.client.get(url)
            scripts = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', resp.text)
            inline = re.findall(r'<script[^>]*>(.*?)</script>', resp.text, re.DOTALL)
            for code in inline:
                for sink in XSS_SINKS:
                    if sink in code:
                        findings.append(new_finding(
                            scan_id, f"DOM XSS Sink: {sink}", "medium", "xss", url,
                            {"sink": sink, "code_preview": code[:100]},
                            0.88, "CWE-79", "A03:2021", "T1189",
                        ))
            if scripts:
                findings.append(new_finding(
                    scan_id, "JavaScript Files Discovered", "info", "js_analysis", url,
                    {"scripts": scripts[:20]},
                    0.99, None, None, "T1590",
                ))
        except Exception:
            pass
        return findings


class SecretDetector(BaseEngine):
    async def detect(self, url: str, scan_id: str) -> list[dict]:
        findings = []
        try:
            resp = await self.client.get(url)
            for pattern, name, sev in SECRET_PATTERNS:
                matches = re.findall(pattern, resp.text, re.IGNORECASE)
                if matches:
                    findings.append(new_finding(
                        scan_id, f"Secret Detected: {name}", sev, "secret_exposure", url,
                        {"type": name, "count": len(matches), "preview": str(matches[0])[:20] + "..."},
                        0.94, "CWE-798", "A02:2021", "T1552",
                    ))
        except Exception:
            pass
        return findings
