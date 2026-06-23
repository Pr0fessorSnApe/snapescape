import base64
import json
import hmac
import hashlib
from snapescape_api.engines.base import BaseEngine, new_finding


class JwtAnalyzer(BaseEngine):
    async def analyze(self, url: str, scan_id: str) -> list[dict]:
        findings = []
        try:
            resp = await self.client.get(url)
            cookies = resp.headers.get("set-cookie", "")
            tokens = []
            for part in cookies.split(";"):
                if "eyJ" in part:
                    tokens.append(part.split("=")[-1].strip())
            # Also check Authorization patterns in page
            if "eyJ" in resp.text:
                import re
                tokens.extend(re.findall(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', resp.text))

            for token in set(tokens):
                findings.extend(self._analyze_token(token, url, scan_id))
        except Exception:
            pass
        return findings

    def _analyze_token(self, token: str, url: str, scan_id: str) -> list[dict]:
        findings = []
        parts = token.split(".")
        if len(parts) != 3:
            return findings
        try:
            header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        except Exception:
            return findings

        if header.get("alg") == "none" or header.get("alg") == "None":
            findings.append(new_finding(
                scan_id, "JWT Algorithm None", "critical", "jwt", url,
                {"header": header, "token_preview": token[:50]},
                0.97, "CWE-347", "A02:2021", "T1550",
            ))

        for weak in ["secret", "password", "123456", "jwt", "key"]:
            try:
                sig = base64.urlsafe_b64encode(
                    hmac.new(weak.encode(), f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256).digest()
                ).decode().rstrip("=")
                if sig == parts[2]:
                    findings.append(new_finding(
                        scan_id, "JWT Weak Secret", "critical", "jwt", url,
                        {"weak_secret": weak},
                        0.96, "CWE-521", "A02:2021", "T1550",
                    ))
            except Exception:
                pass

        if "admin" in str(payload).lower() or payload.get("role") == "admin":
            findings.append(new_finding(
                scan_id, "JWT Sensitive Claims Exposed", "medium", "jwt", url,
                {"payload": payload},
                0.90, "CWE-200", "A01:2021", "T1552",
            ))
        return findings
