"""Secret/sensitive data detector engine."""
import re
from typing import Dict, List


SECRET_PATTERNS: Dict[str, str] = {
    "aws_access_key":     r"AKIA[0-9A-Z]{16}",
    "aws_secret_key":     r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "github_token":       r"ghp_[0-9a-zA-Z]{36}",
    "generic_api_key":    r"(?i)(api[_-]?key|apikey).{0,10}['\"][0-9a-zA-Z\-_]{20,}['\"]",
    "private_key":        r"-----BEGIN (RSA |EC )?PRIVATE KEY-----",
    "bearer_token":       r"(?i)bearer\s+[a-zA-Z0-9\-_\.]{20,}",
    "basic_auth":         r"(?i)basic\s+[a-zA-Z0-9+/=]{20,}",
    "jwt_token":          r"eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
    "google_api_key":     r"AIza[0-9A-Za-z\-_]{35}",
    "slack_token":        r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
    "stripe_key":         r"(?:sk|pk)_(live|test)_[0-9a-zA-Z]{24,}",
    "password_in_url":    r"(?i)(https?://[^:]+:[^@]+@)",
}


class SecretDetector:
    def __init__(self):
        self.compiled = {
            name: re.compile(pattern)
            for name, pattern in SECRET_PATTERNS.items()
        }

    async def detect(self, content: str, url: str = "") -> List[Dict]:
        findings = []
        for secret_type, pattern in self.compiled.items():
            matches = pattern.findall(content)
            for match in matches:
                findings.append({
                    "type":       secret_type,
                    "match":      match if len(str(match)) < 100 else str(match)[:100] + "...",
                    "url":        url,
                    "severity":   "high",
                })
        return findings

    async def scan_response(self, response_text: str, url: str = "") -> List[Dict]:
        return await self.detect(response_text, url)
