from snapescape_api.engines.base import BaseEngine, new_finding

PATHS = [
    ("/.git/HEAD", "Git Repository Exposed", "high", lambda b: b.startswith("ref:")),
    ("/.env", "Environment File Exposed", "critical", lambda b: "=" in b and "<html" not in b.lower()),
    ("/.svn/entries", "SVN Repository Exposed", "high", lambda b: len(b) > 0),
    ("/backup.sql", "Database Backup", "critical", lambda b: "CREATE" in b.upper() or "INSERT" in b.upper()),
    ("/config.php.bak", "Config Backup", "high", lambda b: "php" in b.lower() or "<?" in b),
    ("/.DS_Store", "DS_Store Exposed", "low", lambda b: len(b) > 0),
]


class ExposureEngine(BaseEngine):
    async def analyze(self, url: str, scan_id: str) -> list[dict]:
        findings = []
        base = url.split("?")[0].rstrip("/")
        for path, title, sev, validator in PATHS:
            ep = base + path
            try:
                resp = await self.client.get(ep)
                if resp.status_code == 200 and validator(resp.text):
                    findings.append(new_finding(
                        scan_id, title, sev, "sensitive_exposure", ep,
                        {"preview": resp.text[:200], "status": resp.status_code},
                        0.93, "CWE-538", "A01:2021", "T1530",
                    ))
            except Exception:
                pass
        return findings
