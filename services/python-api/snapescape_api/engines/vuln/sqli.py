from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
from snapescape_api.engines.base import BaseEngine, new_finding

SQLI_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "1' AND '1'='1", "1 OR 1=1", "'; WAITFOR DELAY '0:0:3'--",
    "1' AND SLEEP(3)--", "') OR ('1'='1", "admin'--",
]
SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ORA-", "PostgreSQL", "SQLite3::",
    "unclosed quotation", "quoted string not properly terminated",
    "Microsoft OLE DB Provider", "ODBC SQL Server Driver", "syntax error",
    "Warning: pg_", "valid MySQL result", "com.mysql.jdbc",
]


class SqliEngine(BaseEngine):
    async def analyze(self, url: str, scan_id: str) -> list[dict]:
        findings = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if not params:
            params = {"id": ["1"], "q": ["test"]}
        for param in list(params.keys())[:5]:
            for payload in SQLI_PAYLOADS:
                test_params = {k: v[:] for k, v in params.items()}
                test_params[param] = [payload]
                new_qs = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_qs))
                try:
                    resp = await self.client.get(test_url)
                    body = resp.text.lower()
                    for err in SQLI_ERRORS:
                        if err.lower() in body:
                            findings.append(new_finding(
                                scan_id, "SQL Injection", "critical", "sqli", test_url,
                                {"parameter": param, "payload": payload, "error": err},
                                0.94, "CWE-89", "A03:2021", "T1190",
                            ))
                            return findings
                except Exception:
                    pass
        return findings
