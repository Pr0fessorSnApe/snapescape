from snapescape_api.engines.base import BaseEngine, new_finding

FUZZ_CHARS = ["'", '"', "<", ">", "../", "%00", "%0a", "{{", "${", ";", "|", "&"]


class FuzzEngine(BaseEngine):
    async def fuzz_url(self, url: str, scan_id: str) -> list[dict]:
        findings = []
        base = url if "?" in url else f"{url}?fuzz=1"
        for char in FUZZ_CHARS:
            test = base.replace("=1", f"={char}") if "=1" in base else f"{base}&f={char}"
            try:
                resp = await self.client.get(test)
                if resp.status_code >= 500:
                    findings.append(new_finding(
                        scan_id, "Server Error on Fuzz Input", "medium", "fuzzing", test,
                        {"payload": char, "status": resp.status_code},
                        0.86, "CWE-20", "A03:2021", "T1190",
                    ))
            except Exception:
                pass
        return findings
