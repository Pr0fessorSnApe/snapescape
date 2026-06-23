from snapescape_api.engines.base import BaseEngine, new_finding

BUCKET_PATTERNS = [
    "{target}", "{target}-backup", "{target}-dev", "{target}-staging",
    "{target}-prod", "{target}-assets", "{target}-media", "{target}-static",
    "{target}-files", "{target}-data", "{target}-logs",
]


class CloudBucketEngine(BaseEngine):
    async def discover(self, target: str, scan_id: str) -> list[dict]:
        findings = []
        base = target.replace(".", "-").split(":")[0]
        providers = [
            ("s3", "https://{name}.s3.amazonaws.com"),
            ("gcs", "https://storage.googleapis.com/{name}"),
            ("azure", "https://{name}.blob.core.windows.net"),
            ("digitalocean", "https://{name}.nyc3.digitaloceanspaces.com"),
        ]
        for pattern in BUCKET_PATTERNS:
            name = pattern.format(target=base)
            for provider, url_tpl in providers:
                url = url_tpl.format(name=name)
                try:
                    resp = await self.client.get(url)
                    if resp.status_code in (200, 403):
                        severity = "high" if resp.status_code == 200 else "medium"
                        findings.append(new_finding(
                            scan_id, f"Cloud Bucket Discovered ({provider.upper()})", severity,
                            "cloud_bucket", url,
                            {"provider": provider, "status": resp.status_code, "bucket": name},
                            0.93 if resp.status_code == 200 else 0.87,
                            "CWE-538", "A01:2021", "T1530",
                        ))
                except Exception:
                    pass
        return findings
