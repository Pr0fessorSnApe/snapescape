import uuid
from snapescape_api.engines.base import BaseEngine

WORDLIST = [
    "admin", "api", "backup", "config", "debug", "dev", "test", "staging",
    "login", "dashboard", "uploads", "files", "data", "internal", "private",
    "swagger", "graphql", "v1", "v2", "docs", "console", "actuator", "health",
    ".git", ".env", "robots.txt", "sitemap.xml", "crossdomain.xml",
]


class ContentDiscoveryEngine(BaseEngine):
    async def discover(self, url: str, scan_id: str) -> dict:
        assets, urls = [], []
        base = url.rstrip("/")
        for word in WORDLIST:
            path = word if word.startswith(".") else f"/{word}"
            ep = base + path
            try:
                resp = await self.client.get(ep)
                if resp.status_code in (200, 301, 302, 403):
                    assets.append({
                        "id": str(uuid.uuid4()), "scan_id": scan_id,
                        "asset_type": "endpoint", "value": ep,
                        "metadata": {"status": resp.status_code, "length": len(resp.text)},
                    })
                    if resp.status_code == 200:
                        urls.append(ep)
            except Exception:
                pass
        return {"assets": assets, "urls": urls}
