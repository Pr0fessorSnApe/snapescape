import re
import uuid
from bs4 import BeautifulSoup
from snapescape_api.engines.base import BaseEngine

class ParamMiner(BaseEngine):
    async def mine(self, url: str, scan_id: str) -> list[dict]:
        assets = []
        try:
            resp = await self.client.get(url, follow_redirects=True)
            soup = BeautifulSoup(resp.text, "lxml")
            params = set()
            for form in soup.find_all("form"):
                for inp in form.find_all(["input", "textarea", "select"]):
                    if inp.get("name"):
                        params.add(inp["name"])
            for m in re.finditer(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=', resp.text):
                params.add(m.group(1))
            for p in params:
                assets.append({
                    "id": str(uuid.uuid4()), "scan_id": scan_id,
                    "asset_type": "parameter", "value": p,
                    "metadata": {"source_url": url},
                })
        except Exception:
            pass
        return assets
