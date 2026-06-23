import json
import uuid
from snapescape_api.engines.base import BaseEngine

class PassiveReconEngine(BaseEngine):
    async def scan(self, target: str) -> dict:
        assets = []
        # Certificate Transparency via crt.sh
        try:
            url = f"https://crt.sh/?q=%.{target}&output=json"
            resp = await self.client.get(url, timeout=30.0)
            if resp.status_code == 200:
                entries = resp.json()
                seen = set()
                for entry in entries[:200]:
                    nv = entry.get("name_value", "")
                    for name in nv.split("\n"):
                        name = name.strip().lower()
                        if name.endswith(target) and "*" not in name and name not in seen:
                            seen.add(name)
                            assets.append({
                                "id": str(uuid.uuid4()),
                                "asset_type": "subdomain",
                                "value": name,
                                "metadata": {"source": "crt.sh"},
                            })
        except Exception:
            pass
        return {"assets": assets}
