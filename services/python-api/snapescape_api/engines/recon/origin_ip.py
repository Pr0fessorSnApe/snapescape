import socket
from snapescape_api.engines.base import BaseEngine, new_finding


class OriginIpEngine(BaseEngine):
    async def discover(self, target: str, scan_id: str) -> dict:
        assets, findings = [], []
        try:
            ips = socket.gethostbyname_ex(target)[2]
            for ip in ips:
                assets.append({
                    "asset_type": "ip", "value": ip, "scan_id": scan_id,
                    "metadata": {"source": "dns_resolution"},
                })
            # Historical DNS / direct IP bypass check
            for url in [f"https://{target}", f"http://{target}"]:
                resp = await self.client.get(url, headers={"Host": target})
                server = resp.headers.get("server", "")
                if ips and "cloudflare" not in server.lower():
                    findings.append(new_finding(
                        scan_id, "Potential Origin IP Exposure", "medium",
                        "origin_ip", url,
                        {"ips": ips, "server": server},
                        0.86, "CWE-200", "A05:2021", "T1590",
                    ))
        except Exception:
            pass
        return {"assets": assets, "findings": findings}
