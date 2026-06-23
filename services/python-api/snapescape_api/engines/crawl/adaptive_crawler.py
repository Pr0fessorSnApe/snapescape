import uuid
from collections import deque
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from snapescape_api.engines.base import BaseEngine

class AdaptiveCrawler(BaseEngine):
    MAX_DEPTH = 3
    MAX_PAGES = 50

    async def crawl(self, start_url: str, scan_id: str) -> dict:
        visited = set()
        queue = deque([(start_url, 0)])
        urls, assets, tree = [], {}, {}

        while queue and len(visited) < self.MAX_PAGES:
            url, depth = queue.popleft()
            if url in visited or depth > self.MAX_DEPTH:
                continue
            visited.add(url)
            urls.append(url)
            tree[url] = {"depth": depth, "children": []}

            try:
                resp = await self.client.get(url, follow_redirects=True)
                soup = BeautifulSoup(resp.text, "lxml")
                links = []
                for a in soup.find_all("a", href=True):
                    href = urljoin(url, a["href"])
                    if urlparse(href).netloc == urlparse(start_url).netloc:
                        links.append(href)
                        if href not in visited:
                            queue.append((href, depth + 1))
                            tree[url]["children"].append(href)
                assets.append({
                    "id": str(uuid.uuid4()), "scan_id": scan_id,
                    "asset_type": "url", "value": url,
                    "metadata": {"status": resp.status_code, "links": len(links), "depth": depth},
                })
            except Exception:
                pass
        return {"urls": urls, "assets": assets, "tree": tree}
