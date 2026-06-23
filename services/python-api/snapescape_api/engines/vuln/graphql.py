from snapescape_api.engines.base import BaseEngine, new_finding

GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"]
INTROSPECTION = '{"query":"{ __schema { types { name fields { name } } } }"}'


class GraphqlEngine(BaseEngine):
    async def analyze(self, url: str, scan_id: str) -> list[dict]:
        findings = []
        from urllib.parse import urlparse
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        for path in GRAPHQL_PATHS:
            ep = base + path
            try:
                resp = await self.client.post(ep, content=INTROSPECTION, headers={"Content-Type": "application/json"})
                if "__schema" in resp.text or "types" in resp.text:
                    findings.append(new_finding(
                        scan_id, "GraphQL Introspection Enabled", "medium", "graphql", ep,
                        {"response_preview": resp.text[:300]},
                        0.94, "CWE-200", "A05:2021", "T1590",
                    ))
                # Batch query abuse
                batch = '[{"query":"{ __typename }"},{"query":"{ __typename }"}]'
                batch_resp = await self.client.post(ep, content=batch, headers={"Content-Type": "application/json"})
                if batch_resp.status_code == 200 and "data" in batch_resp.text:
                    findings.append(new_finding(
                        scan_id, "GraphQL Batch Queries Allowed", "low", "graphql", ep,
                        {}, 0.88, "CWE-770", "A05:2021", "T1499",
                    ))
            except Exception:
                pass
        return findings
