"""Attack surface graph engine using NetworkX."""

from __future__ import annotations

import json
from typing import Any

import networkx as nx


class GraphEngine:
    def __init__(self):
        self.graph = nx.DiGraph()

    def build_from_scan(self, scan_id: str, assets: list[dict], findings: list[dict]) -> dict:
        self.graph.clear()
        root = f"scan:{scan_id}"
        self.graph.add_node(root, type="scan", label=scan_id)

        for asset in assets:
            node_id = f"{asset.get('asset_type')}:{asset.get('value')}"
            self.graph.add_node(node_id, **asset)
            parent = asset.get("parent") or asset.get("metadata", {}).get("source_url")
            if parent:
                self.graph.add_edge(parent, node_id, relation="discovered_from")
            else:
                self.graph.add_edge(root, node_id, relation="root_asset")

        for finding in findings:
            fid = f"finding:{finding.get('id')}"
            self.graph.add_node(fid, **finding, type="finding")
            url = finding.get("url", "")
            self.graph.add_edge(url, fid, relation="vulnerable")

        return self.export()

    def export(self) -> dict[str, Any]:
        nodes = [{"id": n, **self.graph.nodes[n]} for n in self.graph.nodes]
        edges = [{"source": u, "target": v, **d} for u, v, d in self.graph.edges(data=True)]
        return {
            "nodes": nodes,
            "edges": edges,
            "stats": {
                "node_count": self.graph.number_of_nodes(),
                "edge_count": self.graph.number_of_edges(),
                "density": nx.density(self.graph) if self.graph.nodes else 0,
            },
        }

    def attack_paths(self, target_node: str) -> list[list[str]]:
        paths = []
        for node in self.graph.nodes:
            if self.graph.nodes[node].get("type") == "finding":
                try:
                    for path in nx.all_simple_paths(self.graph, target_node, node, cutoff=5):
                        paths.append(path)
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    pass
        return paths[:20]

    def to_json(self) -> str:
        return json.dumps(self.export())
