"""
shadow313.core.intelligence_graph
───────────────────────────────────
IntelligenceGraph v3 — threat intelligence graph for Shadow313 core.

Lightweight version used by the v3 kernel and CLI.
Wraps the v4 IntelligenceGraph with v3-compatible API.
"""
from __future__ import annotations

from shadow313.v4.core.intelligence_graph import (
    IntelligenceGraph as _IntelligenceGraphV4,
    GraphNode,
    GraphEdge,
)


class IntelligenceGraph(_IntelligenceGraphV4):
    """
    Shadow313 v3 IntelligenceGraph.
    Extends v4 IntelligenceGraph with v3-compatible methods.
    """

    def add_actor(self, name: str, nation: str = "", aliases: list = None) -> GraphNode:
        """Add a threat actor node (v3 API)."""
        return self.add_node(
            node_type  = "ThreatActor",
            name       = name,
            properties = {"nation": nation, "aliases": aliases or []},
        )

    def add_indicator(self, ioc_type: str, value: str, confidence: float = 0.8) -> GraphNode:
        """Add an IOC indicator node (v3 API)."""
        return self.add_node(
            node_type  = "Indicator",
            name       = value,
            properties = {"ioc_type": ioc_type, "value": value},
            confidence = confidence,
        )

    def link(self, src_name: str, relation: str, dst_name: str) -> bool:
        """Link two nodes by name (v3 API)."""
        src_nodes = self.find_nodes(name_contains=src_name)
        dst_nodes = self.find_nodes(name_contains=dst_name)
        if not src_nodes or not dst_nodes:
            return False
        edge = self.add_edge(src_nodes[0].node_id, dst_nodes[0].node_id, relation)
        return edge is not None

    def get_actor_indicators(self, actor_name: str) -> list[GraphNode]:
        """Get all indicators associated with a threat actor (v3 API)."""
        actors = self.find_nodes(node_type="ThreatActor", name_contains=actor_name)
        if not actors:
            return []
        return self.get_neighbors(actors[0].node_id)