"""
shadow313.v4.core.intelligence_graph
──────────────────────────────────────
IntelligenceGraph v4 — cyber threat knowledge graph.

Nodes: ThreatActor, Campaign, Malware, Infrastructure, Vulnerability, Indicator
Edges: uses, targets, exploits, communicates_with, attributed_to, related_to

Provides:
  - Graph construction from STIX bundles and threat intel feeds
  - ATT&CK technique mapping
  - Actor attribution scoring
  - Lateral movement path analysis
  - Export to STIX 2.1 bundle
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Node types ────────────────────────────────────────────────────────────────

@dataclass
class GraphNode:
    """Base class for all intelligence graph nodes."""
    node_id:    str
    node_type:  str
    name:       str
    properties: dict = field(default_factory=dict)
    created_at: str  = field(default_factory=_now_iso)
    confidence: float = 1.0   # 0.0–1.0

    def to_dict(self) -> dict:
        return {
            "node_id":    self.node_id,
            "node_type":  self.node_type,
            "name":       self.name,
            "properties": self.properties,
            "created_at": self.created_at,
            "confidence": self.confidence,
        }


@dataclass
class GraphEdge:
    """Directed edge between two nodes."""
    edge_id:    str
    src_id:     str
    dst_id:     str
    relation:   str   # uses | targets | exploits | communicates_with | attributed_to
    properties: dict  = field(default_factory=dict)
    confidence: float = 1.0
    created_at: str   = field(default_factory=_now_iso)

    def to_dict(self) -> dict:
        return {
            "edge_id":    self.edge_id,
            "src_id":     self.src_id,
            "dst_id":     self.dst_id,
            "relation":   self.relation,
            "properties": self.properties,
            "confidence": self.confidence,
            "created_at": self.created_at,
        }


# ── Intelligence Graph ────────────────────────────────────────────────────────

class IntelligenceGraph:
    """
    Cyber threat knowledge graph for Shadow313 NEXUS v4.

    Stores threat actors, campaigns, malware, infrastructure,
    vulnerabilities, and indicators as a directed graph.
    """

    def __init__(self, graph_path=None) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: dict[str, GraphEdge] = {}
        self._adjacency: dict[str, list[str]] = {}  # node_id → [edge_ids]

    # ── Node operations ───────────────────────────────────────────────────────

    def add_node(
        self,
        node_type: str,
        name: str,
        properties: Optional[dict] = None,
        confidence: float = 1.0,
        node_id: Optional[str] = None,
    ) -> GraphNode:
        """Add a node to the graph."""
        if node_id is None:
            node_id = hashlib.sha3_256(f"{node_type}:{name}".encode()).hexdigest()[:16]
        node = GraphNode(
            node_id    = node_id,
            node_type  = node_type,
            name       = name,
            properties = properties or {},
            confidence = confidence,
        )
        self._nodes[node_id] = node
        return node

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        return self._nodes.get(node_id)

    def find_nodes(self, node_type: str = "", name_contains: str = "") -> list[GraphNode]:
        """Find nodes by type or name substring."""
        results = list(self._nodes.values())
        if node_type:
            results = [n for n in results if n.node_type == node_type]
        if name_contains:
            results = [n for n in results if name_contains.lower() in n.name.lower()]
        return results

    # ── Edge operations ───────────────────────────────────────────────────────

    def add_edge(
        self,
        src_id: str,
        dst_id: str,
        relation: str,
        properties: Optional[dict] = None,
        confidence: float = 1.0,
    ) -> Optional[GraphEdge]:
        """Add a directed edge between two nodes."""
        if src_id not in self._nodes or dst_id not in self._nodes:
            return None
        edge_id = hashlib.sha3_256(f"{src_id}:{relation}:{dst_id}".encode()).hexdigest()[:16]
        edge = GraphEdge(
            edge_id    = edge_id,
            src_id     = src_id,
            dst_id     = dst_id,
            relation   = relation,
            properties = properties or {},
            confidence = confidence,
        )
        self._edges[edge_id] = edge
        self._adjacency.setdefault(src_id, []).append(edge_id)
        return edge

    def get_neighbors(self, node_id: str, relation: str = "") -> list[GraphNode]:
        """Get all nodes reachable from node_id via outgoing edges."""
        edge_ids = self._adjacency.get(node_id, [])
        neighbors = []
        for eid in edge_ids:
            edge = self._edges.get(eid)
            if edge and (not relation or edge.relation == relation):
                dst = self._nodes.get(edge.dst_id)
                if dst:
                    neighbors.append(dst)
        return neighbors

    # ── ATT&CK mapping ────────────────────────────────────────────────────────

    def map_technique(self, actor_name: str, technique_id: str, confidence: float = 0.8) -> bool:
        """Map a MITRE ATT&CK technique to a threat actor."""
        actors = self.find_nodes(node_type="ThreatActor", name_contains=actor_name)
        if not actors:
            return False
        actor = actors[0]
        tech_node = self.add_node(
            node_type  = "Technique",
            name       = technique_id,
            properties = {"mitre_id": technique_id},
            confidence = confidence,
        )
        self.add_edge(actor.node_id, tech_node.node_id, "uses", confidence=confidence)
        return True

    # ── Attribution scoring ───────────────────────────────────────────────────

    def attribution_score(self, indicator_id: str) -> list[dict]:
        """
        Score threat actor attribution for a given indicator.
        Returns actors sorted by attribution confidence.
        """
        indicator = self._nodes.get(indicator_id)
        if not indicator:
            return []

        scores = []
        for node in self.find_nodes(node_type="ThreatActor"):
            # Count shared edges between actor and indicator's neighbors
            actor_neighbors = set(n.node_id for n in self.get_neighbors(node.node_id))
            indicator_neighbors = set(n.node_id for n in self.get_neighbors(indicator_id))
            overlap = len(actor_neighbors & indicator_neighbors)
            if overlap > 0:
                score = min(1.0, overlap * 0.25 * node.confidence)
                scores.append({"actor": node.name, "score": round(score, 3), "overlap": overlap})

        return sorted(scores, key=lambda x: -x["score"])

    # ── Graph statistics ──────────────────────────────────────────────────────

    def stats(self) -> dict:
        """Return graph statistics."""
        type_counts: dict[str, int] = {}
        for node in self._nodes.values():
            type_counts[node.node_type] = type_counts.get(node.node_type, 0) + 1

        relation_counts: dict[str, int] = {}
        for edge in self._edges.values():
            relation_counts[edge.relation] = relation_counts.get(edge.relation, 0) + 1

        return {
            "total_nodes":    len(self._nodes),
            "total_edges":    len(self._edges),
            "node_types":     type_counts,
            "relation_types": relation_counts,
        }

    # ── STIX export ───────────────────────────────────────────────────────────

    def to_stix_bundle(self) -> dict:
        """Export graph as a STIX 2.1 bundle."""
        objects = []
        for node in self._nodes.values():
            stix_type = {
                "ThreatActor":    "threat-actor",
                "Malware":        "malware",
                "Campaign":       "campaign",
                "Vulnerability":  "vulnerability",
                "Indicator":      "indicator",
                "Infrastructure": "infrastructure",
                "Technique":      "attack-pattern",
            }.get(node.node_type, "observed-data")

            objects.append({
                "type":       stix_type,
                "id":         f"{stix_type}--{node.node_id}",
                "name":       node.name,
                "created":    node.created_at,
                "modified":   node.created_at,
                "confidence": int(node.confidence * 100),
                **node.properties,
            })

        for edge in self._edges.values():
            objects.append({
                "type":             "relationship",
                "id":               f"relationship--{edge.edge_id}",
                "relationship_type": edge.relation,
                "source_ref":       f"unknown--{edge.src_id}",
                "target_ref":       f"unknown--{edge.dst_id}",
                "created":          edge.created_at,
                "modified":         edge.created_at,
                "confidence":       int(edge.confidence * 100),
            })

        return {
            "type":         "bundle",
            "id":           f"bundle--{hashlib.sha3_256(str(len(objects)).encode()).hexdigest()[:16]}",
            "spec_version": "2.1",
            "objects":      objects,
        }