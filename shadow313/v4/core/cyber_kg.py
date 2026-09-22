"""
shadow313.v4.core.cyber_kg
────────────────────────────
Cyber Knowledge Graph — semantic layer over IntelligenceGraph.

Provides higher-level queries:
  - "Which APT groups target financial sector?"
  - "What TTPs does APT29 use?"
  - "Which CVEs are actively exploited by known actors?"
  - "What is the lateral movement path from WS-07 to DC-01?"

Wraps IntelligenceGraph with domain-specific query methods
and ATT&CK Navigator integration.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .intelligence_graph import IntelligenceGraph, GraphNode


@dataclass
class KGQueryResult:
    """Result of a knowledge graph query."""
    query:      str
    results:    list[dict]
    confidence: float
    sources:    list[str] = field(default_factory=list)
    reasoning:  str = ""


class CyberKG:
    """
    Cyber Knowledge Graph — semantic query layer.

    Wraps IntelligenceGraph with domain-specific methods for
    threat intelligence analysis and ATT&CK mapping.
    """

    def __init__(self, graph: Optional[IntelligenceGraph] = None) -> None:
        self.graph = graph or IntelligenceGraph()
        self._seed_default_knowledge()

    def _seed_default_knowledge(self) -> None:
        """Seed the graph with known APT groups and their TTPs."""
        # APT29 — Cozy Bear
        apt29 = self.graph.add_node("ThreatActor", "APT29",
            properties={"aliases": ["Cozy Bear", "The Dukes"], "nation": "Russia",
                        "sector_targets": ["government", "defense", "healthcare"]})
        # APT41 — Double Dragon
        apt41 = self.graph.add_node("ThreatActor", "APT41",
            properties={"aliases": ["Double Dragon", "Winnti"], "nation": "China",
                        "sector_targets": ["technology", "healthcare", "gaming"]})
        # FIN7 — Carbanak
        fin7 = self.graph.add_node("ThreatActor", "FIN7",
            properties={"aliases": ["Carbanak", "Navigator Group"], "nation": "Unknown",
                        "sector_targets": ["financial", "retail", "hospitality"]})
        # Lazarus Group
        lazarus = self.graph.add_node("ThreatActor", "Lazarus Group",
            properties={"aliases": ["Hidden Cobra", "ZINC"], "nation": "North Korea",
                        "sector_targets": ["financial", "cryptocurrency", "defense"]})

        # Common TTPs
        for actor_node, techniques in [
            (apt29,   ["T1059.001", "T1055", "T1078", "T1021.002"]),
            (apt41,   ["T1190", "T1059.004", "T1055.009", "T1014"]),
            (fin7,    ["T1566.001", "T1059.005", "T1547.001", "T1071.001"]),
            (lazarus, ["T1059.001", "T1095", "T1620", "T1041"]),
        ]:
            for ttp in techniques:
                tech = self.graph.add_node("Technique", ttp,
                    properties={"mitre_id": ttp})
                self.graph.add_edge(actor_node.node_id, tech.node_id, "uses")

    def query_actor_ttps(self, actor_name: str) -> KGQueryResult:
        """Get all TTPs used by a threat actor."""
        actors = self.graph.find_nodes(node_type="ThreatActor", name_contains=actor_name)
        if not actors:
            return KGQueryResult(
                query=f"TTPs for {actor_name}", results=[], confidence=0.0,
                reasoning=f"Actor '{actor_name}' not found in knowledge graph",
            )
        actor = actors[0]
        techniques = self.graph.get_neighbors(actor.node_id, relation="uses")
        results = [{"technique": t.name, "mitre_id": t.properties.get("mitre_id", t.name)}
                   for t in techniques]
        return KGQueryResult(
            query      = f"TTPs for {actor_name}",
            results    = results,
            confidence = actor.confidence,
            sources    = ["MITRE ATT&CK", "Shadow313 KG"],
            reasoning  = f"Found {len(results)} techniques attributed to {actor.name}",
        )

    def query_actors_by_sector(self, sector: str) -> KGQueryResult:
        """Find threat actors that target a specific sector."""
        actors = self.graph.find_nodes(node_type="ThreatActor")
        matching = []
        for actor in actors:
            targets = actor.properties.get("sector_targets", [])
            if any(sector.lower() in t.lower() for t in targets):
                matching.append({
                    "actor":      actor.name,
                    "nation":     actor.properties.get("nation", "Unknown"),
                    "aliases":    actor.properties.get("aliases", []),
                    "confidence": actor.confidence,
                })
        return KGQueryResult(
            query      = f"Actors targeting {sector}",
            results    = matching,
            confidence = 0.85 if matching else 0.0,
            sources    = ["Shadow313 KG"],
            reasoning  = f"Found {len(matching)} actors targeting '{sector}' sector",
        )

    def query_lateral_movement_path(
        self,
        src_host: str,
        dst_host: str,
    ) -> KGQueryResult:
        """Find known lateral movement techniques between two hosts."""
        lm_techniques = [
            {"technique": "T1021.002", "name": "SMB/Windows Admin Shares",
             "tool": "PsExec / net use", "requires": "admin credentials"},
            {"technique": "T1021.001", "name": "Remote Desktop Protocol",
             "tool": "mstsc.exe", "requires": "RDP enabled, credentials"},
            {"technique": "T1021.006", "name": "Windows Remote Management",
             "tool": "WinRM / PowerShell remoting", "requires": "WinRM enabled"},
            {"technique": "T1550.002", "name": "Pass the Hash",
             "tool": "Mimikatz / Impacket", "requires": "NTLM hash"},
            {"technique": "T1550.003", "name": "Pass the Ticket",
             "tool": "Rubeus / Mimikatz", "requires": "Kerberos TGT"},
        ]
        return KGQueryResult(
            query      = f"Lateral movement {src_host} → {dst_host}",
            results    = lm_techniques,
            confidence = 0.75,
            sources    = ["MITRE ATT&CK"],
            reasoning  = f"Standard lateral movement techniques applicable to {src_host}→{dst_host}",
        )

    def query_cve_actors(self, cve_id: str) -> KGQueryResult:
        """Find threat actors known to exploit a specific CVE."""
        # Check graph for CVE nodes
        cve_nodes = self.graph.find_nodes(name_contains=cve_id)
        if cve_nodes:
            scores = self.graph.attribution_score(cve_nodes[0].node_id)
            return KGQueryResult(
                query      = f"Actors exploiting {cve_id}",
                results    = scores,
                confidence = 0.8,
                sources    = ["Shadow313 KG"],
                reasoning  = f"Attribution based on graph overlap analysis",
            )
        return KGQueryResult(
            query      = f"Actors exploiting {cve_id}",
            results    = [],
            confidence = 0.0,
            reasoning  = f"CVE {cve_id} not found in knowledge graph",
        )

    def stats(self) -> dict:
        return {
            "graph_stats": self.graph.stats(),
            "actors":      len(self.graph.find_nodes(node_type="ThreatActor")),
            "techniques":  len(self.graph.find_nodes(node_type="Technique")),
        }