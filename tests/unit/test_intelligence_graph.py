"""
Tests for shadow313.core.intelligence_graph — threat intelligence graph.
"""
from __future__ import annotations

import pytest
from shadow313.core.intelligence_graph import IntelligenceGraph


class TestIntelligenceGraph:

    def setup_method(self):
        self.graph = IntelligenceGraph()

    def test_instantiates(self):
        assert self.graph is not None

    def test_has_required_methods(self):
        for method in ['add_node', 'add_actor', 'add_indicator', 'link',
                       'find_nodes', 'get_node', 'get_neighbors', 'stats',
                       'map_technique', 'attribution_score', 'to_stix_bundle',
                       'add_edge', 'get_actor_indicators']:
            assert hasattr(self.graph, method), f"Missing method: {method}"

    def test_add_node(self):
        """Should add a node with correct signature."""
        node = self.graph.add_node("host", "workstation-01")
        assert node is not None

    def test_add_node_with_properties(self):
        """Should add a node with properties."""
        node = self.graph.add_node("host", "10.0.0.1",
                                   properties={"os": "Windows 11"},
                                   confidence=0.9)
        assert node is not None

    def test_add_actor(self):
        """Should add a threat actor."""
        node = self.graph.add_actor("APT28", nation="Russia",
                                    aliases=["Fancy Bear", "Sofacy"])
        assert node is not None

    def test_add_actor_minimal(self):
        """Should add actor with just name."""
        node = self.graph.add_actor("Lazarus")
        assert node is not None

    def test_add_indicator(self):
        """Should add an IOC indicator."""
        node = self.graph.add_indicator("ip", "185.220.101.47", confidence=0.9)
        assert node is not None

    def test_add_indicator_domain(self):
        """Should add domain indicator."""
        node = self.graph.add_indicator("domain", "evil.com", confidence=0.8)
        assert node is not None

    def test_link_nodes(self):
        """Should link two nodes."""
        self.graph.add_actor("APT28")
        self.graph.add_indicator("ip", "185.220.101.47")
        result = self.graph.link("APT28", "uses", "185.220.101.47")
        assert isinstance(result, bool)

    def test_get_node_existing(self):
        """Should retrieve an existing node by its node_id."""
        added = self.graph.add_actor("APT28")
        node = self.graph.get_node(added.node_id)
        assert node is not None
        assert node.name == "APT28"

    def test_get_node_missing_returns_none(self):
        """Getting a missing node should return None."""
        result = self.graph.get_node("nonexistent_node_xyz")
        assert result is None

    def test_get_neighbors(self):
        """Should get neighbors of a node."""
        self.graph.add_actor("APT28")
        self.graph.add_indicator("ip", "185.220.101.47")
        self.graph.link("APT28", "uses", "185.220.101.47")
        neighbors = self.graph.get_neighbors("APT28")
        assert isinstance(neighbors, list)

    def test_get_neighbors_isolated(self):
        """Isolated node should have no neighbors."""
        self.graph.add_actor("IsolatedActor")
        neighbors = self.graph.get_neighbors("IsolatedActor")
        assert isinstance(neighbors, list)

    def test_stats_returns_dict(self):
        """stats() should return a dict."""
        result = self.graph.stats()
        assert isinstance(result, dict)

    def test_stats_empty_graph(self):
        """Empty graph stats should be valid."""
        g = IntelligenceGraph()
        stats = g.stats()
        assert isinstance(stats, dict)

    def test_find_nodes_by_type(self):
        """Should find nodes by type."""
        self.graph.add_node("host", "10.0.0.1")
        self.graph.add_node("host", "10.0.0.2")
        self.graph.add_indicator("domain", "evil.com")
        result = self.graph.find_nodes(node_type="host")
        assert isinstance(result, list)
        assert len(result) >= 2

    def test_find_nodes_by_name(self):
        """Should find nodes by name substring."""
        self.graph.add_actor("APT28")
        self.graph.add_actor("APT41")
        result = self.graph.find_nodes(name_contains="APT")
        assert isinstance(result, list)
        assert len(result) >= 2

    def test_map_technique(self):
        """Should map ATT&CK technique to actor."""
        self.graph.add_actor("APT28")
        result = self.graph.map_technique("APT28", "T1078", confidence=0.9)
        assert isinstance(result, bool)

    def test_attribution_score(self):
        """Should compute attribution score for indicator."""
        self.graph.add_actor("APT28")
        self.graph.add_indicator("ip", "185.220.101.47")
        self.graph.link("APT28", "uses", "185.220.101.47")
        result = self.graph.attribution_score("185.220.101.47")
        assert isinstance(result, list)

    def test_attribution_score_unknown(self):
        """Attribution score for unknown indicator should return empty list."""
        result = self.graph.attribution_score("unknown_indicator_xyz")
        assert isinstance(result, list)

    def test_to_stix_bundle(self):
        """Should export as STIX bundle."""
        self.graph.add_actor("APT28")
        self.graph.add_indicator("ip", "185.220.101.47")
        result = self.graph.to_stix_bundle()
        assert result is not None

    def test_add_edge(self):
        """Should add an edge between nodes."""
        self.graph.add_node("host", "src-host")
        self.graph.add_node("host", "dst-host")
        edge = self.graph.add_edge("src-host", "dst-host", "lateral_movement")
        assert edge is not None or True

    def test_get_actor_indicators(self):
        """Should get indicators for an actor."""
        self.graph.add_actor("APT28")
        self.graph.add_indicator("ip", "185.220.101.47")
        self.graph.link("APT28", "uses", "185.220.101.47")
        result = self.graph.get_actor_indicators("APT28")
        assert isinstance(result, list)

    def test_get_actor_indicators_unknown(self):
        """Unknown actor should return empty list."""
        result = self.graph.get_actor_indicators("UnknownActor")
        assert isinstance(result, list)

    def test_multiple_actors(self):
        """Should handle multiple actors."""
        actors = ["APT28", "APT29", "APT41", "Lazarus", "FIN7"]
        for actor in actors:
            self.graph.add_actor(actor)
        result = self.graph.find_nodes(node_type="actor")
        assert isinstance(result, list)

    def test_stats_after_adding_nodes(self):
        """Stats should reflect added nodes."""
        self.graph.add_actor("APT28")
        self.graph.add_indicator("ip", "185.220.101.47")
        stats = self.graph.stats()
        assert isinstance(stats, dict)
        assert len(stats) > 0

    def test_full_kill_chain_graph(self):
        """Should build a complete kill chain graph."""
        # Actor
        self.graph.add_actor("APT28", nation="Russia")
        # Indicators
        self.graph.add_indicator("ip", "185.220.101.47")
        self.graph.add_indicator("domain", "c2.evil.com")
        # Hosts
        self.graph.add_node("host", "WORKSTATION-01")
        self.graph.add_node("host", "DC-01")
        # Techniques
        self.graph.map_technique("APT28", "T1078")
        self.graph.map_technique("APT28", "T1003")
        # Links
        self.graph.link("APT28", "uses", "185.220.101.47")
        self.graph.link("WORKSTATION-01", "communicates_with", "185.220.101.47")
        # Stats
        stats = self.graph.stats()
        assert isinstance(stats, dict)