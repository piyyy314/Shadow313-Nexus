"""
shadow313.v2.graph.intel_graph
Feature #11 — Intelligence Graph
NetworkX-based graph of hosts/services/CVEs/certs/actors.
Supports query engine, path analysis, export to JSON/GraphML/GexF.
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import networkx as nx
    _HAS_NX = True
except ImportError:
    _HAS_NX = False


# ---------------------------------------------------------------------------
# Node / Edge type constants
# ---------------------------------------------------------------------------

class NodeType:
    HOST    = "host"
    SERVICE = "service"
    CVE     = "cve"
    CERT    = "cert"
    DOMAIN  = "domain"
    ORG     = "org"
    IP      = "ip"
    ACTOR   = "actor"
    FINDING = "finding"


class EdgeType:
    RUNS      = "runs"         # host → service
    AFFECTED  = "affected_by"  # service/host → cve
    RESOLVES  = "resolves_to"  # domain → ip
    ISSUES    = "issues"       # org → cert
    COVERS    = "covers"       # cert → domain
    LINKED_TO = "linked_to"    # generic
    EXPLOITS  = "exploits"     # actor → cve
    TARGETS   = "targets"      # actor → host


# ---------------------------------------------------------------------------
# Pure-Python fallback graph (adjacency list) when NetworkX not available
# ---------------------------------------------------------------------------

class _SimpleGraph:
    """Minimal graph when NetworkX is missing."""
    def __init__(self) -> None:
        self._nodes: dict[str, dict] = {}
        self._edges: list[dict]      = []
        self._adj:   dict[str, list[str]] = {}

    def add_node(self, node_id: str, **attrs) -> None:
        self._nodes[node_id] = attrs
        self._adj.setdefault(node_id, [])

    def add_edge(self, src: str, dst: str, **attrs) -> None:
        self._edges.append({"src": src, "dst": dst, **attrs})
        self._adj.setdefault(src, []).append(dst)
        self._adj.setdefault(dst, []).append(src)

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    def neighbors(self, node_id: str) -> list[str]:
        return self._adj.get(node_id, [])

    def nodes(self, data: bool = False):
        if data:
            return list(self._nodes.items())
        return list(self._nodes.keys())

    def edges(self, data: bool = False):
        if data:
            return [(e["src"], e["dst"], e) for e in self._edges]
        return [(e["src"], e["dst"]) for e in self._edges]

    def number_of_nodes(self) -> int:
        return len(self._nodes)

    def number_of_edges(self) -> int:
        return len(self._edges)

    def get_node(self, node_id: str) -> dict:
        return self._nodes.get(node_id, {})

    def to_dict(self) -> dict:
        return {"nodes": self._nodes, "edges": self._edges}


# ---------------------------------------------------------------------------
# IntelligenceGraph — Feature #11
# ---------------------------------------------------------------------------

class IntelligenceGraph:
    """
    Persistent intelligence graph for Shadow313 v2.
    Models relationships between: hosts, IPs, domains, services, CVEs,
    certificates, organizations, threat actors, and findings.

    Supports:
    - Node/edge CRUD
    - Path queries (shortest path, reachability)
    - Subgraph extraction (e.g., all CVEs affecting a host)
    - Centrality analysis (most connected nodes = highest risk)
    - Export: JSON, GraphML, GexF, adjacency list
    """

    GRAPH_PATH = Path("~/.shadow313/intel_graph.json")

    def __init__(self, persist_path: str | None = None, graph_path=None) -> None:
        if graph_path is not None and persist_path is None:
            persist_path = str(graph_path)
        self._path = Path(persist_path or self.GRAPH_PATH).expanduser()
        if _HAS_NX:
            self._g: Any = nx.MultiDiGraph()
        else:
            self._g = _SimpleGraph()
        self._load()

    # ── Node operations ───────────────────────────────────────────────
    def add_host(self, ip: str, hostname: str = "",
                 os: str = "", tags: list | None = None) -> str:
        node_id = f"host:{ip}"
        self._add_node(node_id, type=NodeType.HOST, ip=ip,
                       hostname=hostname, os=os, tags=tags or [],
                       added_at=_now())
        if hostname:
            dom_id = f"domain:{hostname}"
            self.add_domain(hostname)
            self._add_edge(dom_id, node_id, type=EdgeType.RESOLVES)
        return node_id

    def add_service(self, host_ip: str, port: int, protocol: str,
                    banner: str = "", product: str = "", version: str = "") -> str:
        host_id  = f"host:{host_ip}"
        svc_id   = f"service:{host_ip}:{port}/{protocol}"
        self._add_node(svc_id, type=NodeType.SERVICE, port=port,
                       protocol=protocol, banner=banner[:200],
                       product=product, version=version,
                       added_at=_now())
        self._add_edge(host_id, svc_id, type=EdgeType.RUNS)
        return svc_id

    def add_cve(self, cve_id: str, cvss: float = 0.0, severity: str = "",
                description: str = "", epss: float = 0.0,
                is_kev: bool = False) -> str:
        node_id = f"cve:{cve_id}"
        self._add_node(node_id, type=NodeType.CVE, cve_id=cve_id,
                       cvss=cvss, severity=severity,
                       description=description[:300],
                       epss=epss, is_kev=is_kev, added_at=_now())
        return node_id

    def add_domain(self, domain: str, registrar: str = "") -> str:
        node_id = f"domain:{domain}"
        if not self._g.has_node(node_id):
            self._add_node(node_id, type=NodeType.DOMAIN, domain=domain,
                           registrar=registrar, added_at=_now())
        return node_id

    def add_cert(self, subject: str, issuer: str, not_after: str,
                 fingerprint: str = "", domains: list | None = None) -> str:
        node_id = f"cert:{fingerprint or subject[:20]}"
        self._add_node(node_id, type=NodeType.CERT, subject=subject,
                       issuer=issuer, not_after=not_after,
                       fingerprint=fingerprint, added_at=_now())
        for dom in (domains or []):
            dom_id = f"domain:{dom}"
            self.add_domain(dom)
            self._add_edge(node_id, dom_id, type=EdgeType.COVERS)
        return node_id

    def add_finding(self, title: str, severity: str, module: str,
                    host_ip: str = "", cve_id: str = "") -> str:
        node_id = f"finding:{title[:30].replace(' ','_')}:{_now()[:10]}"
        self._add_node(node_id, type=NodeType.FINDING, title=title,
                       severity=severity, module=module, added_at=_now())
        if host_ip:
            self._add_edge(f"host:{host_ip}", node_id, type=EdgeType.LINKED_TO)
        if cve_id:
            cve_node = f"cve:{cve_id}"
            if self._g.has_node(cve_node):
                self._add_edge(node_id, cve_node, type=EdgeType.AFFECTED)
        return node_id

    def link_cve_to_service(self, cve_id: str, host_ip: str, port: int,
                             protocol: str = "tcp") -> None:
        cve_id_node = f"cve:{cve_id}"
        svc_id      = f"service:{host_ip}:{port}/{protocol}"
        if not self._g.has_node(cve_id_node):
            self.add_cve(cve_id)
        if not self._g.has_node(svc_id):
            self.add_service(host_ip, port, protocol)
        self._add_edge(svc_id, cve_id_node, type=EdgeType.AFFECTED)

    def link_cve_to_host(self, cve_id: str, host_ip: str) -> None:
        cve_node  = f"cve:{cve_id}"
        host_node = f"host:{host_ip}"
        if not self._g.has_node(cve_node):
            self.add_cve(cve_id)
        if not self._g.has_node(host_node):
            self.add_host(host_ip)
        self._add_edge(host_node, cve_node, type=EdgeType.AFFECTED)

    # ── Ingestion from module outputs ────────────────────────────────
    def ingest_recon_output(self, recon_data: dict) -> int:
        count = 0
        target = recon_data.get("target", "")
        ip     = recon_data.get("ip", target)
        if ip:
            self.add_host(ip, hostname=target)
            count += 1
        for port_info in recon_data.get("ports", []):
            port   = port_info.get("port", 0)
            proto  = port_info.get("protocol", "tcp")
            banner = port_info.get("banner", "")
            if port:
                self.add_service(ip or target, port, proto, banner=banner)
                count += 1
        return count

    def ingest_vuln_output(self, vuln_data: dict, host_ip: str = "") -> int:
        count = 0
        for f in vuln_data.get("findings", []):
            cve_id = f.get("cve", "")
            if cve_id:
                self.add_cve(
                    cve_id,
                    cvss=f.get("cvss_v3", 0.0),
                    severity=f.get("severity", ""),
                    description=f.get("description", ""),
                    epss=f.get("epss", {}).get("epss", 0.0) if isinstance(f.get("epss"), dict) else 0.0,
                    is_kev=f.get("kev", {}).get("is_kev", False) if isinstance(f.get("kev"), dict) else False,
                )
                if host_ip:
                    self.link_cve_to_host(cve_id, host_ip)
                count += 1
        return count

    # ── Query engine ──────────────────────────────────────────────────
    def get_node(self, node_id: str) -> dict:
        if _HAS_NX:
            return dict(self._g.nodes.get(node_id, {}))
        return self._g.get_node(node_id)

    def neighbors(self, node_id: str) -> list[str]:
        if _HAS_NX:
            return list(self._g.successors(node_id)) + list(self._g.predecessors(node_id))
        return self._g.neighbors(node_id)

    def find_nodes(self, node_type: str | None = None,
                   **attrs) -> list[dict]:
        """Find nodes by type and attribute filters."""
        results = []
        nodes_data = self._g.nodes(data=True) if _HAS_NX else self._g.nodes(data=True)
        for nid, data in nodes_data:
            if node_type and data.get("type") != node_type:
                continue
            match = all(data.get(k) == v for k, v in attrs.items())
            if match:
                results.append({"id": nid, **data})
        return results

    def cves_for_host(self, host_ip: str) -> list[dict]:
        """Get all CVEs linked to a host (direct + via services)."""
        cves = []
        host_node = f"host:{host_ip}"
        # Direct
        for neighbor in self.neighbors(host_node):
            data = self.get_node(neighbor)
            if data.get("type") == NodeType.CVE:
                cves.append({"id": neighbor, **data})
        # Via services
        for neighbor in self.neighbors(host_node):
            data = self.get_node(neighbor)
            if data.get("type") == NodeType.SERVICE:
                for n2 in self.neighbors(neighbor):
                    d2 = self.get_node(n2)
                    if d2.get("type") == NodeType.CVE:
                        cves.append({"id": n2, **d2})
        # Deduplicate
        seen = set()
        unique = []
        for c in cves:
            if c["id"] not in seen:
                seen.add(c["id"])
                unique.append(c)
        return unique

    def hosts_for_cve(self, cve_id: str) -> list[dict]:
        """Get all hosts affected by a CVE."""
        cve_node = f"cve:{cve_id}"
        hosts = []
        if _HAS_NX:
            for pred in self._g.predecessors(cve_node):
                data = self.get_node(pred)
                if data.get("type") in (NodeType.HOST, NodeType.SERVICE):
                    hosts.append({"id": pred, **data})
        else:
            for eid, src, dst in [(e, e["src"], e["dst"])
                                   for e in self._g._edges
                                   if e["dst"] == cve_node]:
                data = self.get_node(src)
                hosts.append({"id": src, **data})
        return hosts

    def shortest_path(self, src: str, dst: str) -> list[str]:
        """Find shortest path between two nodes."""
        if not _HAS_NX:
            return []
        try:
            return list(nx.shortest_path(self._g.to_undirected(), src, dst))
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    def risk_ranking(self, top_k: int = 10) -> list[dict]:
        """Rank hosts by number of connected CVEs (simple risk proxy)."""
        hosts = self.find_nodes(node_type=NodeType.HOST)
        ranked = []
        for h in hosts:
            cves = self.cves_for_host(h.get("ip", h["id"].split(":")[1]))
            critical_cves = [c for c in cves if c.get("severity", "").upper() == "CRITICAL"]
            kev_cves      = [c for c in cves if c.get("is_kev")]
            score = (len(critical_cves) * 10 + len(kev_cves) * 20 +
                     len(cves) + sum(c.get("epss", 0) * 100 for c in cves))
            ranked.append({
                "host":          h.get("id",""),
                "ip":            h.get("ip",""),
                "hostname":      h.get("hostname",""),
                "total_cves":    len(cves),
                "critical_cves": len(critical_cves),
                "kev_cves":      len(kev_cves),
                "risk_score":    round(score, 2),
            })
        ranked.sort(key=lambda x: x["risk_score"], reverse=True)
        return ranked[:top_k]

    def centrality(self) -> dict[str, float]:
        """Betweenness centrality for all nodes (requires NetworkX)."""
        if not _HAS_NX:
            return {}
        try:
            return nx.betweenness_centrality(self._g.to_undirected())
        except Exception:
            return {}

    def stats(self) -> dict:
        node_types: dict[str, int] = {}
        for _, data in self._g.nodes(data=True):
            t = data.get("type", "unknown")
            node_types[t] = node_types.get(t, 0) + 1
        return {
            "total_nodes": self._g.number_of_nodes(),
            "total_edges": self._g.number_of_edges(),
            "node_types":  node_types,
            "backend":     "networkx" if _HAS_NX else "simple",
        }

    # ── Export ────────────────────────────────────────────────────────
    def to_dict(self) -> dict:
        if _HAS_NX:
            nodes = [{"id": nid, **data}
                     for nid, data in self._g.nodes(data=True)]
            edges = [{"src": u, "dst": v, "type": data.get("type","linked_to")}
                     for u, v, data in self._g.edges(data=True)]
            return {"nodes": nodes, "edges": edges}
        return self._g.to_dict()

    def export_graphml(self, path: str) -> str:
        if not _HAS_NX:
            raise ImportError("pip install networkx")
        p = Path(path).expanduser().resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
        nx.write_graphml(self._g, str(p))
        return str(p)

    def export_gexf(self, path: str) -> str:
        if not _HAS_NX:
            raise ImportError("pip install networkx")
        p = Path(path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        nx.write_gexf(self._g, str(p))
        return str(p)

    def export_json(self, path: str | None = None) -> str:
        p = Path(path or self._path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2, default=str))
        return str(p)

    # ── Persistence ───────────────────────────────────────────────────
    def save(self) -> None:
        self.export_json(str(self._path))

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text())
            for node in data.get("nodes", []):
                nid = node.pop("id", None)
                if nid:
                    self._add_node(nid, **node)
            for edge in data.get("edges", []):
                src = edge.pop("src", None)
                dst = edge.pop("dst", None)
                if src and dst:
                    self._add_edge(src, dst, **edge)
        except Exception:
            pass

    def _add_node(self, node_id: str, **attrs) -> None:
        if _HAS_NX:
            self._g.add_node(node_id, **attrs)
        else:
            self._g.add_node(node_id, **attrs)

    def _add_edge(self, src: str, dst: str, **attrs) -> None:
        if not self._g.has_node(src):
            self._add_node(src, type="unknown")
        if not self._g.has_node(dst):
            self._add_node(dst, type="unknown")
        if _HAS_NX:
            self._g.add_edge(src, dst, **attrs)
        else:
            self._g.add_edge(src, dst, **attrs)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Backward-compatibility aliases ────────────────────────────────────────────
# Track added nodes by their original ID (before prefix is added)
_IG_NODE_REGISTRY: dict = {}  # instance_id -> set of node_ids

def _ig_add_node(self, node_id: str, node_type: str = "host", **kwargs):
    """Compatibility alias — routes to add_host, add_domain, or add_cve."""
    # Track the original node_id
    inst_id = id(self)
    if inst_id not in _IG_NODE_REGISTRY:
        _IG_NODE_REGISTRY[inst_id] = set()
    _IG_NODE_REGISTRY[inst_id].add(node_id)

    nt = node_type.lower()
    if nt in ("host", "ip", "server", "workstation"):
        return self.add_host(node_id, **{k: v for k, v in kwargs.items() if k in ("hostname", "os", "tags")})
    elif nt in ("domain", "fqdn"):
        return self.add_domain(node_id)
    elif nt in ("cve", "vulnerability"):
        return self.add_cve(node_id, **{k: v for k, v in kwargs.items() if k in ("cvss", "description")})
    else:
        return self.add_host(node_id)

def _ig_add_edge(self, src: str, dst: str, relation: str = "connects", **kwargs):
    """Compatibility alias for add_edge."""
    # Track nodes
    inst_id = id(self)
    if inst_id not in _IG_NODE_REGISTRY:
        _IG_NODE_REGISTRY[inst_id] = set()
    _IG_NODE_REGISTRY[inst_id].add(src)
    _IG_NODE_REGISTRY[inst_id].add(dst)
    # Try to add edge via internal method
    try:
        src_id = f"host:{src}" if not src.startswith(("host:", "domain:", "cve:", "service:")) else src
        dst_id = f"host:{dst}" if not dst.startswith(("host:", "domain:", "cve:", "service:")) else dst
        self._add_edge(src_id, dst_id, type=relation)
        return True
    except Exception:
        return False

def _ig_has_node(self, node_id: str) -> bool:
    """Check if node exists — checks registry and internal nodes dict."""
    inst_id = id(self)
    # Check our registry first (tracks original IDs)
    if inst_id in _IG_NODE_REGISTRY and node_id in _IG_NODE_REGISTRY[inst_id]:
        return True
    # Check internal nodes dict with common prefixes
    if hasattr(self, '_nodes'):
        if node_id in self._nodes:
            return True
        for prefix in ("host:", "domain:", "cve:", "service:"):
            if f"{prefix}{node_id}" in self._nodes:
                return True
    return False

IntelligenceGraph.add_node = _ig_add_node
IntelligenceGraph.add_edge = _ig_add_edge
IntelligenceGraph.has_node = _ig_has_node
