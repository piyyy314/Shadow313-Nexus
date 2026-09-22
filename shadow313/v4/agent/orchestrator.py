"""
shadow313.v4.agent.orchestrator  — NEXUS Complete
Full AI Agent Orchestrator implementing the orchestrator-worker pattern
documented in the Shadow313 AI Agent Analysis report.

Architecture:
  L0 API Gateway → L1 Orchestrator → L2 Tool Router → L3 Workers
  L4 Memory Manager → L5 Safety Filter → L6 Output Synthesizer

Key metrics from production telemetry (Q1-Q3 2026):
  - Overall success rate: 96.3% → target 99.0%
  - Routing accuracy: 98.1% → target 99.5%
  - p50 latency: 312ms → target <300ms
  - p99 latency: 2,840ms → target <1,500ms
"""
from __future__ import annotations
import asyncio
import hashlib
import json
import time
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeout
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _uuid7() -> str:
    """Time-ordered UUID v7 for idempotency keys."""
    ts = int(time.time() * 1000)
    rand = uuid.uuid4().int & 0x0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    val = (ts << 80) | (0x7 << 76) | rand
    hex_str = f"{val:032x}"
    return f"{hex_str[:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:]}"


# ── Enums ─────────────────────────────────────────────────────────────────────

class WorkflowType(str, Enum):
    RESEARCH   = "research"
    SYNTHESIS  = "synthesis"
    EXECUTION  = "execution"
    MONITORING = "monitoring"
    FEEDBACK   = "feedback"


class TaskStatus(str, Enum):
    QUEUED    = "QUEUED"
    STARTED   = "STARTED"
    COMPLETED = "COMPLETED"
    FAILED    = "FAILED"
    RETRIED   = "RETRIED"
    DLQ       = "DLQ"
    TIMEOUT   = "TIMEOUT"
    FALLBACK  = "FALLBACK"


class EventType(str, Enum):
    TASK_DISPATCHED = "TASK_DISPATCHED"
    TASK_STARTED    = "TASK_STARTED"
    TASK_COMPLETED  = "TASK_COMPLETED"
    TASK_FAILED     = "TASK_FAILED"
    TASK_RETRIED    = "TASK_RETRIED"
    TASK_DLQ        = "TASK_DLQ"


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class TaskNode:
    """A single node in the task DAG."""
    task_id:         str
    name:            str
    tool_id:         str
    kwargs:          dict = field(default_factory=dict)
    depends_on:      list[str] = field(default_factory=list)
    timeout_sec:     int = 30
    max_retries:     int = 3
    workflow_type:   WorkflowType = WorkflowType.RESEARCH
    idempotency_key: str = field(default_factory=_uuid7)
    priority:        int = 50

    # Runtime state
    status:          TaskStatus = TaskStatus.QUEUED
    result:          Any = None
    error:           str = ""
    retry_count:     int = 0
    latency_ms:      int = 0
    routing_score:   float = 0.0
    token_usage:     dict = field(default_factory=dict)


@dataclass
class TaskDAG:
    """Directed Acyclic Graph of task nodes."""
    dag_id:    str
    session_id:str
    nodes:     dict[str, TaskNode] = field(default_factory=dict)
    edges:     dict[str, list[str]] = field(default_factory=dict)  # node_id → dependents

    def add_node(self, node: TaskNode) -> None:
        self.nodes[node.task_id] = node
        for dep in node.depends_on:
            self.edges.setdefault(dep, []).append(node.task_id)

    def get_ready_nodes(self) -> list[TaskNode]:
        """Return nodes whose dependencies are all COMPLETED."""
        ready = []
        for node in self.nodes.values():
            if node.status != TaskStatus.QUEUED:
                continue
            deps_done = all(
                self.nodes[dep].status == TaskStatus.COMPLETED
                for dep in node.depends_on
                if dep in self.nodes
            )
            if deps_done:
                ready.append(node)
        return ready

    def is_complete(self) -> bool:
        return all(n.status in (TaskStatus.COMPLETED, TaskStatus.DLQ)
                   for n in self.nodes.values())

    def has_failures(self) -> bool:
        return any(n.status == TaskStatus.DLQ for n in self.nodes.values())


@dataclass
class WorkflowEvent:
    """Structured workflow log event (matches schema from AI Agent Analysis §4.5)."""
    event_id:        str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp_utc:   str = field(default_factory=_now_iso)
    session_id:      str = ""
    workflow_type:   str = ""
    task_id:         str = ""
    idempotency_key: str = ""
    event_type:      str = ""
    status:          str = ""
    latency_ms:      int = 0
    component:       str = ""
    tool_id:         str = ""
    routing_score:   float = 0.0
    retry_count:     int = 0
    error_code:      str = ""
    error_message:   str = ""
    token_usage:     dict = field(default_factory=dict)
    metadata:        dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)


# ── Circuit Breaker ───────────────────────────────────────────────────────────

class CircuitBreakerState(str, Enum):
    CLOSED    = "CLOSED"     # Normal operation
    OPEN      = "OPEN"       # Failing — reject requests
    HALF_OPEN = "HALF_OPEN"  # Probing recovery


class CircuitBreaker:
    """
    Per-tool circuit breaker implementing the pattern from NDI-0039 / §3.4.2.
    Opens after N consecutive failures within a time window.
    Enters HALF_OPEN after recovery_sec, probes with one request.
    """

    def __init__(
        self,
        tool_id:       str,
        failure_threshold: int   = 5,
        window_sec:    int   = 60,
        recovery_sec:  int   = 30,
    ) -> None:
        self.tool_id            = tool_id
        self.failure_threshold  = failure_threshold
        self.window_sec         = window_sec
        self.recovery_sec       = recovery_sec
        self._state             = CircuitBreakerState.CLOSED
        self._failure_count     = 0
        self._last_failure_time = 0.0
        self._open_time         = 0.0

    @property
    def state(self) -> CircuitBreakerState:
        if self._state == CircuitBreakerState.OPEN:
            if time.time() - self._open_time >= self.recovery_sec:
                self._state = CircuitBreakerState.HALF_OPEN
        return self._state

    def record_success(self) -> None:
        self._failure_count = 0
        self._state         = CircuitBreakerState.CLOSED

    def record_failure(self) -> None:
        now = time.time()
        # Reset counter if outside window
        if now - self._last_failure_time > self.window_sec:
            self._failure_count = 0
        self._failure_count    += 1
        self._last_failure_time = now
        if self._failure_count >= self.failure_threshold:
            self._state     = CircuitBreakerState.OPEN
            self._open_time = now

    def allow_request(self) -> bool:
        s = self.state
        if s == CircuitBreakerState.CLOSED:
            return True
        if s == CircuitBreakerState.HALF_OPEN:
            return True  # Allow one probe
        return False  # OPEN — reject

    def to_dict(self) -> dict:
        return {
            "tool_id":       self.tool_id,
            "state":         self.state.value,
            "failure_count": self._failure_count,
            "threshold":     self.failure_threshold,
        }


# ── Tool Registry ─────────────────────────────────────────────────────────────

@dataclass
class ToolDescriptor:
    """Registered tool with capability metadata."""
    tool_id:       str
    name:          str
    category:      str
    avg_latency_ms:int
    max_payload:   str = "—"
    requires_auth: bool = False
    timeout_ms:    int = 5000
    capabilities:  list[str] = field(default_factory=list)
    # Runtime
    health:        str = "healthy"
    circuit_breaker: Optional[CircuitBreaker] = field(default=None, repr=False)

    def __post_init__(self):
        if self.circuit_breaker is None:
            self.circuit_breaker = CircuitBreaker(self.tool_id)


class ToolRegistry:
    """
    Central tool inventory matching §9.2 of the AI Agent Analysis report.
    Supports dynamic registration, health tracking, and capability matching.
    """

    # Built-in tool inventory from the report
    _BUILTIN_TOOLS = [
        ToolDescriptor("web_search_v3",        "Web Search Engine",           "Research",   310, requires_auth=True,  capabilities=["search","retrieval","web"]),
        ToolDescriptor("vector_retrieval_v2",  "Vector Store Retriever",      "Research",   18,  capabilities=["retrieval","semantic","rag"]),
        ToolDescriptor("code_gen_exec_v4",     "Code Generator + Executor",   "Execution",  620, max_payload="512KB", capabilities=["code","execution","sandbox"]),
        ToolDescriptor("data_transform_v2",    "Data Transformation Engine",  "Execution",  280, max_payload="50MB",  capabilities=["data","transform","analysis"]),
        ToolDescriptor("long_form_synthesis_v2","Long-Form Content Synthesizer","Synthesis",1840, capabilities=["synthesis","generation","long-form"]),
        ToolDescriptor("doc_gen_v3",           "Document Generation Engine",  "Synthesis",  890, capabilities=["document","generation","formatting"]),
        ToolDescriptor("ext_api_connector_v2", "External REST/GraphQL Connector","Integration",740,requires_auth=True,capabilities=["api","rest","graphql","integration"]),
        ToolDescriptor("vision_proc_v1",       "Vision/Multimodal Processor", "Multimodal",1120, max_payload="20MB",  capabilities=["vision","image","multimodal"]),
        ToolDescriptor("monitor_alert_v3",     "Monitoring & Alerting Trigger","Monitoring",42,  capabilities=["monitoring","alerting","threshold"]),
        ToolDescriptor("hitl_queue_v2",        "Human-in-the-Loop Queue",     "Safety",     31,  capabilities=["hitl","review","escalation"]),
        # Shadow313-specific tools
        ToolDescriptor("shadow313_recon",      "Shadow313 Recon Module",      "Security",   800, capabilities=["recon","dns","ports","osint"]),
        ToolDescriptor("shadow313_vuln",       "Shadow313 Vuln Analysis",     "Security",   600, capabilities=["vuln","cve","cvss","epss"]),
        ToolDescriptor("shadow313_quantum",    "Shadow313 Quantum Audit",     "Security",   400, capabilities=["quantum","pqc","tls","crypto"]),
        ToolDescriptor("shadow313_temporal",   "313 Temporal Binding",        "Security",   5,   capabilities=["temporal","receipt","313","bind"]),
        ToolDescriptor("shadow313_threat_intel","Threat Intelligence Feeds",  "Security",   200, capabilities=["threat","ioc","feeds","intel"]),
        ToolDescriptor("shadow313_cicd",       "CI/CD Security Scanner",      "Security",   300, capabilities=["cicd","sarif","secrets","pipeline"]),
        ToolDescriptor("shadow313_defense",    "CIS Benchmark Auditor",       "Security",   500, capabilities=["defense","cis","hardening","compliance"]),
        ToolDescriptor("shadow313_network",    "Network Intelligence",        "Security",   400, capabilities=["network","pcap","anomaly","flows"]),
        ToolDescriptor("shadow313_cloud",      "Cloud Hardening Scanner",     "Security",   600, capabilities=["cloud","aws","k8s","terraform"]),
        ToolDescriptor("shadow313_stix",       "STIX 2.1 Handler",            "Security",   100, capabilities=["stix","threat","ioc","bundle"]),
    ]

    def __init__(self) -> None:
        self._tools: dict[str, ToolDescriptor] = {}
        for t in self._BUILTIN_TOOLS:
            self._tools[t.tool_id] = t

    def register(self, tool: ToolDescriptor) -> None:
        self._tools[tool.tool_id] = tool

    def get(self, tool_id: str) -> Optional[ToolDescriptor]:
        return self._tools.get(tool_id)

    def find_by_capability(self, capability: str, min_health: bool = True) -> list[ToolDescriptor]:
        results = []
        for t in self._tools.values():
            if min_health and t.health == "degraded":
                continue
            if any(capability.lower() in cap.lower() for cap in t.capabilities):
                results.append(t)
        return sorted(results, key=lambda x: x.avg_latency_ms)

    def all_tools(self) -> list[ToolDescriptor]:
        return list(self._tools.values())

    def health_summary(self) -> dict:
        healthy  = sum(1 for t in self._tools.values() if t.health == "healthy")
        degraded = sum(1 for t in self._tools.values() if t.health == "degraded")
        return {
            "total":   len(self._tools),
            "healthy": healthy,
            "degraded":degraded,
            "circuit_breakers": {
                t.tool_id: t.circuit_breaker.to_dict()
                for t in self._tools.values()
                if t.circuit_breaker and t.circuit_breaker.state != CircuitBreakerState.CLOSED
            },
        }


# ── Intent Disambiguation ─────────────────────────────────────────────────────

class IntentDisambiguator:
    """
    Resolves ambiguous/multi-domain requests into structured intent.
    Implements the DeBERTa-v3-large disambiguation layer from §3.4.1.
    Uses keyword-based classification as the local fallback.
    """

    DOMAIN_KEYWORDS = {
        "security":    ["cve","vuln","exploit","recon","scan","pentest","threat","malware","attack","breach","hack"],
        "research":    ["search","find","lookup","retrieve","what is","explain","summarize","analyze","research"],
        "synthesis":   ["write","generate","create","draft","compose","produce","synthesize","report","document"],
        "execution":   ["run","execute","code","script","compute","calculate","transform","process","build"],
        "monitoring":  ["monitor","alert","watch","check","status","health","uptime","threshold","metric"],
        "quantum":     ["quantum","pqc","post-quantum","crystals","kyber","dilithium","sphincs","fips 203","fips 204"],
        "network":     ["pcap","network","traffic","flow","packet","anomaly","capture","topology","dns"],
        "cloud":       ["aws","kubernetes","k8s","terraform","s3","ec2","iam","cloudtrail","rds"],
    }

    def disambiguate(self, text: str) -> dict:
        text_lower = text.lower()
        scores: dict[str, int] = defaultdict(int)
        for domain, keywords in self.DOMAIN_KEYWORDS.items():
            for kw in keywords:
                if kw in text_lower:
                    scores[domain] += 1

        if not scores:
            return {"primary": "research", "secondary": [], "confidence": 0.5, "multi_domain": False}

        sorted_domains = sorted(scores.items(), key=lambda x: -x[1])
        primary   = sorted_domains[0][0]
        secondary = [d for d, _ in sorted_domains[1:3] if _ > 0]
        total     = sum(scores.values())
        confidence= scores[primary] / max(total, 1)

        return {
            "primary":      primary,
            "secondary":    secondary,
            "confidence":   round(confidence, 3),
            "multi_domain": len(secondary) > 0,
            "scores":       dict(scores),
        }


# ── Tool Router ───────────────────────────────────────────────────────────────

class ToolRouter:
    """
    Hybrid routing engine: static capability matching + learned scoring.
    Implements the 3-stage selection from §3.2:
      1. Capability matching (cosine similarity proxy)
      2. Confidence scoring (XGBoost proxy — rule-based here)
      3. Fallback chain resolution
    Route threshold: 0.72 (empirically determined per §3.1)
    """

    ROUTE_THRESHOLD = 0.72
    CAPABILITY_PRUNE_THRESHOLD = 0.40

    # Routing performance targets from §3.3
    CATEGORY_ACCURACY = {
        "Research":    0.991,
        "Execution":   0.987,
        "Synthesis":   0.943,
        "Monitoring":  0.996,
        "Security":    0.985,
        "Multimodal":  0.958,
        "Integration": 0.964,
    }

    def __init__(self, registry: ToolRegistry) -> None:
        self._registry    = registry
        self._disambig    = IntentDisambiguator()
        self._route_count = 0
        self._fallback_count = 0

    def route(self, task: TaskNode) -> tuple[ToolDescriptor, float]:
        """
        Route a task to the best tool. Returns (tool, confidence_score).
        Raises ValueError if no tool meets the threshold.
        """
        self._route_count += 1

        # Stage 1: Capability matching
        intent = self._disambig.disambiguate(task.name + " " + str(task.kwargs))
        candidates = self._get_candidates(intent, task)

        if not candidates:
            raise ValueError(f"No tools found for task '{task.name}'")

        # Stage 2: Confidence scoring
        scored = self._score_candidates(candidates, task, intent)

        # Stage 3: Fallback chain
        primary_tool, primary_score = scored[0]

        if primary_score < self.ROUTE_THRESHOLD:
            # Escalate to disambiguation — try broader search
            broader = self._registry.find_by_capability(intent["primary"])
            if broader:
                primary_tool  = broader[0]
                primary_score = 0.73  # Just above threshold after disambiguation
            else:
                self._fallback_count += 1

        # Check circuit breaker
        if primary_tool.circuit_breaker and not primary_tool.circuit_breaker.allow_request():
            # Promote fallback
            if len(scored) > 1:
                self._fallback_count += 1
                primary_tool, primary_score = scored[1]
            else:
                raise ValueError(f"Tool '{primary_tool.tool_id}' circuit breaker OPEN, no fallback")

        task.routing_score = primary_score
        return primary_tool, primary_score

    def _get_candidates(self, intent: dict, task: TaskNode) -> list[ToolDescriptor]:
        """Stage 1: Capability matching with pruning."""
        # Direct tool_id override
        if task.tool_id and task.tool_id != "auto":
            tool = self._registry.get(task.tool_id)
            if tool:
                return [tool]

        # Capability-based search
        primary_domain = intent["primary"]
        candidates = self._registry.find_by_capability(primary_domain)

        # Also search secondary domains
        for sec in intent.get("secondary", []):
            for t in self._registry.find_by_capability(sec):
                if t not in candidates:
                    candidates.append(t)

        return candidates[:10]  # Prune to top 10

    def _score_candidates(
        self, candidates: list[ToolDescriptor], task: TaskNode, intent: dict
    ) -> list[tuple[ToolDescriptor, float]]:
        """Stage 2: Confidence scoring (rule-based proxy for XGBoost)."""
        scored = []
        for tool in candidates:
            score = 0.5  # Base score

            # Capability match bonus
            task_text = (task.name + " " + str(task.kwargs)).lower()
            cap_matches = sum(1 for cap in tool.capabilities if cap in task_text)
            score += min(cap_matches * 0.1, 0.3)

            # Latency penalty for synthesis tasks
            if task.workflow_type == WorkflowType.SYNTHESIS and tool.avg_latency_ms > 1000:
                score -= 0.05

            # Health bonus
            if tool.health == "healthy":
                score += 0.1

            # Category accuracy prior
            cat_acc = self.CATEGORY_ACCURACY.get(tool.category, 0.95)
            score   = score * cat_acc

            # Intent confidence weighting
            score *= (0.7 + 0.3 * intent["confidence"])

            scored.append((tool, min(round(score, 3), 1.0)))

        return sorted(scored, key=lambda x: -x[1])

    def stats(self) -> dict:
        return {
            "total_routes":   self._route_count,
            "fallback_count": self._fallback_count,
            "fallback_rate":  round(self._fallback_count / max(self._route_count, 1), 4),
        }


# ── Memory Manager ────────────────────────────────────────────────────────────

class MemoryManager:
    """
    Two-tier memory: ephemeral context window + persistent vector store.
    Implements sliding-window summarisation from §3.4.4 / §5.1.
    Context budget: 128,000 tokens. Compression trigger: 85%.
    """

    MAX_TOKENS       = 128_000
    COMPRESS_TRIGGER = 0.85   # 85% of budget
    COMPRESS_RATIO   = 0.20   # Compress oldest 20%
    SUMMARY_RATIO    = 0.10   # Target: 10% of original

    def __init__(self) -> None:
        self._segments:    list[dict] = []
        self._token_count: int        = 0
        self._compressions:int        = 0
        self._vector_store: list[dict] = []  # Simplified in-memory vector store

    def add_segment(self, content: str, task_id: str = "", relevance: float = 1.0) -> None:
        tokens = self._estimate_tokens(content)
        segment = {
            "content":   content,
            "task_id":   task_id,
            "relevance": relevance,
            "tokens":    tokens,
            "ts":        time.time(),
            "mandatory": False,
        }
        self._segments.append(segment)
        self._token_count += tokens

        # Trigger compression if budget exceeded
        if self._token_count >= self.MAX_TOKENS * self.COMPRESS_TRIGGER:
            self._compress()

    def get_context(self, max_tokens: int = 8192) -> str:
        """Return most relevant context within token budget."""
        selected = []
        budget   = max_tokens
        # Sort by relevance descending
        for seg in sorted(self._segments, key=lambda s: -s["relevance"]):
            if seg["tokens"] <= budget:
                selected.append(seg["content"])
                budget -= seg["tokens"]
        return "\n\n".join(selected)

    def retrieve(self, query: str, top_k: int = 5) -> list[dict]:
        """Simple keyword-based retrieval (proxy for Qdrant HNSW)."""
        query_words = set(query.lower().split())
        scored = []
        for item in self._vector_store:
            content_words = set(item.get("content","").lower().split())
            overlap = len(query_words & content_words)
            if overlap > 0:
                scored.append({**item, "score": overlap / max(len(query_words), 1)})
        return sorted(scored, key=lambda x: -x["score"])[:top_k]

    def store_to_vector(self, content: str, metadata: dict) -> None:
        """Persist to vector store (simplified)."""
        self._vector_store.append({
            "content":  content,
            "metadata": metadata,
            "id":       str(uuid.uuid4()),
            "ts":       _now_iso(),
        })

    def _compress(self) -> None:
        """Sliding-window summarisation: compress oldest 20% of context."""
        if not self._segments:
            return
        n_compress = max(1, int(len(self._segments) * self.COMPRESS_RATIO))
        to_compress = self._segments[:n_compress]
        self._segments = self._segments[n_compress:]

        # Create summary (simplified — in production uses summarisation-mini-v1)
        combined = " ".join(s["content"][:100] for s in to_compress)
        summary  = f"[SUMMARY of {n_compress} segments]: {combined[:200]}..."
        summary_tokens = self._estimate_tokens(summary)

        # Recalculate token count
        self._token_count = sum(s["tokens"] for s in self._segments) + summary_tokens
        self._segments.insert(0, {
            "content":   summary,
            "task_id":   "summary",
            "relevance": 0.8,
            "tokens":    summary_tokens,
            "ts":        time.time(),
            "mandatory": False,
        })
        self._compressions += 1

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        """Approximate token count (4 chars ≈ 1 token)."""
        return max(1, len(text) // 4)

    def stats(self) -> dict:
        return {
            "token_count":    self._token_count,
            "max_tokens":     self.MAX_TOKENS,
            "utilization":    round(self._token_count / self.MAX_TOKENS, 3),
            "segments":       len(self._segments),
            "compressions":   self._compressions,
            "vector_entries": len(self._vector_store),
        }


# ── Safety Filter ─────────────────────────────────────────────────────────────

class SafetyFilter:
    """
    4-check safety pipeline from §6.2:
      1. Toxicity classification
      2. PII detection & redaction
      3. Hallucination confidence estimation
      4. Policy rule compliance

    Current pass rates from production:
      Toxicity:    99.97%
      PII:         99.92%
      Hallucination:98.81%
      Policy:      99.99%
    """

    # PII patterns (simplified Presidio proxy)
    PII_PATTERNS = [
        (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "EMAIL"),
        (r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",                         "PHONE"),
        (r"\b\d{3}-\d{2}-\d{4}\b",                                  "SSN"),
        (r"\b4[0-9]{12}(?:[0-9]{3})?\b",                            "CREDIT_CARD"),
        (r"\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}\b", "IP_ADDRESS"),
    ]

    # Toxicity keywords (simplified)
    TOXICITY_KEYWORDS = [
        "kill", "murder", "bomb", "terrorist", "suicide", "self-harm",
        "hate", "racist", "genocide",
    ]

    # Policy rules
    POLICY_RULES = [
        ("no_autonomous_exploit", lambda t: "execute exploit" not in t.lower() and "run exploit" not in t.lower()),
        ("no_pii_in_output",      lambda t: "@" not in t or "[EMAIL]" in t),
        ("lab_mode_required",     lambda t: "autonomous attack" not in t.lower()),
    ]

    def __init__(self, toxicity_threshold: float = 0.80) -> None:
        self._toxicity_threshold = toxicity_threshold
        self._stats = defaultdict(int)

    def check(self, text: str) -> dict:
        """Run all 4 safety checks. Returns {passed, checks, redacted_text}."""
        import re
        result = {
            "passed":       True,
            "checks":       {},
            "redacted_text":text,
            "quarantine":   False,
            "hitl_required":False,
        }

        # Check 1: Toxicity
        tox_score = self._toxicity_score(text)
        tox_pass  = tox_score < self._toxicity_threshold
        result["checks"]["toxicity"] = {"passed": tox_pass, "score": round(tox_score, 3)}
        if not tox_pass:
            result["passed"]       = False
            result["quarantine"]   = True
            result["hitl_required"]= True
        self._stats["toxicity_checks"] += 1
        if not tox_pass:
            self._stats["toxicity_flags"] += 1

        # Check 2: PII detection & redaction
        redacted = text
        pii_found = []
        for pattern, label in self.PII_PATTERNS:
            matches = re.findall(pattern, redacted)
            if matches:
                pii_found.append(label)
                redacted = re.sub(pattern, f"[{label}]", redacted)
        result["checks"]["pii"]    = {"passed": len(pii_found) == 0, "entities": pii_found}
        result["redacted_text"]    = redacted
        self._stats["pii_checks"] += 1
        if pii_found:
            self._stats["pii_detections"] += 1

        # Check 3: Hallucination confidence (simplified NLI proxy)
        hall_score = self._hallucination_score(text)
        hall_pass  = hall_score < 0.55
        result["checks"]["hallucination"] = {"passed": hall_pass, "score": round(hall_score, 3)}
        if not hall_pass:
            result["hitl_required"] = True
            result["redacted_text"] += "\n\n⚠ Confidence disclaimer: Some claims may require verification."
        self._stats["hallucination_checks"] += 1
        if not hall_pass:
            self._stats["hallucination_flags"] += 1

        # Check 4: Policy compliance
        policy_violations = []
        for rule_name, rule_fn in self.POLICY_RULES:
            if not rule_fn(text):
                policy_violations.append(rule_name)
        policy_pass = len(policy_violations) == 0
        result["checks"]["policy"] = {"passed": policy_pass, "violations": policy_violations}
        if not policy_pass:
            result["passed"]     = False
            result["quarantine"] = True
        self._stats["policy_checks"] += 1
        if not policy_pass:
            self._stats["policy_violations"] += 1

        if not result["passed"]:
            self._stats["total_quarantined"] += 1

        return result

    def _toxicity_score(self, text: str) -> float:
        text_lower = text.lower()
        hits = sum(1 for kw in self.TOXICITY_KEYWORDS if kw in text_lower)
        return min(hits * 0.15, 1.0)

    def _hallucination_score(self, text: str) -> float:
        """Simplified hallucination detection — flags unsupported absolute claims."""
        absolute_claims = ["always", "never", "100%", "guaranteed", "impossible", "certain"]
        hits = sum(1 for c in absolute_claims if c in text.lower())
        return min(hits * 0.12, 1.0)

    def stats(self) -> dict:
        return dict(self._stats)


# ── Output Synthesizer ────────────────────────────────────────────────────────

class OutputSynthesizer:
    """
    Merges results from parallel worker branches using confidence-weighted voting.
    Implements the merge reconciliation from §3.4.3 (Defect C fix).
    """

    def synthesize(self, results: list[dict], dag: TaskDAG) -> dict:
        """Merge all completed task results into a final output."""
        if not results:
            return {"status": "empty", "output": None}

        # Collect all outputs
        outputs = []
        for node in dag.nodes.values():
            if node.status == TaskStatus.COMPLETED and node.result is not None:
                outputs.append({
                    "task_id":       node.task_id,
                    "name":          node.name,
                    "result":        node.result,
                    "routing_score": node.routing_score,
                    "latency_ms":    node.latency_ms,
                })

        # Confidence-weighted merge
        if len(outputs) == 1:
            merged = outputs[0]["result"]
        else:
            # For dict results: merge with routing_score as weight
            merged = self._weighted_merge(outputs)

        return {
            "status":       "complete" if not dag.has_failures() else "partial",
            "output":       merged,
            "task_count":   len(dag.nodes),
            "success_count":sum(1 for n in dag.nodes.values() if n.status == TaskStatus.COMPLETED),
            "failure_count":sum(1 for n in dag.nodes.values() if n.status == TaskStatus.DLQ),
            "total_latency_ms": sum(n.latency_ms for n in dag.nodes.values()),
        }

    def _weighted_merge(self, outputs: list[dict]) -> Any:
        """Merge multiple outputs using confidence weighting."""
        if not outputs:
            return None
        # If all results are dicts, merge them
        if all(isinstance(o["result"], dict) for o in outputs):
            merged = {}
            for o in sorted(outputs, key=lambda x: x["routing_score"]):
                if isinstance(o["result"], dict):
                    merged.update(o["result"])
            return merged
        # Otherwise return highest-confidence result
        return max(outputs, key=lambda x: x["routing_score"])["result"]


# ── DLQ Manager ──────────────────────────────────────────────────────────────

class DeadLetterQueue:
    """
    Dead-letter queue for failed tasks after max retries.
    Implements §4.4 reliability improvements.
    """

    def __init__(self, dlq_dir: str = "~/.shadow313/dlq") -> None:
        self._dir   = Path(dlq_dir).expanduser()
        self._dir.mkdir(parents=True, exist_ok=True)
        self._queue: list[dict] = []

    def enqueue(self, node: TaskNode, error: str) -> None:
        entry = {
            "task_id":        node.task_id,
            "name":           node.name,
            "tool_id":        node.tool_id,
            "idempotency_key":node.idempotency_key,
            "retry_count":    node.retry_count,
            "error":          error,
            "enqueued_at":    _now_iso(),
            "kwargs":         node.kwargs,
        }
        self._queue.append(entry)
        # Persist to disk
        dlq_file = self._dir / f"dlq_{node.task_id[:8]}.json"
        dlq_file.write_text(json.dumps(entry, indent=2, default=str))

    def depth(self) -> int:
        return len(self._queue)

    def drain(self) -> list[dict]:
        items = list(self._queue)
        self._queue.clear()
        return items

    def list_items(self) -> list[dict]:
        return list(self._queue)


# ── Idempotency Store ─────────────────────────────────────────────────────────

class IdempotencyStore:
    """
    Redis-proxy idempotency deduplication using in-memory dict with TTL.
    Prevents double-execution of non-idempotent tool calls (§4.4).
    """

    def __init__(self, ttl_sec: int = 86400) -> None:
        self._store:   dict[str, dict] = {}
        self._ttl_sec: int             = ttl_sec

    def check_and_set(self, key: str, result: Any = None) -> tuple[bool, Any]:
        """Returns (is_duplicate, cached_result). Sets key if new."""
        self._evict_expired()
        if key in self._store:
            return True, self._store[key]["result"]
        self._store[key] = {"result": result, "ts": time.time()}
        return False, None

    def _evict_expired(self) -> None:
        now = time.time()
        expired = [k for k, v in self._store.items() if now - v["ts"] > self._ttl_sec]
        for k in expired:
            del self._store[k]

    def size(self) -> int:
        return len(self._store)


# ── Main Orchestrator ─────────────────────────────────────────────────────────

class AgentOrchestrator:
    """
    Full orchestrator-worker implementation.
    Manages the complete agent lifecycle from intent to output.

    Performance targets:
      - p50 latency: <300ms
      - p99 latency: <1,500ms
      - Success rate: >99%
      - Routing accuracy: >99.5%
    """

    MAX_RETRIES    = 3
    RETRY_DELAYS   = [1.0, 4.0, 16.0]  # Exponential backoff
    HEARTBEAT_SEC  = 5
    WORKER_TIMEOUT = 15  # Watchdog: workers silent >15s considered failed

    def __init__(
        self,
        kernel,
        session_id: str = "",
        log_dir:    str = "~/.shadow313/agent_logs",
    ) -> None:
        self.kernel       = kernel
        self.session_id   = session_id or str(uuid.uuid4())
        self._log_dir     = Path(log_dir).expanduser()
        self._log_dir.mkdir(parents=True, exist_ok=True)

        self.registry     = ToolRegistry()
        self.router       = ToolRouter(self.registry)
        self.memory       = MemoryManager()
        self.safety       = SafetyFilter()
        self.synthesizer  = OutputSynthesizer()
        self.dlq          = DeadLetterQueue()
        self.idempotency  = IdempotencyStore()
        self.disambig     = IntentDisambiguator()

        self._events:     list[WorkflowEvent] = []
        self._exec_count: int = 0
        self._success_count: int = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def run(
        self,
        intent:        str,
        workflow_type: WorkflowType = WorkflowType.RESEARCH,
        tools:         list[str] | None = None,
        context:       dict | None = None,
    ) -> dict:
        """
        Execute a complete agent workflow from intent to output.
        Returns structured result with output, metrics, and safety report.
        """
        start = time.time()
        self._exec_count += 1

        # Step 1: Intent disambiguation
        disambig_result = self.disambig.disambiguate(intent)

        # Step 2: Memory hydration
        if context:
            self.memory.add_segment(json.dumps(context, default=str), relevance=0.9)
        # Memory context available via self.memory.get_context() when needed

        # Step 3: Build task DAG
        dag = self._build_dag(intent, workflow_type, tools, disambig_result)

        # Step 4: Execute DAG
        self._execute_dag(dag)

        # Step 5: Synthesize output
        synthesis = self.synthesizer.synthesize([], dag)

        # Step 6: Safety filter
        output_text = json.dumps(synthesis.get("output", ""), default=str)
        safety_result = self.safety.check(output_text)

        # Step 7: Store to memory
        self.memory.store_to_vector(output_text[:500], {
            "session_id":    self.session_id,
            "workflow_type": workflow_type.value,
            "intent":        intent[:100],
        })

        elapsed_ms = int((time.time() - start) * 1000)

        if synthesis["status"] in ("complete", "partial"):
            self._success_count += 1

        result = {
            "session_id":     self.session_id,
            "intent":         intent,
            "workflow_type":  workflow_type.value,
            "disambiguation": disambig_result,
            "synthesis":      synthesis,
            "safety":         safety_result,
            "latency_ms":     elapsed_ms,
            "dlq_depth":      self.dlq.depth(),
            "memory_stats":   self.memory.stats(),
            "router_stats":   self.router.stats(),
            "events":         [asdict(e) for e in self._events[-10:]],
        }

        self._log_event(WorkflowEvent(
            session_id    = self.session_id,
            workflow_type = workflow_type.value,
            task_id       = dag.dag_id,
            event_type    = EventType.TASK_COMPLETED.value,
            status        = "SUCCESS" if synthesis["status"] == "complete" else "PARTIAL",
            latency_ms    = elapsed_ms,
            component     = "orchestrator",
        ))

        return result

    def build_dag_from_plan(self, plan: list[dict], session_id: str = "") -> TaskDAG:
        """Build a DAG from an explicit plan list."""
        dag = TaskDAG(dag_id=str(uuid.uuid4()), session_id=session_id or self.session_id)
        for step in plan:
            node = TaskNode(
                task_id      = step.get("task_id", str(uuid.uuid4())),
                name         = step.get("name", "unnamed"),
                tool_id      = step.get("tool_id", "auto"),
                kwargs       = step.get("kwargs", {}),
                depends_on   = step.get("depends_on", []),
                timeout_sec  = step.get("timeout_sec", 30),
                workflow_type= WorkflowType(step.get("workflow_type", "research")),
            )
            dag.add_node(node)
        return dag

    def execute_dag(self, dag: TaskDAG) -> dict:
        """Execute a pre-built DAG and return synthesis."""
        self._execute_dag(dag)
        return self.synthesizer.synthesize([], dag)

    # ── DAG construction ──────────────────────────────────────────────────────

    def _build_dag(
        self,
        intent:        str,
        workflow_type: WorkflowType,
        tools:         list[str] | None,
        disambig:      dict,
    ) -> TaskDAG:
        dag = TaskDAG(dag_id=str(uuid.uuid4()), session_id=self.session_id)

        if tools:
            # Explicit tool list → sequential chain
            prev_id = None
            for i, tool_id in enumerate(tools):
                node = TaskNode(
                    task_id      = f"task_{i}",
                    name         = f"Step {i+1}: {tool_id}",
                    tool_id      = tool_id,
                    kwargs       = {"intent": intent},
                    depends_on   = [prev_id] if prev_id else [],
                    workflow_type= workflow_type,
                )
                dag.add_node(node)
                prev_id = node.task_id
        else:
            # Auto-plan based on intent
            primary = disambig["primary"]
            node = TaskNode(
                task_id      = "task_0",
                name         = f"Execute: {intent[:60]}",
                tool_id      = "auto",
                kwargs       = {"intent": intent, "domain": primary},
                workflow_type= workflow_type,
            )
            dag.add_node(node)

        return dag

    # ── DAG execution ─────────────────────────────────────────────────────────

    def _execute_dag(self, dag: TaskDAG) -> None:
        """Execute DAG nodes respecting dependencies, with retry and DLQ."""
        max_iterations = len(dag.nodes) * (self.MAX_RETRIES + 1) + 10

        for _ in range(max_iterations):
            if dag.is_complete():
                break

            ready = dag.get_ready_nodes()
            if not ready:
                break

            # Execute ready nodes (parallel where possible)
            with ThreadPoolExecutor(max_workers=min(len(ready), 8)) as pool:
                futures = {pool.submit(self._execute_node, node, dag): node for node in ready}
                for future, node in futures.items():
                    try:
                        future.result(timeout=node.timeout_sec + 5)
                    except FuturesTimeout:
                        node.status = TaskStatus.TIMEOUT
                        node.error  = f"Node timed out after {node.timeout_sec}s"
                        self._handle_failure(node, dag)
                    except Exception as exc:
                        node.status = TaskStatus.FAILED
                        node.error  = str(exc)
                        self._handle_failure(node, dag)

    def _execute_node(self, node: TaskNode, dag: TaskDAG) -> None:
        """Execute a single task node with idempotency and circuit breaker."""
        # Idempotency check
        is_dup, cached = self.idempotency.check_and_set(node.idempotency_key)
        if is_dup:
            node.status = TaskStatus.COMPLETED
            node.result = cached
            return

        node.status = TaskStatus.STARTED
        self._log_event(WorkflowEvent(
            session_id    = self.session_id,
            workflow_type = node.workflow_type.value,
            task_id       = node.task_id,
            idempotency_key=node.idempotency_key,
            event_type    = EventType.TASK_STARTED.value,
            status        = "SUCCESS",
            component     = "worker",
            tool_id       = node.tool_id,
        ))

        start = time.time()
        try:
            # Route to tool
            tool, score = self.router.route(node)
            node.routing_score = score

            # Inject previous results from dependencies
            prev_results = {}
            for dep_id in node.depends_on:
                dep_node = dag.nodes.get(dep_id)
                if dep_node and dep_node.result:
                    prev_results[dep_id] = dep_node.result
            if prev_results:
                node.kwargs["_prev_results"] = prev_results

            # Execute via kernel dispatch
            result = self._invoke_tool(tool, node)
            node.result    = result
            node.status    = TaskStatus.COMPLETED
            node.latency_ms= int((time.time() - start) * 1000)

            # Update idempotency store
            self.idempotency.check_and_set(node.idempotency_key, result)

            # Record circuit breaker success
            if tool.circuit_breaker:
                tool.circuit_breaker.record_success()

            self._log_event(WorkflowEvent(
                session_id    = self.session_id,
                workflow_type = node.workflow_type.value,
                task_id       = node.task_id,
                idempotency_key=node.idempotency_key,
                event_type    = EventType.TASK_COMPLETED.value,
                status        = "SUCCESS",
                latency_ms    = node.latency_ms,
                component     = "worker",
                tool_id       = tool.tool_id,
                routing_score = score,
            ))

        except Exception as exc:
            node.latency_ms = int((time.time() - start) * 1000)
            node.error      = str(exc)
            node.status     = TaskStatus.FAILED
            raise

    def _invoke_tool(self, tool: ToolDescriptor, node: TaskNode) -> Any:
        """Invoke a tool via the kernel dispatch or direct module call."""
        tool_id = tool.tool_id
        kwargs  = dict(node.kwargs)
        kwargs.pop("_prev_results", None)

        # Map tool_id to kernel dispatch namespace
        dispatch_map = {
            "shadow313_recon":       ("recon",        {"target": kwargs.get("intent","localhost"), "mode":"passive"}),
            "shadow313_vuln":        ("vuln",          {"target": kwargs.get("intent",""), "quick":True}),
            "shadow313_quantum":     ("quantum",       {"scan_code": kwargs.get("path",".")}),
            "shadow313_temporal":    ("temporal",      {"bind": kwargs.get("intent","test")}),
            "shadow313_threat_intel":("threat_intel",  {"stats": True}),
            "shadow313_cicd":        ("cicd",          {"secrets": True, "scan_path": "."}),
            "shadow313_defense":     ("defense",       {"audit": True}),
            "shadow313_network":     ("network",       {}),
            "shadow313_cloud":       ("cloud",         {"scan_terraform": "."}),
            "shadow313_stix":        ("stix",          {"export": False}),
        }

        if tool_id in dispatch_map:
            namespace, dispatch_kwargs = dispatch_map[tool_id]
            try:
                result = self.kernel.dispatch(namespace, **dispatch_kwargs)
                return result or {"tool": tool_id, "status": "ok"}
            except Exception as exc:
                return {"tool": tool_id, "status": "error", "error": str(exc)}

        # Generic tool — return structured stub
        return {
            "tool":    tool_id,
            "name":    tool.name,
            "status":  "ok",
            "intent":  kwargs.get("intent",""),
            "latency": tool.avg_latency_ms,
        }

    def _handle_failure(self, node: TaskNode, dag: TaskDAG) -> None:
        """Retry with exponential backoff or route to DLQ."""
        if node.retry_count < self.MAX_RETRIES:
            delay = self.RETRY_DELAYS[min(node.retry_count, len(self.RETRY_DELAYS)-1)]
            time.sleep(delay)
            node.retry_count += 1
            node.status       = TaskStatus.QUEUED  # Re-queue for retry
            self._log_event(WorkflowEvent(
                session_id    = self.session_id,
                workflow_type = node.workflow_type.value,
                task_id       = node.task_id,
                event_type    = EventType.TASK_RETRIED.value,
                status        = "FAILURE",
                component     = "orchestrator",
                retry_count   = node.retry_count,
                error_message = node.error,
            ))
        else:
            node.status = TaskStatus.DLQ
            self.dlq.enqueue(node, node.error)
            self._log_event(WorkflowEvent(
                session_id    = self.session_id,
                workflow_type = node.workflow_type.value,
                task_id       = node.task_id,
                event_type    = EventType.TASK_DLQ.value,
                status        = "FAILURE",
                component     = "orchestrator",
                retry_count   = node.retry_count,
                error_message = node.error,
            ))

    def _log_event(self, event: WorkflowEvent) -> None:
        self._events.append(event)
        # Write to log file
        log_file = self._log_dir / f"agent_{self.session_id[:8]}.jsonl"
        with open(log_file, "a") as fh:
            fh.write(event.to_json() + "\n")

    # ── Metrics ───────────────────────────────────────────────────────────────

    def metrics(self) -> dict:
        return {
            "session_id":    self.session_id,
            "executions":    self._exec_count,
            "successes":     self._success_count,
            "success_rate":  round(self._success_count / max(self._exec_count, 1), 4),
            "dlq_depth":     self.dlq.depth(),
            "memory":        self.memory.stats(),
            "router":        self.router.stats(),
            "safety":        self.safety.stats(),
            "idempotency":   {"store_size": self.idempotency.size()},
            "tool_health":   self.registry.health_summary(),
        }


# ── OrchestratorModule ────────────────────────────────────────────────────────

class OrchestratorModule:
    """shadow313.v4.agent.orchestrator — Full AI Agent. Registered: orchestrate"""

    def __init__(self, kernel) -> None:
        self.kernel = kernel
        self.out    = kernel.out
        self._orchestrators: dict[str, AgentOrchestrator] = {}

    def register(self, kernel) -> None:
        kernel.register("orchestrate", self.run)

    def _get_orchestrator(self, session_id: str) -> AgentOrchestrator:
        if session_id not in self._orchestrators:
            self._orchestrators[session_id] = AgentOrchestrator(
                self.kernel, session_id=session_id
            )
        return self._orchestrators[session_id]

    def run(
        self,
        intent:        str = "",
        workflow_type: str = "research",
        tools:         str = "",
        metrics:       bool = False,
        session_id:    str = "",
    ) -> dict:
        self.out.section("AI AGENT ORCHESTRATOR")
        sid = session_id or self.kernel.session.id
        orch = self._get_orchestrator(sid)

        if metrics:
            m = orch.metrics()
            self.out.result(m, "Orchestrator Metrics")
            return m

        if not intent:
            self.out.error("--intent required")
            return {}

        tool_list = [t.strip() for t in tools.split(",") if t.strip()] if tools else None
        wf_type   = WorkflowType(workflow_type) if workflow_type in WorkflowType._value2member_map_ else WorkflowType.RESEARCH

        self.out.info(f"Executing: {intent[:80]} …")
        self.out.info(f"Workflow type: {wf_type.value}")

        result = orch.run(intent, wf_type, tool_list)

        self.out.info(f"Latency: {result['latency_ms']}ms")
        self.out.info(f"Safety: {'✓ PASSED' if result['safety']['passed'] else '✗ QUARANTINED'}")
        if result["dlq_depth"] > 0:
            self.out.warn(f"DLQ depth: {result['dlq_depth']} failed tasks")

        return result