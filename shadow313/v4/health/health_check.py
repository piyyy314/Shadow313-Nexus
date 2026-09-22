"""
shadow313.v4.health.health_check  — NEXUS Complete
System health check and self-diagnostic module (doctor).

Checks:
  - All module initialization status
  - AI backend connectivity
  - Dependency availability (optional and required)
  - Storage health (disk space, permissions)
  - Network connectivity (external feeds)
  - Cryptographic subsystem health
  - 313 Temporal Binding status
  - Performance baseline check
  - Security configuration audit
"""
from __future__ import annotations
import importlib
import json
import os
import shutil
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class HealthCheck:
    """Result of a single health check."""
    name:     str
    status:   str   # OK | WARN | FAIL | SKIP
    message:  str   = ""
    value:    Any   = None
    latency_ms:float= 0.0


@dataclass
class HealthReport:
    """Complete system health report."""
    timestamp:  str = field(default_factory=_now_iso)
    version:    str = "4.0.0-NEXUS"
    checks:     list[HealthCheck] = field(default_factory=list)
    overall:    str = "UNKNOWN"

    @property
    def ok_count(self) -> int:
        return sum(1 for c in self.checks if c.status == "OK")

    @property
    def warn_count(self) -> int:
        return sum(1 for c in self.checks if c.status == "WARN")

    @property
    def fail_count(self) -> int:
        return sum(1 for c in self.checks if c.status == "FAIL")

    def compute_overall(self) -> str:
        if self.fail_count > 0:
            return "DEGRADED"
        if self.warn_count > 0:
            return "WARNING"
        return "HEALTHY"

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "version":   self.version,
            "overall":   self.overall,
            "summary":   {"ok": self.ok_count, "warn": self.warn_count, "fail": self.fail_count},
            "checks":    [{"name":c.name,"status":c.status,"message":c.message,"value":c.value,"latency_ms":round(c.latency_ms,2)} for c in self.checks],
        }


def _check(name: str, fn) -> HealthCheck:
    """Run a health check function and return result."""
    t0 = time.perf_counter()
    try:
        result = fn()
        latency = (time.perf_counter() - t0) * 1000
        if isinstance(result, HealthCheck):
            result.latency_ms = latency
            return result
        return HealthCheck(name=name, status="OK", message=str(result), latency_ms=latency)
    except Exception as exc:
        latency = (time.perf_counter() - t0) * 1000
        return HealthCheck(name=name, status="FAIL", message=str(exc), latency_ms=latency)


class SystemHealthChecker:
    """
    Comprehensive system health checker for Shadow313 NEXUS.
    """

    def __init__(self, kernel=None) -> None:
        self._kernel = kernel

    def check_all(self, quick: bool = False) -> HealthReport:
        """Run all health checks."""
        report = HealthReport()

        checks = [
            # Core
            ("Python Version",          self._check_python_version),
            ("Shadow313 Import",        self._check_shadow313_import),
            ("Config System",           self._check_config),
            ("Session System",          self._check_session),
            # Storage
            ("Storage Directory",       self._check_storage_dir),
            ("Disk Space",              self._check_disk_space),
            ("File Permissions",        self._check_permissions),
            # AI
            ("AI Engine Config",        self._check_ai_config),
            ("Ollama Connectivity",     self._check_ollama),
            # Modules
            ("V1 Modules",              self._check_v1_modules),
            ("V2 Modules",              self._check_v2_modules),
            ("V3 Modules",              self._check_v3_modules),
            ("V4 Modules",              self._check_v4_modules),
            # Crypto
            ("Cryptography Library",    self._check_cryptography),
            ("Temporal Binding",        self._check_temporal_binding),
            # Optional deps
            ("PyYAML",                  lambda: self._check_import("yaml", "pyyaml")),
            ("Rich",                    lambda: self._check_import("rich", "rich")),
            ("DNSPython",               lambda: self._check_import("dns", "dnspython", optional=True)),
            ("Cryptography",            lambda: self._check_import("cryptography", "cryptography", optional=True)),
            ("NetworkX",                lambda: self._check_import("networkx", "networkx", optional=True)),
            ("FastAPI",                 lambda: self._check_import("fastapi", "fastapi", optional=True)),
            ("ChromaDB",                lambda: self._check_import("chromadb", "chromadb", optional=True)),
            ("Scikit-learn",            lambda: self._check_import("sklearn", "scikit-learn", optional=True)),
        ]

        if not quick:
            checks.extend([
                ("Network Connectivity",    self._check_network),
                ("NVD API",                 self._check_nvd_api),
                ("EPSS API",                self._check_epss_api),
                ("Docker",                  self._check_docker),
                ("Security Config",         self._check_security_config),
                ("Ledger System",           self._check_ledger),
                ("Workflow Engine",         self._check_workflow),
            ])

        for name, fn in checks:
            check = _check(name, fn)
            report.checks.append(check)

        report.overall = report.compute_overall()
        return report

    # ── Individual checks ─────────────────────────────────────────────────────

    def _check_python_version(self) -> HealthCheck:
        version = sys.version_info
        if version >= (3, 11):
            return HealthCheck("Python Version", "OK",
                               f"Python {version.major}.{version.minor}.{version.micro}",
                               value=f"{version.major}.{version.minor}.{version.micro}")
        return HealthCheck("Python Version", "WARN",
                           f"Python {version.major}.{version.minor} — recommend 3.11+")

    def _check_shadow313_import(self) -> HealthCheck:
        import shadow313
        return HealthCheck("Shadow313 Import", "OK",
                           f"shadow313 {shadow313.__version__} ({shadow313.__codename__})",
                           value=shadow313.__version__)

    def _check_config(self) -> HealthCheck:
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            from shadow313.core.config import Config
            cfg = Config(config_path=Path(tmpdir) / "config.yaml")
            backend = cfg.get("ai", "backend", default="ollama")
            return HealthCheck("Config System", "OK",
                               f"Config loaded, AI backend: {backend}", value=backend)

    def _check_session(self) -> HealthCheck:
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            from shadow313.core.session import Session
            s = Session(sessions_dir=tmpdir)
            s.write("health.json", {"check": True})
            data = s.read("health.json")
            if data and data.get("check"):
                return HealthCheck("Session System", "OK",
                                   f"Session {s.id[:8]}… created and verified")
            return HealthCheck("Session System", "FAIL", "Session write/read failed")

    def _check_storage_dir(self) -> HealthCheck:
        storage = Path("~/.shadow313").expanduser()
        if not storage.exists():
            storage.mkdir(parents=True, exist_ok=True)
            return HealthCheck("Storage Directory", "WARN",
                               f"Created {storage} (first run)")
        subdirs = ["sessions","plugins","wordlists","logs","data","reports","receipts"]
        missing = [d for d in subdirs if not (storage / d).exists()]
        if missing:
            for d in missing:
                (storage / d).mkdir(parents=True, exist_ok=True)
            return HealthCheck("Storage Directory", "WARN",
                               f"Created missing subdirs: {missing}")
        return HealthCheck("Storage Directory", "OK",
                           f"{storage} — all subdirs present", value=str(storage))

    def _check_disk_space(self) -> HealthCheck:
        storage = Path("~/.shadow313").expanduser()
        try:
            usage = shutil.disk_usage(storage)
            free_gb = usage.free / (1024**3)
            total_gb = usage.total / (1024**3)
            pct_used = (usage.used / usage.total) * 100
            if free_gb < 1.0:
                return HealthCheck("Disk Space", "FAIL",
                                   f"Only {free_gb:.1f}GB free — Shadow313 needs at least 1GB",
                                   value=f"{free_gb:.1f}GB free")
            if free_gb < 5.0:
                return HealthCheck("Disk Space", "WARN",
                                   f"{free_gb:.1f}GB free ({pct_used:.0f}% used)",
                                   value=f"{free_gb:.1f}GB free")
            return HealthCheck("Disk Space", "OK",
                               f"{free_gb:.1f}GB free of {total_gb:.0f}GB ({pct_used:.0f}% used)",
                               value=f"{free_gb:.1f}GB free")
        except Exception as exc:
            return HealthCheck("Disk Space", "WARN", f"Could not check disk space: {exc}")

    def _check_permissions(self) -> HealthCheck:
        storage = Path("~/.shadow313").expanduser()
        issues = []
        for path in [storage, storage / "sessions"]:
            if path.exists():
                mode = oct(path.stat().st_mode)[-3:]
                if mode[2] != "0":  # World-writable
                    issues.append(f"{path} is world-writable ({mode})")
        if issues:
            return HealthCheck("File Permissions", "WARN", "; ".join(issues))
        return HealthCheck("File Permissions", "OK", "Storage permissions look secure")

    def _check_ai_config(self) -> HealthCheck:
        if not self._kernel:
            return HealthCheck("AI Engine Config", "SKIP", "No kernel available")
        backend  = self._kernel.ai.backend
        model    = self._kernel.ai.model
        endpoint = self._kernel.ai.endpoint
        return HealthCheck("AI Engine Config", "OK",
                           f"Backend: {backend}, Model: {model}, Endpoint: {endpoint}",
                           value={"backend": backend, "model": model})

    def _check_ollama(self) -> HealthCheck:
        if not self._kernel:
            return HealthCheck("Ollama Connectivity", "SKIP", "No kernel available")
        if self._kernel.ai.backend == "disabled":
            return HealthCheck("Ollama Connectivity", "SKIP", "AI backend disabled")
        if self._kernel.ai.backend != "ollama":
            return HealthCheck("Ollama Connectivity", "SKIP",
                               f"Using {self._kernel.ai.backend} backend")
        available = self._kernel.ai.is_available()
        if available:
            models = self._kernel.ai.list_models()
            return HealthCheck("Ollama Connectivity", "OK",
                               f"Connected, {len(models)} models available",
                               value=models[:3])
        return HealthCheck("Ollama Connectivity", "WARN",
                           f"Ollama not reachable at {self._kernel.ai.endpoint}. "
                           "Install: https://ollama.com")

    def _check_v1_modules(self) -> HealthCheck:
        if not self._kernel:
            return HealthCheck("V1 Modules", "SKIP", "No kernel available")
        v1_modules = ["recon","vuln","exploit","network","defense","quantum","plugins","cicd","docs"]
        loaded = [m for m in v1_modules if m in self._kernel._modules]
        missing = [m for m in v1_modules if m not in self._kernel._modules]
        if missing:
            return HealthCheck("V1 Modules", "WARN",
                               f"Missing: {missing}", value={"loaded": len(loaded), "missing": missing})
        return HealthCheck("V1 Modules", "OK",
                           f"All {len(v1_modules)} V1 modules loaded", value=len(loaded))

    def _check_v2_modules(self) -> HealthCheck:
        if not self._kernel:
            return HealthCheck("V2 Modules", "SKIP", "No kernel available")
        v2_modules = ["rag","agent","epss","kev","attack_map","ml_anomaly","ja3","dns_covert",
                      "campaign","graph","dashboard","report","plugin_sign","threat_intel",
                      "sandbox","cloud","crypto_agility"]
        loaded  = [m for m in v2_modules if m in self._kernel._modules]
        missing = [m for m in v2_modules if m not in self._kernel._modules]
        status  = "OK" if not missing else "WARN"
        return HealthCheck("V2 Modules", status,
                           f"{len(loaded)}/{len(v2_modules)} V2 modules loaded",
                           value={"loaded": len(loaded), "missing": missing[:5]})

    def _check_v3_modules(self) -> HealthCheck:
        if not self._kernel:
            return HealthCheck("V3 Modules", "SKIP", "No kernel available")
        v3_modules = ["browser_recon","container_scan","ad_audit","siem","collab","malware"]
        loaded  = [m for m in v3_modules if m in self._kernel._modules]
        missing = [m for m in v3_modules if m not in self._kernel._modules]
        status  = "OK" if not missing else "WARN"
        return HealthCheck("V3 Modules", status,
                           f"{len(loaded)}/{len(v3_modules)} V3 modules loaded",
                           value={"loaded": len(loaded), "missing": missing})

    def _check_v4_modules(self) -> HealthCheck:
        if not self._kernel:
            return HealthCheck("V4 Modules", "SKIP", "No kernel available")
        v4_modules = ["temporal","nexus","stix","mobile_api","finetune","orchestrate",
                      "nexus_router","ledger","workflow","tools","simulate","benchmark",
                      "health_check","vanguard","aegis","ghost_watch","quantum_nexus",
                      "satellite","threat_actor","update"]
        loaded  = [m for m in v4_modules if m in self._kernel._modules]
        missing = [m for m in v4_modules if m not in self._kernel._modules]
        status  = "OK" if len(missing) <= 3 else "WARN"
        return HealthCheck("V4 Modules", status,
                           f"{len(loaded)}/{len(v4_modules)} V4 modules loaded",
                           value={"loaded": len(loaded), "missing": missing[:5]})

    def _check_cryptography(self) -> HealthCheck:
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            import os
            key = os.urandom(32)
            nonce = os.urandom(12)
            aesgcm = AESGCM(key)
            ct = aesgcm.encrypt(nonce, b"health check", None)
            pt = aesgcm.decrypt(nonce, ct, None)
            assert pt == b"health check"
            return HealthCheck("Cryptography Library", "OK",
                               "AES-256-GCM encrypt/decrypt verified")
        except ImportError:
            return HealthCheck("Cryptography Library", "WARN",
                               "cryptography library not installed — encrypted sessions unavailable. "
                               "Install: pip install cryptography")

    def _check_temporal_binding(self) -> HealthCheck:
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            from shadow313.v4.temporal_binding.temporal_binding import TemporalBindingEngine
            engine  = TemporalBindingEngine(receipts_dir=Path(tmpdir), ipfs_enabled=False)
            receipt = engine.bind({"health_check": True})
            if receipt.timestamp % 1000 == 313:
                return HealthCheck("Temporal Binding", "OK",
                                   f"313-BIND receipt: {receipt.receipt_id}",
                                   value=receipt.receipt_id)
            return HealthCheck("Temporal Binding", "FAIL",
                               f"Timestamp {receipt.timestamp} does not end in 313")

    def _check_import(self, module: str, package: str, optional: bool = False) -> HealthCheck:
        try:
            importlib.import_module(module)
            return HealthCheck(package, "OK", f"{package} available")
        except ImportError:
            status = "WARN" if optional else "FAIL"
            return HealthCheck(package, status,
                               f"{package} not installed. Install: pip install {package}")

    def _check_network(self) -> HealthCheck:
        from urllib import request as urlreq
        try:
            req = urlreq.Request("https://api.first.org/data/v1/epss?cve=CVE-2021-44228",
                                 headers={"User-Agent": "shadow313/4.0"})
            with urlreq.urlopen(req, timeout=5) as resp:
                return HealthCheck("Network Connectivity", "OK",
                                   f"Internet reachable (HTTP {resp.status})")
        except Exception as exc:
            return HealthCheck("Network Connectivity", "WARN",
                               f"Internet not reachable: {exc}. Offline mode active.")

    def _check_nvd_api(self) -> HealthCheck:
        from urllib import request as urlreq
        try:
            req = urlreq.Request(
                "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1",
                headers={"User-Agent": "shadow313/4.0"}
            )
            with urlreq.urlopen(req, timeout=10) as resp:
                return HealthCheck("NVD API", "OK", f"NVD API reachable (HTTP {resp.status})")
        except Exception as exc:
            return HealthCheck("NVD API", "WARN", f"NVD API unreachable: {exc}")

    def _check_epss_api(self) -> HealthCheck:
        from urllib import request as urlreq
        try:
            req = urlreq.Request(
                "https://api.first.org/data/v1/epss?cve=CVE-2021-44228",
                headers={"User-Agent": "shadow313/4.0"}
            )
            with urlreq.urlopen(req, timeout=10) as resp:
                return HealthCheck("EPSS API", "OK", f"EPSS API reachable (HTTP {resp.status})")
        except Exception as exc:
            return HealthCheck("EPSS API", "WARN", f"EPSS API unreachable: {exc}")

    def _check_docker(self) -> HealthCheck:
        import subprocess
        try:
            result = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
            if result.returncode == 0:
                return HealthCheck("Docker", "OK", "Docker daemon running")
            return HealthCheck("Docker", "WARN", "Docker installed but daemon not running")
        except FileNotFoundError:
            return HealthCheck("Docker", "WARN",
                               "Docker not installed — CVE sandbox unavailable. "
                               "Install: https://docs.docker.com/engine/install/")
        except Exception as exc:
            return HealthCheck("Docker", "WARN", f"Docker check failed: {exc}")

    def _check_security_config(self) -> HealthCheck:
        if not self._kernel:
            return HealthCheck("Security Config", "SKIP", "No kernel available")
        issues = []
        cfg = self._kernel.config

        # Check plugin signing
        if not cfg.get("plugins", "require_signed", default=False):
            issues.append("Plugin signing disabled (require_signed: false)")

        # Check session encryption
        if not cfg.get("storage", "encrypt", default=False):
            issues.append("Session encryption disabled")

        # Check AI backend
        if cfg.get("ai", "backend", default="ollama") == "openai":
            api_key = os.environ.get("OPENAI_API_KEY", "")
            if not api_key:
                issues.append("OpenAI backend configured but OPENAI_API_KEY not set")

        if issues:
            return HealthCheck("Security Config", "WARN",
                               f"{len(issues)} security config issues: {'; '.join(issues)}")
        return HealthCheck("Security Config", "OK", "Security configuration looks good")

    def _check_ledger(self) -> HealthCheck:
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            from shadow313.v4.ledger.ledger_engine import LedgerSyncEngine
            engine = LedgerSyncEngine(
                node_id="health-check", peer_nodes=["p1"],
                ledger_dir=str(Path(tmpdir) / "ledger")
            )
            entry = engine.append("health_check", {"status": "ok"})
            health = engine.health_check()
            return HealthCheck("Ledger System", "OK",
                               f"Ledger operational, epoch {health['epoch']}, seq {entry.sequence}",
                               value=health)

    def _check_workflow(self) -> HealthCheck:
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            from shadow313.v4.workflow.workflow_engine import WorkflowEngine, WorkflowDefinition, WorkflowNode
            engine = WorkflowEngine(log_dir=tmpdir)
            wf = WorkflowDefinition(
                workflow_id="health-wf", name="Health Check",
                steps=[WorkflowNode(node_id="s1", node_type="builtin.schema_validate")],
            )
            engine.register(wf)
            result = engine.execute("health-wf")
            if result.get("status") == "complete":
                return HealthCheck("Workflow Engine", "OK",
                                   f"Workflow executed in {result.get('latency_ms',0)}ms")
            return HealthCheck("Workflow Engine", "WARN",
                               f"Workflow status: {result.get('status','unknown')}")


class HealthModule:
    """shadow313.v4.health — System Health Check. Registered: health_check"""

    def __init__(self, kernel) -> None:
        self.kernel  = kernel
        self.out     = kernel.out
        self.checker = SystemHealthChecker(kernel)

    def register(self, kernel) -> None:
        kernel.register("health_check", self.run)

    def run(
        self,
        quick:  bool = False,
        full:   bool = False,
        save:   str  = "",
        json_output:bool = False,
    ) -> dict:
        self.out.section("SHADOW313 NEXUS — SYSTEM HEALTH CHECK")

        if not quick and not full:
            quick = True  # Default

        self.out.info(f"Running {'quick' if quick else 'full'} health check …")
        report = self.checker.check_all(quick=quick)

        # Display results
        rows = []
        for check in report.checks:
            icon = {"OK":"✓","WARN":"⚠","FAIL":"✗","SKIP":"○"}.get(check.status,"?")
            rows.append([f"{icon} {check.name}", check.status,
                         check.message[:60], f"{check.latency_ms:.1f}ms"])

        self.out.table(["Check","Status","Message","Latency"], rows,
                       f"Health Report — {report.overall}")

        # Summary
        if report.overall == "HEALTHY":
            self.out.success(f"System HEALTHY: {report.ok_count} OK, {report.warn_count} WARN, {report.fail_count} FAIL")
        elif report.overall == "WARNING":
            self.out.warn(f"System WARNING: {report.ok_count} OK, {report.warn_count} WARN, {report.fail_count} FAIL")
        else:
            self.out.error(f"System DEGRADED: {report.ok_count} OK, {report.warn_count} WARN, {report.fail_count} FAIL")

        report_dict = report.to_dict()

        if save:
            Path(save).write_text(json.dumps(report_dict, indent=2))
            self.out.success(f"Health report saved → {save}")

        return report_dict