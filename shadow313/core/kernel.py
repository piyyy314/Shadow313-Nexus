"""
shadow313.core.kernel  — v4
Central orchestration layer: module registry, command bus, lifecycle management.

BUG FIXES vs v1:
  - _autoload_modules() silently swallowed ImportError for ALL modules even
    when the module file existed but had a syntax error — now distinguishes
    ModuleNotFoundError (optional dep missing) from other errors.
  - dispatch() caught KeyboardInterrupt but re-raised nothing, leaving the
    process in an undefined state — now re-raises after logging.
  - ai_status() called list_models() even when backend was 'disabled' — fixed.
  - Kernel had no __repr__ for debugging — added.
"""
from __future__ import annotations
import importlib
import time
import traceback
from typing import Any, Callable

from .config    import Config
from .session   import Session
from .output    import OutputFormatter
from .ai_engine import AIEngine


class Kernel:
    """
    Shadow313 Core Kernel — v4.
    Bootstraps all modules, routes commands, manages session state.
    Command-bus pattern: modules register handlers via register().
    """

    def __init__(
        self,
        config_path: str | None = None,
        session_id: str | None = None,
        output_fmt: str | None = None,
        verbose: bool = False,
    ) -> None:
        self.config  = Config(config_path)
        self.session = Session(
            sessions_dir = self.config.get("storage", "sessions_dir",
                                           default="~/.shadow313/sessions"),
            session_id   = session_id,
            encrypt      = self.config.get("storage", "encrypt", default=False),
        )
        fmt = output_fmt or self.config.get("output", "format", default="rich")
        self.out = OutputFormatter(
            fmt     = fmt,
            color   = self.config.get("output", "color",   default=True),
            verbose = verbose or self.config.get("output", "verbose", default=False),
        )
        self.ai = AIEngine(self.config.get("ai", default={}))

        # Module registry: namespace → handler callable
        self._registry: dict[str, Callable] = {}
        self._modules:  dict[str, Any]      = {}

        # Auto-load all built-in modules
        self._autoload_modules()

    # ── Module registry ───────────────────────────────────────────────────────
    def register(self, namespace: str, handler: Callable) -> None:
        self._registry[namespace] = handler

    def dispatch(self, namespace: str, **kwargs) -> Any:
        if namespace not in self._registry:
            self.out.error(f"Unknown command namespace: '{namespace}'")
            return None
        self.session.audit("kernel", f"dispatch:{namespace}")
        try:
            return self._registry[namespace](**kwargs)
        except KeyboardInterrupt:
            self.out.warn("\nInterrupted by user.")
            raise  # FIX: re-raise so the process can exit cleanly
        except Exception as exc:
            self.out.error(f"Module '{namespace}' raised: {exc}")
            if self.out.verbose:
                traceback.print_exc()
            return None

    def get_module(self, name: str) -> Any | None:
        return self._modules.get(name)

    # ── Auto-loader ───────────────────────────────────────────────────────────
    _BUILTIN_MODULES = [
        # V1 modules
        ("recon",   "shadow313.modules.recon.ReconModule"),
        ("vuln",    "shadow313.modules.vuln.VulnModule"),
        ("exploit", "shadow313.modules.exploit.ExploitModule"),
        ("network", "shadow313.modules.network.NetworkModule"),
        ("defense", "shadow313.modules.defense.DefenseModule"),
        ("quantum", "shadow313.modules.quantum.QuantumModule"),
        ("plugins", "shadow313.modules.plugins.PluginManager"),
        ("cicd",    "shadow313.modules.cicd.CICDModule"),
        ("docs",    "shadow313.modules.docs.DocsModule"),
        # V2 modules
        ("rag",          "shadow313.v2.rag.rag_engine.RAGModule"),
        ("agent",        "shadow313.v2.agent.agent.AgentModule"),
        ("epss",         "shadow313.v2.vuln_upgrades.epss_kev.EPSSModule"),
        ("kev",          "shadow313.v2.vuln_upgrades.epss_kev.KEVModule"),
        ("attack_map",   "shadow313.v2.vuln_upgrades.attack_mapping.ATTACKModule"),
        ("ml_anomaly",   "shadow313.v2.network_upgrades.ml_anomaly.MLAnomalyModule"),
        ("ja3",          "shadow313.v2.network_upgrades.ja3_fingerprint.JA3Module"),
        ("dns_covert",   "shadow313.v2.network_upgrades.dns_covert.DNSCovertModule"),
        ("campaign",     "shadow313.v2.campaign.campaign.CampaignModule"),
        ("graph",        "shadow313.v2.graph.intel_graph.GraphModule"),
        ("dashboard",    "shadow313.v2.dashboard.app.DashboardModule"),
        ("report",       "shadow313.v2.reports.pdf_report.ReportModule"),
        ("plugin_sign",  "shadow313.v2.plugin_signing.plugin_signer.PluginSignerModule"),
        ("threat_intel", "shadow313.v2.threat_intel.threat_intel.ThreatIntelModule"),
        ("sandbox",      "shadow313.v2.docker_sandbox.docker_sandbox.SandboxModule"),
        ("cloud",        "shadow313.v2.cloud_hardening.cloud_hardening.CloudModule"),
        ("crypto_agility","shadow313.v2.crypto_agility.crypto_agility.CryptoAgilityModule"),
        # V3 modules
        ("browser_recon","shadow313.v3.browser_recon.browser_recon.BrowserReconModule"),
        ("container_scan","shadow313.v3.container_scan.container_scan.ContainerScanModule"),
        ("ad_audit",     "shadow313.v3.ad_auditor.ad_auditor.ADAuditModule"),
        ("siem",         "shadow313.v3.siem.siem.SIEMModule"),
        ("collab",       "shadow313.v3.collab.collab.CollabModule"),
        ("malware",      "shadow313.v3.malware_sandbox.malware_sandbox.MalwareSandboxModule"),
        # V4 NEXUS Complete modules
        ("orchestrate",  "shadow313.v4.agent.orchestrator.OrchestratorModule"),
        ("nexus_router", "shadow313.v4.nexus_router.nexus_router.NexusRouterModule"),
        ("ledger",       "shadow313.v4.ledger.ledger_engine.LedgerModule"),
        ("workflow",     "shadow313.v4.workflow.workflow_engine.WorkflowModule"),
        ("tools",        "shadow313.v4.tools.advanced_tools.AdvancedToolsModule"),
        ("simulate",     "shadow313.v4.simulation.simulation_harness.SimulationModule"),
        ("benchmark",    "shadow313.v4.benchmarks.benchmark_suite.BenchmarkModule"),
        ("health_check", "shadow313.v4.health.health_check.HealthModule"),
        ("update",       "shadow313.v4.update.updater.UpdateModule"),
        ("vanguard",     "shadow313.v4.vanguard.vanguard.VanguardModule"),
        ("aegis",        "shadow313.v4.aegis.aegis.AegisModule"),
        ("ghost_watch",  "shadow313.v4.ghost_watch.ghost_watch.GhostWatchModule"),
        ("quantum_nexus","shadow313.v4.quantum_nexus.quantum_nexus.QuantumNEXUSModule"),
        ("satellite",    "shadow313.v4.satellite.satellite.SatelliteModule"),
        ("threat_actor", "shadow313.v4.threat_actor.threat_actor.ThreatActorModule"),
        # V4 Aegis sub-modules
        ("pe_analyze",   "shadow313.v4.aegis.pe_analyzer.PEAnalyzerModule"),
        ("dns_intercept_ot", "shadow313.v4.aegis.dns_intercept.DNSInterceptModule"),
    ]

    def _autoload_modules(self) -> None:
        for name, cls_path in self._BUILTIN_MODULES:
            try:
                mod_path, cls_name = cls_path.rsplit(".", 1)
                module   = importlib.import_module(mod_path)
                cls      = getattr(module, cls_name)
                instance = cls(kernel=self)
                self._modules[name] = instance
                if hasattr(instance, "register"):
                    instance.register(self)
            except ModuleNotFoundError as exc:
                # Optional dependency missing — expected, log at verbose level
                self.out.verbose_msg(
                    f"[kernel] Module '{name}' skipped (missing dep): {exc}"
                )
            except ImportError as exc:
                # FIX: distinguish import errors from syntax/runtime errors
                self.out.verbose_msg(
                    f"[kernel] Module '{name}' import error: {exc}"
                )
            except Exception as exc:
                # Unexpected error — always log
                self.out.verbose_msg(
                    f"[kernel] Module '{name}' init error: {type(exc).__name__}: {exc}"
                )

    # ── Session / config helpers ──────────────────────────────────────────────
    def print_session_info(self) -> None:
        self.out.result(self.session.summary(), title="Session Info")

    def ai_status(self) -> dict:
        available = self.ai.is_available()
        # FIX: don't call list_models() when backend is disabled
        models = []
        if available and self.ai.backend == "ollama":
            models = self.ai.list_models()
        return {
            "backend":   self.ai.backend,
            "model":     self.ai.model,
            "endpoint":  self.ai.endpoint,
            "available": available,
            "models":    models,
        }

    def __repr__(self) -> str:
        return (
            f"<Kernel v4 session={self.session.id[:8]}... "
            f"modules={list(self._modules.keys())} "
            f"ai={self.ai.backend}>"
        )