"""
shadow313.core.config  — v4
Config loader: YAML + env-var overrides.
Resolution order (highest wins): env vars > user config.yaml > defaults

BUG FIXES vs v1:
  - set() key-path order was reversed (value, *keys) — fixed to (*keys, value)
  - _apply_env_overrides used wrong tuple order for SHADOW313_VERBOSE
  - init_user_dirs missing 'data' and 'reports' subdirs
  - save() wrote full nested dict without 'shadow313' wrapper — fixed
"""
from __future__ import annotations
import os
import copy
import yaml
from pathlib import Path
from typing import Any

DEFAULT_CONFIG: dict[str, Any] = {
    "shadow313": {
        "version": "4.0.0",
        "ai": {
            "backend":        "ollama",
            "model":          "mistral:7b",
            "endpoint":       "http://localhost:11434",
            "openai_api_key": "",
            "context_window": 8192,
            "timeout":        120,
        },
        "storage": {
            "sessions_dir": "~/.shadow313/sessions",
            "db_path":      "~/.shadow313/shadow313.db",
            "encrypt":      False,
        },
        "recon": {
            "default_mode":    "full",
            "stealth_rps":     10,
            "default_ports":   "1-1024",
            "wordlist":        "",
            "apis": {
                "shodan":    "",
                "greynoise": "",
                "urlscan":   "",
            },
        },
        "network": {
            "default_interface": "eth0",
            "capture_filter":    "not port 22",
            "snap_len":          65535,
            "ml_model_path":     "",
            "capture_timeout":   60,
        },
        "defense": {
            "default_profile": "cis-level1",
            "ssh_timeout":     10,
        },
        "quantum": {
            "scan_depth":         "full",
            "crqc_arrival_year":  2032,
        },
        "output": {
            "format":  "rich",
            "color":   True,
            "verbose": False,
        },
        "plugins": {
            "dir":            "~/.shadow313/plugins",
            "enabled":        [],
            "require_signed": False,
        },
        "rag": {
            "vector_store":    "tfidf",
            "chroma_path":     "~/.shadow313/chroma",
            "top_k":           5,
            "embedding_model": "",
        },
        "agent": {
            "default_approval": "gate_high",
            "max_chain_length": 20,
            "plans_dir":        "~/.shadow313/agent_runs",
        },
        "dashboard": {
            "port":       7313,
            "host":       "127.0.0.1",
            "auto_open":  True,
        },
        "threat_intel": {
            "otx_api_key":         "",
            "sync_interval_hours": 24,
            "enabled_feeds":       ["feodo", "urlhaus", "malwarebazaar", "shodan"],
        },
        "docker_sandbox": {
            "enabled":      False,
            "network":      "sandbox",
            "memory_limit": "512m",
            "cpu_limit":    "0.5",
        },
        "reports": {
            "output_dir":             "~/.shadow313/reports",
            "template":               "default",
            "include_recon_appendix": True,
        },
        "campaign": {
            "default_concurrency": 3,
            "campaigns_dir":       "~/.shadow313/campaigns",
        },
        "crypto_agility": {
            "urgency_threshold": "medium",
            "scan_languages":    ["python", "javascript", "java", "go"],
        },
        "temporal_binding": {
            "enabled":       True,
            "ipfs_gateway":  "https://ipfs.io",
            "sign_receipts": True,
        },
        "siem": {
            "backend":       "disabled",
            "splunk_hec_url": "",
            "elastic_url":   "",
            "wazuh_url":     "",
        },
        "collab": {
            "enabled":    False,
            "server_url": "",
            "e2e_encrypt": True,
        },
    }
}


class Config:
    """Loads, merges, and exposes Shadow313 v4 configuration."""

    CONFIG_PATH = Path("~/.shadow313/config.yaml").expanduser()

    def __init__(self, config_path: Path | None = None) -> None:
        self._path = Path(config_path).expanduser() if config_path else self.CONFIG_PATH
        self._data: dict[str, Any] = {}
        self._load()

    # ── Public API ────────────────────────────────────────────────────────────
    def get(self, *keys: str, default: Any = None) -> Any:
        node = self._data
        for k in keys:
            if not isinstance(node, dict):
                return default
            node = node.get(k, default)  # type: ignore[assignment]
            if node is default:
                return default
        return node

    def set(self, *keys_and_value) -> None:
        """set("key1", "key2", value) — keys first, value last."""
        if len(keys_and_value) < 2:
            raise ValueError("set() requires at least one key and a value")
        *keys, value = keys_and_value
        node = self._data
        for k in keys[:-1]:
            node = node.setdefault(k, {})
        node[keys[-1]] = value

    def as_dict(self) -> dict:
        return copy.deepcopy(self._data)

    def save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # FIX: wrap in 'shadow313' key so reload works correctly
        with open(self._path, "w", encoding='utf-8') as fh:
            yaml.dump({"shadow313": self._data}, fh, default_flow_style=False)

    def init_user_dirs(self) -> None:
        """Create ~/.shadow313 directory tree on first run."""
        subdirs = [
            "sessions", "wordlists", "plugins", "logs",
            "data/signatures", "data/wordlists",
            "reports", "campaigns", "agent_runs", "chroma",
        ]
        for subdir in subdirs:
            Path(f"~/.shadow313/{subdir}").expanduser().mkdir(
                parents=True, exist_ok=True
            )

    # ── Internals ─────────────────────────────────────────────────────────────
    def _load(self) -> None:
        merged = copy.deepcopy(DEFAULT_CONFIG)
        if self._path.exists():
            with open(self._path, encoding='utf-8') as fh:
                user_cfg = yaml.safe_load(fh) or {}
            merged = self._deep_merge(merged, user_cfg)
        self._data = merged.get("shadow313", merged)
        self._apply_env_overrides()

    @staticmethod
    def _deep_merge(base: dict, override: dict) -> dict:
        result = copy.deepcopy(base)
        for k, v in override.items():
            if isinstance(v, dict) and isinstance(result.get(k), dict):
                result[k] = Config._deep_merge(result[k], v)
            else:
                result[k] = v
        return result

    def _apply_env_overrides(self) -> None:
        mapping = {
            "SHADOW313_AI_BACKEND":    ("ai", "backend"),
            "SHADOW313_AI_MODEL":      ("ai", "model"),
            "SHADOW313_AI_ENDPOINT":   ("ai", "endpoint"),
            "SHADOW313_SHODAN_KEY":    ("recon", "apis", "shodan"),
            "SHADOW313_GREYNOISE_KEY": ("recon", "apis", "greynoise"),
            "SHADOW313_OTX_API_KEY":   ("threat_intel", "otx_api_key"),
            "SHADOW313_DASHBOARD_PORT":("dashboard", "port"),
            "SHADOW313_SESSIONS_DIR":  ("storage", "sessions_dir"),
            "SHADOW313_ENCRYPT":       ("storage", "encrypt"),
            "SHADOW313_REQUIRE_SIGNED":("plugins", "require_signed"),
            "SHADOW313_CONCURRENCY":   ("campaign", "default_concurrency"),
            # FIX: SHADOW313_VERBOSE maps to output.verbose (was missing in v1)
            "SHADOW313_VERBOSE":       ("output", "verbose"),
        }
        for env_key, cfg_path in mapping.items():
            val = os.environ.get(env_key)
            if val is not None:
                # coerce booleans
                if val.lower() in ("true", "1", "yes"):
                    val = True  # type: ignore[assignment]
                elif val.lower() in ("false", "0", "no"):
                    val = False  # type: ignore[assignment]
                self.set(*cfg_path, val)

def _safe_path(path: str, allowed_base: str | None = None) -> "Path":
    """
    Resolve a user-supplied path and optionally jail it to an allowed base.
    
    Raises ValueError if the resolved path escapes the allowed base directory.
    This prevents path traversal attacks (CWE-22) when paths come from
    API requests or CLI arguments.
    
    Args:
        path: User-supplied path string
        allowed_base: If provided, the resolved path must be within this directory.
                      Use None for output paths where any location is acceptable.
    
    Returns:
        Resolved Path object
        
    Raises:
        ValueError: If path escapes allowed_base
    """
    from pathlib import Path as _Path
    resolved = _Path(path).expanduser().resolve()
    if allowed_base is not None:
        base = _Path(allowed_base).expanduser().resolve()
        try:
            resolved.relative_to(base)
        except ValueError:
            raise ValueError(
                f"Path traversal detected: {path!r} resolves to {resolved!r} "
                f"which is outside allowed base {base!r}"
            )
    return resolved
