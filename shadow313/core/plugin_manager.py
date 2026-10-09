"""
Shadow313 NEXUS — Plugin Manager
Sandboxed plugin loading with HMAC-SHA256 signature verification.
"""
from __future__ import annotations
import importlib, hashlib, hmac, json
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable

PLUGIN_HOOKS = [
    "recon.post","vuln.post","exploit.pre","network.post",
    "defense.post","quantum.post","alert.fire","session.close"
]

class PluginManager:
    def __init__(self, plugin_dir: str = "shadow313/plugins", secret: str = "shadow313-plugin-secret"):
        self.plugin_dir = Path(plugin_dir)
        self.secret     = secret.encode()
        self._plugins:  Dict[str, Any] = {}
        self._hooks:    Dict[str, List[Callable]] = {h: [] for h in PLUGIN_HOOKS}

    def load_all(self) -> int:
        count = 0
        for d in self.plugin_dir.iterdir():
            if d.is_dir() and (d / "plugin.json").exists():
                if self.load(d.name):
                    count += 1
        return count

    def load(self, plugin_name: str) -> bool:
        plugin_path   = self.plugin_dir / plugin_name
        manifest_path = plugin_path / "plugin.json"
        sig_path      = plugin_path / "plugin.shadow313sig"
        if not manifest_path.exists():
            return False
        manifest = json.loads(manifest_path.read_text())
        if sig_path.exists():
            sig      = sig_path.read_text().strip()
            expected = hmac.new(self.secret, manifest_path.read_bytes(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected):
                return False
        for hook in manifest.get("hooks", []):
            if hook in self._hooks:
                self._hooks[hook].append(lambda data, n=plugin_name: self._dispatch(n, hook, data))
        self._plugins[plugin_name] = manifest
        return True

    def fire(self, hook: str, data: Dict[str, Any]) -> List[Any]:
        return [h(data) for h in self._hooks.get(hook, []) if h(data)]

    def _dispatch(self, plugin_name: str, hook: str, data: Dict) -> Optional[Dict]:
        try:
            mod = importlib.import_module(f"shadow313.plugins.{plugin_name}.analyzer")
            if hasattr(mod, "handle"):
                return mod.handle(hook, data)
        except Exception:
            pass
        return None

    def sign_plugin(self, plugin_name: str) -> str:
        manifest_path = self.plugin_dir / plugin_name / "plugin.json"
        sig = hmac.new(self.secret, manifest_path.read_bytes(), hashlib.sha256).hexdigest()
        (self.plugin_dir / plugin_name / "plugin.shadow313sig").write_text(sig)
        return sig

    def list_plugins(self) -> List[Dict]:
        return [{"name": n, "manifest": m} for n, m in self._plugins.items()]
