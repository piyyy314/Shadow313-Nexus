"""
shadow313.modules.plugins  — v4
Plugin system: YAML manifests, sandboxed subprocess execution, JSON-IPC.
"""
from __future__ import annotations
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


MANIFEST_TEMPLATE = """\
name: my-plugin
version: 1.0.0
author: handle
description: Short description of what this plugin does
hooks:
  - recon.post
entry: plugin.py
requires: []
shadow313_min_version: "4.0.0"
"""

PLUGIN_ENTRY_TEMPLATE = """\
#!/usr/bin/env python3
\"\"\"{name} — Shadow313 Plugin\nHook: {hook}\"\"\"
import json, sys

def main():
    ctx = json.load(sys.stdin)
    result = {{"plugin": "{name}", "status": "ok", "data": {{}}}}
    print(json.dumps(result))

if __name__ == "__main__":
    main()
"""

VALID_HOOKS = {
    "recon.post","vuln.post","network.post","defense.post","quantum.post",
    "exploit.post","output.transform","ask.pre","session.start","session.end",
}


class PluginManifest:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._data: dict = {}
        self._load()

    def _load(self) -> None:
        manifest_file = self.path / "plugin.yaml"
        if not manifest_file.exists():
            manifest_file = self.path / "manifest.yaml"
        if not manifest_file.exists():
            raise FileNotFoundError(f"No plugin.yaml in {self.path}")
        if _HAS_YAML:
            with open(manifest_file, encoding='utf-8') as fh:
                self._data = yaml.safe_load(fh) or {}
        else:
            self._data = self._minimal_parse(manifest_file.read_text())

    @staticmethod
    def _minimal_parse(text: str) -> dict:
        data: dict[str,Any] = {}
        current_list = None
        for line in text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            if line.startswith("  - "):
                if current_list is not None:
                    data[current_list].append(line[4:].strip())
            elif ":" in line:
                key, _, val = line.partition(":")
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if val:
                    data[key] = val
                else:
                    data[key] = []
                    current_list = key
        return data

    @property
    def name(self) -> str:
        return self._data.get("name", self.path.name)

    @property
    def version(self) -> str:
        return str(self._data.get("version","0.0.0"))

    @property
    def description(self) -> str:
        return self._data.get("description","")

    @property
    def author(self) -> str:
        return self._data.get("author","unknown")

    @property
    def hooks(self) -> list[str]:
        return self._data.get("hooks",[])

    @property
    def entry(self) -> str:
        return self._data.get("entry","plugin.py")

    @property
    def requires(self) -> list[str]:
        return self._data.get("requires",[])

    @property
    def entry_path(self) -> Path:
        return self.path / self.entry

    def validate(self) -> list[str]:
        errors = []
        if not self.name:
            errors.append("Missing 'name' field")
        if not self.entry_path.exists():
            errors.append(f"Entry file not found: {self.entry_path}")
        for hook in self.hooks:
            if hook not in VALID_HOOKS:
                errors.append(f"Invalid hook '{hook}'")
        return errors

    def to_dict(self) -> dict:
        return {
            "name":self.name,"version":self.version,"description":self.description,
            "author":self.author,"hooks":self.hooks,"entry":self.entry,
            "requires":self.requires,"path":str(self.path),
        }


class PluginExecutor:
    TIMEOUT = 30

    def __init__(self, manifest: PluginManifest) -> None:
        self.manifest = manifest

    def execute(self, context: dict) -> dict:
        scoped_ctx = self._build_scoped_context(context)
        input_json = json.dumps(scoped_ctx)
        try:
            proc = subprocess.run(
                [sys.executable, str(self.manifest.entry_path)],
                input=input_json, capture_output=True, text=True,
                timeout=self.TIMEOUT, cwd=str(self.manifest.path),
                env={**os.environ,"SHADOW313_PLUGIN_MODE":"1","PYTHONPATH":str(self.manifest.path)},
            )
            if proc.returncode != 0:
                return {"plugin":self.manifest.name,"status":"error","error":proc.stderr[:500]}
            if not proc.stdout.strip():
                return {"plugin":self.manifest.name,"status":"no_output"}
            try:
                return json.loads(proc.stdout)
            except json.JSONDecodeError:
                return {"plugin":self.manifest.name,"status":"invalid_output","raw":proc.stdout[:500]}
        except subprocess.TimeoutExpired:
            return {"plugin":self.manifest.name,"status":"timeout","error":f"Plugin exceeded {self.TIMEOUT}s timeout"}
        except Exception as exc:
            return {"plugin":self.manifest.name,"status":"error","error":str(exc)}

    @staticmethod
    def _build_scoped_context(context: dict) -> dict:
        ALLOWED_KEYS = {"session_id","target","module","hook","module_output","timestamp","plugin_config"}
        return {k:v for k,v in context.items() if k in ALLOWED_KEYS}

    def install_requirements(self) -> tuple[bool,str]:
        if not self.manifest.requires:
            return True, "No requirements"
        try:
            proc = subprocess.run(
                [sys.executable,"-m","pip","install","--quiet",*self.manifest.requires],
                capture_output=True, text=True, timeout=120,
            )
            if proc.returncode == 0:
                return True, f"Installed: {', '.join(self.manifest.requires)}"
            return False, proc.stderr[:500]
        except Exception as exc:
            return False, str(exc)


class PluginRegistry:
    def __init__(self, plugins_dir: str = "~/.shadow313/plugins") -> None:
        self.plugins_dir = Path(plugins_dir).expanduser()
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        self._loaded: dict[str,PluginManifest] = {}
        self._enabled: set[str] = set()

    def discover(self) -> list[PluginManifest]:
        manifests = []
        for entry in self.plugins_dir.iterdir():
            if entry.is_dir():
                try:
                    m = PluginManifest(entry)
                    manifests.append(m)
                    self._loaded[m.name] = m
                except Exception as _exc:  # S01-fixed
                    import logging as _log; _log.getLogger(__name__).debug("suppressed: %s", _exc)
                    pass
        return manifests

    def enable(self, name: str) -> bool:
        if name in self._loaded:
            self._enabled.add(name)
            return True
        return False

    def disable(self, name: str) -> bool:
        self._enabled.discard(name)
        return True

    def get_enabled(self) -> list[PluginManifest]:
        return [self._loaded[n] for n in self._enabled if n in self._loaded]

    def get_hooks(self, hook: str) -> list[PluginManifest]:
        return [p for p in self.get_enabled() if hook in p.hooks]

    def install(self, plugin_path: str) -> tuple[bool,str]:
        src = Path(plugin_path).expanduser()
        if not src.is_dir():
            return False, f"Plugin directory not found: {src}"
        try:
            m = PluginManifest(src)
        except Exception as exc:
            return False, f"Invalid plugin manifest: {exc}"
        errors = m.validate()
        if errors:
            return False, f"Validation errors: {'; '.join(errors)}"
        dest = self.plugins_dir / m.name
        if dest.exists():
            import shutil
            shutil.rmtree(dest)
        import shutil
        shutil.copytree(str(src), str(dest))
        m2 = PluginManifest(dest)
        self._loaded[m2.name] = m2
        return True, f"Plugin '{m2.name}' installed → {dest}"

    def remove(self, name: str) -> tuple[bool,str]:
        self._enabled.discard(name)
        plugin_dir = self.plugins_dir / name
        if plugin_dir.exists():
            import shutil
            shutil.rmtree(plugin_dir)
            self._loaded.pop(name, None)
            return True, f"Plugin '{name}' removed"
        return False, f"Plugin '{name}' not found"

    def list_all(self) -> list[dict]:
        self.discover()
        return [{**m.to_dict(),"enabled":m.name in self._enabled} for m in self._loaded.values()]


class HookDispatcher:
    def __init__(self, registry: PluginRegistry, session_id: str) -> None:
        self.registry   = registry
        self.session_id = session_id

    def fire(self, hook: str, module: str, module_output: Any = None, target: str = "") -> list[dict]:
        plugins = self.registry.get_hooks(hook)
        if not plugins:
            return []
        results = []
        ctx = {"session_id":self.session_id,"hook":hook,"module":module,
               "target":target,"module_output":module_output,"timestamp":_now()}
        for plugin in plugins:
            executor = PluginExecutor(plugin)
            results.append(executor.execute(ctx))
        return results


class PluginScaffolder:
    def __init__(self, plugins_dir: str = "~/.shadow313/plugins") -> None:
        self.plugins_dir = Path(plugins_dir).expanduser()

    def create(self, name: str, hook: str = "recon.post", author: str = "") -> Path:
        dest = self.plugins_dir / name
        dest.mkdir(parents=True, exist_ok=True)
        manifest = MANIFEST_TEMPLATE.replace("my-plugin", name)
        (dest / "plugin.yaml").write_text(manifest)
        entry = PLUGIN_ENTRY_TEMPLATE.format(name=name, hook=hook)
        (dest / "plugin.py").write_text(entry)
        readme = (f"# {name}\n\nA Shadow313 plugin.\n\n"
                  f"## Hook\n`{hook}`\n\n"
                  "## Usage\n```bash\n"
                  f"shadow313 plugin --install ./{name}/\n"
                  f"shadow313 plugin --enable {name}\n```\n")
        (dest / "README.md").write_text(readme)
        return dest


class PluginManager:
    def __init__(self, kernel) -> None:
        self.kernel    = kernel
        cfg            = kernel.config.get("plugins", default={})
        plugins_dir    = cfg.get("dir","~/.shadow313/plugins")
        self.out       = kernel.out
        self.session   = kernel.session
        self.registry  = PluginRegistry(plugins_dir)
        self.dispatcher= HookDispatcher(self.registry, kernel.session.id)
        self.scaffolder= PluginScaffolder(plugins_dir)
        for name in cfg.get("enabled",[]):
            self.registry.discover()
            self.registry.enable(name)

    def register(self, kernel) -> None:
        kernel.register("plugins", self.run)

    def run(self, list_plugins: bool = False, install: str = "", enable: str = "",
            disable: str = "", remove: str = "", new: str = "", hook: str = "",
            new_author: str = "") -> dict:
        self.out.section("PLUGIN MANAGER")
        result: dict[str,Any] = {"timestamp":_now()}

        if list_plugins or not any([install,enable,disable,remove,new]):
            plugins = self.registry.list_all()
            result["plugins"] = plugins
            if plugins:
                rows = [[p["name"],p["version"],p["author"],", ".join(p["hooks"]),"✓" if p["enabled"] else ""]
                        for p in plugins]
                self.out.table(["Name","Version","Author","Hooks","Enabled"], rows,
                               f"Installed Plugins ({len(plugins)})")
            else:
                self.out.info("No plugins installed. Use: shadow313 plugin --install ./my-plugin/")

        if install:
            ok, msg = self.registry.install(install)
            self.out.success(msg) if ok else self.out.error(msg)
            if ok:
                result["installed"] = install

        if enable:
            if self.registry.enable(enable):
                self.out.success(f"Plugin '{enable}' enabled.")
            else:
                self.out.error(f"Plugin '{enable}' not found.")

        if disable:
            self.registry.disable(disable)
            self.out.success(f"Plugin '{disable}' disabled.")

        if remove:
            ok, msg = self.registry.remove(remove)
            self.out.success(msg) if ok else self.out.error(msg)

        if new:
            path = self.scaffolder.create(new, hook=hook or "recon.post", author=new_author)
            self.out.success(f"Plugin scaffold created → {path}")
            result["scaffold_path"] = str(path)

        self.session.audit("plugins","run")
        return result

    def fire_hook(self, hook: str, module: str, output: Any = None, target: str = "") -> list[dict]:
        return self.dispatcher.fire(hook, module, output, target)