"""shadow313.modules.plugins.manifest — Plugin manifest loader and validator."""
from __future__ import annotations
from pathlib import Path
from typing import Any

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

VALID_HOOKS = {
    "recon.post", "vuln.post", "network.post", "defense.post",
    "quantum.post", "exploit.post", "output.transform", "ask.pre",
    "session.start", "session.end",
}

MANIFEST_TEMPLATE = """\
name: my-plugin
version: 1.0.0
author: handle
description: Short description of what this plugin does
hooks:
  - recon.post
entry: plugin.py
requires: []
shadow313_min_version: "2.0.0"
"""

PLUGIN_ENTRY_TEMPLATE = '''\
#!/usr/bin/env python3
"""
{name} — Shadow313 Plugin
Hook: {hook}
"""
import json, sys

def main():
    ctx = json.load(sys.stdin)
    result = {{"plugin": "{name}", "status": "ok", "data": {{}}}}
    print(json.dumps(result))

if __name__ == "__main__":
    main()
'''


class PluginManifest:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._data: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        for name in ("plugin.yaml", "manifest.yaml"):
            manifest_file = self.path / name
            if manifest_file.exists():
                if _HAS_YAML:
                    with open(manifest_file, encoding="utf-8") as fh:
                        self._data = yaml.safe_load(fh) or {}
                else:
                    self._data = self._minimal_parse(manifest_file.read_text())
                return
        raise FileNotFoundError(f"No plugin.yaml in {self.path}")

    @staticmethod
    def _minimal_parse(text: str) -> dict:
        data: dict[str, Any] = {}
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
        return str(self._data.get("version", "0.0.0"))

    @property
    def description(self) -> str:
        return self._data.get("description", "")

    @property
    def author(self) -> str:
        return self._data.get("author", "unknown")

    @property
    def hooks(self) -> list[str]:
        return self._data.get("hooks", [])

    @property
    def entry(self) -> str:
        return self._data.get("entry", "plugin.py")

    @property
    def requires(self) -> list[str]:
        return self._data.get("requires", [])

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
            "name": self.name, "version": self.version,
            "description": self.description, "author": self.author,
            "hooks": self.hooks, "entry": self.entry,
            "requires": self.requires, "path": str(self.path),
        }