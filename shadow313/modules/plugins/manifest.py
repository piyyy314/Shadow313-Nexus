"""Plugin manifest parsing and path-containment validation."""
from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None

VALID_HOOKS = {
    "recon.post",
    "vuln.post",
    "network.post",
    "defense.post",
    "quantum.post",
    "exploit.post",
    "output.transform",
    "ask.pre",
    "session.start",
    "session.end",
}
PLUGIN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
ENTRY_RE = re.compile(r"^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")

MANIFEST_TEMPLATE = """\\
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

PLUGIN_ENTRY_TEMPLATE = '''\\
#!/usr/bin/env python3
"""
{name} — Shadow313 Plugin
Hook: {hook}
"""
import json
import sys


def main():
    context = json.load(sys.stdin)
    result = {{"plugin": "{name}", "status": "ok", "data": {{}}}}
    print(json.dumps(result))


if __name__ == "__main__":
    main()
'''


class PluginManifest:
    """Load a plugin manifest and reject path escapes before execution or install."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path).expanduser().resolve()
        self._data: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.is_dir():
            raise NotADirectoryError(self.path)
        for name in ("plugin.yaml", "manifest.yaml"):
            manifest_file = self.path / name
            if manifest_file.is_file():
                if (
                    manifest_file.is_symlink()
                    or not manifest_file.resolve().is_relative_to(self.path)
                ):
                    raise ValueError(
                        "Plugin manifest must be a regular file inside its plugin directory"
                    )
                if manifest_file.stat().st_size > 64 * 1024:
                    raise ValueError("Plugin manifest exceeds the 64 KiB size limit")
                text = manifest_file.read_text(encoding="utf-8")
                if yaml is not None:
                    data = yaml.safe_load(text) or {}
                else:
                    data = self._minimal_parse(text)
                if not isinstance(data, dict):
                    raise ValueError("Plugin manifest must contain a YAML mapping")
                self._data = data
                return
        raise FileNotFoundError(f"No plugin.yaml or manifest.yaml in {self.path}")

    @staticmethod
    def _minimal_parse(text: str) -> dict[str, Any]:
        data: dict[str, Any] = {}
        current_list: str | None = None
        for line in text.splitlines():
            if line.lstrip().startswith("#") or not line.strip():
                continue
            if line.startswith("  - ") and current_list is not None:
                data[current_list].append(line[4:].strip())
            elif ":" in line:
                key, _, value = line.partition(":")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if value:
                    data[key] = value
                    current_list = None
                else:
                    data[key] = []
                    current_list = key
        return data

    @property
    def name(self) -> str:
        return str(self._data.get("name", self.path.name))

    @property
    def version(self) -> str:
        return str(self._data.get("version", "0.0.0"))

    @property
    def description(self) -> str:
        return str(self._data.get("description", ""))

    @property
    def author(self) -> str:
        return str(self._data.get("author", "unknown"))

    @property
    def hooks(self) -> list[str]:
        value = self._data.get("hooks", [])
        return value if isinstance(value, list) else []

    @property
    def entry(self) -> str:
        return str(self._data.get("entry", "plugin.py"))

    @property
    def requires(self) -> list[str]:
        value = self._data.get("requires", [])
        return value if isinstance(value, list) else []

    @property
    def entry_path(self) -> Path:
        entry = self.entry
        if not ENTRY_RE.fullmatch(entry):
            raise ValueError("Plugin entry must be a relative plugin-local path")
        parts = PurePosixPath(entry).parts
        if any(part in {"", ".", ".."} for part in parts) or ":" in entry or "\\" in entry:
            raise ValueError("Plugin entry contains an unsafe path component")
        candidate = (self.path.joinpath(*parts)).resolve()
        if not candidate.is_relative_to(self.path):
            raise ValueError("Plugin entry resolves outside its plugin directory")
        return candidate

    def validate(self) -> list[str]:
        errors: list[str] = []
        if not PLUGIN_NAME_RE.fullmatch(self.name) or self.name in {".", ".."}:
            errors.append("Plugin name must be a simple 1-64 character identifier")
        try:
            entry_path = self.entry_path
            if not entry_path.is_file():
                errors.append("Plugin entry must be an existing regular file")
        except (OSError, ValueError) as exc:
            errors.append(f"Invalid plugin entry: {exc}")
        if not isinstance(self._data.get("hooks", []), list):
            errors.append("Plugin hooks must be a list")
        else:
            for hook in self.hooks:
                if not isinstance(hook, str) or hook not in VALID_HOOKS:
                    errors.append(f"Invalid hook {hook!r}")
        if not isinstance(self._data.get("requires", []), list):
            errors.append("Plugin requirements must be a list")
        elif any(not isinstance(item, str) or not item.strip() for item in self.requires):
            errors.append("Plugin requirements must contain non-empty strings")
        return errors

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "hooks": self.hooks,
            "entry": self.entry,
            "requires": self.requires,
            "path": str(self.path),
        }
