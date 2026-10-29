"""shadow313.modules.plugins.runner — Sandboxed subprocess plugin executor."""
from __future__ import annotations
import json
import os
import subprocess
import sys
from typing import Any

from .manifest import PluginManifest

TIMEOUT = 30


class PluginRunner:
    """Runs a plugin entry script in an isolated subprocess via JSON-over-stdin/stdout."""

    def __init__(self, manifest: PluginManifest) -> None:
        """Select the plugin manifest to execute or install requirements for."""
        self.manifest = manifest

    def execute(self, context: dict) -> dict:
        """Run the entry script with filtered JSON input and return its decoded JSON output.

        The subprocess inherits the environment with plugin-specific overrides
        and has a 30-second timeout. Process failures, timeouts, and invalid or
        absent output return status records. Input serialization errors occur
        before execution and propagate; valid JSON output is returned as-is.
        """
        scoped_ctx = self._build_scoped_context(context)
        input_json = json.dumps(scoped_ctx)
        try:
            proc = subprocess.run(
                [sys.executable, str(self.manifest.entry_path)],
                input=input_json,
                capture_output=True,
                text=True,
                timeout=TIMEOUT,
                cwd=str(self.manifest.path),
                check=False,
                env={
                    **os.environ,
                    "SHADOW313_PLUGIN_MODE": "1",
                    "PYTHONPATH": str(self.manifest.path),
                },
            )
            if proc.returncode != 0:
                return {"plugin": self.manifest.name, "status": "error",
                        "error": proc.stderr[:500]}
            if not proc.stdout.strip():
                return {"plugin": self.manifest.name, "status": "no_output"}
            try:
                return json.loads(proc.stdout)
            except json.JSONDecodeError:
                return {"plugin": self.manifest.name, "status": "invalid_output",
                        "raw": proc.stdout[:500]}
        except subprocess.TimeoutExpired:
            return {"plugin": self.manifest.name, "status": "timeout",
                    "error": f"Plugin exceeded {TIMEOUT}s timeout"}
        except Exception as exc:
            return {"plugin": self.manifest.name, "status": "error", "error": str(exc)}

    @staticmethod
    def _build_scoped_context(context: dict) -> dict:
        """Return only allowed top-level context keys, retaining their original values."""
        ALLOWED_KEYS = {
            "session_id", "target", "module", "hook",
            "module_output", "timestamp", "plugin_config",
        }
        return {k: v for k, v in context.items() if k in ALLOWED_KEYS}

    def install_requirements(self) -> tuple[bool, str]:
        """Install declared requirements into the current Python environment using pip.

        Return (success, message), converting process errors and the 120-second
        timeout into failure results. No declared requirements succeeds immediately.
        """
        if not self.manifest.requires:
            return True, "No requirements"
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--quiet",
                 *self.manifest.requires],
                capture_output=True, text=True, timeout=120, check=False,
            )
            if proc.returncode == 0:
                return True, f"Installed: {', '.join(self.manifest.requires)}"
            return False, proc.stderr[:500]
        except Exception as exc:
            return False, str(exc)