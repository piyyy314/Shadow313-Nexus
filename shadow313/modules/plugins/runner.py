"""Sandbox-aware plugin executor.

Plugins execute only inside bubblewrap with isolated namespaces, read-only
runtime/plugin mounts, no network namespace access, and a minimal environment.
If bubblewrap is unavailable, execution fails closed.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from .manifest import PluginManifest
from .signing import PluginArtifactSigner

TIMEOUT = 30
MAX_CONTEXT_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 64 * 1024


class PluginRunner:
    """Execute plugin code only when the Linux bubblewrap sandbox is available."""

    def __init__(
        self,
        manifest: PluginManifest,
        require_signed: bool = True,
        signer: PluginArtifactSigner | None = None,
    ) -> None:
        self.manifest = manifest
        self.require_signed = require_signed
        self.signer = signer or PluginArtifactSigner()

    def _sandbox_command(self) -> list[str] | None:
        if not sys.platform.startswith("linux"):
            return None
        bwrap = shutil.which("bwrap")
        if bwrap is None:
            return None

        plugin_root = self.manifest.path.resolve()
        entry_path = self.manifest.entry_path.resolve()
        if not entry_path.is_relative_to(plugin_root):
            raise ValueError("Plugin entry escapes its root directory")
        entry_relative = entry_path.relative_to(plugin_root).as_posix()

        command = [
            bwrap,
            "--die-with-parent",
            "--new-session",
            "--unshare-all",
        ]

        mounted_roots: list[Path] = []
        for runtime_path in (
            Path("/usr"),
            Path("/bin"),
            Path("/lib"),
            Path("/lib64"),
        ):
            if not runtime_path.exists():
                continue
            source_path = runtime_path.resolve()
            if any(
                source_path == root or source_path.is_relative_to(root)
                for root in mounted_roots
            ):
                continue
            command.extend(["--ro-bind", str(source_path), str(runtime_path)])
            mounted_roots.append(source_path)

        prefix = Path(sys.prefix).resolve()
        if not any(
            prefix == root or prefix.is_relative_to(root)
            for root in mounted_roots
        ):
            command.extend(["--ro-bind", str(prefix), str(prefix)])

        command.extend(["--dir", "/etc"])
        ld_cache = Path("/etc/ld.so.cache")
        if ld_cache.is_file():
            command.extend(["--ro-bind", str(ld_cache), str(ld_cache)])

        certs = Path("/etc/ssl/certs")
        if certs.is_dir():
            command.extend(["--dir", "/etc/ssl"])
            command.extend(["--ro-bind", str(certs), "/etc/ssl/certs"])

        command.extend(
            [
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--tmpfs",
                "/plugin-tmp",
                "--dir",
                "/plugin",
                "--ro-bind",
                str(plugin_root),
                "/plugin",
                "--chdir",
                "/plugin",
                "--setenv",
                "HOME",
                "/plugin-tmp",
                "--setenv",
                "TMPDIR",
                "/plugin-tmp",
                "--setenv",
                "PATH",
                "/usr/bin:/bin",
                "--setenv",
                "PYTHONPATH",
                "/plugin",
                "--setenv",
                "PYTHONNOUSERSITE",
                "1",
                "--setenv",
                "PYTHONDONTWRITEBYTECODE",
                "1",
                "--",
                sys.executable,
                f"/plugin/{entry_relative}",
            ]
        )
        return command

    def execute(self, context: dict) -> dict:
        """Run a plugin with bounded input, isolated environment, and timeout."""
        try:
            if self.require_signed:
                verification = self.signer.verify(self.manifest.path)
                if not verification.get("valid"):
                    return {
                        "plugin": self.manifest.name,
                        "status": "signature_invalid",
                        "reason": verification.get(
                            "reason",
                            "Plugin artifact signature is invalid",
                        ),
                    }
            entry_path = self.manifest.entry_path
            if not entry_path.is_file():
                return {"plugin": self.manifest.name, "status": "invalid_entry"}

            scoped_context = self._build_scoped_context(context)
            input_json = json.dumps(scoped_context)
            if len(input_json.encode("utf-8")) > MAX_CONTEXT_BYTES:
                return {
                    "plugin": self.manifest.name,
                    "status": "rejected",
                    "reason": "Plugin context exceeds the configured size limit",
                }

            command = self._sandbox_command()
            if command is None:
                return {
                    "plugin": self.manifest.name,
                    "status": "sandbox_unavailable",
                    "reason": "bubblewrap is required; plugin code was not executed",
                }

            proc = subprocess.run(
                command,
                input=input_json,
                capture_output=True,
                text=True,
                timeout=TIMEOUT,
                check=False,
                preexec_fn=self._set_resource_limits,
                env={
                    "HOME": "/plugin-tmp",
                    "LANG": "C.UTF-8",
                    "PATH": "/usr/bin:/bin",
                    "PYTHONNOUSERSITE": "1",
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "SHADOW313_PLUGIN_MODE": "1",
                    "TMPDIR": "/plugin-tmp",
                },
            )
            if len(proc.stdout.encode("utf-8")) > MAX_OUTPUT_BYTES:
                return {
                    "plugin": self.manifest.name,
                    "status": "rejected",
                    "reason": "Plugin output exceeds the configured size limit",
                }
            if proc.returncode != 0:
                return {
                    "plugin": self.manifest.name,
                    "status": "error",
                    "error": proc.stderr[:500],
                }
            if not proc.stdout.strip():
                return {"plugin": self.manifest.name, "status": "no_output"}
            try:
                result = json.loads(proc.stdout)
            except json.JSONDecodeError:
                return {
                    "plugin": self.manifest.name,
                    "status": "invalid_output",
                    "raw": proc.stdout[:500],
                }
            if not isinstance(result, dict):
                return {
                    "plugin": self.manifest.name,
                    "status": "invalid_output",
                    "reason": "Plugin output must be a JSON object",
                }
            return result
        except subprocess.TimeoutExpired:
            return {
                "plugin": self.manifest.name,
                "status": "timeout",
                "error": f"Plugin exceeded {TIMEOUT}s timeout",
            }
        except (OSError, ValueError, TypeError) as exc:
            return {
                "plugin": self.manifest.name,
                "status": "error",
                "error": f"{type(exc).__name__}: {exc}",
            }

    @staticmethod
    def _set_resource_limits() -> None:
        """Apply process, memory, CPU, file-size, and descriptor limits in Linux."""
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (20, 25))
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        if hasattr(resource, "RLIMIT_NPROC"):
            resource.setrlimit(resource.RLIMIT_NPROC, (16, 16))

    @staticmethod
    def _build_scoped_context(context: dict) -> dict:
        allowed_keys = {
            "session_id",
            "target",
            "module",
            "hook",
            "module_output",
            "timestamp",
            "plugin_config",
        }
        return {key: value for key, value in context.items() if key in allowed_keys}

    def install_requirements(self) -> tuple[bool, str]:
        """Never install plugin dependencies into the host Python environment."""
        if not self.manifest.requires:
            return True, "No requirements"
        return (
            False,
            "Plugin dependency installation is disabled in the host environment; "
            "build dependencies into a dedicated, isolated plugin image instead.",
        )
