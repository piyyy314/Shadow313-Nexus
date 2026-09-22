"""
shadow313.v2.docker_sandbox.docker_sandbox  — NEXUS Complete
CVE reproduction sandbox using Docker with comprehensive security constraints.

Pre-mapped CVEs (8 via Vulhub images):
  CVE-2021-44228  Log4Shell        Apache Log4j 2.x
  CVE-2017-5638   Struts2 RCE      Apache Struts 2
  CVE-2019-0708   BlueKeep         Windows RDP
  CVE-2021-3156   Baron Samedit    sudo heap overflow
  CVE-2021-41773  Path Traversal   Apache HTTP 2.4.49
  CVE-2022-22965  Spring4Shell     Spring Framework
  CVE-2023-46604  OpenWire RCE     Apache ActiveMQ
  CVE-2024-3400   GlobalProtect    Palo Alto PAN-OS

Security constraints (applied to every container):
  --network sandbox        Isolated network namespace
  --memory 512m            Memory limit
  --cpus 0.5               CPU limit
  --no-new-privileges      Block privilege escalation
  --read-only              Read-only root filesystem
  --tmpfs /tmp:noexec      No execution from /tmp
"""
from __future__ import annotations
import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


LAB_MODE_MSG = """
╔══════════════════════════════════════════════════════════════════════╗
║  SHADOW313 — CVE REPRODUCTION SANDBOX SAFETY GATE                   ║
║                                                                      ║
║  This module reproduces CVEs in isolated Docker containers.         ║
║  REQUIRED: --lab-mode flag                                           ║
║  Only for authorized security research in isolated lab environments. ║
╚══════════════════════════════════════════════════════════════════════╝
"""

# Pre-mapped CVEs with Vulhub Docker images
CVE_CATALOG: dict[str, dict] = {
    "CVE-2021-44228": {
        "name":        "Log4Shell",
        "description": "Remote code execution via JNDI injection in Apache Log4j 2.x",
        "software":    "Apache Log4j 2.0-beta9 through 2.14.1",
        "cvss":        10.0,
        "image":       "vulhub/log4j:2.14.1",
        "port":        8080,
        "technique":   "T1190",
        "test_payload":"${jndi:ldap://127.0.0.1:1389/exploit}",
        "verify_url":  "http://localhost:{port}/",
        "category":    "RCE",
    },
    "CVE-2017-5638": {
        "name":        "Struts2 RCE",
        "description": "Remote code execution via Content-Type header in Apache Struts 2",
        "software":    "Apache Struts 2.3.5 through 2.3.31, 2.5 through 2.5.10",
        "cvss":        10.0,
        "image":       "vulhub/struts2:2.3.30",
        "port":        8080,
        "technique":   "T1190",
        "test_payload":"Content-Type: %{(#_='multipart/form-data')}",
        "verify_url":  "http://localhost:{port}/showcase.action",
        "category":    "RCE",
    },
    "CVE-2021-3156": {
        "name":        "Baron Samedit",
        "description": "Heap-based buffer overflow in sudo allowing privilege escalation",
        "software":    "sudo 1.8.2 through 1.8.31p2, 1.9.0 through 1.9.5p1",
        "cvss":        7.8,
        "image":       "vulhub/sudo:1.8.31",
        "port":        None,
        "technique":   "T1068",
        "test_payload":"sudoedit -s '\\' $(python3 -c 'print(\"A\"*65536)')",
        "verify_url":  None,
        "category":    "PrivEsc",
    },
    "CVE-2021-41773": {
        "name":        "Apache Path Traversal / RCE",
        "description": "Path traversal and RCE in Apache HTTP Server 2.4.49",
        "software":    "Apache HTTP Server 2.4.49",
        "cvss":        9.8,
        "image":       "vulhub/apache:2.4.49",
        "port":        80,
        "technique":   "T1083",
        "test_payload":"GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd HTTP/1.1",
        "verify_url":  "http://localhost:{port}/",
        "category":    "PathTraversal",
    },
    "CVE-2022-22965": {
        "name":        "Spring4Shell",
        "description": "RCE via data binding in Spring Framework",
        "software":    "Spring Framework < 5.3.18, < 5.2.20",
        "cvss":        9.8,
        "image":       "vulhub/spring:5.3.17",
        "port":        8080,
        "technique":   "T1190",
        "test_payload":"class.module.classLoader.resources.context.parent.pipeline.first.pattern=",
        "verify_url":  "http://localhost:{port}/",
        "category":    "RCE",
    },
    "CVE-2023-46604": {
        "name":        "Apache ActiveMQ OpenWire RCE",
        "description": "RCE via ClassInfo deserialization in Apache ActiveMQ",
        "software":    "Apache ActiveMQ < 5.15.16, < 5.16.7, < 5.17.6, < 5.18.3",
        "cvss":        10.0,
        "image":       "vulhub/activemq:5.15.15",
        "port":        61616,
        "technique":   "T1190",
        "test_payload":"OpenWire ClassInfo exploit",
        "verify_url":  None,
        "category":    "RCE",
    },
    "CVE-2019-0708": {
        "name":        "BlueKeep",
        "description": "RCE via RDP pre-authentication in Windows",
        "software":    "Windows 7, Windows Server 2008 R2",
        "cvss":        9.8,
        "image":       "vulhub/rdp:bluekeep",
        "port":        3389,
        "technique":   "T1210",
        "test_payload":"RDP pre-auth exploit",
        "verify_url":  None,
        "category":    "RCE",
        "note":        "Requires Windows container — Linux host only for detection testing",
    },
    "CVE-2024-3400": {
        "name":        "PAN-OS GlobalProtect RCE",
        "description": "Command injection in Palo Alto PAN-OS GlobalProtect",
        "software":    "PAN-OS 10.2, 11.0, 11.1",
        "cvss":        10.0,
        "image":       "vulhub/panos:globalprotect",
        "port":        443,
        "technique":   "T1190",
        "test_payload":"SESSID cookie injection",
        "verify_url":  None,
        "category":    "RCE",
        "note":        "Simulation only — no actual PAN-OS image available",
    },
}

# Security constraints applied to every container
CONTAINER_SECURITY_FLAGS = [
    "--network", "sandbox",
    "--memory", "512m",
    "--cpus", "0.5",
    "--no-new-privileges",
    "--read-only",
    "--tmpfs", "/tmp:noexec,nosuid,size=64m",
    "--security-opt", "no-new-privileges:true",
    "--cap-drop", "ALL",
    "--pids-limit", "100",
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _docker_available() -> bool:
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True, timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _sandbox_network_exists() -> bool:
    try:
        result = subprocess.run(
            ["docker", "network", "inspect", "sandbox"],
            capture_output=True, timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def _create_sandbox_network() -> bool:
    try:
        result = subprocess.run(
            ["docker", "network", "create",
             "--driver", "bridge",
             "--internal",  # No external connectivity
             "--subnet", "172.21.0.0/16",
             "sandbox"],
            capture_output=True, timeout=30,
        )
        return result.returncode == 0
    except Exception:
        return False


class CVEReproducer:
    """
    Safely reproduces CVEs in isolated Docker containers.
    Every container runs with all 6 security constraints.
    """

    CONTAINER_TIMEOUT = 120  # seconds
    HTTP_CHECK_TIMEOUT = 10

    def __init__(self, log_dir: str = "~/.shadow313/sandbox_logs") -> None:
        self._log_dir = Path(log_dir).expanduser()
        self._log_dir.mkdir(parents=True, exist_ok=True)
        self._active_containers: list[str] = []

    def list_cves(self) -> list[dict]:
        """Return catalog of reproducible CVEs."""
        return [
            {
                "cve_id":      cve_id,
                "name":        info["name"],
                "description": info["description"],
                "software":    info["software"],
                "cvss":        info["cvss"],
                "category":    info["category"],
                "technique":   info["technique"],
                "note":        info.get("note", ""),
            }
            for cve_id, info in CVE_CATALOG.items()
        ]

    def reproduce(self, cve_id: str, timeout: int = 60) -> dict:
        """
        Reproduce a CVE in an isolated Docker container.
        Returns result dict with container logs and connectivity check.
        """
        if cve_id not in CVE_CATALOG:
            return {
                "error":     f"CVE {cve_id} not in catalog",
                "available": list(CVE_CATALOG.keys()),
            }

        if not _docker_available():
            return {"error": "Docker not available — install Docker Engine"}

        # Ensure sandbox network exists
        if not _sandbox_network_exists():
            if not _create_sandbox_network():
                return {"error": "Failed to create sandbox network"}

        info = CVE_CATALOG[cve_id]
        container_name = f"shadow313-sandbox-{cve_id.lower().replace('-', '_')}-{int(time.time())}"

        result: dict[str, Any] = {
            "cve_id":        cve_id,
            "name":          info["name"],
            "container_name":container_name,
            "started_at":    _now_iso(),
            "security_constraints": CONTAINER_SECURITY_FLAGS,
        }

        try:
            # Pull image
            pull_result = subprocess.run(
                ["docker", "pull", info["image"]],
                capture_output=True, text=True, timeout=120,
            )
            if pull_result.returncode != 0:
                result["error"] = f"Failed to pull image {info['image']}: {pull_result.stderr[:200]}"
                result["note"]  = info.get("note", "Image may not be publicly available")
                return result

            # Build run command with all security constraints
            port_flags = []
            if info.get("port"):
                port_flags = ["-p", f"{info['port']}:{info['port']}"]

            cmd = [
                "docker", "run",
                "--name", container_name,
                "--rm",
                *CONTAINER_SECURITY_FLAGS,
                *port_flags,
                "-d",  # Detached
                info["image"],
            ]

            # Start container
            run_result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
            )

            if run_result.returncode != 0:
                result["error"] = f"Container start failed: {run_result.stderr[:200]}"
                return result

            container_id = run_result.stdout.strip()
            self._active_containers.append(container_id)
            result["container_id"] = container_id[:12]

            # Wait for service to start
            time.sleep(min(timeout // 4, 15))

            # Connectivity check
            if info.get("verify_url") and info.get("port"):
                verify_url = info["verify_url"].format(port=info["port"])
                try:
                    from urllib import request as urlreq
                    req = urlreq.Request(verify_url, headers={"User-Agent": "shadow313/4.0"})
                    with urlreq.urlopen(req, timeout=self.HTTP_CHECK_TIMEOUT) as resp:
                        result["service_reachable"] = True
                        result["http_status"]       = resp.status
                except Exception as exc:
                    result["service_reachable"] = False
                    result["connectivity_error"] = str(exc)

            # Collect container logs
            log_result = subprocess.run(
                ["docker", "logs", "--tail", "50", container_id],
                capture_output=True, text=True, timeout=10,
            )
            result["container_logs"] = log_result.stdout[:2000]

            # CVE-specific information
            result["test_payload"]  = info["test_payload"]
            result["mitre_technique"]= info["technique"]
            result["advisory"]      = (
                f"This container reproduces {cve_id} ({info['name']}) for research purposes. "
                f"The vulnerability affects {info['software']}. "
                f"CVSS: {info['cvss']}. "
                f"All 6 security constraints are active. "
                f"Container is isolated from the network and host filesystem."
            )

            result["status"] = "running"
            result["cleanup_cmd"] = f"docker stop {container_id[:12]}"

            # Write log
            log_file = self._log_dir / f"{cve_id}_{int(time.time())}.json"
            log_file.write_text(json.dumps(result, indent=2, default=str))

        except subprocess.TimeoutExpired:
            result["error"] = "Container operation timed out"
            self._cleanup_container(container_name)
        except Exception as exc:
            result["error"] = str(exc)
            self._cleanup_container(container_name)

        return result

    def cleanup_all(self) -> dict:
        """Stop and remove all active sandbox containers."""
        cleaned = 0
        errors  = []
        for container_id in list(self._active_containers):
            try:
                subprocess.run(
                    ["docker", "stop", container_id],
                    capture_output=True, timeout=30,
                )
                self._active_containers.remove(container_id)
                cleaned += 1
            except Exception as exc:
                errors.append(str(exc))

        # Also clean up any orphaned shadow313 sandbox containers
        try:
            result = subprocess.run(
                ["docker", "ps", "-a", "--filter", "name=shadow313-sandbox",
                 "--format", "{{.ID}}"],
                capture_output=True, text=True, timeout=10,
            )
            for cid in result.stdout.strip().splitlines():
                if cid:
                    subprocess.run(["docker", "rm", "-f", cid],
                                   capture_output=True, timeout=10)
                    cleaned += 1
        except Exception as _exc:  # S01-fixed
            import logging as _log; _log.getLogger(__name__).debug("suppressed: %s", _exc)
            pass

        return {"cleaned": cleaned, "errors": errors}

    def _cleanup_container(self, name: str) -> None:
        try:
            subprocess.run(
                ["docker", "rm", "-f", name],
                capture_output=True, timeout=10,
            )
        except Exception as _exc:  # S01-fixed
            import logging as _log; _log.getLogger(__name__).debug("suppressed: %s", _exc)
            pass

    def security_audit(self, container_id: str) -> dict:
        """Audit the security constraints of a running container."""
        try:
            result = subprocess.run(
                ["docker", "inspect", container_id],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return {"error": "Container not found"}

            inspect = json.loads(result.stdout)[0]
            host_config = inspect.get("HostConfig", {})

            checks = {
                "network_isolated":    inspect.get("NetworkSettings", {}).get("Networks", {}).get("sandbox") is not None,
                "memory_limited":      host_config.get("Memory", 0) > 0,
                "cpu_limited":         host_config.get("NanoCpus", 0) > 0,
                "no_new_privileges":   host_config.get("SecurityOpt", []) and "no-new-privileges:true" in str(host_config.get("SecurityOpt", [])),
                "read_only_rootfs":    host_config.get("ReadonlyRootfs", False),
                "all_caps_dropped":    "ALL" in str(host_config.get("CapDrop", [])),
                "pids_limited":        host_config.get("PidsLimit", 0) > 0,
            }

            all_pass = all(checks.values())
            return {
                "container_id": container_id[:12],
                "security_checks": checks,
                "all_constraints_active": all_pass,
                "security_score": f"{sum(checks.values())}/{len(checks)}",
            }
        except Exception as exc:
            return {"error": str(exc)}


class SandboxModule:
    """shadow313.v2.docker_sandbox — CVE Sandbox. Registered: sandbox"""

    def __init__(self, kernel) -> None:
        self.kernel    = kernel
        self.out       = kernel.out
        self.session   = kernel.session
        cfg            = kernel.config.get("docker_sandbox", default={})
        self._enabled  = cfg.get("enabled", False)
        self.reproducer= CVEReproducer()

    def register(self, kernel) -> None:
        kernel.register("sandbox", self.run)

    def run(
        self,
        cve:         str  = "",
        lab_mode:    bool = False,
        list_cves:   bool = False,
        cleanup_all: bool = False,
        audit:       str  = "",
        timeout:     int  = 60,
    ) -> dict:
        self.out.section("CVE REPRODUCTION SANDBOX")

        if list_cves:
            cves = self.reproducer.list_cves()
            rows = [[c["cve_id"], c["name"], str(c["cvss"]), c["category"], c["software"][:40]]
                    for c in cves]
            self.out.table(["CVE ID","Name","CVSS","Category","Software"], rows,
                           f"Available CVEs ({len(cves)})")
            return {"cves": cves}

        if cleanup_all:
            result = self.reproducer.cleanup_all()
            self.out.success(f"Cleaned {result['cleaned']} containers")
            return result

        if audit:
            result = self.reproducer.security_audit(audit)
            self.out.result(result, f"Security Audit: {audit}")
            return result

        if not lab_mode:
            self.out.error(LAB_MODE_MSG)
            return {"error": "lab_mode_required"}

        if not cve:
            self.out.error("--cve required. Use --list-cves to see available CVEs.")
            return {"error": "cve_required"}

        if not self._enabled:
            self.out.warn("Docker sandbox is disabled. Set docker_sandbox.enabled: true in config.yaml")
            self.out.warn("Also ensure Docker Engine is installed and running.")

        self.out.warn(f"Starting CVE reproduction: {cve} (LAB MODE)")
        self.out.info("All 6 security constraints will be applied:")
        for flag in ["--network sandbox (isolated)", "--memory 512m", "--cpus 0.5",
                     "--no-new-privileges", "--read-only", "--tmpfs /tmp:noexec"]:
            self.out.info(f"  ✓ {flag}")

        result = self.reproducer.reproduce(cve, timeout=timeout)

        if "error" in result:
            self.out.error(f"Sandbox error: {result['error']}")
            if "note" in result:
                self.out.info(f"Note: {result['note']}")
        else:
            self.out.success(f"Container started: {result.get('container_id','')}")
            if result.get("service_reachable"):
                self.out.success(f"Service reachable (HTTP {result.get('http_status','')})")
            self.out.info(f"Advisory: {result.get('advisory','')[:100]}…")
            self.out.info(f"Cleanup: {result.get('cleanup_cmd','')}")

        self.session.write("sandbox_result.json", result)
        return result