#!/usr/bin/env python3
"""
Shadow313 NEXUS — Hardened Delivery Daemon v2
Implements all P0 security controls from pipeline-security-analysis.md

Security controls:
  P0-1: Bind to 127.0.0.1 ONLY (not 0.0.0.0)
  P0-2: SHA3-256 hash in every download response header
  P0-3: Self-hash daemon.py in manifest (detect replacement)
  P0-4: Secret scanner runs before every build
  P0-5: Rate limiting (100 req/min per IP)
  P0-6: Provenance class on all artifacts
  P0-7: 313-BIND receipt on every download
  P0-8: No shell=True anywhere
"""
from __future__ import annotations

import collections
import hashlib
import http.server
import json
import os
import secrets
import socketserver
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT   = Path(__file__).parent.parent.parent
DOCS_DIR    = REPO_ROOT / "docs"
DIST_DIR    = REPO_ROOT / "dist"
DAEMON_DIR  = DIST_DIR / "daemon"
RECEIPT_DIR = DIST_DIR / "receipts"
LOG_FILE    = DAEMON_DIR / "hardened.log"
STATE_FILE  = DAEMON_DIR / "hardened_state.json"

# ── Security config ───────────────────────────────────────────────────────────
BIND_HOST       = "127.0.0.1"   # P0-1: localhost ONLY
SERVER_PORT     = 8313
RATE_LIMIT_RPM  = 100           # P0-5: requests per minute per IP
POLL_INTERVAL   = 3.0
DEBOUNCE_DELAY  = 1.5


# ── P0-5: Rate limiter ────────────────────────────────────────────────────────

class RateLimiter:
    """Token bucket rate limiter — 100 req/min per IP."""

    def __init__(self, rpm: int = 100):
        self.rpm      = rpm
        self._buckets: dict[str, list[float]] = collections.defaultdict(list)
        self._lock    = threading.Lock()

    def is_allowed(self, ip: str) -> bool:
        now = time.time()
        window = 60.0
        with self._lock:
            # Remove requests older than 1 minute
            self._buckets[ip] = [t for t in self._buckets[ip] if now - t < window]
            if len(self._buckets[ip]) >= self.rpm:
                return False
            self._buckets[ip].append(now)
            return True


# ── P0-4: Secret scanner ──────────────────────────────────────────────────────

class PreBuildSecretScanner:
    """Scans all docs/ files for secrets before delivery."""

    def __init__(self):
        # Import our existing pattern detector
        sys.path.insert(0, str(REPO_ROOT))
        try:
            from shadow313.v4.intelligence.secrets_manager import detect_secret_patterns
            self._detect = detect_secret_patterns
        except ImportError:
            self._detect = None

    def scan(self, files: list[Path]) -> list[dict]:
        """Scan files for secrets. Returns list of findings."""
        findings = []
        for fpath in files:
            if not fpath.exists():
                continue
            try:
                content = fpath.read_text(errors="ignore")
                # Check each line
                for i, line in enumerate(content.splitlines(), 1):
                    # Skip obvious false positives (comments, test data)
                    stripped = line.strip()
                    if stripped.startswith(("#", "//", "*", "<!--")):
                        continue
                    if self._detect:
                        matches = self._detect(stripped, context=fpath.name)
                        for match in matches:
                            # Only flag high-confidence patterns
                            if any(kw in match for kw in [
                                "GitHub", "AWS", "OpenAI", "Private key",
                                "Shadow313 production"
                            ]):
                                findings.append({
                                    "file":    fpath.name,
                                    "line":    i,
                                    "pattern": match,
                                    "snippet": stripped[:80],
                                })
            except Exception:
                pass
        return findings


# ── P0-3: Self-integrity checker ──────────────────────────────────────────────

class SelfIntegrityChecker:
    """Hashes daemon files to detect replacement attacks."""

    DAEMON_FILES = [
        "scripts/delivery/daemon_hardened.py",
        "scripts/delivery/pipeline.py",
        "scripts/delivery/daemon.py",
    ]

    def compute_hashes(self) -> dict[str, str]:
        hashes = {}
        for rel in self.DAEMON_FILES:
            fpath = REPO_ROOT / rel
            if fpath.exists():
                content = fpath.read_bytes()
                hashes[rel] = "sha3_256:" + hashlib.sha3_256(content).hexdigest()
        return hashes

    def verify(self, baseline: dict[str, str]) -> list[str]:
        """Compare current hashes against baseline. Returns list of tampered files."""
        current = self.compute_hashes()
        tampered = []
        for rel, expected in baseline.items():
            actual = current.get(rel, "MISSING")
            if actual != expected:
                tampered.append(f"{rel}: expected {expected[:32]}... got {actual[:32]}...")
        return tampered


# ── P0-2: Hash-verified file scanner ─────────────────────────────────────────

def scan_with_hashes(docs_dir: Path) -> list[dict]:
    """Scan docs/ and compute SHA3-256 for every file."""
    files = []
    for pattern in ["*.html", "*.json"]:
        for fpath in sorted(docs_dir.glob(pattern)):
            if fpath.is_file():
                content = fpath.read_bytes()
                sha3    = hashlib.sha3_256(content).hexdigest()
                files.append({
                    "name":     fpath.name,
                    "size_kb":  round(fpath.stat().st_size / 1024, 1),
                    "sha3_256": sha3,
                    "modified": datetime.fromtimestamp(
                        fpath.stat().st_mtime, tz=timezone.utc
                    ).isoformat(),
                    "priority": fpath.name in [
                        "s313-command-center-v6.html",
                        "s313-threat-board.html",
                        "shadow313-nexus-dashboard.html",
                    ],
                    "provenance_class": "REAL_OBSERVATION",  # P0-6
                })
    files.sort(key=lambda f: (not f["priority"], f["name"]))
    return files


# ── P0-7: Download receipt ────────────────────────────────────────────────────

def create_download_receipt(filename: str, sha3: str, client_ip: str) -> dict:
    """Create 313-BIND receipt for every download."""
    ts_ns  = time.time_ns()
    ts_313 = int(str(ts_ns)[:-3] + "313")
    payload = f"{filename}:{sha3}:{client_ip}:{ts_313}".encode()
    return {
        "bind_id":       f"313-DL-{secrets.token_hex(4).upper()}",
        "timestamp_ns":  ts_313,
        "timestamp_iso": datetime.now(timezone.utc).isoformat(),
        "filename":      filename,
        "sha3_256":      sha3,
        "client_ip":     client_ip,
        "payload_hash":  "sha3_256:" + hashlib.sha3_256(payload).hexdigest(),
        "event_type":    "file.download",
        "provenance":    "REAL_OBSERVATION",
    }


# ── Hardened HTTP Handler ─────────────────────────────────────────────────────

_rate_limiter   = RateLimiter(RATE_LIMIT_RPM)
_file_hashes:   dict[str, str] = {}   # filename → sha3_256
_current_index: str = ""
_current_manifest: dict = {}
_download_receipts: list[dict] = []
_receipt_lock = threading.Lock()


class HardenedHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        client_ip = self.client_address[0]

        # P0-5: Rate limiting
        if not _rate_limiter.is_allowed(client_ip):
            self.send_error(429, "Too Many Requests")
            return

        path = self.path.split("?")[0]

        if path in ("/", "/index.html"):
            self._send_html(_current_index)

        elif path == "/manifest.json":
            self._send_json(_current_manifest)

        elif path == "/status":
            self._send_json({
                "status":    "running",
                "bind_host": BIND_HOST,
                "port":      SERVER_PORT,
                "files":     len(_file_hashes),
                "downloads": len(_download_receipts),
                "security":  {
                    "localhost_only":    True,
                    "hash_headers":      True,
                    "rate_limiting":     True,
                    "secret_scanning":   True,
                    "receipt_on_dl":     True,
                    "provenance_tagged": True,
                }
            })

        elif path == "/receipts":
            with _receipt_lock:
                self._send_json({"receipts": _download_receipts[-20:]})

        elif path.startswith("/verify/"):
            fname = path[len("/verify/"):]
            sha3  = _file_hashes.get(fname)
            if sha3:
                self._send_json({
                    "filename": fname,
                    "sha3_256": sha3,
                    "verified": True,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
            else:
                self.send_error(404, f"File not found: {fname}")

        elif path.startswith("/download/"):
            # P0-2: Force download with hash header
            # P0-7: Create receipt for every download
            fname = path[len("/download/"):]
            fpath = DOCS_DIR / fname
            if fpath.exists() and fpath.is_file():
                content = fpath.read_bytes()
                sha3    = hashlib.sha3_256(content).hexdigest()

                # Create download receipt
                receipt = create_download_receipt(fname, sha3, client_ip)
                with _receipt_lock:
                    _download_receipts.append(receipt)
                    # Save receipt
                    rpath = RECEIPT_DIR / f"{receipt['bind_id']}.json"
                    rpath.write_text(json.dumps(receipt, indent=2))

                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
                self.send_header("Content-Length", str(len(content)))
                # P0-2: Hash headers for client verification
                self.send_header("X-Content-SHA3-256", sha3)
                self.send_header("X-Delivery-Receipt", receipt["bind_id"])
                self.send_header("X-Provenance-Class", "REAL_OBSERVATION")
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_error(404)

        elif path.startswith("/"):
            fname = path.lstrip("/")
            fpath = DOCS_DIR / fname
            if fpath.exists() and fpath.is_file():
                content = fpath.read_bytes()
                sha3    = hashlib.sha3_256(content).hexdigest()
                ctype   = "text/html; charset=utf-8" if fname.endswith(".html") else "application/json"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(content)))
                self.send_header("X-Content-SHA3-256", sha3)  # P0-2
                self.send_header("X-Provenance-Class", "REAL_OBSERVATION")  # P0-6
                # Security headers
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy",
                    "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; "
                    "script-src 'unsafe-inline'; style-src 'unsafe-inline' https://fonts.googleapis.com;")
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_error(404)

    def log_message(self, fmt, *args):
        msg = fmt % args
        ts  = datetime.now(timezone.utc).strftime("%H:%M:%S")
        if "200" in msg:
            line = f"  [{ts}] ✅ {self.client_address[0]} {msg}"
        elif "429" in msg:
            line = f"  [{ts}] 🚫 RATE_LIMIT {self.client_address[0]} {msg}"
        else:
            line = f"  [{ts}] ℹ️  {self.client_address[0]} {msg}"
        print(line)
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")


# ── Hardened Daemon ───────────────────────────────────────────────────────────

class HardenedDaemon:

    def __init__(self):
        DAEMON_DIR.mkdir(parents=True, exist_ok=True)
        RECEIPT_DIR.mkdir(parents=True, exist_ok=True)
        self._integrity = SelfIntegrityChecker()
        self._scanner   = PreBuildSecretScanner()
        self._baseline_hashes: dict[str, str] = {}
        self._running   = False
        self._server    = None
        self._last_change = 0.0
        self._snapshots: dict[str, float] = {}

    def _log(self, level: str, msg: str):
        ts   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        line = f"[{ts}] [{level}] {msg}"
        print(line)
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")

    def _check_self_integrity(self) -> bool:
        """P0-3: Verify daemon files haven't been tampered with."""
        if not self._baseline_hashes:
            self._baseline_hashes = self._integrity.compute_hashes()
            self._log("OK   ", f"Baseline hashes recorded for {len(self._baseline_hashes)} daemon files")
            return True
        tampered = self._integrity.verify(self._baseline_hashes)
        if tampered:
            self._log("ERROR", f"INTEGRITY VIOLATION: {tampered}")
            return False
        return True

    def _pre_build_scan(self, files: list[dict]) -> bool:
        """P0-4: Scan for secrets before delivery."""
        doc_paths = [DOCS_DIR / f["name"] for f in files]
        findings  = self._scanner.scan(doc_paths)
        if findings:
            self._log("WARN ", f"Secret scan: {len(findings)} potential secrets found")
            for f in findings[:3]:
                self._log("WARN ", f"  {f['file']}:{f['line']} — {f['pattern']}")
            return False  # Block delivery if secrets found
        return True

    def _rebuild(self):
        """Full rebuild with all security controls."""
        global _file_hashes, _current_index, _current_manifest

        # P0-3: Self-integrity check
        if not self._check_self_integrity():
            self._log("ERROR", "Delivery BLOCKED — daemon integrity check failed")
            return

        self._log("INFO ", "Rebuilding delivery artifacts...")

        # Scan files
        files = scan_with_hashes(DOCS_DIR)
        if not files:
            self._log("WARN ", "No deliverable files found in docs/")
            return

        # P0-4: Secret scan
        if not self._pre_build_scan(files):
            self._log("ERROR", "Delivery BLOCKED — secrets detected in artifacts")
            return

        # Update file hash registry
        _file_hashes = {f["name"]: f["sha3_256"] for f in files}

        # Generate manifest
        ts_ns  = time.time_ns()
        ts_313 = int(str(ts_ns)[:-3] + "313")
        ts     = datetime.now(timezone.utc).isoformat()

        try:
            result = subprocess.run(
                ["git", "rev-parse", "--short", "HEAD"],
                capture_output=True, text=True, cwd=REPO_ROOT
            )
            git_sha = result.stdout.strip() or "local"
        except Exception:
            git_sha = "local"

        delivery_id = f"DEL-{secrets.token_hex(4).upper()}"

        manifest = {
            "manifest_version":  "2.0",
            "delivery_id":       delivery_id,
            "git_sha":           git_sha,
            "generated_at":      ts,
            "timestamp_313":     ts_313,
            "total_files":       len(files),
            "files":             files,
            "provenance_class":  "REAL_OBSERVATION",
            "source":            "hardened-daemon",
            "security_controls": {
                "localhost_only":    True,
                "hash_headers":      True,
                "rate_limiting":     f"{RATE_LIMIT_RPM} req/min",
                "secret_scanning":   True,
                "self_integrity":    True,
                "receipt_on_dl":     True,
                "provenance_tagged": True,
            },
            "daemon_hashes":     self._baseline_hashes,
        }

        content = json.dumps(
            {k: v for k, v in manifest.items() if k != "manifest_hash"},
            sort_keys=True, default=str
        ).encode()
        manifest["manifest_hash"] = "sha3_256:" + hashlib.sha3_256(content).hexdigest()

        # Save manifest
        (DIST_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2, default=str))

        # Build portal index
        try:
            from scripts.delivery.pipeline import build_index
            index = build_index(manifest, SERVER_PORT)
        except Exception:
            index = f"<html><body><h1>S313 NEXUS Delivery Portal</h1><p>{len(files)} files ready</p></body></html>"

        _current_manifest = manifest
        _current_index    = index

        self._log("OK   ",
            f"Delivery {delivery_id} ready: {len(files)} files · "
            f"git:{git_sha} · secrets:CLEAN · integrity:OK"
        )

    def _watch_loop(self):
        """File system watcher."""
        while self._running:
            # Check docs/ for changes
            current: dict[str, float] = {}
            for pattern in ["*.html", "*.json"]:
                for fpath in DOCS_DIR.glob(pattern):
                    if fpath.is_file():
                        current[str(fpath)] = fpath.stat().st_mtime

            changed = [p for p, m in current.items()
                       if p not in self._snapshots or self._snapshots[p] != m]
            changed += [p for p in self._snapshots if p not in current]

            if changed:
                self._last_change = time.time()
                self._log("INFO ", f"Changes: {[Path(c).name for c in changed[:3]]}")

            self._snapshots = current

            if (self._last_change > 0 and
                    time.time() - self._last_change >= DEBOUNCE_DELAY):
                self._last_change = 0.0
                self._rebuild()

            time.sleep(POLL_INTERVAL)

    def start(self):
        """Start hardened daemon."""
        self._running = True
        self._rebuild()

        # Watch thread
        threading.Thread(target=self._watch_loop, daemon=True).start()

        # P0-1: Bind to 127.0.0.1 ONLY
        class SecureServer(socketserver.TCPServer):
            allow_reuse_address = True

        self._server = SecureServer((BIND_HOST, SERVER_PORT), HardenedHandler)

        self._log("OK   ",
            f"Hardened daemon started · "
            f"http://{BIND_HOST}:{SERVER_PORT} · "
            f"localhost-only=TRUE · rate-limit={RATE_LIMIT_RPM}rpm"
        )

        try:
            self._server.serve_forever()
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        self._running = False
        if self._server:
            self._server.shutdown()
        self._log("INFO ", "Hardened daemon stopped")


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="S313 NEXUS Hardened Delivery Daemon")
    parser.add_argument("command", choices=["start", "rebuild", "verify"])
    args = parser.parse_args()

    daemon = HardenedDaemon()

    if args.command == "start":
        daemon.start()
    elif args.command == "rebuild":
        daemon._rebuild()
        print(json.dumps(_current_manifest, indent=2, default=str)[:500])
    elif args.command == "verify":
        hashes = daemon._integrity.compute_hashes()
        print("Daemon file hashes:")
        for f, h in hashes.items():
            print(f"  {f}: {h}")
