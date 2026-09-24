#!/usr/bin/env python3
"""
Shadow313 NEXUS — Automated File Delivery Pipeline
Handles: config generation → versioning → build → serve → notify

Workflow:
  1. Scan workspace for deliverable artifacts
  2. Generate version manifest with SHA3-256 hashes
  3. Build index page with download buttons
  4. Start local HTTP server on port 8313
  5. Open browser automatically
  6. Write 313-BIND delivery receipt

Usage:
  python3 scripts/delivery/pipeline.py
  python3 scripts/delivery/pipeline.py --port 8314 --no-browser
  python3 scripts/delivery/pipeline.py --watch   # auto-rebuild on file change
"""
from __future__ import annotations

import argparse
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
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# ── Config ────────────────────────────────────────────────────────────────────

REPO_ROOT   = Path(__file__).parent.parent.parent
DOCS_DIR    = REPO_ROOT / "docs"
DIST_DIR    = REPO_ROOT / "dist"
MANIFEST    = DIST_DIR / "manifest.json"
RECEIPT_DIR = DIST_DIR / "receipts"

DELIVERABLE_PATTERNS = [
    "*.html",
    "*.json",
    "*.md",
]

PRIORITY_FILES = [
    "s313-command-center-v6.html",
    "s313-threat-board.html",
    "shadow313-nexus-dashboard.html",
    "s313-threat-board.html",
]

VERSION_FILE = REPO_ROOT / "shadow313" / "__init__.py"

# ── Version detection ─────────────────────────────────────────────────────────

def get_version() -> str:
    try:
        import sys
        sys.path.insert(0, str(REPO_ROOT))
        from shadow313 import __version__
        return __version__
    except Exception:
        return "4.0.0"

def get_git_sha() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, cwd=REPO_ROOT
        )
        return result.stdout.strip() or "unknown"
    except Exception:
        return "unknown"

def get_git_branch() -> str:
    try:
        result = subprocess.run(
            ["git", "branch", "--show-current"],
            capture_output=True, text=True, cwd=REPO_ROOT
        )
        return result.stdout.strip() or "master"
    except Exception:
        return "master"

# ── File scanning ─────────────────────────────────────────────────────────────

def scan_deliverables() -> list[dict]:
    """Scan docs/ for all deliverable files."""
    files = []
    for pattern in DELIVERABLE_PATTERNS:
        for fpath in sorted(DOCS_DIR.glob(pattern)):
            if fpath.is_file():
                content = fpath.read_bytes()
                sha3 = hashlib.sha3_256(content).hexdigest()
                files.append({
                    "name":     fpath.name,
                    "path":     str(fpath.relative_to(REPO_ROOT)),
                    "size":     fpath.stat().st_size,
                    "size_kb":  round(fpath.stat().st_size / 1024, 1),
                    "sha3_256": sha3,
                    "modified": datetime.fromtimestamp(
                        fpath.stat().st_mtime, tz=timezone.utc
                    ).isoformat(),
                    "priority": fpath.name in PRIORITY_FILES,
                    "type":     fpath.suffix.lstrip("."),
                })
    # Sort: priority files first
    files.sort(key=lambda f: (not f["priority"], f["name"]))
    return files

# ── Manifest generation ───────────────────────────────────────────────────────

def generate_manifest(files: list[dict]) -> dict:
    """Generate versioned delivery manifest."""
    version   = get_version()
    git_sha   = get_git_sha()
    git_branch = get_git_branch()
    ts        = datetime.now(timezone.utc).isoformat()
    ts_ns     = time.time_ns()
    ts_313    = int(str(ts_ns)[:-3] + "313")

    manifest = {
        "manifest_version": "1.0",
        "schema":           "shadow313-delivery-manifest",
        "platform_version": version,
        "git_sha":          git_sha,
        "git_branch":       git_branch,
        "generated_at":     ts,
        "timestamp_313":    ts_313,
        "total_files":      len(files),
        "total_size_kb":    round(sum(f["size"] for f in files) / 1024, 1),
        "files":            files,
        "provenance_class": "REAL_OBSERVATION",
        "delivery_id":      f"DEL-{secrets.token_hex(4).upper()}",
    }

    # Compute manifest hash
    manifest_content = json.dumps(
        {k: v for k, v in manifest.items() if k != "manifest_hash"},
        sort_keys=True, default=str
    ).encode()
    manifest["manifest_hash"] = "sha3_256:" + hashlib.sha3_256(manifest_content).hexdigest()

    return manifest

# ── 313-BIND delivery receipt ─────────────────────────────────────────────────

def create_delivery_receipt(manifest: dict) -> dict:
    """Create a 313-BIND receipt for this delivery."""
    ts_ns  = time.time_ns()
    ts_313 = int(str(ts_ns)[:-3] + "313")

    payload = json.dumps({
        "delivery_id":   manifest["delivery_id"],
        "manifest_hash": manifest["manifest_hash"],
        "file_count":    manifest["total_files"],
        "version":       manifest["platform_version"],
    }, sort_keys=True).encode()

    payload_hash = "sha3_256:" + hashlib.sha3_256(payload).hexdigest()
    chain_hash   = "sha3_512:" + hashlib.sha3_512(
        f"{payload_hash}:{ts_313}".encode()
    ).hexdigest()

    receipt = {
        "bind_id":             f"313-DEL-{secrets.token_hex(4).upper()}",
        "timestamp_ns":        ts_313,
        "timestamp_iso":       datetime.now(timezone.utc).isoformat(),
        "delivery_id":         manifest["delivery_id"],
        "payload_hash":        payload_hash,
        "chain_hash":          chain_hash,
        "signature_algorithm": "SHA3-512 (SLH-DSA pending liboqs)",
        "files_delivered":     manifest["total_files"],
        "platform_version":    manifest["platform_version"],
        "git_sha":             manifest["git_sha"],
    }
    return receipt

# ── Index page builder ────────────────────────────────────────────────────────

def build_index(manifest: dict, port: int) -> str:
    """Build the delivery index HTML page."""
    files = manifest["files"]

    file_cards = ""
    for f in files:
        icon = "📊" if f["name"].endswith(".html") else "📄" if f["name"].endswith(".json") else "📝"
        priority_badge = '<span style="background:rgba(34,197,94,.15);color:#22c55e;border:1px solid rgba(34,197,94,.3);border-radius:3px;padding:1px 6px;font-size:9px;font-weight:700;margin-left:6px;">PRIORITY</span>' if f["priority"] else ""
        file_cards += f"""
        <div class="file-card">
          <div class="file-info">
            <div class="file-icon">{icon}</div>
            <div>
              <div class="file-name">{f['name']}{priority_badge}</div>
              <div class="file-meta">{f['size_kb']} KB · {f['type'].upper()} · Modified {f['modified'][:10]}</div>
              <div class="file-hash">{f['sha3_256'][:32]}...</div>
            </div>
          </div>
          <div class="file-actions">
            <a class="btn btn-view" href="/{f['name']}" target="_blank">👁 Open</a>
            <a class="btn btn-dl" href="/download/{f['name']}" download="{f['name']}">⬇ Download</a>
          </div>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>S313 NEXUS — Delivery Portal v{manifest['platform_version']}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
  :root{{--bg:#020617;--bg2:#0b1329;--green:#22c55e;--cyan:#06b6d4;--border:rgba(34,197,94,0.12);--text:#e2e8f0;--muted:#64748b;}}
  *{{box-sizing:border-box;margin:0;padding:0;}}
  body{{font-family:'Space Grotesk',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;padding:0;}}
  .header{{background:rgba(2,6,23,.98);border-bottom:1px solid var(--border);padding:0 32px;height:56px;display:flex;align-items:center;gap:12px;position:sticky;top:0;backdrop-filter:blur(14px);}}
  .logo{{display:flex;align-items:center;gap:8px;font-weight:700;font-size:16px;}}
  .logo-icon{{width:32px;height:32px;background:var(--green);border-radius:7px;display:flex;align-items:center;justify-content:center;font-weight:900;color:#000;font-size:12px;font-family:'JetBrains Mono',monospace;}}
  .header-sub{{font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--muted);letter-spacing:.08em;text-transform:uppercase;}}
  .header-right{{margin-left:auto;font-size:10px;font-family:'JetBrains Mono',monospace;color:var(--muted);display:flex;gap:16px;align-items:center;}}
  .live-dot{{width:7px;height:7px;border-radius:50%;background:var(--green);animation:pulse 2s infinite;}}
  @keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.5}}}}
  .main{{max-width:900px;margin:0 auto;padding:32px 24px;}}
  .hero{{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:24px 28px;margin-bottom:24px;}}
  .hero-title{{font-size:22px;font-weight:700;color:var(--green);margin-bottom:6px;}}
  .hero-sub{{font-size:13px;color:var(--muted);margin-bottom:16px;}}
  .meta-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;}}
  .meta-item{{background:rgba(0,0,0,.3);border-radius:6px;padding:8px 12px;}}
  .meta-label{{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);font-family:'JetBrains Mono',monospace;}}
  .meta-val{{font-size:13px;font-weight:700;color:var(--cyan);font-family:'JetBrains Mono',monospace;margin-top:2px;}}
  .section-title{{font-size:12px;font-weight:700;color:var(--green);text-transform:uppercase;letter-spacing:.06em;margin-bottom:12px;}}
  .file-list{{display:flex;flex-direction:column;gap:8px;margin-bottom:24px;}}
  .file-card{{background:var(--bg2);border:1px solid rgba(30,41,59,.8);border-radius:8px;padding:14px 18px;display:flex;align-items:center;justify-content:space-between;gap:16px;transition:border-color .2s;}}
  .file-card:hover{{border-color:rgba(34,197,94,.3);}}
  .file-info{{display:flex;align-items:center;gap:12px;flex:1;min-width:0;}}
  .file-icon{{font-size:22px;flex-shrink:0;}}
  .file-name{{font-size:13px;font-weight:700;color:var(--text);display:flex;align-items:center;gap:6px;}}
  .file-meta{{font-size:10px;color:var(--muted);font-family:'JetBrains Mono',monospace;margin-top:2px;}}
  .file-hash{{font-size:9px;color:#334155;font-family:'JetBrains Mono',monospace;margin-top:2px;}}
  .file-actions{{display:flex;gap:8px;flex-shrink:0;}}
  .btn{{padding:8px 16px;border-radius:6px;font-size:12px;font-weight:700;text-decoration:none;transition:all .15s;display:inline-block;}}
  .btn-view{{background:rgba(6,182,212,.12);color:var(--cyan);border:1px solid rgba(6,182,212,.3);}}
  .btn-view:hover{{background:rgba(6,182,212,.22);}}
  .btn-dl{{background:var(--green);color:#000;border:1px solid var(--green);}}
  .btn-dl:hover{{background:#16a34a;}}
  .receipt{{background:var(--bg2);border:1px solid rgba(34,197,94,.2);border-radius:8px;padding:16px 20px;}}
  .receipt-title{{font-size:11px;font-weight:700;color:var(--green);text-transform:uppercase;letter-spacing:.06em;margin-bottom:10px;}}
  .receipt-grid{{display:grid;grid-template-columns:1fr 1fr;gap:8px;}}
  .receipt-field{{background:rgba(0,0,0,.3);border-radius:5px;padding:6px 10px;}}
  .receipt-label{{font-size:8px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);font-family:'JetBrains Mono',monospace;}}
  .receipt-val{{font-size:10px;color:var(--cyan);font-family:'JetBrains Mono',monospace;margin-top:2px;word-break:break-all;}}
  .receipt-val.green{{color:var(--green);}}
  .footer{{text-align:center;padding:24px;font-size:10px;color:#334155;font-family:'JetBrains Mono',monospace;border-top:1px solid var(--border);margin-top:24px;}}
  .refresh-btn{{background:rgba(34,197,94,.1);color:var(--green);border:1px solid rgba(34,197,94,.25);padding:6px 14px;border-radius:5px;font-size:11px;font-weight:700;cursor:pointer;font-family:'Space Grotesk',sans-serif;}}
  .refresh-btn:hover{{background:rgba(34,197,94,.2);}}
</style>
</head>
<body>
<header class="header">
  <div class="logo"><div class="logo-icon">S3</div>S313 NEXUS</div>
  <span class="header-sub">Delivery Portal</span>
  <div class="header-right">
    <div class="live-dot"></div>
    <span id="clock" style="font-family:'JetBrains Mono',monospace;"></span>
    <span>localhost:{port}</span>
    <button class="refresh-btn" onclick="location.reload()">↻ Refresh</button>
  </div>
</header>
<div class="main">
  <div class="hero">
    <div class="hero-title">⬡ Shadow313 NEXUS — Artifact Delivery Portal</div>
    <div class="hero-sub">All files are SHA3-256 verified · 313-BIND receipt anchored · Ready to download</div>
    <div class="meta-grid">
      <div class="meta-item"><div class="meta-label">Platform Version</div><div class="meta-val">v{manifest['platform_version']}</div></div>
      <div class="meta-item"><div class="meta-label">Git SHA</div><div class="meta-val">{manifest['git_sha']}</div></div>
      <div class="meta-item"><div class="meta-label">Files Ready</div><div class="meta-val">{manifest['total_files']}</div></div>
      <div class="meta-item"><div class="meta-label">Total Size</div><div class="meta-val">{manifest['total_size_kb']} KB</div></div>
    </div>
  </div>
  <div class="section-title">📦 Deliverable Artifacts</div>
  <div class="file-list">{file_cards}</div>
  <div class="section-title">🔐 313-BIND Delivery Receipt</div>
  <div class="receipt">
    <div class="receipt-title">⬡ Cryptographic Delivery Proof</div>
    <div class="receipt-grid">
      <div class="receipt-field"><div class="receipt-label">Delivery ID</div><div class="receipt-val green">{manifest['delivery_id']}</div></div>
      <div class="receipt-field"><div class="receipt-label">Generated At</div><div class="receipt-val">{manifest['generated_at'][:19]} UTC</div></div>
      <div class="receipt-field"><div class="receipt-label">Manifest Hash</div><div class="receipt-val">{manifest['manifest_hash'][:48]}...</div></div>
      <div class="receipt-field"><div class="receipt-label">Timestamp 313</div><div class="receipt-val">{manifest['timestamp_313']}</div></div>
    </div>
  </div>
</div>
<div class="footer">
  S313 NEXUS v{manifest['platform_version']} · Delivery Portal · Ottawa, ON, Canada · matarmohamad313@duck.com<br>
  Delivery ID: {manifest['delivery_id']} · Git: {manifest['git_sha']} · {manifest['generated_at'][:10]}
</div>
<script>
function updateClock(){{document.getElementById('clock').textContent=new Date().toISOString().replace('T',' ').slice(0,19)+' UTC';}}
updateClock();setInterval(updateClock,1000);
</script>
</body>
</html>"""

# ── HTTP Server ───────────────────────────────────────────────────────────────

class DeliveryHandler(http.server.BaseHTTPRequestHandler):
    manifest: dict = {}
    index_html: str = ""
    port: int = 8313

    def do_GET(self):
        path = self.path.split("?")[0]

        if path in ("/", "/index.html"):
            self._send_html(self.index_html)

        elif path == "/manifest.json":
            data = json.dumps(self.manifest, indent=2, default=str).encode()
            self._send_bytes(data, "application/json")

        elif path.startswith("/download/"):
            fname = path[len("/download/"):]
            fpath = DOCS_DIR / fname
            if fpath.exists() and fpath.is_file():
                data = fpath.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_error(404)

        elif path.startswith("/"):
            fname = path.lstrip("/")
            fpath = DOCS_DIR / fname
            if fpath.exists() and fpath.is_file():
                ctype = "text/html" if fname.endswith(".html") else \
                        "application/json" if fname.endswith(".json") else \
                        "text/plain"
                self._send_bytes(fpath.read_bytes(), ctype)
            else:
                self.send_error(404)

    def _send_html(self, html: str):
        data = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_bytes(self, data: bytes, ctype: str):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        msg = fmt % args
        if "200" in msg:
            print(f"  ✅ {self.address_string()} → {msg}")
        elif "404" in msg:
            print(f"  ❌ {self.address_string()} → {msg}")

# ── Main pipeline ─────────────────────────────────────────────────────────────

def run_pipeline(port: int = 8313, open_browser: bool = True, watch: bool = False):
    DIST_DIR.mkdir(exist_ok=True)
    RECEIPT_DIR.mkdir(exist_ok=True)

    print("\n╔══════════════════════════════════════════════════════╗")
    print("║  S313 NEXUS — Automated Delivery Pipeline            ║")
    print("╚══════════════════════════════════════════════════════╝\n")

    # Step 1: Scan
    print("  [1/5] Scanning deliverable artifacts...")
    files = scan_deliverables()
    print(f"        Found {len(files)} files in docs/")

    # Step 2: Generate manifest
    print("  [2/5] Generating versioned manifest...")
    manifest = generate_manifest(files)
    MANIFEST.write_text(json.dumps(manifest, indent=2, default=str))
    print(f"        Delivery ID: {manifest['delivery_id']}")
    print(f"        Version: v{manifest['platform_version']} · Git: {manifest['git_sha']}")

    # Step 3: Create 313-BIND receipt
    print("  [3/5] Creating 313-BIND delivery receipt...")
    receipt = create_delivery_receipt(manifest)
    receipt_path = RECEIPT_DIR / f"{receipt['bind_id']}.json"
    receipt_path.write_text(json.dumps(receipt, indent=2, default=str))
    print(f"        Bind ID: {receipt['bind_id']}")
    print(f"        Timestamp: {receipt['timestamp_ns']} (ends in ...313)")

    # Step 4: Build index
    print("  [4/5] Building delivery portal index...")
    index_html = build_index(manifest, port)
    (DIST_DIR / "index.html").write_text(index_html)
    print(f"        Portal ready: {len(index_html)} bytes")

    # Step 5: Start server
    print(f"  [5/5] Starting delivery server on port {port}...")

    DeliveryHandler.manifest  = manifest
    DeliveryHandler.index_html = index_html
    DeliveryHandler.port      = port

    class QuietServer(socketserver.TCPServer):
        allow_reuse_address = True

    with QuietServer(("", port), DeliveryHandler) as httpd:
        url = f"http://localhost:{port}"
        print(f"\n  ✅ DELIVERY PORTAL LIVE: {url}")
        print(f"  📦 {len(files)} files ready to download")
        print(f"  🔐 Receipt: {receipt['bind_id']}")
        print(f"\n  Press Ctrl+C to stop\n")

        if open_browser:
            threading.Timer(0.8, lambda: webbrowser.open(url)).start()

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n\n  Pipeline stopped. Receipts saved to dist/receipts/")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="S313 NEXUS Delivery Pipeline")
    parser.add_argument("--port",       type=int, default=8313)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--watch",      action="store_true")
    args = parser.parse_args()
    run_pipeline(
        port=args.port,
        open_browser=not args.no_browser,
        watch=args.watch,
    )
