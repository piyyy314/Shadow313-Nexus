#!/usr/bin/env python3
"""
Shadow313 NEXUS — Local File Server
Serves HTML/JSON files from docs/ on localhost:8313
Run in Ubuntu WSL2: python3 scripts/serve_files.py
Then open: http://localhost:8313
"""
import http.server
import socketserver
import os
import json
from pathlib import Path

PORT = 8313
DOCS_DIR = Path(__file__).parent.parent / "docs"

HTML_INDEX = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>S313 NEXUS — File Server</title>
<style>
  body{font-family:'Segoe UI',sans-serif;background:#020617;color:#e2e8f0;padding:40px;max-width:800px;margin:0 auto;}
  h1{color:#22c55e;font-size:24px;margin-bottom:8px;}
  .sub{color:#64748b;font-size:13px;margin-bottom:32px;font-family:monospace;}
  .file-list{display:flex;flex-direction:column;gap:10px;}
  .file-card{background:#0b1329;border:1px solid rgba(34,197,94,.2);border-radius:8px;padding:16px 20px;display:flex;align-items:center;justify-content:space-between;}
  .file-name{font-family:monospace;color:#06b6d4;font-size:14px;}
  .file-size{color:#475569;font-size:12px;font-family:monospace;}
  .btn{background:#22c55e;color:#000;font-weight:700;padding:8px 20px;border-radius:6px;text-decoration:none;font-size:13px;}
  .btn:hover{background:#16a34a;}
  .btn-view{background:rgba(6,182,212,.15);color:#06b6d4;border:1px solid rgba(6,182,212,.3);margin-right:8px;}
  .btn-view:hover{background:rgba(6,182,212,.25);}
  footer{margin-top:40px;color:#334155;font-size:11px;font-family:monospace;}
</style>
</head>
<body>
<h1>⬡ S313 NEXUS File Server</h1>
<div class="sub">localhost:{port} · Shadow313 NEXUS v4.0.0 · Ottawa, ON, Canada</div>
<div class="file-list">
{files}
</div>
<footer>Run: python3 scripts/serve_files.py · Stop: Ctrl+C</footer>
</body>
</html>"""

class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.send_index()
        else:
            # Serve file from docs/
            rel = self.path.lstrip('/')
            fpath = DOCS_DIR / rel
            if fpath.exists() and fpath.is_file():
                self.send_response(200)
                if rel.endswith('.html'):
                    self.send_header('Content-Type', 'text/html; charset=utf-8')
                elif rel.endswith('.json'):
                    self.send_header('Content-Type', 'application/json')
                else:
                    self.send_header('Content-Type', 'application/octet-stream')
                    self.send_header('Content-Disposition', f'attachment; filename="{fpath.name}"')
                self.send_header('Content-Length', str(fpath.stat().st_size))
                self.end_headers()
                self.wfile.write(fpath.read_bytes())
            else:
                self.send_error(404, f"File not found: {rel}")

    def send_index(self):
        files_html = ""
        priority = [
            "s313-command-center-v6.html",
            "s313-threat-board.html",
            "shadow313-nexus-dashboard.html",
        ]
        # Show priority files first, then rest
        all_files = list(DOCS_DIR.glob("*.html")) + list(DOCS_DIR.glob("*.json"))
        ordered = []
        for name in priority:
            p = DOCS_DIR / name
            if p.exists():
                ordered.append(p)
        for f in sorted(all_files):
            if f not in ordered:
                ordered.append(f)

        for fpath in ordered:
            size_kb = fpath.stat().st_size // 1024
            files_html += f"""
  <div class="file-card">
    <div>
      <div class="file-name">{fpath.name}</div>
      <div class="file-size">{size_kb} KB</div>
    </div>
    <div>
      <a class="btn btn-view" href="/{fpath.name}" target="_blank">👁 Open</a>
      <a class="btn" href="/{fpath.name}" download="{fpath.name}">⬇ Download</a>
    </div>
  </div>"""

        html = HTML_INDEX.format(port=PORT, files=files_html)
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(html.encode())))
        self.end_headers()
        self.wfile.write(html.encode())

    def log_message(self, fmt, *args):
        print(f"  [{self.address_string()}] {fmt % args}")

if __name__ == '__main__':
    os.chdir(DOCS_DIR)
    print(f"""
╔══════════════════════════════════════════════════════╗
║  S313 NEXUS File Server                              ║
║  http://localhost:{PORT}                              ║
║  Serving: {DOCS_DIR}
║  Stop: Ctrl+C                                        ║
╚══════════════════════════════════════════════════════╝
""")
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        httpd.serve_forever()
