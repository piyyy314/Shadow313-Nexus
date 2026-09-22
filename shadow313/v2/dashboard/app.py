"""
shadow313.v2.dashboard.app  — v4
FastAPI + HTMX security operations dashboard.
Dark terminal aesthetic, SSE live feed, RAG-enhanced AI chat.
Port: 7313
"""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Shadow313 NEXUS Dashboard</title>
<script src="https://unpkg.com/htmx.org@1.9.10"></script>
<style>
  :root { --bg: #0d1117; --surface: #161b22; --border: #30363d; --accent: #58a6ff; --danger: #f85149; --warn: #d29922; --success: #3fb950; --text: #c9d1d9; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Cascadia Code', 'Fira Code', monospace; }
  header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 12px 24px; display: flex; align-items: center; gap: 16px; }
  header h1 { color: var(--accent); font-size: 1.2em; }
  .badge { background: var(--accent); color: #000; padding: 2px 8px; border-radius: 12px; font-size: 0.75em; font-weight: bold; }
  nav { background: var(--surface); border-right: 1px solid var(--border); width: 200px; min-height: calc(100vh - 50px); padding: 16px 0; position: fixed; top: 50px; }
  nav a { display: block; padding: 10px 20px; color: var(--text); text-decoration: none; font-size: 0.9em; }
  nav a:hover, nav a.active { background: var(--border); color: var(--accent); }
  main { margin-left: 200px; padding: 24px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }
  .card h3 { color: var(--accent); font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
  .card .value { font-size: 2em; font-weight: bold; }
  .card .value.danger { color: var(--danger); }
  .card .value.warn { color: var(--warn); }
  .card .value.success { color: var(--success); }
  table { width: 100%; border-collapse: collapse; }
  th { background: var(--border); padding: 10px; text-align: left; font-size: 0.85em; color: var(--accent); }
  td { padding: 8px 10px; border-bottom: 1px solid var(--border); font-size: 0.85em; }
  tr:hover { background: var(--surface); }
  .sev-CRITICAL { color: var(--danger); font-weight: bold; }
  .sev-HIGH { color: #ff7b72; }
  .sev-MEDIUM { color: var(--warn); }
  .sev-LOW { color: var(--success); }
  .chat-box { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; height: 400px; overflow-y: auto; margin-bottom: 12px; }
  .chat-input { display: flex; gap: 8px; }
  .chat-input input { flex: 1; background: var(--bg); border: 1px solid var(--border); color: var(--text); padding: 10px; border-radius: 6px; font-family: inherit; }
  .chat-input button { background: var(--accent); color: #000; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-weight: bold; }
  .live-feed { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 16px; height: 300px; overflow-y: auto; font-size: 0.8em; }
  .event-line { padding: 4px 0; border-bottom: 1px solid var(--border); }
  .event-line .ts { color: #6e7681; margin-right: 8px; }
  .section-title { font-size: 1.1em; color: var(--accent); margin: 24px 0 12px; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
</style>
</head>
<body>
<header>
  <h1>⬡ Shadow313 NEXUS</h1>
  <span class="badge">v4.0.0</span>
  <span style="margin-left: auto; color: #6e7681; font-size: 0.8em;" id="clock"></span>
</header>
<nav>
  <a href="#overview" class="active">📊 Overview</a>
  <a href="#findings">🔍 Findings</a>
  <a href="#sessions">📁 Sessions</a>
  <a href="#graph">🕸 Graph</a>
  <a href="#chat">🤖 AI Chat</a>
  <a href="#live">📡 Live Feed</a>
</nav>
<main>
  <div id="overview">
    <div class="section-title">Overview</div>
    <div class="grid" hx-get="/api/stats" hx-trigger="load, every 30s" hx-swap="innerHTML">
      <div class="card"><h3>Sessions</h3><div class="value" id="stat-sessions">—</div></div>
      <div class="card"><h3>Total Findings</h3><div class="value warn" id="stat-findings">—</div></div>
      <div class="card"><h3>Critical</h3><div class="value danger" id="stat-critical">—</div></div>
      <div class="card"><h3>Receipts</h3><div class="value success" id="stat-receipts">—</div></div>
    </div>
  </div>

  <div id="findings">
    <div class="section-title">Recent Findings</div>
    <div hx-get="/api/findings" hx-trigger="load" hx-swap="innerHTML">
      <p style="color: #6e7681;">Loading findings…</p>
    </div>
  </div>

  <div id="chat">
    <div class="section-title">AI Security Assistant (RAG-Enhanced)</div>
    <div class="chat-box" id="chat-messages">
      <div class="event-line"><span class="ts">NEXUS</span> Shadow313 AI ready. Ask me anything about your security posture.</div>
    </div>
    <div class="chat-input">
      <input type="text" id="chat-input" placeholder="Ask a security question…" onkeydown="if(event.key==='Enter')sendChat()">  {# nosec S03 - HTML event handler, not credential comparison #}
      <button onclick="sendChat()">Send</button>
    </div>
  </div>

  <div id="live">
    <div class="section-title">Live Event Feed</div>
    <div class="live-feed" id="live-feed">
      <div class="event-line"><span class="ts">NEXUS</span> Connecting to event stream…</div>
    </div>
  </div>
</main>

<script>
// Clock
setInterval(() => {
  document.getElementById('clock').textContent = new Date().toUTCString();
}, 1000);

// Chat
async function sendChat() {
  const input = document.getElementById('chat-input');
  const msg   = input.value.trim();
  if (!msg) return;
  input.value = '';
  const box = document.getElementById('chat-messages');
  box.innerHTML += `<div class="event-line"><span class="ts">You</span> ${msg}</div>`;
  box.scrollTop = box.scrollHeight;
  try {
    const resp = await fetch('/api/chat', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({question: msg})
    });
    const data = await resp.json();
    box.innerHTML += `<div class="event-line"><span class="ts" style="color:var(--accent)">AI</span> ${data.answer || data.error || 'No response'}</div>`;
    box.scrollTop = box.scrollHeight;
  } catch(e) {
    box.innerHTML += `<div class="event-line"><span class="ts" style="color:var(--danger)">Error</span> ${e.message}</div>`;
  }
}

// SSE Live Feed
const evtSource = new EventSource('/api/events');
evtSource.onmessage = (e) => {
  const feed = document.getElementById('live-feed');
  const ts   = new Date().toISOString().slice(11,19);
  feed.innerHTML += `<div class="event-line"><span class="ts">${ts}</span> ${e.data}</div>`;
  feed.scrollTop = feed.scrollHeight;
};
</script>
</body>
</html>"""


class DashboardModule:
    """shadow313.v2.dashboard — Web dashboard. Registered: dashboard"""

    def __init__(self, kernel) -> None:
        self.kernel = kernel
        self.out    = kernel.out
        cfg         = kernel.config.get("dashboard", default={})
        self._port  = int(cfg.get("port", 7313))
        self._host  = cfg.get("host", "127.0.0.1")
        self._auto_open = cfg.get("auto_open", True)

    def register(self, kernel) -> None:
        kernel.register("dashboard", self.run)

    def run(
        self,
        port: int = 0,
        host: str = "",
        no_browser: bool = False,
    ) -> dict:
        self.out.section("WEB DASHBOARD")
        port = port or self._port
        host = host or self._host

        try:
            self._start_fastapi(host, port, no_browser)
        except ImportError:
            self.out.warn("FastAPI not installed — pip install shadow313[dashboard]")
            self.out.info("Serving static HTML dashboard instead …")
            self._serve_static(host, port)
        return {"host": host, "port": port}

    def _start_fastapi(self, host: str, port: int, no_browser: bool) -> None:
        from fastapi import FastAPI
        from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
        import uvicorn

        app    = FastAPI(title="Shadow313 NEXUS Dashboard")
        kernel = self.kernel

        @app.get("/", response_class=HTMLResponse)
        async def index():
            return DASHBOARD_HTML

        @app.get("/api/status")
        async def status():
            return {"status": "ok", "version": "4.0.0", "session": kernel.session.id}

        @app.get("/api/stats")
        async def stats():
            sessions_dir = Path(kernel.config.get("storage","sessions_dir",
                                                   default="~/.shadow313/sessions")).expanduser()
            session_count = len(list(sessions_dir.glob("*"))) if sessions_dir.exists() else 0
            findings = (kernel.session.read("findings.json") or {}).get("findings", [])
            temporal = kernel.get_module("temporal")
            receipts = len(temporal.engine.list_receipts()) if temporal else 0
            return {
                "sessions":  session_count,
                "findings":  len(findings),
                "critical":  sum(1 for f in findings if f.get("severity","").upper() == "CRITICAL"),
                "receipts":  receipts,
            }

        @app.get("/api/findings")
        async def get_findings(severity: str = "", limit: int = 50):
            findings = (kernel.session.read("findings.json") or {}).get("findings", [])
            if severity:
                findings = [f for f in findings if f.get("severity","").upper() == severity.upper()]
            return findings[:limit]

        @app.post("/api/chat")
        async def chat(body: dict):
            question = body.get("question", "")
            if not question:
                return {"error": "No question provided"}
            rag = kernel.get_module("rag")
            if rag:
                answer = rag.engine.ask(question)
            else:
                answer = kernel.ai.chat(question)
            return {"answer": answer}

        @app.get("/api/events")
        async def events():
            import asyncio

            async def generate():
                yield "data: Shadow313 NEXUS dashboard connected\n\n"
                max_heartbeats = 10000  # FIX: prevent infinite loop — ~14 hours at 5s interval
                for _ in range(max_heartbeats):
                    await asyncio.sleep(5)
                    yield f"data: Heartbeat — {datetime.now(timezone.utc).isoformat()}\n\n"
                yield "data: Stream ended\n\n"

            return StreamingResponse(generate(), media_type="text/event-stream")

        self.out.success(f"Dashboard starting at http://{host}:{port}")
        if not no_browser and self._auto_open:
            import webbrowser
            webbrowser.open(f"http://{host}:{port}")

        uvicorn.run(app, host=host, port=port, log_level="warning")

    def _serve_static(self, host: str, port: int) -> None:
        """Fallback: serve static HTML with Python's built-in HTTP server."""
        import http.server
        import threading

        html_path = Path("/tmp/shadow313_dashboard.html")
        html_path.write_text(DASHBOARD_HTML)

        class Handler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(DASHBOARD_HTML.encode())
            def log_message(self, *args):
                pass

        server = http.server.HTTPServer((host, port), Handler)
        self.out.success(f"Static dashboard at http://{host}:{port}")
        server.serve_forever()