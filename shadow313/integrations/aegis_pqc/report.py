"""
shadow313.integrations.aegis_pqc.report
─────────────────────────────────────────
Generate HTML and JSON reports with embedded 313 receipts.

Every report includes:
  - The full audit findings
  - The 313-BIND receipt (bind_id, timestamp, chain_hash, signature)
  - IPFS anchor link
  - QR code placeholder for the IPFS CID
  - Verification instructions
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Tuple

from .parser import PQCAuditResult
from ...core.binding_sdk.binder import BindReceipt


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Aegis PQC Audit — {bind_id}</title>
<style>
  :root {{
    --green:#22c55e; --red:#ef4444; --amber:#f59e0b;
    --cyan:#06b6d4; --purple:#a78bfa;
  }}
  * {{ box-sizing:border-box; margin: 0; padding: 0; }}
  body {{ font-family:'Segoe UI',system-ui,sans-serif; background:#050a05; color:#e2e8f0; padding:24px; }}
  .header {{ background:linear-gradient(135deg,#0a1a0a,#0d2a0d);
             border-bottom:2px solid var(--green); padding:20px; margin-bottom:20px; border-radius:8px; }}
  .header h1 {{ font-size:22px; color:var(--green); letter-spacing:.05em; }}
  .header .sub {{ font-size:12px; color:#94a3b8; margin-top:6px; font-family:monospace; }}
  .receipt-banner {{
    background:rgba(34,197,94,0.06); border:1px solid rgba(34,197,94,0.25);
    border-radius:10px; margin-bottom:20px; padding:16px;
  }}
  .receipt-banner h2 {{ font-size:13px; color:var(--green); margin-bottom:10px;
                        text-transform:uppercase; letter-spacing:.08em; }}
  .receipt-grid {{ display:grid; grid-template-columns:repeat(3,1fr); gap:12px; }}
  .receipt-field {{ background:rgba(0,0,0,0.3); border-radius:6px; padding:10px; }}
  .receipt-field .label {{ font-size:9px; color:#475569; text-transform:uppercase;
                           letter-spacing:.1em; font-family:monospace; margin-bottom:4px; }}
  .receipt-field .value {{ font-size:11px; color:var(--cyan); font-family:monospace;
                           word-break:break-all; }}
  .receipt-field .value.green {{ color:var(--green); }}
  .receipt-field .value.amber {{ color:var(--amber); }}
  .kpi-row {{ display:grid; grid-template-columns:repeat(5,1fr); gap:12px;
              padding:0; margin-bottom:20px; }}
  .kpi {{ background:rgba(13,26,13,.9); border:1px solid rgba(34,197,94,.15);
          border-radius:10px; padding:16px; text-align:center; }}
  .kpi .num {{ font-size:28px; font-weight:700; }}
  .kpi .lbl {{ font-size:10px; color:#94a3b8; margin-top:3px;
               text-transform:uppercase; letter-spacing:.08em; }}
  .critical {{ color:var(--red); }} .high {{ color:var(--amber); }}
  .medium {{ color:var(--cyan); }} .low {{ color:#94a3b8; }}
  .safe {{ color:var(--green); }}
  .section {{ padding:0; margin-bottom:20px; }}
  .section h2 {{ font-size:14px; font-weight:700; color:var(--green); margin-bottom:12px;
                 padding-bottom:6px; border-bottom:1px solid rgba(34,197,94,.15); }}
  .component {{ background:rgba(13,26,13,.7); border:1px solid rgba(34,197,94,.1);
                border-radius:8px; padding:12px; margin-bottom:8px; }}
  .comp-header {{ display:flex; align-items:center; gap:10px; margin-bottom:6px; }}
  .risk-badge {{ font-size:10px; font-weight:700; padding:2px 8px; border-radius:4px;
                 text-transform:uppercase; letter-spacing:.06em; }}
  .risk-CRITICAL {{ background:rgba(239,68,68,.15); color:var(--red);
                    border:1px solid rgba(239,68,68,.3); }}
  .risk-HIGH {{ background:rgba(245,158,11,.15); color:var(--amber);
                border:1px solid rgba(245,158,11,.3); }}
  .risk-ACCEPTABLE {{ background:rgba(34,197,94,.12); color:var(--green);
                      border:1px solid rgba(34,197,94,.25); }}
  .risk-LOW {{ background:rgba(148,163,184,.1); color:#94a3b8;
               border:1px solid rgba(148,163,184,.2); }}
  .comp-name {{ font-weight:600; font-size:13px; }}
  .comp-algo {{ font-size:11px; color:#94a3b8; font-family:monospace; }}
  .comp-detail {{ font-size:11px; color:#64748b; margin-top:4px; }}
  .comp-fix {{ font-size:11px; color:var(--green); background:rgba(34,197,94,.05);
               border-left:2px solid var(--green); padding:4px 8px;
               border-radius:0 4px 4px 0; margin-top:6px; }}
  .verify-box {{ background:rgba(6,182,212,.05); border:1px solid rgba(6,182,212,.2);
                 border-radius:8px; padding:16px; margin:20px 0; }}
  .verify-box h3 {{ font-size:12px; color:var(--cyan); margin-bottom:8px; }}
  .verify-box code {{ font-size:11px; color:#94a3b8; font-family:monospace;
                      display:block; margin-top:4px; }}
  .footer {{ text-align:center; padding:16px 0; font-size:10px; color:#475569;
             border-top:1px solid rgba(34,197,94,.1); margin-top:20px; }}
</style>
</head>
<body>
<div class="header">
  <h1>&#x2B21; Aegis PQC Audit &#x2014; Bound Report</h1>
  <div class="sub">
    Source: {source_file} &nbsp;|&nbsp;
    Format: {source_format} &nbsp;|&nbsp;
    Generated: {generated_at} &nbsp;|&nbsp;
    Tool: {tool_name} v{tool_version}
  </div>
</div>

<!-- 313 Receipt Banner -->
<div class="receipt-banner">
  <h2>&#x2B21; 313 Temporal Binding Receipt &#x2014; Cryptographic Proof of Audit</h2>
  <div class="receipt-grid">
    <div class="receipt-field">
      <div class="label">Bind ID</div>
      <div class="value green">{bind_id}</div>
    </div>
    <div class="receipt-field">
      <div class="label">Timestamp (nanoseconds)</div>
      <div class="value">{timestamp_ns}</div>
    </div>
    <div class="receipt-field">
      <div class="label">Timestamp (UTC)</div>
      <div class="value">{timestamp_iso}</div>
    </div>
    <div class="receipt-field">
      <div class="label">Payload Hash (SHA-3-256)</div>
      <div class="value">{payload_hash}</div>
    </div>
    <div class="receipt-field">
      <div class="label">Chain Hash (SHA-3-512)</div>
      <div class="value">{chain_hash}</div>
    </div>
    <div class="receipt-field">
      <div class="label">Signature Algorithm</div>
      <div class="value amber">{signature_algorithm}</div>
    </div>
    <div class="receipt-field">
      <div class="label">IPFS CID</div>
      <div class="value">{ipfs_cid}</div>
    </div>
    <div class="receipt-field">
      <div class="label">IPFS Anchored</div>
      <div class="value {ipfs_color}">{ipfs_anchored}</div>
    </div>
    <div class="receipt-field">
      <div class="label">App ID</div>
      <div class="value">{app_id} v{app_version}</div>
    </div>
  </div>
</div>

<!-- KPI Row -->
<div class="kpi-row">
  <div class="kpi">
    <div class="num {status_color}">{overall_risk_score}</div>
    <div class="lbl">Risk Score /100</div>
  </div>
  <div class="kpi">
    <div class="num critical">{critical_count}</div>
    <div class="lbl">Critical</div>
  </div>
  <div class="kpi">
    <div class="num high">{high_count}</div>
    <div class="lbl">High</div>
  </div>
  <div class="kpi">
    <div class="num safe">{quantum_safe_count}</div>
    <div class="lbl">Quantum Safe</div>
  </div>
  <div class="kpi">
    <div class="num safe">{quantum_readiness_pct}%</div>
    <div class="lbl">PQC Readiness</div>
  </div>
</div>

<!-- Components -->
<div class="section">
  <h2>Cryptographic Components ({total_components} total)</h2>
  {components_html}
</div>

<!-- Verification Instructions -->
<div class="verify-box">
  <h3>&#x2B21; How to Verify This Receipt</h3>
  <p style="font-size:11px;color:#94a3b8;">
    This audit is cryptographically bound to timestamp {timestamp_ns} (ending in ...313).
    Anyone can verify this receipt independently:
  </p>
  <code># Using Shadow313 CLI:</code>
  <code>shadow313 verify {bind_id}</code>
  <code></code>
  <code># Or retrieve from IPFS:</code>
  <code>ipfs cat {ipfs_cid}</code>
  <code></code>
  <code># Chain hash verification:</code>
  <code>echo -n '{verify_canonical}' | sha3sum -a 512</code>
</div>

<div class="footer">
  Aegis PQC Audit &nbsp;&#xB7;&nbsp; Shadow313 NEXUS &nbsp;&#xB7;&nbsp;
  313 Temporal Binding Protocol &nbsp;&#xB7;&nbsp; Ottawa, ON, Canada &nbsp;&#xB7;&nbsp;
  Receipt: {bind_id}
</div>
</body>
</html>"""


def _component_html(comp: "PQCComponent") -> str:
    risk_class = f"risk-{comp.risk_level}"
    fix_html = ""
    if comp.pqc_replacement:
        fix_html = f'<div class="comp-fix">&#x1F527; Migrate to: {comp.pqc_replacement}</div>'
    if comp.action_plan:
        fix_html += f'<div class="comp-fix">&#x1F4CB; {comp.action_plan}</div>'
    failure_html = ""
    if comp.failure_channel:
        failure_html = f'<div class="comp-detail">&#x26A0;&#xFE0F; {comp.failure_channel}</div>'
    code_html = ""
    if comp.target_code_line:
        code_html = f'<div class="comp-detail" style="font-family:monospace">&#x1F4CD; {comp.target_code_line}</div>'

    safe_color = "#22c55e" if comp.is_quantum_safe else "#ef4444"
    return f"""
<div class="component">
  <div class="comp-header">
    <span class="risk-badge {risk_class}">{comp.risk_level}</span>
    <span class="comp-name">{comp.name}</span>
    <span class="comp-algo">{comp.algorithm}</span>
    <span style="margin-left:auto;font-size:10px;color:#475569;">{comp.crypto_type}</span>
  </div>
  <div class="comp-detail">PQC Readiness: <span style="color:{safe_color}">{comp.pqc_readiness}</span></div>
  {failure_html}
  {code_html}
  {fix_html}
</div>"""


def generate_bound_report(
    audit: PQCAuditResult,
    receipt: BindReceipt,
    output_dir: str = "aegis_bound_reports",
) -> Tuple[str, str]:
    """
    Generate HTML and JSON reports with embedded 313 receipt.

    Returns:
        (html_path, json_path) tuple of generated file paths
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    safe_bind_id = receipt.bind_id.replace("-", "_")

    # Build components HTML
    components_html = "\n".join(_component_html(c) for c in audit.components)

    # Status color
    status_color = {
        "VULNERABLE": "critical",
        "DEGRADED":   "high",
        "SECURE":     "safe",
    }.get(audit.overall_status, "")

    # Canonical string for verification
    verify_canonical = json.dumps({
        "payload_hash": receipt.payload_hash,
        "timestamp_ns": receipt.timestamp_ns,
        "prev_hash":    receipt.prev_chain_hash,
        "app_id":       receipt.app_id,
    }, sort_keys=True, separators=(',', ':'))

    # Render HTML
    html = HTML_TEMPLATE.format(
        bind_id              = receipt.bind_id,
        source_file          = audit.source_file,
        source_format        = audit.source_format,
        generated_at         = audit.generated_at,
        tool_name            = audit.tool_name,
        tool_version         = audit.tool_version,
        timestamp_ns         = receipt.timestamp_ns,
        timestamp_iso        = receipt.timestamp_iso,
        payload_hash         = receipt.payload_hash,
        chain_hash           = receipt.chain_hash,
        signature_algorithm  = receipt.signature_algorithm,
        ipfs_cid             = receipt.ipfs_cid or "Not anchored",
        ipfs_anchored        = "✅ Anchored" if receipt.ipfs_anchored else "⚠️ Not anchored",
        ipfs_color           = "green" if receipt.ipfs_anchored else "amber",
        app_id               = receipt.app_id,
        app_version          = receipt.app_version,
        overall_risk_score   = audit.overall_risk_score,
        status_color         = status_color,
        critical_count       = audit.critical_count,
        high_count           = audit.high_count,
        quantum_safe_count   = audit.quantum_safe_count,
        quantum_readiness_pct= audit.quantum_readiness_pct,
        total_components     = len(audit.components),
        components_html      = components_html,
        verify_canonical     = verify_canonical[:80] + "...",
    )

    html_path = str(out / f"aegis_bound_{safe_bind_id}.html")
    json_path = str(out / f"aegis_bound_{safe_bind_id}.json")

    Path(html_path).write_text(html, encoding="utf-8")

    # JSON report
    json_report = {
        "receipt": receipt.to_dict(),
        "audit":   audit.to_bind_payload(),
        "summary": audit.to_summary(),
    }
    Path(json_path).write_text(
        json.dumps(json_report, indent=2, default=str),
        encoding="utf-8",
    )

    return html_path, json_path