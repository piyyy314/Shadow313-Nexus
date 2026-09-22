"""
shadow313.integrations.stia.report
────────────────────────────────────
Generates HTML and JSON bound reports for STIA scan results
with embedded 313 Temporal Binding receipt metadata.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Tuple

from .parser import STIAScanResult


def generate_stia_report(
    result: STIAScanResult,
    receipt: Optional[object],
    output_dir: str = "stia_bound_reports",
) -> Tuple[str, str]:
    """
    Generate HTML + JSON bound report for a STIA scan result.

    Returns:
        (html_path, json_path) — absolute paths to generated files.
        Returns ("", "") if output directory cannot be created.
    """
    try:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in result.target_id)
        base_name = f"stia_{safe_id}_{ts}"

        json_path = str(out / f"{base_name}.json")
        html_path = str(out / f"{base_name}.html")

        # ── JSON report ───────────────────────────────────────────────────────
        report_data = {
            "report_type":    "STIA_313_BOUND",
            "generated_at":   datetime.now(timezone.utc).isoformat(),
            "scan_result":    result.to_bind_payload(),
            "nexus_findings": result.to_nexus_findings(),
            "receipt":        _receipt_to_dict(receipt),
        }
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(report_data, fh, indent=2, default=str)

        # ── HTML report ───────────────────────────────────────────────────────
        html = _render_html(result, receipt, report_data)
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(html)

        return html_path, json_path

    except Exception as exc:
        import logging
        logging.getLogger("shadow313.stia.report").warning("Report generation failed: %s", exc)
        return "", ""


# ── Internal helpers ──────────────────────────────────────────────────────────

def _receipt_to_dict(receipt: Optional[object]) -> dict:
    """Safely convert receipt to dict regardless of type."""
    if receipt is None:
        return {}
    if hasattr(receipt, "to_dict"):
        return receipt.to_dict()
    # BindReceipt from SDK
    return {
        "bind_id":             getattr(receipt, "bind_id", None),
        "timestamp_ns":        getattr(receipt, "timestamp_ns", None),
        "timestamp_iso":       getattr(receipt, "timestamp_iso", None),
        "payload_hash":        getattr(receipt, "payload_hash", None),
        "chain_hash":          getattr(receipt, "chain_hash", None),
        "signature_algorithm": getattr(receipt, "signature_algorithm", None),
        "ipfs_cid":            getattr(receipt, "ipfs_cid", None),
        "ipfs_anchored":       getattr(receipt, "ipfs_anchored", False),
        "app_id":              getattr(receipt, "app_id", None),
        "app_version":         getattr(receipt, "app_version", None),
    }


def _risk_color(risk_level: str) -> str:
    return {
        "CRITICAL": "#ff2d55",
        "HIGH":     "#ff9500",
        "MEDIUM":   "#ffcc00",
        "LOW":      "#34c759",
        "NONE":     "#8e8e93",
    }.get(risk_level.upper(), "#8e8e93")


def _render_html(
    result: STIAScanResult,
    receipt: Optional[object],
    report_data: dict,
) -> str:
    """Render a self-contained HTML report."""
    risk_color = _risk_color(result.risk_level)
    receipt_dict = report_data.get("receipt", {})
    bind_id = receipt_dict.get("bind_id", "N/A")
    ts_iso  = receipt_dict.get("timestamp_iso", "N/A")
    ipfs    = receipt_dict.get("ipfs_cid") or "Not anchored"
    sig_algo = receipt_dict.get("signature_algorithm", "N/A")
    chain_hash = receipt_dict.get("chain_hash", "N/A")
    if chain_hash and len(chain_hash) > 40:
        chain_hash = chain_hash[:40] + "…"

    cve_rows = "".join(
        f"<tr><td>{cve}</td></tr>" for cve in result.cve_list
    ) or "<tr><td>None identified</td></tr>"

    tactic_rows = "".join(
        f"<tr><td>{t}</td></tr>" for t in result.mitre_tactics
    ) or "<tr><td>None identified</td></tr>"

    technique_rows = "".join(
        f"<tr><td>{t}</td></tr>" for t in result.mitre_techniques
    ) or "<tr><td>None identified</td></tr>"

    artifact_rows = "".join(
        f"<tr><td>{json.dumps(a, default=str)}</td></tr>"
        for a in result.forensic_artifacts
    ) or "<tr><td>None recorded</td></tr>"

    neutralized_badge = (
        '<span style="color:#34c759;font-weight:bold">✓ NEUTRALIZED</span>'
        if result.is_neutralized else
        '<span style="color:#ff9500;font-weight:bold">⚠ ACTIVE</span>'
    )

    ghost_badge = (
        '<span style="color:#00d4ff">👻 Ghost-Watch Stream Active</span>'
        if result.ghost_stream else ""
    )

    signal_badge = (
        '<span style="color:#ff2d55">⚡ Signal Anomaly Detected</span>'
        if result.signal_anomaly else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>STIA 313-BIND Report — {result.target_id}</title>
<style>
  :root {{
    --bg: #0a0a0f; --surface: #12121a; --border: #1e1e2e;
    --text: #e0e0e0; --muted: #888; --green: #00ff88;
    --accent: {risk_color};
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Courier New', monospace;
          font-size: 13px; padding: 24px; }}
  h1 {{ color: var(--green); font-size: 18px; margin-bottom: 4px; }}
  h2 {{ color: var(--accent); font-size: 14px; margin: 20px 0 8px; border-bottom: 1px solid var(--border); padding-bottom: 4px; }}
  .header {{ border: 1px solid var(--accent); padding: 16px; margin-bottom: 20px; border-radius: 4px; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 3px;
            background: var(--accent); color: #000; font-weight: bold; font-size: 12px; }}
  .meta {{ color: var(--muted); font-size: 11px; margin-top: 8px; }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 16px; }}
  th {{ background: var(--surface); color: var(--green); text-align: left;
        padding: 6px 10px; border: 1px solid var(--border); font-size: 11px; }}
  td {{ padding: 5px 10px; border: 1px solid var(--border); vertical-align: top;
        word-break: break-all; }}
  tr:nth-child(even) td {{ background: var(--surface); }}
  .receipt {{ background: var(--surface); border: 1px solid var(--green);
              padding: 12px; border-radius: 4px; margin-top: 20px; }}
  .receipt-title {{ color: var(--green); font-weight: bold; margin-bottom: 8px; }}
  .kv {{ display: flex; gap: 12px; margin: 3px 0; }}
  .kv-key {{ color: var(--muted); min-width: 160px; }}
  .kv-val {{ color: var(--text); word-break: break-all; }}
  .badges {{ margin: 8px 0; display: flex; gap: 12px; flex-wrap: wrap; }}
</style>
</head>
<body>

<div class="header">
  <h1>🛡 STIA 313-BIND REPORT</h1>
  <div style="margin-top:8px">
    <span class="badge">{result.risk_level}</span>
    &nbsp;
    <strong style="font-size:15px">{result.target_name or result.target_id}</strong>
  </div>
  <div class="badges">
    {neutralized_badge}
    {ghost_badge}
    {signal_badge}
  </div>
  <div class="meta">
    Target ID: {result.target_id} &nbsp;|&nbsp;
    Type: {result.target_type or "N/A"} &nbsp;|&nbsp;
    Severity: {result.severity_score:.1f}/10 &nbsp;|&nbsp;
    Parsed: {result.parsed_at}
  </div>
</div>

<h2>Threat Assessment</h2>
<table>
  <tr><th>Field</th><th>Value</th></tr>
  <tr><td>Threat Profile</td><td>{result.threat_profile or "N/A"}</td></tr>
  <tr><td>Risk Level</td><td><span style="color:{risk_color};font-weight:bold">{result.risk_level}</span></td></tr>
  <tr><td>Severity Score</td><td>{result.severity_score:.1f} / 10.0</td></tr>
  <tr><td>Status</td><td>{result.status}</td></tr>
  <tr><td>Orbital Slot</td><td>{result.orbital_slot or "N/A"}</td></tr>
  <tr><td>Frequency</td><td>{f"{result.frequency_mhz:.2f} MHz" if result.frequency_mhz else "N/A"}</td></tr>
  <tr><td>SNR</td><td>{f"{result.snr_db:.1f} dB" if result.snr_db is not None else "N/A"}</td></tr>
</table>

<h2>CVEs Identified ({len(result.cve_list)})</h2>
<table><tr><th>CVE ID</th></tr>{cve_rows}</table>

<h2>MITRE ATT&CK Tactics ({len(result.mitre_tactics)})</h2>
<table><tr><th>Tactic</th></tr>{tactic_rows}</table>

<h2>MITRE ATT&CK Techniques ({len(result.mitre_techniques)})</h2>
<table><tr><th>Technique ID</th></tr>{technique_rows}</table>

<h2>Forensic Artifacts ({len(result.forensic_artifacts)})</h2>
<table><tr><th>Artifact</th></tr>{artifact_rows}</table>

<div class="receipt">
  <div class="receipt-title">🔐 313 Temporal Binding Receipt</div>
  <div class="kv"><span class="kv-key">Bind ID:</span><span class="kv-val">{bind_id}</span></div>
  <div class="kv"><span class="kv-key">Timestamp:</span><span class="kv-val">{ts_iso}</span></div>
  <div class="kv"><span class="kv-key">IPFS Anchor:</span><span class="kv-val">{ipfs}</span></div>
  <div class="kv"><span class="kv-key">Signature Algorithm:</span><span class="kv-val">{sig_algo}</span></div>
  <div class="kv"><span class="kv-key">Chain Hash:</span><span class="kv-val">{chain_hash}</span></div>
</div>

</body>
</html>"""