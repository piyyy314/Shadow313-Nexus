"""
shadow313.cli.main  — v4 NEXUS
Primary CLI entry point — argparse-based command router.
All commands dispatch through the Core Kernel's command bus.

BUG FIXES vs v1:
  - _dispatch() had no handler for 'status' command — added.
  - 'ask' command fallback used sys.argv[2:] which broke when --no-stream
    was passed — fixed to use args.question only.
  - 'session --purge' used hardcoded Config() without passing config_path —
    fixed to use kernel.config.
  - Missing commands: agent, campaign, graph, serve, report, threat-intel,
    sandbox, cloud, crypto-agility, rag, temporal, nexus, stix — all added.
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shadow313",
        description="Shadow313 NEXUS v4.0.0 — Local-First AI-Powered Security Intelligence CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  shadow313 recon --target example.com --mode full
  shadow313 vuln --audit-deps requirements.txt --epss --kev
  shadow313 network --analyze ./capture.pcap --ai-score
  shadow313 defense --audit --profile cis-level2
  shadow313 quantum --scan-host example.com:443
  shadow313 exploit --cve CVE-2024-1234 --lab-mode
  shadow313 temporal --bind-session
  shadow313 nexus --status
  shadow313 ask "how do I scan for post-quantum vulnerabilities?"

Docs:
  shadow313 docs --topic recon
  shadow313 learn --module quantum --interactive
  shadow313 session --list
""",
    )

    # ── Global flags ──────────────────────────────────────────────────────────
    parser.add_argument("--version",   action="version",  version="shadow313 v4.0.0-NEXUS")
    parser.add_argument("--config",    metavar="PATH",    help="Config file path")
    parser.add_argument("--session",   metavar="UUID",    help="Resume session by ID")
    parser.add_argument("--output",    choices=["rich","json","markdown","plain"], help="Output format override")
    parser.add_argument("--verbose",   action="store_true", help="Verbose output")
    parser.add_argument("--no-color",  action="store_true", help="Disable color output")
    parser.add_argument("--no-banner", action="store_true", help="Skip ASCII banner")
    parser.add_argument("--no-ai",     action="store_true", help="Disable AI features")

    sub = parser.add_subparsers(dest="command", title="Commands", metavar="<command>")

    # ── recon ─────────────────────────────────────────────────────────────────
    p_recon = sub.add_parser("recon", help="Reconnaissance — DNS, ports, OSINT, AI profiling")
    p_recon.add_argument("--target",   required=True, metavar="HOST/IP/URL", help="Target")
    p_recon.add_argument("--mode",     default="full", choices=["full","active","passive"])
    p_recon.add_argument("--ports",    default="", metavar="RANGE/LIST")
    p_recon.add_argument("--stealth",  action="store_true")
    p_recon.add_argument("--wordlist", metavar="FILE")

    # ── vuln ──────────────────────────────────────────────────────────────────
    p_vuln = sub.add_parser("vuln", help="Vulnerability analysis — CVE, CVSS, EPSS, KEV, AI triage")
    p_vuln.add_argument("--from-session", metavar="UUID", dest="from_session")
    p_vuln.add_argument("--target",       metavar="SVC")
    p_vuln.add_argument("--audit-deps",   metavar="FILE", dest="audit_deps")
    p_vuln.add_argument("--quick",        action="store_true")
    p_vuln.add_argument("--internet-facing", action="store_true", dest="internet_facing")
    p_vuln.add_argument("--epss",         action="store_true", help="Enrich with EPSS scores")
    p_vuln.add_argument("--kev",          action="store_true", help="Check CISA KEV catalog")
    p_vuln.add_argument("--update-db",    action="store_true", dest="update_db")

    # ── exploit ───────────────────────────────────────────────────────────────
    p_exp = sub.add_parser("exploit", help="Exploitation assistance [ADVISORY / LAB MODE ONLY]")
    p_exp.add_argument("--lab-mode",      action="store_true", dest="lab_mode")
    p_exp.add_argument("--confirm-scope", metavar="AUTHORIZED", dest="confirm_scope")
    p_exp.add_argument("--cve",           metavar="CVE-ID")
    p_exp.add_argument("--assist",        metavar="MODE", choices=["ctf","post","scope-init"])
    p_exp.add_argument("--challenge",     metavar="DESC")
    p_exp.add_argument("--wordlist",      action="store_true")
    p_exp.add_argument("--wl-context",   metavar="CTX", dest="wl_context")
    p_exp.add_argument("--wl-type",      metavar="TYPE", dest="wl_type",
                       choices=["password","username","path"], default="password")
    p_exp.add_argument("--payload",       metavar="NAME")
    p_exp.add_argument("--post-exploit",  action="store_true", dest="post_exploit")
    p_exp.add_argument("--platform",      default="linux", choices=["linux","windows"])
    p_exp.add_argument("--target",        metavar="HOST")
    p_exp.add_argument("--scope-path",   metavar="FILE", dest="scope_path")
    p_exp.add_argument("--decode",        metavar="DATA")
    p_exp.add_argument("--ops",           metavar="OPS")

    # ── network ───────────────────────────────────────────────────────────────
    p_net = sub.add_parser("network", help="Network intelligence — capture, PCAP, anomaly, topology")
    p_net.add_argument("--capture",    metavar="IFACE")
    p_net.add_argument("--duration",   type=int, default=30)
    p_net.add_argument("--analyze",    metavar="PCAP")
    p_net.add_argument("--ai-score",   action="store_true", dest="ai_score")
    p_net.add_argument("--topo",       action="store_true")
    p_net.add_argument("--range",      metavar="CIDR", dest="topo_range")
    p_net.add_argument("--filter",     metavar="BPF", dest="bpf_filter")
    p_net.add_argument("--ml-anomaly", action="store_true", dest="ml_anomaly")
    p_net.add_argument("--ja3",        action="store_true")
    p_net.add_argument("--dns-covert", action="store_true", dest="dns_covert")

    # ── defense ───────────────────────────────────────────────────────────────
    p_def = sub.add_parser("defense", help="Defensive hardening — CIS audit, firewall, AI remediation")
    p_def.add_argument("--audit",      action="store_true")
    p_def.add_argument("--profile",    default="cis-level1", choices=["cis-level1","cis-level2"])
    p_def.add_argument("--firewall",   action="store_true")
    p_def.add_argument("--fw-tool",   default="auto", choices=["auto","ufw","iptables","nftables"], dest="fw_tool")
    p_def.add_argument("--remediate",  action="store_true")
    p_def.add_argument("--output",    choices=["bash","ansible"], default="bash", dest="output_fmt")
    p_def.add_argument("--apply",     action="store_true", dest="apply_fixes")

    # ── quantum ───────────────────────────────────────────────────────────────
    p_q = sub.add_parser("quantum", help="Post-quantum crypto audit — TLS, certs, source code")
    p_q.add_argument("--scan-host",   metavar="HOST:PORT", dest="scan_host")
    p_q.add_argument("--audit-certs", metavar="PATH", dest="audit_certs")
    p_q.add_argument("--scan-code",   metavar="PATH", dest="scan_code")
    p_q.add_argument("--lang",        metavar="LANG", choices=["python","javascript","java","go","c","rust"])
    p_q.add_argument("--report",      action="store_true")

    # ── plugin ────────────────────────────────────────────────────────────────
    p_plug = sub.add_parser("plugin", help="Plugin lifecycle management")
    p_plug.add_argument("--list",    action="store_true", dest="list_plugins")
    p_plug.add_argument("--install", metavar="PATH")
    p_plug.add_argument("--enable",  metavar="NAME")
    p_plug.add_argument("--disable", metavar="NAME")
    p_plug.add_argument("--remove",  metavar="NAME")
    p_plug.add_argument("--new",     metavar="NAME")
    p_plug.add_argument("--hook",    metavar="HOOK")
    p_plug.add_argument("--author",  metavar="HANDLE", dest="new_author")
    p_plug.add_argument("--sign",    metavar="PATH")
    p_plug.add_argument("--verify",  metavar="PATH")
    p_plug.add_argument("--verify-all", action="store_true", dest="verify_all")

    # ── cicd ──────────────────────────────────────────────────────────────────
    p_ci = sub.add_parser("cicd", help="CI/CD integration — SARIF, secret scan, templates")
    p_ci.add_argument("--scan",       action="store_true")
    p_ci.add_argument("--threshold",  default="high", choices=["critical","high","medium","low"])
    p_ci.add_argument("--output",     choices=["rich","json","sarif","junit"], default="rich")
    p_ci.add_argument("--secrets",    action="store_true")
    p_ci.add_argument("--diff",       metavar="FILE/-")
    p_ci.add_argument("--generate",   metavar="TEMPLATE", choices=["github-actions","gitlab-ci","pre-commit"])
    p_ci.add_argument("--pr-summary", action="store_true", dest="pr_summary")
    p_ci.add_argument("--from",       metavar="FILE", dest="from_file")
    p_ci.add_argument("--quiet",      action="store_true")
    p_ci.add_argument("--scan-path",  metavar="PATH", dest="scan_path", default=".")

    # ── docs ──────────────────────────────────────────────────────────────────
    p_docs = sub.add_parser("docs", help="Documentation, module reference, man pages")
    p_docs.add_argument("--topic",    metavar="MODULE")
    p_docs.add_argument("--glossary", action="store_true")
    p_docs.add_argument("--man",      action="store_true")
    p_docs.add_argument("--man-dir",  metavar="DIR", dest="output_dir", default=".")

    # ── ask ───────────────────────────────────────────────────────────────────
    p_ask = sub.add_parser("ask", help="AI-powered natural language security Q&A")
    p_ask.add_argument("question", nargs="?", default="")
    p_ask.add_argument("--no-stream", action="store_false", dest="stream")

    # ── learn ─────────────────────────────────────────────────────────────────
    p_learn = sub.add_parser("learn", help="Interactive module tutorials")
    p_learn.add_argument("--module",      metavar="NAME")
    p_learn.add_argument("--interactive", action="store_true")
    p_learn.add_argument("--step",        type=int, default=0)

    # ── session ───────────────────────────────────────────────────────────────
    p_sess = sub.add_parser("session", help="Session management")
    p_sess.add_argument("--list",  action="store_true")
    p_sess.add_argument("--info",  metavar="UUID")
    p_sess.add_argument("--purge", metavar="UUID")
    p_sess.add_argument("--rekey", metavar="UUID")

    # ── update ────────────────────────────────────────────────────────────────
    p_upd = sub.add_parser("update", help="Update local databases (CVE, ExploitDB, KEV, EPSS)")
    p_upd.add_argument("--db",      metavar="DB", choices=["cve","exploitdb","kev","epss","all"], required=True)
    p_upd.add_argument("--api-key", metavar="KEY", dest="api_key", default="")

    # ── status ────────────────────────────────────────────────────────────────
    sub.add_parser("status", help="System status — AI engine, modules, session info")

    # ── V2 commands ───────────────────────────────────────────────────────────
    p_agent = sub.add_parser("agent", help="Agentic auto-chain module execution")
    p_agent.add_argument("--plan",         default="quick_vuln", choices=["full_pentest","quick_vuln","defense_audit","crypto_audit"])
    p_agent.add_argument("--target",       metavar="HOST", default="")
    p_agent.add_argument("--approval",     choices=["auto","gate_high","full_human"], default="")
    p_agent.add_argument("--suggest-plan", action="store_true", dest="suggest_plan")
    p_agent.add_argument("--list-runs",    action="store_true", dest="list_runs")

    p_campaign = sub.add_parser("campaign", help="Multi-target parallel scanning campaigns")
    p_campaign.add_argument("--targets",     metavar="FILE")
    p_campaign.add_argument("--modules",     default="recon,vuln")
    p_campaign.add_argument("--concurrency", type=int, default=0)
    p_campaign.add_argument("--resume",      metavar="ID")
    p_campaign.add_argument("--list",        action="store_true", dest="list_campaigns")
    p_campaign.add_argument("--name",        default="")

    p_graph = sub.add_parser("graph", help="Intelligence graph queries and export")
    p_graph.add_argument("--ingest-session", metavar="DIR", dest="ingest_session")
    p_graph.add_argument("--query",          metavar="TYPE")
    p_graph.add_argument("--query-arg",      metavar="ARG", dest="query_arg")
    p_graph.add_argument("--risk-ranking",   action="store_true", dest="risk_ranking")
    p_graph.add_argument("--export",         metavar="FORMAT", choices=["graphml","gexf"])
    p_graph.add_argument("--export-path",    metavar="PATH", dest="export_path")
    p_graph.add_argument("--stats",          action="store_true")

    p_serve = sub.add_parser("serve", help="Web dashboard (FastAPI + HTMX)")
    p_serve.add_argument("--port",       type=int, default=0)
    p_serve.add_argument("--host",       default="")
    p_serve.add_argument("--no-browser", action="store_true", dest="no_browser")

    p_report = sub.add_parser("report", help="PDF/HTML security report generation")
    p_report.add_argument("--from-session",  metavar="UUID", dest="from_session")
    p_report.add_argument("--from-campaign", metavar="ID",   dest="from_campaign")
    p_report.add_argument("--output",        metavar="PATH")
    p_report.add_argument("--format",        choices=["html","pdf"], default="html")

    p_ti = sub.add_parser("threat-intel", help="Threat intelligence feed management")
    p_ti.add_argument("--sync",            action="store_true")
    p_ti.add_argument("--lookup",          metavar="IOC")
    p_ti.add_argument("--enrich",          action="store_true")
    p_ti.add_argument("--enrich-session",  metavar="UUID", dest="enrich_session")
    p_ti.add_argument("--stats",           action="store_true")

    p_sb = sub.add_parser("sandbox", help="CVE reproduction in Docker (lab mode)")
    p_sb.add_argument("--cve",         metavar="CVE-ID")
    p_sb.add_argument("--lab-mode",    action="store_true", dest="lab_mode")
    p_sb.add_argument("--list-cves",   action="store_true", dest="list_cves")
    p_sb.add_argument("--cleanup-all", action="store_true", dest="cleanup_all")

    p_cloud = sub.add_parser("cloud", help="Cloud / K8s / Terraform hardening audit")
    p_cloud.add_argument("--scan-aws",       action="store_true", dest="scan_aws")
    p_cloud.add_argument("--scan-k8s",       action="store_true", dest="scan_k8s")
    p_cloud.add_argument("--scan-terraform", metavar="PATH", dest="scan_terraform")
    p_cloud.add_argument("--scan-all",       action="store_true", dest="scan_all")
    p_cloud.add_argument("--output",         choices=["rich","sarif"], default="rich")

    p_ca = sub.add_parser("crypto-agility", help="PQC migration scanning and planning")
    p_ca.add_argument("--scan",                metavar="PATH")
    p_ca.add_argument("--snippet",             metavar="ID")
    p_ca.add_argument("--test-tls",            metavar="HOST:PORT", dest="test_tls")
    p_ca.add_argument("--migration-plan",      action="store_true", dest="migration_plan")
    p_ca.add_argument("--list-pqc-algorithms", action="store_true", dest="list_pqc_algorithms")
    p_ca.add_argument("--languages",           default="")

    p_rag = sub.add_parser("rag", help="RAG knowledge base management")
    p_rag.add_argument("--ingest-nvd",     metavar="FILE", dest="ingest_nvd")
    p_rag.add_argument("--ingest-session", metavar="DIR",  dest="ingest_session")
    p_rag.add_argument("--query",          metavar="TEXT")
    p_rag.add_argument("--namespace",      default="")
    p_rag.add_argument("--stats",          action="store_true")

    # ── V4 commands ───────────────────────────────────────────────────────────
    p_temp = sub.add_parser("temporal", help="313 Temporal Binding Protocol (NEXUS)")
    p_temp.add_argument("--bind",          metavar="CONTENT")
    p_temp.add_argument("--bind-session",  action="store_true", dest="bind_session")
    p_temp.add_argument("--verify",        metavar="RECEIPT-ID")
    p_temp.add_argument("--list-receipts", action="store_true", dest="list_receipts")

    p_nexus = sub.add_parser("nexus", help="NEXUS platform orchestration")
    p_nexus.add_argument("--status",              action="store_true")
    p_nexus.add_argument("--bind-all",            action="store_true", dest="bind_all")
    p_nexus.add_argument("--verify-chain",        action="store_true", dest="verify_chain")
    p_nexus.add_argument("--insider-attack-demo", action="store_true", dest="insider_attack_demo")
    p_nexus.add_argument("--posture-report",      action="store_true", dest="posture_report")

    p_stix = sub.add_parser("stix", help="STIX 2.1 bundle import/export")
    p_stix.add_argument("--import",              metavar="FILE", dest="import_file")
    p_stix.add_argument("--export",              action="store_true")
    p_stix.add_argument("--export-path",         metavar="PATH", dest="export_path")
    p_stix.add_argument("--ingest-threat-intel", action="store_true", dest="ingest_threat_intel")

    p_finetune = sub.add_parser("finetune", help="LoRA fine-tuning config generator")
    p_finetune.add_argument("--generate-config",  action="store_true", dest="generate_config")
    p_finetune.add_argument("--dataset-path",     default="shadow313_training_data.jsonl", dest="dataset_path")
    p_finetune.add_argument("--output-dir",       default="./shadow313-7b-output", dest="output_dir")
    p_finetune.add_argument("--generate-dataset", action="store_true", dest="generate_dataset")
    p_finetune.add_argument("--dataset-size",     type=int, default=100, dest="dataset_size")

    p_mobile = sub.add_parser("mobile-api", help="Mobile companion REST API server")
    p_mobile.add_argument("--port",  type=int, default=7314)
    p_mobile.add_argument("--host",  default="127.0.0.1")
    p_mobile.add_argument("--token", default="")

    p_browser = sub.add_parser("browser-recon", help="Browser-based SPA fingerprinting")
    p_browser.add_argument("--target",          required=True)
    p_browser.add_argument("--use-playwright",  action="store_true", dest="use_playwright")
    p_browser.add_argument("--csp-audit",       action="store_true", dest="csp_audit")

    p_container = sub.add_parser("container-scan", help="Container/image CVE scanning")
    p_container.add_argument("--image",      metavar="IMAGE")
    p_container.add_argument("--dockerfile", metavar="PATH")
    p_container.add_argument("--scan-dir",   metavar="DIR", dest="scan_dir")

    p_ad = sub.add_parser("ad-audit", help="Active Directory security auditing")
    p_ad.add_argument("--server",   required=True)
    p_ad.add_argument("--domain",   required=True)
    p_ad.add_argument("--username", required=True)
    p_ad.add_argument("--password", default="")

    p_siem = sub.add_parser("siem", help="SIEM integration (Splunk/Elastic/Wazuh)")
    p_siem.add_argument("--forward-session",  metavar="UUID", dest="forward_session")
    p_siem.add_argument("--forward-findings", action="store_true", dest="forward_findings")
    p_siem.add_argument("--test",             action="store_true")

    p_malware = sub.add_parser("malware", help="Malware analysis sandbox")
    p_malware.add_argument("--file",      metavar="PATH")
    p_malware.add_argument("--directory", metavar="DIR")
    p_malware.add_argument("--execute",   action="store_true")
    p_malware.add_argument("--lab-mode",  action="store_true", dest="lab_mode")
    p_malware.add_argument("--yara-only", action="store_true", dest="yara_only")


    # ── Vanguard ──────────────────────────────────────────────────────────────
    p_vanguard = sub.add_parser('vanguard', help='Autonomous vulnerability chain planning')
    p_vanguard.add_argument('--plan',           action='store_true')
    p_vanguard.add_argument('--template',       default='web_rce_to_persistence')
    p_vanguard.add_argument('--target',         default='')
    p_vanguard.add_argument('--verify',         action='store_true')
    p_vanguard.add_argument('--lab-mode',       action='store_true', dest='lab_mode')
    p_vanguard.add_argument('--list-chains',    action='store_true', dest='list_chains')
    p_vanguard.add_argument('--list-templates', action='store_true', dest='list_templates')

    # ── Aegis ─────────────────────────────────────────────────────────────────
    p_aegis = sub.add_parser('aegis', help='Active defense platform (CADL escalation)')
    p_aegis.add_argument('--ingest',          metavar='EVENT_TYPE', default='')
    p_aegis.add_argument('--event-type',      default='unknown', dest='event_type')
    p_aegis.add_argument('--source-ip',       default='0.0.0.0', dest='source_ip')
    p_aegis.add_argument('--list-incidents',  action='store_true', dest='list_incidents')
    p_aegis.add_argument('--resolve',         metavar='INCIDENT_ID', default='')
    p_aegis.add_argument('--stats',           action='store_true')
    p_aegis.add_argument('--simulate',        action='store_true')
    p_aegis.add_argument('--cadl-level',      type=int, default=0, dest='cadl_level')

    # ── Ghost-Watch ───────────────────────────────────────────────────────────
    p_gw = sub.add_parser('ghost-watch', help='Deception platform (WE-FORGE, BSAU, AETHER)')
    p_gw.add_argument('--forge',         metavar='FILE/CONTENT', default='')
    p_gw.add_argument('--recipient',     default='')
    p_gw.add_argument('--detect',        metavar='FILE/CONTENT', default='')
    p_gw.add_argument('--list-docs',     action='store_true', dest='list_docs')
    p_gw.add_argument('--monitor-node',  metavar='NODE_ID', default='', dest='monitor_node')
    p_gw.add_argument('--score-node',    metavar='NODE_ID', default='', dest='score_node')
    p_gw.add_argument('--correlate',     action='store_true')
    p_gw.add_argument('--deploy-decoy',  metavar='TYPE', default='', dest='deploy_decoy')
    p_gw.add_argument('--port',          type=int, default=0)
    p_gw.add_argument('--list-hubs',     action='store_true', dest='list_hubs')
    p_gw.add_argument('--stats',         action='store_true')

    # ── Quantum NEXUS ─────────────────────────────────────────────────────────
    p_qn = sub.add_parser('quantum-nexus', help='Advanced quantum security (HNDL, QKD, sensor fusion)')
    p_qn.add_argument('--hndl-analyze',    action='store_true', dest='hndl_analyze')
    p_qn.add_argument('--algorithm',       default='RSA-2048')
    p_qn.add_argument('--sensitivity',     default='CONFIDENTIAL')
    p_qn.add_argument('--volume-gb',       type=float, default=1.0, dest='volume_gb')
    p_qn.add_argument('--retention',       type=int, default=10)
    p_qn.add_argument('--qkd-monitor',     action='store_true', dest='qkd_monitor')
    p_qn.add_argument('--qber',            type=float, default=0.0)
    p_qn.add_argument('--simulate-bb84',   action='store_true', dest='simulate_bb84')
    p_qn.add_argument('--eavesdrop',       action='store_true')
    p_qn.add_argument('--fuse-sensors',    action='store_true', dest='fuse_sensors')
    p_qn.add_argument('--mlkem-timing',    action='store_true', dest='mlkem_timing')
    p_qn.add_argument('--full-assessment', action='store_true', dest='full_assessment')
    p_qn.add_argument('--stats',           action='store_true')

    # ── Satellite ─────────────────────────────────────────────────────────────
    p_sat = sub.add_parser('satellite', help='VSAT satellite ground segment security')
    p_sat.add_argument('--gps-check',    action='store_true', dest='gps_check')
    p_sat.add_argument('--freq-mhz',     type=float, default=1575.42, dest='freq_mhz')
    p_sat.add_argument('--snr-db',       type=float, default=35.0, dest='snr_db')
    p_sat.add_argument('--vsat-audit',   metavar='STATION_ID', default='', dest='vsat_audit')
    p_sat.add_argument('--rf-analyze',   action='store_true', dest='rf_analyze')
    p_sat.add_argument('--clock-skew',   type=float, default=0.0, dest='clock_skew')
    p_sat.add_argument('--simulate',     action='store_true')
    p_sat.add_argument('--stats',        action='store_true')

    # ── Threat Actor ──────────────────────────────────────────────────────────
    p_ta = sub.add_parser('threat-actor', help='Threat actor profiling and attribution')
    p_ta.add_argument('--attribute',     action='store_true')
    p_ta.add_argument('--techniques',    default='')
    p_ta.add_argument('--tools',         default='')
    p_ta.add_argument('--indicators',    default='')
    p_ta.add_argument('--profile',       metavar='APT_NAME', default='')
    p_ta.add_argument('--list-actors',   action='store_true', dest='list_actors')
    p_ta.add_argument('--fingerprint',   action='store_true')
    p_ta.add_argument('--from-session',  metavar='UUID', default='', dest='from_session')

    # ── Benchmark ─────────────────────────────────────────────────────────────
    p_bench = sub.add_parser('benchmark', help='Performance benchmark suite')
    p_bench.add_argument('--quick',  action='store_true')
    p_bench.add_argument('--full',   action='store_true')
    p_bench.add_argument('--bench',  metavar='NAME', default='')
    p_bench.add_argument('--save',   metavar='PATH', default='')

    # ── Health ────────────────────────────────────────────────────────────────
    p_health = sub.add_parser('health', help='System health check')
    p_health.add_argument('--quick',       action='store_true')
    p_health.add_argument('--full',        action='store_true')
    p_health.add_argument('--save',        metavar='PATH', default='')
    p_health.add_argument('--json',        action='store_true', dest='json_output')

    # ── Doctor (alias for health --full) ──────────────────────────────────────
    p_doctor = sub.add_parser('doctor', help='Full system diagnostic (alias for health --full)')

    # ── Ghost-Watch CADL ──────────────────────────────────────────────────────
    p_cadl = sub.add_parser('cadl', help='CADL escalation control (via Aegis)')
    p_cadl.add_argument('--level',      type=int, choices=[1,2,3,4,5], default=1)
    p_cadl.add_argument('--incident',   default='')
    p_cadl.add_argument('--simulate',   action='store_true')

    # ── Quantum NEXUS ACTS ────────────────────────────────────────────────────
    p_acts = sub.add_parser('acts', help='ACTS deception stack (via Ghost-Watch)')
    p_acts.add_argument('--deploy',     metavar='TYPE', default='api_server')
    p_acts.add_argument('--port',       type=int, default=0)
    p_acts.add_argument('--list',       action='store_true')

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args   = parser.parse_args(argv)

    if args.command is None:
        _boot(args)
        parser.print_help()
        return 0

    kernel = _boot(args)
    if kernel is None:
        return 1

    return _dispatch(kernel, args, parser)


def _boot(args):
    """Initialise Kernel — returns kernel instance or None on failure."""
    try:
        from shadow313.core.kernel import Kernel
        output_fmt = getattr(args, "output", None)
        if output_fmt in ("json","sarif","junit"):
            verbose = False
        else:
            verbose = getattr(args, "verbose", False)

        kernel = Kernel(
            config_path = getattr(args, "config", None),
            session_id  = getattr(args, "session", None),
            output_fmt  = output_fmt,
            verbose     = verbose,
        )
        if getattr(args, "no_ai", False):
            kernel.config.set("ai", "backend", "disabled")

        if not getattr(args, "no_banner", False) and output_fmt not in ("json","sarif","junit"):
            kernel.out.banner()

        return kernel
    except Exception as exc:
        print(f"[shadow313] Fatal: could not initialise kernel — {exc}", file=sys.stderr)
        if getattr(args, "verbose", False):
            import traceback
            traceback.print_exc()
        return None


def _dispatch(kernel, args, parser) -> int:
    cmd = args.command

    # ── V1 commands ───────────────────────────────────────────────────────────
    if cmd == "recon":
        wordlist = None
        if getattr(args, "wordlist", None):
            wl_path = Path(args.wordlist)
            if wl_path.exists():
                wordlist = wl_path.read_text().splitlines()
        kernel.dispatch("recon", target=args.target, mode=args.mode,
                        ports=args.ports, stealth=args.stealth, wordlist=wordlist)

    elif cmd == "vuln":
        if getattr(args, "update_db", False):
            vm = kernel.get_module("vuln")
            if vm:
                vm.update_cve_db(api_key=getattr(args,"api_key",""))
        else:
            kernel.dispatch("vuln",
                            from_session    = getattr(args,"from_session","") or "",
                            target          = getattr(args,"target","") or "",
                            audit_deps      = getattr(args,"audit_deps","") or "",
                            quick           = args.quick,
                            internet_facing = args.internet_facing,
                            epss            = args.epss,
                            kev             = args.kev)

    elif cmd == "exploit":
        if getattr(args,"decode",None):
            em = kernel.get_module("exploit")
            if em:
                ops    = [o.strip() for o in (args.ops or "").split(",") if o.strip()]
                result = em.decode(args.decode, ops)
                kernel.out.result(result, "Decode Results")
        else:
            kernel.dispatch("exploit",
                            cve          = getattr(args,"cve","") or "",
                            assist       = getattr(args,"assist","") or "",
                            challenge    = getattr(args,"challenge","") or "",
                            wordlist     = args.wordlist,
                            wl_context   = getattr(args,"wl_context","") or "",
                            wl_type      = getattr(args,"wl_type","password"),
                            payload      = getattr(args,"payload","") or "",
                            post_exploit = args.post_exploit,
                            platform     = args.platform,
                            lab_mode     = args.lab_mode,
                            confirm_scope= getattr(args,"confirm_scope","") or "",
                            scope_path   = getattr(args,"scope_path","") or "",
                            target       = getattr(args,"target","") or "")

    elif cmd == "network":
        kernel.dispatch("network",
                        capture    = getattr(args,"capture","") or "",
                        duration   = args.duration,
                        analyze    = getattr(args,"analyze","") or "",
                        ai_score   = args.ai_score,
                        topo       = args.topo,
                        topo_range = getattr(args,"topo_range","") or "",
                        bpf_filter = getattr(args,"bpf_filter","") or "")
        # V2 network upgrades
        if args.ml_anomaly:
            kernel.dispatch("ml_anomaly")
        if args.ja3:
            kernel.dispatch("ja3", analyze=getattr(args,"analyze","") or "")
        if args.dns_covert:
            kernel.dispatch("dns_covert", analyze=getattr(args,"analyze","") or "")

    elif cmd == "defense":
        kernel.dispatch("defense",
                        audit      = args.audit,
                        profile    = args.profile,
                        firewall   = args.firewall,
                        fw_tool    = args.fw_tool,
                        remediate  = args.remediate,
                        output_fmt = args.output_fmt,
                        apply_fixes= args.apply_fixes)

    elif cmd == "quantum":
        kernel.dispatch("quantum",
                        scan_host   = getattr(args,"scan_host","") or "",
                        audit_certs = getattr(args,"audit_certs","") or "",
                        scan_code   = getattr(args,"scan_code","") or "",
                        lang        = getattr(args,"lang","") or "",
                        report      = args.report)

    elif cmd == "plugin":
        if getattr(args,"sign",None):
            kernel.dispatch("plugin_sign", sign=args.sign)
        elif getattr(args,"verify",None):
            kernel.dispatch("plugin_sign", verify=args.verify)
        elif args.verify_all:
            kernel.dispatch("plugin_sign", verify_all=True)
        else:
            kernel.dispatch("plugins",
                            list_plugins = args.list_plugins,
                            install      = getattr(args,"install","") or "",
                            enable       = getattr(args,"enable","") or "",
                            disable      = getattr(args,"disable","") or "",
                            remove       = getattr(args,"remove","") or "",
                            new          = getattr(args,"new","") or "",
                            hook         = getattr(args,"hook","") or "",
                            new_author   = getattr(args,"new_author","") or "")

    elif cmd == "cicd":
        kernel.dispatch("cicd",
                        scan       = args.scan,
                        threshold  = args.threshold,
                        output     = args.output,
                        secrets    = args.secrets,
                        diff       = getattr(args,"diff","") or "",
                        generate   = getattr(args,"generate","") or "",
                        pr_summary = args.pr_summary,
                        from_file  = getattr(args,"from_file","") or "",
                        quiet      = args.quiet,
                        scan_path  = args.scan_path)

    elif cmd == "docs":
        kernel.dispatch("docs",
                        topic      = getattr(args,"topic","") or "",
                        glossary   = args.glossary,
                        man        = args.man,
                        output_dir = getattr(args,"output_dir","."))

    elif cmd == "ask":
        # FIX: use args.question only, not sys.argv fallback
        question = args.question or ""
        kernel.dispatch("ask", question=question, stream=args.stream)

    elif cmd == "learn":
        kernel.dispatch("learn",
                        module      = getattr(args,"module","") or "",
                        interactive = args.interactive,
                        step        = args.step)

    elif cmd == "session":
        from shadow313.core.session import Session
        sessions_dir = kernel.config.get("storage","sessions_dir",default="~/.shadow313/sessions")
        if args.list:
            sessions = Session.list_sessions(sessions_dir)
            rows = [[s.get("session_id","")[:8],s.get("created_at","")[:19],s.get("target","")]
                    for s in sessions]
            kernel.out.table(["Session ID","Created","Target"], rows, f"Sessions ({len(sessions)})")
        elif args.info:
            s = Session.resume(args.info)
            kernel.out.result(s.summary(), "Session Info")
        elif args.purge:
            # FIX: use kernel.config instead of hardcoded Config()
            ok = Session.delete(args.purge, sessions_dir)
            if ok:
                kernel.out.success(f"Session {args.purge} deleted.")
            else:
                kernel.out.error(f"Session not found: {args.purge}")

    elif cmd == "update":
        vm = kernel.get_module("vuln")
        if args.db in ("cve","all") and vm:
            vm.update_cve_db(api_key=args.api_key)
        if args.db in ("kev","all"):
            kernel.dispatch("kev", sync=True)
        if args.db in ("epss","all"):
            kernel.dispatch("epss", update=True)
        if args.db in ("exploitdb","all"):
            kernel.out.warn("ExploitDB update: download exploits.csv from "
                            "https://gitlab.com/exploit-database/exploitdb and place in "
                            "~/.shadow313/data/exploits.csv")

    elif cmd == "status":
        # FIX: was missing in v1
        kernel.out.section("SHADOW313 NEXUS STATUS")
        ai_info = kernel.ai_status()
        kernel.out.result(ai_info, "AI Engine")
        kernel.print_session_info()
        modules = list(kernel._modules.keys())
        kernel.out.success(f"Loaded modules ({len(modules)}): {', '.join(modules)}")

    # ── V2 commands ───────────────────────────────────────────────────────────
    elif cmd == "agent":
        kernel.dispatch("agent",
                        plan         = args.plan,
                        target       = args.target,
                        approval     = args.approval,
                        suggest_plan = args.suggest_plan,
                        list_runs    = args.list_runs)

    elif cmd == "campaign":
        kernel.dispatch("campaign",
                        targets         = getattr(args,"targets","") or "",
                        modules         = args.modules,
                        concurrency     = args.concurrency,
                        list_campaigns  = args.list_campaigns,
                        name            = args.name)

    elif cmd == "graph":
        kernel.dispatch("graph",
                        ingest_session = getattr(args,"ingest_session","") or "",
                        query          = getattr(args,"query","") or "",
                        query_arg      = getattr(args,"query_arg","") or "",
                        risk_ranking   = args.risk_ranking,
                        export         = getattr(args,"export","") or "",
                        export_path    = getattr(args,"export_path","") or "",
                        stats          = args.stats)

    elif cmd == "serve":
        kernel.dispatch("dashboard",
                        port       = args.port,
                        host       = args.host,
                        no_browser = args.no_browser)

    elif cmd == "report":
        kernel.dispatch("report",
                        from_session  = getattr(args,"from_session","") or "",
                        from_campaign = getattr(args,"from_campaign","") or "",
                        output        = getattr(args,"output","") or "",
                        format        = args.format)

    elif cmd == "threat-intel":
        kernel.dispatch("threat_intel",
                        sync           = args.sync,
                        lookup         = getattr(args,"lookup","") or "",
                        enrich         = args.enrich,
                        enrich_session = getattr(args,"enrich_session","") or "",
                        stats          = args.stats)

    elif cmd == "sandbox":
        kernel.dispatch("sandbox",
                        cve         = getattr(args,"cve","") or "",
                        lab_mode    = args.lab_mode,
                        list_cves   = args.list_cves,
                        cleanup_all = args.cleanup_all)

    elif cmd == "cloud":
        kernel.dispatch("cloud",
                        scan_aws       = args.scan_aws,
                        scan_k8s       = args.scan_k8s,
                        scan_terraform = getattr(args,"scan_terraform","") or "",
                        scan_all       = args.scan_all,
                        output         = args.output)

    elif cmd == "crypto-agility":
        kernel.dispatch("crypto_agility",
                        scan                = getattr(args,"scan","") or "",
                        snippet             = getattr(args,"snippet","") or "",
                        test_tls            = getattr(args,"test_tls","") or "",
                        migration_plan      = args.migration_plan,
                        list_pqc_algorithms = args.list_pqc_algorithms,
                        languages           = args.languages)

    elif cmd == "rag":
        kernel.dispatch("rag",
                        ingest_nvd     = getattr(args,"ingest_nvd","") or "",
                        ingest_session = getattr(args,"ingest_session","") or "",
                        query          = getattr(args,"query","") or "",
                        namespace      = args.namespace,
                        stats          = args.stats)

    # ── V4 commands ───────────────────────────────────────────────────────────
    elif cmd == "temporal":
        kernel.dispatch("temporal",
                        bind          = getattr(args,"bind","") or "",
                        bind_session  = args.bind_session,
                        verify        = getattr(args,"verify","") or "",
                        list_receipts = args.list_receipts)

    elif cmd == "nexus":
        kernel.dispatch("nexus",
                        status              = args.status,
                        bind_all            = args.bind_all,
                        verify_chain        = args.verify_chain,
                        insider_attack_demo = args.insider_attack_demo,
                        posture_report      = args.posture_report)

    elif cmd == "stix":
        kernel.dispatch("stix",
                        import_file         = getattr(args,"import_file","") or "",
                        export              = args.export,
                        export_path         = getattr(args,"export_path","") or "",
                        ingest_threat_intel = args.ingest_threat_intel)

    elif cmd == "finetune":
        kernel.dispatch("finetune",
                        generate_config  = args.generate_config,
                        dataset_path     = args.dataset_path,
                        output_dir       = args.output_dir,
                        generate_dataset = args.generate_dataset,
                        dataset_size     = args.dataset_size)

    elif cmd == "mobile-api":
        kernel.dispatch("mobile_api",
                        port  = args.port,
                        host  = args.host,
                        token = args.token)

    elif cmd == "browser-recon":
        kernel.dispatch("browser_recon",
                        target         = args.target,
                        use_playwright = args.use_playwright,
                        csp_audit      = args.csp_audit)

    elif cmd == "container-scan":
        kernel.dispatch("container_scan",
                        image      = getattr(args,"image","") or "",
                        dockerfile = getattr(args,"dockerfile","") or "",
                        scan_dir   = getattr(args,"scan_dir","") or "")

    elif cmd == "ad-audit":
        kernel.dispatch("ad_audit",
                        server   = args.server,
                        domain   = args.domain,
                        username = args.username,
                        password = args.password)

    elif cmd == "siem":
        kernel.dispatch("siem",
                        forward_session  = getattr(args,"forward_session","") or "",
                        forward_findings = args.forward_findings,
                        test             = args.test)

    elif cmd == "malware":
        kernel.dispatch("malware",
                        file      = getattr(args,"file","") or "",
                        directory = getattr(args,"directory","") or "",
                        execute   = args.execute,
                        lab_mode  = args.lab_mode,
                        yara_only = args.yara_only)


    # ── Vanguard ──────────────────────────────────────────────────────────────
    elif cmd == 'vanguard':
        kernel.dispatch('vanguard',
                        plan           = args.plan,
                        template       = args.template,
                        target         = args.target,
                        verify         = args.verify,
                        lab_mode       = args.lab_mode,
                        list_chains    = args.list_chains,
                        list_templates = args.list_templates)

    # ── Aegis ─────────────────────────────────────────────────────────────────
    elif cmd == 'aegis':
        kernel.dispatch('aegis',
                        ingest         = args.ingest,
                        event_type     = args.event_type,
                        source_ip      = args.source_ip,
                        list_incidents = args.list_incidents,
                        resolve        = args.resolve,
                        stats          = args.stats,
                        simulate       = args.simulate,
                        cadl_level     = args.cadl_level)

    # ── Ghost-Watch ───────────────────────────────────────────────────────────
    elif cmd == 'ghost-watch':
        kernel.dispatch('ghost_watch',
                        forge          = args.forge,
                        recipient      = args.recipient,
                        detect         = args.detect,
                        list_docs      = args.list_docs,
                        monitor_node   = args.monitor_node,
                        score_node     = args.score_node,
                        correlate      = args.correlate,
                        deploy_decoy   = args.deploy_decoy,
                        port           = args.port,
                        list_hubs      = args.list_hubs,
                        stats          = args.stats)

    # ── Quantum NEXUS ─────────────────────────────────────────────────────────
    elif cmd == 'quantum-nexus':
        kernel.dispatch('quantum_nexus',
                        hndl_analyze   = args.hndl_analyze,
                        algorithm      = args.algorithm,
                        sensitivity    = args.sensitivity,
                        volume_gb      = args.volume_gb,
                        retention      = args.retention,
                        qkd_monitor    = args.qkd_monitor,
                        qber           = args.qber,
                        simulate_bb84  = args.simulate_bb84,
                        eavesdrop      = args.eavesdrop,
                        fuse_sensors   = args.fuse_sensors,
                        mlkem_timing   = args.mlkem_timing,
                        full_assessment= args.full_assessment,
                        stats          = args.stats)

    # ── Satellite ─────────────────────────────────────────────────────────────
    elif cmd == 'satellite':
        kernel.dispatch('satellite',
                        gps_check      = args.gps_check,
                        freq_mhz       = args.freq_mhz,
                        snr_db         = args.snr_db,
                        vsat_audit     = args.vsat_audit,
                        rf_analyze     = args.rf_analyze,
                        clock_skew     = args.clock_skew,
                        simulate       = args.simulate,
                        stats          = args.stats)

    # ── Threat Actor ──────────────────────────────────────────────────────────
    elif cmd == 'threat-actor':
        kernel.dispatch('threat_actor',
                        attribute      = args.attribute,
                        techniques     = args.techniques,
                        tools          = args.tools,
                        indicators     = args.indicators,
                        profile        = args.profile,
                        list_actors    = args.list_actors,
                        fingerprint    = args.fingerprint,
                        from_session   = args.from_session)

    # ── Benchmark ─────────────────────────────────────────────────────────────
    elif cmd == 'benchmark':
        kernel.dispatch('benchmark',
                        quick          = args.quick,
                        full           = args.full,
                        bench          = args.bench,
                        save           = args.save)

    # ── Health ────────────────────────────────────────────────────────────────
    elif cmd == 'health':
        kernel.dispatch('health_check',
                        quick          = args.quick,
                        full           = args.full,
                        save           = args.save,
                        json_output    = args.json_output)

    # ── Doctor ────────────────────────────────────────────────────────────────
    elif cmd == 'doctor':
        kernel.dispatch('health_check', quick=False, full=True)

    # ── CADL ──────────────────────────────────────────────────────────────────
    elif cmd == 'cadl':
        if args.simulate:
            kernel.dispatch('aegis', simulate=True)
        else:
            kernel.dispatch('aegis', cadl_level=args.level, ingest=args.incident or 'manual')

    # ── ACTS ──────────────────────────────────────────────────────────────────
    elif cmd == 'acts':
        if args.list:
            kernel.dispatch('ghost_watch', list_hubs=True)
        else:
            kernel.dispatch('ghost_watch', deploy_decoy=args.deploy, port=args.port)

    else:
        parser.print_help()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())