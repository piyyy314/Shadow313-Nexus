# Shadow313 CHANGELOG

## [4.0.0-NEXUS] — 2026-08-12

### 🆕 New: V4 NEXUS Modules
- **313 Temporal Binding Protocol** (`shadow313 temporal`): Nanosecond-precise cryptographic receipts signed with SLH-DSA (FIPS 205), anchored to IPFS. Every computation produces a verifiable 313-BIND receipt.
- **NEXUS Platform** (`shadow313 nexus`): Platform orchestration, insider attack demonstration, security posture reports, bind-all session outputs.
- **STIX 2.1 Handler** (`shadow313 stix`): Import/export STIX 2.1 bundles, IOC extraction, ATT&CK STIX integration, threat intel ingestion.
- **Mobile API** (`shadow313 mobile-api`): FastAPI REST server for iOS/Android companion app with JWT auth support.
- **LoRA Fine-Tune UI** (`shadow313 finetune`): Unsloth + QLoRA training config generator, dataset builder from session findings, GGUF export for Ollama.

### 🆕 New: V3 Modules
- **Browser Recon** (`shadow313 browser-recon`): Playwright-powered SPA fingerprinting, CSP analysis, API endpoint discovery, security header audit.
- **Container Scanning** (`shadow313 container-scan`): Dockerfile linting (12 rules), Trivy/Grype CVE scanning, base image risk scoring.
- **Active Directory Auditor** (`shadow313 ad-audit`): Kerberoastable accounts, AS-REP roasting, unconstrained delegation, password policy, RBAC analysis.
- **SIEM Integration** (`shadow313 siem`): Forward findings to Splunk HEC, Elasticsearch bulk API, Wazuh REST API.
- **Collaborative Sessions** (`shadow313 collab`): Multi-user session sharing, finding sharing, collaborative notes, event timeline.
- **Malware Sandbox** (`shadow313 malware`): YARA-like pattern matching (10 rules), static binary analysis, Docker behavioral execution (lab mode).

### 🆕 New: V2 Modules
- **RAG Knowledge Base** (`shadow313 rag`): ChromaDB-backed vector store with TF-IDF fallback, 5 namespaces (CVE/MITRE/OWASP/session/general).
- **Agentic Auto-Chain** (`shadow313 agent`): 4 built-in plans (full_pentest, quick_vuln, defense_audit, crypto_audit), approval gates, plan persistence.
- **EPSS Scoring** (`shadow313 vuln --epss`): FIRST.org EPSS v3 API, batch requests (100 CVEs/request), SQLite cache.
- **CISA KEV** (`shadow313 vuln --kev`): Known Exploited Vulnerabilities catalog, auto-CRITICAL promotion, 12h TTL.
- **ATT&CK Mapping** (`shadow313 vuln --attack-map`): 70+ keyword→technique mappings, Navigator v4 JSON export.
- **ML Anomaly Detection** (`shadow313 network --ml-anomaly`): IsolationForest → ONNX → z-score fallback, 14-feature vector.
- **JA3/JA3S Fingerprinting** (`shadow313 network --ja3`): Pure-Python TLS fingerprinting, 9 known-malicious signatures.
- **DNS Covert Channel Detection** (`shadow313 network --dns-covert`): 6 heuristic rules, DoH detection.
- **Campaign Manager** (`shadow313 campaign`): Asyncio-parallel multi-target scanning, configurable concurrency.
- **Intelligence Graph** (`shadow313 graph`): NetworkX MultiDiGraph, 9 node types, risk ranking, GraphML/GEXF export.
- **Web Dashboard** (`shadow313 serve`): FastAPI + HTMX, dark terminal aesthetic, SSE live feed, RAG AI chat.
- **PDF Reports** (`shadow313 report`): HTML/PDF security reports, AI executive summaries, 313-BIND receipt embedding.
- **Plugin Code Signing** (`shadow313 plugin --sign`): HMAC-SHA256 + cosign/sigstore, plugin trust registry.
- **Threat Intelligence** (`shadow313 threat-intel`): FeodoTracker, URLhaus, MalwareBazaar, Shodan InternetDB, OTX feeds.
- **Docker CVE Sandbox** (`shadow313 sandbox`): 8 pre-mapped CVEs, 6 security constraints, Vulhub images.
- **Cloud Hardening** (`shadow313 cloud`): AWS (7 checks), Kubernetes (7 checks), Terraform (11 rules + tfsec).
- **Crypto Agility** (`shadow313 crypto-agility`): 7 PQC migration snippets, 11 NIST algorithms, hybrid TLS testing.

### 🐛 Bug Fixes (v1 → v4)

#### Core
- **Config.set()**: Key-path order was reversed `(value, *keys)` → fixed to `(*keys, value)`
- **Config.save()**: Did not wrap output in `shadow313:` key, breaking reload → fixed
- **Config._apply_env_overrides()**: `SHADOW313_VERBOSE` was missing from env mapping → added
- **Config.init_user_dirs()**: Missing `data/`, `reports/`, `receipts/`, `campaigns/`, `agent_runs/` subdirs → added
- **Session._load_meta()**: Version field hardcoded `"1.0.0"` → now reads from `__version__`
- **Session.resume()**: No UUID format validation → added regex check, raises `ValueError` on invalid ID
- **Session.audit()**: Did not ensure parent directory exists before opening `audit.log` → fixed
- **Session.list_sessions()**: `stat().st_mtime` failed on broken symlinks → wrapped in try/except
- **AIEngine._ollama_stream()**: Infinite loop risk if `done` key never arrived → added 10,000 packet counter guard
- **AIEngine.stream()**: Non-ollama backends ignored `system_prompt` parameter → fixed
- **AIEngine.chat()**: No context truncation, could exceed context window → added `_truncate_context()` with 12,000 char limit
- **OutputFormatter.banner()**: Version hardcoded `"v1.0.0"` → now reads from `__version__`
- **OutputFormatter.table()**: Empty rows caused `ZeroDivisionError` in width calculation → added guard
- **OutputFormatter.finding()**: Rich color map used wrong color names → fixed to `bright_red`/`red`
- **OutputFormatter._print_list()**: Called `_print_dict()` with title causing duplicate section headers → fixed
- **Kernel._autoload_modules()**: Swallowed all `ImportError` silently → now distinguishes `ModuleNotFoundError` from syntax errors
- **Kernel.dispatch()**: Caught `KeyboardInterrupt` but didn't re-raise → now re-raises for clean exit
- **Kernel.ai_status()**: Called `list_models()` even when backend was `disabled` → fixed

#### Modules
- **CVEDatabase**: `references` is a reserved SQLite keyword → renamed column to `refs`
- **CVEDatabase.insert_cve()**: `with` block and `conn.execute()` were missing → restored
- **CVEDatabase.update_from_nvd()**: No retry on HTTP 503 (NVD rate limit) → added exponential backoff
- **DependencyAuditor._parse_requirements()**: Failed on `package[extra]>=1.0` format → fixed regex
- **compute_risk_score()**: Final `min(10.0, ...)` cap was applied before both multipliers → fixed
- **NetworkModule.LiveCapture.capture()**: Used `-G` flag (rotate) instead of subprocess `timeout` → fixed
- **NetworkModule.geoip_enrich()**: No cap on IP count, could exceed ip-api rate limit → capped at 20
- **NetworkModule.TopologyMapper._ping()**: Hardcoded `-W` flag fails on macOS (uses `-t`) → added platform detection
- **PCAPParser**: No validation of PCAP magic bytes → added check, returns error dict for invalid files
- **QuantumModule.SourceCodeScanner**: Duplicate findings for same (file, line, algo) → added dedup set
- **CICDModule**: `status` command was missing → added
- **CLI._dispatch()**: `ask` command used `sys.argv[2:]` fallback breaking with `--no-stream` → fixed to use `args.question`
- **CLI._dispatch()**: `session --purge` used hardcoded `Config()` → fixed to use `kernel.config`
- **TFIDFVectorStore**: O(n²) search loop with no early exit → replaced with `heapq` top-k
- **TFIDFVectorStore**: No deduplication in query results → added seen-set
- **TFIDFVectorStore**: Per-feature z-score was computed globally → fixed to per-feature
- **JA3Scanner**: GREASE value set was incomplete (missing `0x8A8A`) → completed RFC 8701 set
- **JA3Scanner**: Padding extension `0x0000` not excluded from JA3 hash → fixed per spec
- **JA3Scanner**: `_parse_client_hello()` had no bounds checking → added throughout
- **DNSCovertDetector**: Shannon entropy used `math.log()` without base → fixed to `math.log2()`
- **DNSCovertDetector**: DNS query extraction included non-DNS packets → added port 53 filter
- **DNSCovertDetector**: Rate detection used wall-clock time instead of PCAP timestamps → fixed
- **DNSCovertDetector**: Tunnel tool pattern matching was case-sensitive → fixed to lowercase
- **ATTACKMapper**: Navigator JSON used hardcoded `score=1` → now uses finding count for gradient
- **ATTACKMapper**: `fetch_live_mitre()` had no timeout or retry → added 30s timeout + 2 retries
- **EPSSFetcher**: Batch API called with >100 CVEs → chunked to 100 per request (API limit)
- **KEVSyncer**: Used `requests.get()` without timeout → switched to `urllib` with 30s timeout
- **EPSSKEVDatabase**: Naive datetime vs aware datetime comparison in `_is_stale()` → fixed UTC-aware
- **CampaignManager**: `asyncio.Semaphore` used in non-async context → wrapped in `asyncio.run()`
- **CampaignManager**: Campaign state file used unsanitized `campaign_id` as filename → added sanitization
- **CampaignManager**: `_run_target()` swallowed all exceptions silently → now records error status
- **IntelligenceGraph.shortest_path()**: `NetworkXNoPath` exception not caught → wrapped
- **IntelligenceGraph.risk_ranking()**: Division by zero when no CVEs → added `max(1, …)`
- **IntelligenceGraph.ingest_session()**: Read files without existence check → added check
- **DockerfileLinter**: Did not handle backslash line continuations → added `_join_continuations()`
- **TerraformScanner**: Regex matched comments → added comment line filtering
- **AWSChecker._check_rds_public()**: Used wrong key `dbInstances` → fixed to `DBInstances`
- **SplunkHECSender**: Missing `Content-Type: application/json` header → added
- **ElasticsearchSender**: Bulk format missing trailing newline → fixed
- **ThreatIntelManager.enrich_findings()**: Modified input list in-place → now returns new list
- **ThreatIntelManager.lookup_ioc()**: Short hex strings misidentified as SHA256 → added length check
- **ThreatIntelManager.sync_all()**: One failed feed aborted all others → wrapped each in try/except
- **HybridTLSTester**: Used deprecated `ssl.PROTOCOL_TLS` → updated to `ssl.PROTOCOL_TLS_CLIENT`
- **CryptoMigrationEngine.scan()**: Duplicate findings for same (file, line, pattern) → added dedup set
- **TemporalBindingEngine._wait_for_313()**: Busy-loop with no sleep → added 0.1ms sleep
- **TemporalBindingEngine._sign_slh_dsa()**: Imported pqcrypto inside loop → moved to call-time with fallback
- **TemporalBindingEngine.verify_receipt()**: Case-sensitive SHA3-512 comparison → normalized to lowercase

### 🏗️ Architecture Changes
- Refactored v1 monolithic module files into proper submodule structure
- Added `shadow313/v2/`, `shadow313/v3/`, `shadow313/v4/` package namespaces
- Kernel auto-loads all 28+ modules with graceful fallback for missing optional deps
- All modules now support `_prev_result` injection for agentic chaining
- 313 Temporal Binding integrated into recon and vuln modules automatically
- `pyproject.toml` updated with 14 optional dependency groups

---

## [2.0.0] — 2026-06-01

### Added
- V2 advanced modules: RAG, Agent, EPSS, KEV, ATT&CK, ML Anomaly, JA3, DNS Covert
- Campaign Manager, Intelligence Graph, Web Dashboard, PDF Reports
- Plugin Code Signing, Threat Intelligence Feeds, Docker CVE Sandbox
- Cloud/K8s/Terraform Hardening, Crypto Agility Framework
- AES-256-GCM encrypted session store (PBKDF2, 480,000 iterations)
- Full config.yaml reference with all v2 settings

---

## [1.0.0] — 2026-06-18

### Added
- Initial release: 9 core modules (Recon, Vuln, Exploit, Network, Defense, Quantum, Plugins, CI/CD, Docs)
- Ollama/OpenAI-compatible AI backends
- UUID-scoped session management
- SARIF 2.1.0 output, 13-pattern secret scanning
- CIS Level 1/2 benchmark checks (18 checks)
- Post-quantum crypto audit with NIST PQC migration roadmap
- Plugin system with 10 lifecycle hooks
- GitHub Actions / GitLab CI template generation