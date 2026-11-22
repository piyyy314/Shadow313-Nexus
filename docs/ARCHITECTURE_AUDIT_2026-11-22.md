# Shadow313 NEXUS — Architecture and Repository Audit

**Audit date:** 2026-11-22  
**Reference master commit:** 76092ff411913841a65576f26d13aa492b63e9d9  
**Reference PR #116 head:** 3e06d4cb232a0128c83d6f979bc0521069c1f7d2

## Scope and limits

This review inventoried the full tracked Git tree, grouped files by type and directory, inspected repository metadata and key Python/API/CLI/security/deployment files, examined tracked PowerShell scripts for token-in-remote and direct-to-master patterns, compared PR #116 against its common ancestor and master, and read live GitHub Actions job conclusions and security logs.

This is a repository architecture and engineering review, not a penetration test. It does not claim that every runtime path, external service, or production host was executed or independently verified.

## Executive assessment

Shadow313 NEXUS is a substantial cybersecurity engineering toolkit and lab platform with a Python application, CLI, APIs, SOC-oriented components, static dashboards, detection content, Docker assets, and a growing validation suite.

It is not yet equivalent to a production SIEM/SOAR platform such as Wazuh or Security Onion. The repository documentation identifies Hetzner as the planned backend host, not a verified live deployment. Until a production backend, telemetry ingestion, storage, access controls, and incident workflows are deployed and validated, backend-dependent dashboards and integrations must remain labelled as demos, simulations, or unavailable.

## Reference architecture benchmark

These are architectural references, not a ranked top-ten list. Each solves a different part of the security operations lifecycle.

| Reference | Mature design pattern to learn from | Shadow313 NEXUS implication |
|---|---|---|
| [Wazuh](https://documentation.wazuh.com/current/getting-started/architecture.html) | Distinct agents, server, indexer, and dashboard | Define a real telemetry path and storage boundary before claiming live SOC coverage |
| [Security Onion](https://docs.securityonion.net/en/3/dev/architecture/) | Manager, sensor, search nodes, and explicit ingest flow | Separate collection, processing, indexing, and analyst UI |
| [OpenCTI](https://github.com/OpenCTI-Platform/opencti) | Platform, workers, connectors, and threat-intelligence data model | Give CTI connectors explicit contracts, provenance, and lifecycle |
| [Velociraptor](https://docs.velociraptor.app/docs/artifacts/) | Reusable, parameterized, documented forensic artifacts | Treat collection and investigation content as versioned, testable artifacts |
| [TheHive](https://docs.strangebee.com/thehive/overview/) | Case-centric incident lifecycle, evidence, tasks, and automation | Make incident records, evidence, approvals, and analyst actions first-class |
| [Falco](https://falco.org/docs/) | Runtime event sources, rule engine, plugins, and alerts | Keep detections declarative and separate event collection from alert delivery |
| [Sigma](https://github.com/SigmaHQ/sigma) | Vendor-neutral detection rules and validation ecosystem | Version, lint, test, and map rules to data sources and ATT&CK techniques |
| [MISP](https://github.com/MISP/MISP) | Structured threat-intelligence sharing and correlation | Define STIX/TAXII or equivalent exchange contracts before adding more feeds |
| [MITRE Caldera](https://github.com/mitre/caldera) | Controlled adversary emulation and repeatable operation plans | Tie purple-team simulations to explicit authorization and detection validation |
| [Suricata](https://github.com/OISF/suricata) | Network IDS/NSM engine with structured event output | Integrate network telemetry through a documented, testable ingestion contract |

## Current repository inventory

At the PR #116 reference head, the tracked tree contains 1,065 files and 180 directories, including 643 Python files, 190 HTML pages, 34 PowerShell files, and 72 Markdown documents. This breadth is a strength, but it also increases the importance of clear ownership, canonical sources, and tested generation pipelines.

## What is already strong

- A broad Python package structure, CLI entry points, SDK/platform packages, and API contracts.
- Separate SentinelOS and ShiatoAli SOC-oriented components, including PostgreSQL integration tests and migrations.
- Docker and Compose support for local development.
- Sigma detection content and security-oriented utilities.
- A substantial unit, integration, packaging, HTML, navigation, API, and security validation suite.
- Security policy, contributing guidance, dependency scanning, SAST, secret scanning, container scanning, and deployment workflows.
- Clearer demo/live disclosures on dashboards, marketplace pages, and receipt demonstrations.
- PR #116 has been reconciled with current master without merging the PR.

## Findings and remediation priorities

### P0 — Operational truth and production boundaries

1. Backend deployment is not verified. The static website and Vercel quality workflow do not prove that the Python backend, SOC services, or optional integrations are live.
2. No production deployment was performed during this audit. Production claims require a successful deployment job and a matching provider deployment record.
3. Static dashboard numbers, marketplace analytics, compliance scores, and simulated receipt data must never be presented as live observations.

### P1 — Security and supply chain

1. Legacy direct-to-master automation: token-in-remote and direct-push scripts were retired from the active PR #116 tree.
2. Trivy: the latest completed scan at the reference head reported zero actionable critical/high findings and zero high/critical secret findings, but retained 50 high findings without a published fixed version. These remain a warning and require periodic package/advisory review.
3. Dependency/SAST: the completed audit reported no known dependency vulnerabilities, Safety reported zero vulnerabilities, and Bandit retained 379 findings with zero high severity. Medium/low findings are not treated as clean.
4. Secret detection: Gitleaks completed a full-history scan and reported no leaks on the reference head.
5. Snyk: prior code/security checks reported exhausted quotas. A quota-blocked or pending Snyk scan is not a successful scan.
6. Release integrity: the release workflow's PyInstaller hidden import was corrected from the distribution name pyyaml to the import module yaml. A successful future release build is still required to validate packaged executables.
7. Reproducibility: no Python dependency lockfile was found in the reference tree. Add a reviewed lock or constraints file for deployment and release environments.
8. Artifact provenance: no complete SBOM plus signed build-provenance workflow was verified. Add SBOM generation, provenance attestations, and release-asset verification before treating downloadable binaries as production-trusted.

### P1 — Cryptographic assurance boundaries

Some modules are explicitly simulated, but their output structures still deserve careful treatment:

- The Aegis PQC integration assigns a hash-chain value to a field named signature; a hash is not a digital signature.
- The custom 313 timestamp suffix is a format marker, not a trusted timestamp or proof of time.
- HMAC fallback signatures are not publicly verifiable without the relevant secret key.
- CMMC/control-mapping output must not be described as independent certification or a verified audit unless the evidence, signer identity, key custody, and verification process are actually implemented.

Before production use, make unsigned, simulated, locally authenticated, and publicly verifiable states distinct in the API schema and UI.

### P2 — Structure and governance

1. The repository contains versioned namespaces such as v2, v3, and v4; define supported, deprecated, and experimental status for each.
2. local_bundle duplicates selected website content. A canonical synchronization/build script is needed to prevent drift.
3. The original completeness auditor only covered a subset of Python roots and used a faulty route-auth heuristic. Fix and integrate that tool before treating its output as a complete repository audit.
4. Coverage is collected in some workflows, but no minimum coverage threshold was found. Establish a measured baseline before adding a realistic fail_under gate.
5. Keep workstation-specific logs, reports, tokens, and local model data out of the tracked source tree.
6. Maintain CODEOWNERS, pull-request/feature templates, and ADRs so ownership, review, and architecture decisions remain explicit.

### P2 — Product architecture

Before describing the project as a production SOC, define and test these service boundaries:

- Endpoint/network collection and authenticated enrollment.
- Normalized event schema, ingestion API, queueing, retention, and indexing.
- Detection execution and rule versioning with replayable test fixtures.
- Alert triage, case management, evidence provenance, analyst tasks, and response approvals.
- Threat-intelligence connectors and data provenance.
- Role-based access, tenant isolation, audit logging, and secrets/key management.
- Operational health checks, backup/restore, capacity limits, and disaster recovery.

## Deployment observations

- The latest production Vercel deployment inspected was READY but dated 2026-10-31 and built from commit 0b2c22ba, not the current master or PR #116 head.
- Its aliases included shadow313.com and shadow313.dev.
- A newer preview deployment existed for a different branch, but no Vercel deployment record was found for PR #116 head 3e06d4c.
- Vercel reported no runtime errors for the inspected project during the preceding seven days.
- The current PR Vercel workflow is a quality-check workflow; its success is not a production deployment.

## Immediate roadmap

1. Keep PR #116's master integration and all current-head checks green; do not merge it automatically.
2. Finish retiring direct-to-master workstation scripts and use branch-based GitHub CLI workflows.
3. Keep Snyk quota issues visible and periodically rerun once the provider permits scans.
4. Review the 50 unpatched Trivy high findings when vendors publish fixes; do not suppress them.
5. Validate the corrected PyInstaller release build on all target operating systems.
6. Introduce a Python lock/constraints strategy, SBOM, provenance attestation, and signed release assets.
7. Establish a coverage baseline and a non-regressing coverage floor.
8. Build a canonical local-bundle generator and test all copied routes/assets.
9. Correct and integrate the repository completeness auditor.
10. Formalize module lifecycle and service/API contracts.
11. Provision and harden the backend before promoting simulated SOC functions to live status.

## Deployment and merge boundary

PR #116 remains open and unmerged. PR #115 remains separate and merged. No production deployment, repository settings change, history rewrite, or manual deployment trigger was performed as part of this audit.
