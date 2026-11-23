# Shadow313 Platform Integration Status

Last reviewed: 2026-11-22  
Audited master revision: `f95c99b24613d781527f19550360987bedd362b1`

This is the current integration control sheet. It supersedes older status notes in this file that referred to PRs #115/#116 as open or described earlier infrastructure and CI states. For the repository relationship inventory and branch reconciliation findings, see [Repository Relationship Audit](REPOSITORY_RELATIONSHIP_AUDIT_2026-11-22.md).

## System of record

- **Shadow313-Nexus** is the canonical repository for the Shadow313 Python package, CLI, API, SDK, platform modules, static website, and delivery workflows.
- **SentinelOS** is retained under `sentinelos/` in this repository. It is a dashboard/UI subsystem with an in-repository NEXUS API bridge; it is not a separate repository or independent backend.
- **ShiatoAli SOC** is an embedded subsystem under `shadow313/v4/shiatoali/`, with API routing and migration assets in this repository. Do not create a second SOC service or duplicate its event/case data stores without an architecture decision.
- The Python API is the authoritative service boundary. The Vercel-hosted website and Node API gateway are not the Python backend.

## Verified repository state

At the audited master revision:

- 1,262 tracked paths were present: 647 Python files, 190 HTML files, and 77 Markdown files, plus configuration, workflows, assets, scripts, and deployment resources.
- No open pull requests were returned by GitHub.
- PRs #115, #116, #140, #141, and #147–#151 are closed and merged.
- The latest observed master runs completed successfully:
  - [Full Pre-Deploy Validation #45101043265](https://github.com/piyyy314/Shadow313-Nexus/actions/runs/45101043265)
  - [API Endpoint Validation #45101043259](https://github.com/piyyy314/Shadow313-Nexus/actions/runs/45101043259)
  - [CI/CD #45101043412](https://github.com/piyyy314/Shadow313-Nexus/actions/runs/45101043412)
  - [Vercel workflow #45101043364](https://github.com/piyyy314/Shadow313-Nexus/actions/runs/45101043364)
  - [Nightly Security Scan #45098876581](https://github.com/piyyy314/Shadow313-Nexus/actions/runs/45098876581)
- The pre-deploy run passed file integrity and route validation, repository completeness audit, Git hygiene, Python/API validation, HTML validation, configuration validation, shell validation, the Python test suite, and the final validation gate.
- CI/CD passed Python 3.11 and 3.12 tests, lint/format, Docker build, distribution build, and security scan. PyPI/TestPyPI publication jobs were skipped because no release publication was requested.
- The nightly scan's four jobs (Trivy, Dockerfile/Compose audit, full-history secret scan, and dependency audit) completed successfully.
- Snyk quota errors are tracked as provider/quota limitations, not as successful scans and not as a reason to disable the other security controls.

A successful workflow run is evidence for that exact commit and job set. It does not prove that every optional service is configured, that a production backend is running, or that every third-party integration is connected.

## Hosting and runtime boundaries

| Component | Current responsibility | Verified state |
|---|---|---|
| GitHub | Source control, reviews, CI | In use |
| Vercel | Public static website and Node API gateway | Workflow checks passing |
| Cloudflare | DNS for `shadow313.com` | User-designated DNS provider |
| Vercel DNS | Existing `shadow313.dev` DNS configuration | Retained |
| GitHub Pages | Secondary delivery portal for generated `dist/` artifacts | Separate from the website |
| Hetzner | Planned Python API/backend host | Not yet provisioned/deployed |

The Python backend is not yet deployed as a hosted service. The Vercel gateway forwards only its reviewed route allowlist and requires server-side `SHADOW313_BACKEND_URL` and `SHADOW313_BACKEND_API_KEY` configuration. Do not expose backend credentials to browser code or public build variables. Do not describe website availability as proof that backend-dependent features are online.

Render, Netlify, and Railway are not part of the approved hosting topology. Do not add another host without an explicit architecture decision.

## Repository relationships

The current relationship inventory is in [Repository Relationship Audit](REPOSITORY_RELATIONSHIP_AUDIT_2026-11-22.md). In brief:

- `NEXUS-OmniSec-Unified`, `NEXUS-COMMAND-CORE`, and `personal-ai-agent` are separate repositories and potential integration candidates, not established runtime dependencies of this repository.
- The similarly named `Shiatoali-` repository is a Blockscout-based blockchain explorer, not the embedded ShiatoAli SOC subsystem.
- No standalone `SentinelOS-Shadow313` repository was found in the repository search; SentinelOS currently exists as the `sentinelos/` directory here.
- This repository is not a GitHub fork and has no `.gitmodules` file. Do not infer a live connection from a name, README link, or copied source tree.

## Branch reconciliation

There are 26 non-master branches. Several contain substantial work but have diverged from current master. Six high-impact branches were compared against master:

| Branch | Ahead | Behind | Handling |
|---|---:|---:|---|
| `fix/agent-dispatch-fail-closed-20261122` | 43 | 23 | Review unique changes; do not merge wholesale |
| `fix/hosted-python-backend-proxy` | 33 | 29 | PR #141 is already merged; treat branch as historical/squash-diverged |
| `fix/temporal-signature-verification-20261122` | 9 | 22 | Review signature changes and tests selectively |
| `fix/vercel-public-site-boundary-20261122` | 7 | 23 | Compare with current Vercel allowlist and workflow before reuse |
| `feat/omni-shadow313-engineering-skill` | 21 | 92 | Review for unique skill improvements; do not merge wholesale |
| `fix/ci-audit-blockers` | 450 | 27 | PR #116 is already merged; historical branch, not a merge candidate |

GitHub reports these branches as divergent because the PRs were squash-merged or the branches contain additional history. Do not merge or delete them solely from ahead/behind counts. Inspect their unique commits and file changes first. Backups should be retained until the relevant work is either recovered or explicitly retired.

## Shared integration contracts

All future clients and modules should use these rules:

### Identity and authorization
- The Python API is the authoritative enforcement point.
- Authentication is not authorization; define roles and per-action scopes.
- Service identities must be distinct from human identities.
- Inject secrets at runtime, rotate them, and never commit them.
- High-impact response actions require explicit approval and an auditable actor.

### Security event envelope
Use a versioned envelope with stable event IDs, UTC occurrence/ingestion times, source and sensor identifiers, host, event type, severity, actor/network context, protected raw evidence, and tenant ID when multi-tenancy is enabled. Require idempotent ingestion, bounded payloads, stable pagination, retention, and explicit sensitive-data handling.

### API and UI
- Publish one versioned OpenAPI contract and validate clients against it.
- Browser clients must not access databases or receive service secrets.
- Keep CORS origins explicit; never combine wildcard origins with credentials.
- UI health indicators must reflect actual API/dependency health.
- Do not duplicate event, alert, case, or identity stores across repositories.

### Production data and audit
- SQLite is suitable for local single-instance use.
- Multi-worker production requires PostgreSQL runtime wiring, migrations, concurrency/transaction tests, backup/restore tests, and monitoring.
- Case history and privileged actions need access controls, retention, export, and tamper-evident audit protection.

## Ordered integration backlog

### P0 — production boundary and security evidence
- [ ] Provision and harden the planned Hetzner backend host before enabling backend-dependent production routes.
- [ ] Configure backend URL/key as server-side secrets only, then verify TLS, auth, health checks, backups, restore, and external exposure.
- [ ] Reconcile the remaining divergent branches; salvage unique fixes through fresh branches based on current master.
- [ ] Recheck the historical TLS-key rotation/history-remediation follow-up before claiming the old exposure is fully remediated.

### P1 — ShiatoAli production readiness
- [ ] Verify PostgreSQL adapter runtime selection and migration execution in the deployment path.
- [ ] Add PostgreSQL transaction, concurrent-ingestion, duplicate-event, retention, and restore tests to the release gate.
- [ ] Add stable cursor pagination, analyst RBAC, case ownership, and workflow transition validation.
- [ ] Protect case activity and privileged actions with a tamper-evident audit chain.

### P2 — bounded cross-repository integration
- [ ] Compare event, alert, case, identity, and API contracts in NEXUS-OmniSec-Unified before reusing components.
- [ ] Publish the canonical event schema and OpenAPI contract.
- [ ] Connect NEXUS-COMMAND-CORE only as an authenticated UI client; never couple it directly to databases.
- [ ] Evaluate personal-ai-agent as a bounded tool/agent integration with explicit permissions, isolation, and data-sharing controls.
- [ ] Add end-to-end tests across UI, API, ingestion, alerting, and case workflows.

### P3 — SOC capability expansion
- [ ] Sigma-compatible rule format and test harness.
- [ ] Threat-intelligence enrichment with provenance and expiry.
- [ ] Alert correlation, deduplication, suppression, and analyst feedback.
- [ ] SIEM/endpoint telemetry connectors.
- [ ] SOAR playbooks with dry-run, approval, least privilege, and rollback.
- [ ] Operational dashboards backed by real service telemetry.
