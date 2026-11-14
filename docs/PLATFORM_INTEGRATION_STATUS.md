# Shadow313 Platform Integration Status

Last reviewed: 2026-11-13

This document is the integration control sheet for the Shadow313 repositories.
It separates implemented code, work in review, and work that still requires
integration or runtime evidence. A feature described in a README or branch is
not considered production-ready until its tests, deployment, permissions, and
operational behavior have been verified.

## System-of-record decision

- **Shadow313-Nexus** is the primary product repository and canonical Python
  package/API: `shadow313-nexus`, imported as `shadow313`.
- **ShiatoAli SOC** is being added as a versioned module within that package
  through [draft PR #115](https://github.com/piyyy314/Shadow313-Nexus/pull/115).
  Keep it additive; do not create a second SOC API or duplicate its event/case
  database in another module.
- **NEXUS-OmniSec-Unified** is a separate monorepo with its own React client,
  Python core, deployment stack, and a separate event-feed implementation.
  Treat it as an integration candidate, not as a dependency or a production
  extension of Shadow313-Nexus until API, identity, event schema, and release
  ownership are agreed.
- **NEXUS-COMMAND-CORE** is a separate React/TypeScript command-center UI using
  Firebase and Google AI services according to its README. Treat it as a
  possible UI client, not as a trusted backend or shared identity provider.

## Repository boundaries

| Repository | Current role | Integration decision |
|---|---|---|
| [Shadow313-Nexus](https://github.com/piyyy314/Shadow313-Nexus) | Primary Python CLI, API, V1–V4 modules, docs and deployment | Canonical backend and package |
| [NEXUS-OmniSec-Unified](https://github.com/piyyy314/NEXUS-OmniSec-Unified) | Separate React/Python platform and security-event implementation | Reuse only after capability and API comparison; avoid duplicate event stores |
| [NEXUS-COMMAND-CORE](https://github.com/piyyy314/NEXUS-COMMAND-CORE) | React 19 / TypeScript operator workstation | Candidate frontend; connect through documented APIs |
| [personal-ai-agent](https://github.com/piyyy314/personal-ai-agent) | Separate AI-agent and analytics project | Candidate for bounded agent integrations; no shared secrets or implicit trust |

## ShiatoAli SOC: implementation and review status

Draft PR #115 currently adds:

- SQLite-backed normalized event ingestion with duplicate-event handling.
- Initial defensive detections for suspicious PowerShell, potential web shells,
  network discovery utilities, and repeated authentication failures.
- Authenticated health, event, alert, and case-management routes.
- Case-to-alert links and a case activity timeline.
- A PostgreSQL/Alembic schema foundation and tests for offline migration SQL.

The PR's own limitations are important:

- The running service still uses SQLite; the PostgreSQL adapter and runtime
  configuration are not implemented by the migration files alone.
- SQLite is a single-instance foundation, not the multi-worker production
  database.
- The case activity history is append-oriented but not a tamper-proof ledger.
- The starter detections are triage signals, not proof of compromise.
- No endpoint agent, automated host isolation, or external reputation
  enrichment is included.

### Latest observed PR checks

For PR #115 head `87aa028462f6fe1e60ab15872e3cd7fba1d725ca`:

- Unit tests for Python 3.11 and 3.12: passed.
- Secret detection, SAST, dependency scan, Dockerfile lint, shell/config and
  file-integrity checks: passed.
- Python/API validation, config validation, file-integrity checks, shell
  validation, HTML validation, quality checks, and live API endpoint validation:
  passed.
- Unit test matrix for Python 3.11 and 3.12: passed. The separate aggregate
  Python Test Suite job was cancelled after the validation gate had already
  failed; do not count that cancelled job as a pass.
- Repository-wide Ruff lint: failed with thousands of existing diagnostics
  across unrelated package files. The observed run emitted no Ruff diagnostics
  for the new `shiatoali` package.
- Security scan: failed because the full-tree Bandit scan returned findings.
  Its uploaded report counted 69 medium and 106 low severity findings, and zero
  high severity findings. No findings were listed under the new
  `shiatoali` package in that report. These are baseline findings requiring
  triage, not proof that every finding is exploitable.
- The overall validation gate failed. Deployment, Docker build, and publishing
  jobs were skipped; this PR has not demonstrated a production deployment.

Do not merge the draft until the latest checks complete, the lint baseline is
handled transparently, and the runtime persistence/configuration review is
complete.

## Critical repository hygiene and deployment work

The following open PRs in Shadow313-Nexus require review:

1. [PR #107 — remove committed TLS private key](https://github.com/piyyy314/Shadow313-Nexus/pull/107).
   Treat the old private key as compromised. Removing it from the current tree
   does not remove it from Git history. Revoke/replace the certificate and key,
   verify deployment references, and plan history cleanup before considering
   the incident closed.
2. [PR #108 — Debian and Python packaging security updates](https://github.com/piyyy314/Shadow313-Nexus/pull/108).
   Review package compatibility and rebuild the production image; do not assume
   a source-level dependency bump fixes the deployed image until it is rebuilt
   and scanned.
3. [PR #109 — Open WebUI URL and Nginx memory limit](https://github.com/piyyy314/Shadow313-Nexus/pull/109).
   The PR body explicitly says the stack has not been run with this change.
   Validate the Compose stack and upload path before deployment.

## Shared integration contracts

All future modules and clients should converge on these contracts:

### Identity and authorization

- One identity authority and documented token/API-key lifecycle.
- Explicit roles and per-action permissions; authentication alone is not
  authorization.
- Service-to-service identities must be separate from human user identities.
- Secrets are injected at runtime, rotated, and never committed to Git.
- High-impact response actions require explicit approval and a recorded actor.

### Security event envelope

Use a versioned event envelope with at least:

- `schema_version`, `event_id`, `occurred_at`, `ingested_at`
- `source`, `sensor_id`, `host`, `event_type`
- `severity`, `message`, `user`, `source_ip`, `destination_ip`
- `raw` or a protected reference to raw evidence
- `tenant_id` where multi-tenant operation is enabled

Require idempotent ingestion, bounded payload sizes, UTC timestamps, stable
pagination cursors, retention rules, and explicit handling of sensitive data.
Do not silently merge the distinct SQLite stores in the two repositories.

### API and UI

- The Python API remains the authoritative enforcement point.
- Browser clients use documented, versioned endpoints and never receive
  database credentials or service secrets.
- CORS origins are explicit; do not use wildcard origins with credentials.
- UI status indicators must reflect real API and dependency health, not
  hard-coded success labels.
- Use one API contract/OpenAPI source and generate or validate clients against
  it.

### Data and audit

- SQLite may be used for local single-instance development.
- Production multi-worker operation requires PostgreSQL integration, migrations,
  transaction/concurrency tests, backup/restore tests, and operational
  monitoring.
- Case history and security audit records need tamper-evident integrity
  protection, access controls, retention, and export procedures.
- Keep security events, alert state, analyst cases, and immutable audit records
  as distinct concepts with explicit relationships.

## Ordered integration backlog

### P0 — Security and release blockers

- [ ] Revoke and rotate the exposed TLS private key; verify it is absent from
  current artifacts and handle Git history exposure.
- [ ] Complete review and validation of PRs #107, #108, and #109.
- [ ] Finish PR #115 CI checks and review the new SOC routes, store lifecycle,
  permissions, and deployment configuration.
- [ ] Ensure all API startup paths fail closed when required credentials are
  absent.
- [ ] Verify backups, restore, TLS termination, and external exposure boundaries.

### P1 — Make ShiatoAli production-capable

- [ ] Implement a PostgreSQL repository adapter; wire it to the running service.
- [ ] Add schema migrations to deployment startup/release procedure with a
  least-privileged migration role.
- [ ] Add transaction, concurrent-ingestion, duplicate-event, retention, and
  restore tests against PostgreSQL.
- [ ] Add stable cursor pagination and event retention/archival.
- [ ] Add a tamper-evident audit chain for case activity and privileged actions.
- [ ] Add analyst RBAC, case ownership, and workflow transition validation.

### P2 — Unify platform integration

- [ ] Compare the event, alert, case, identity, and API implementations in
  NEXUS-OmniSec-Unified against ShiatoAli before choosing what to reuse.
- [ ] Publish the canonical versioned event schema and OpenAPI contract.
- [ ] Connect NEXUS-COMMAND-CORE as a UI client through authenticated API
  endpoints; do not couple it directly to databases.
- [ ] Define service identities, authorization scopes, and audit attribution.
- [ ] Add end-to-end tests across UI, API, event ingestion, alert creation, and
  case workflow.
- [ ] Add a single deployment manifest and release/rollback procedure only
  after component boundaries are stable.

### P3 — SOC capability expansion

- [ ] Sigma-compatible detection rule format and rule test harness.
- [ ] Threat-intelligence enrichment with source provenance and expiry.
- [ ] Alert deduplication, correlation, suppression, and analyst feedback.
- [ ] SIEM source connectors and endpoint telemetry ingestion.
- [ ] SOAR playbooks with dry-run mode, approval gates, least privilege, and
  rollback.
- [ ] Live dashboard, investigation timeline, and operational health metrics.

## README, API contract, and website consistency review (2026-11-13)

PR #116 also updates the project README, OpenAPI contract, and public HTML
content to remove unsupported operational and assurance claims. The reviewed
changes distinguish source-implemented features from browser demonstrations,
static snapshots, optional integrations, and unavailable remote services.

Key corrections include:

- The OpenAPI contract now identifies the MIT license and matches the Python
  API request schemas and authentication requirements for detection, web-shell
  scanning, receipt creation, ATT&CK coverage, and receipt retrieval.
- The API receipt endpoint is documented as unsigned
  `UNSIGNED-SHA3-512-DEMO`, process-local, capped, and not IPFS-anchored or
  SLH-DSA-signed.
- Reconnaissance, vulnerability, mobile, event-stream, and persisted-audit API
  routes return explicit unavailable responses until their workers/backends
  exist.
- ATT&CK coverage is a static code-defined snapshot, not live SOC telemetry.
- Public dashboards, marketplace analytics, case studies, ROI calculators,
  and architecture pages are identified as illustrative unless backed by
  current connected-service evidence.
- Unsupported FIPS validation, FedRAMP/CMMC/SOC 2/PIPEDA compliance,
  production-readiness, zero-PII, and subscription claims are withdrawn.
- The public-site builder injects a general reference/demo notice into each
  allowlisted HTML output. This notice supplements, but does not replace,
  page-specific accuracy and source review.

At the latest observed PR #116 head during this review
(`3c317fb77bc70a90f8859be444612b5aca423d4f`), the newly triggered GitHub
Actions runs were still queued or in progress. The two Snyk code-test statuses
continued to report quota exhaustion. Do not call the documentation changes
validated until the exact head's HTML, route, lint, and test workflows finish.

## Definition of done

A module is integrated only when all of the following are true:

1. It has an owner, repository boundary, and supported version.
2. Its API and data contracts are documented and validated.
3. Authentication, authorization, secrets, and audit behavior are tested.
4. Unit, integration, and relevant security checks pass on the exact commit.
5. Deployment, health checks, backups, and rollback are verified in a test
   environment.
6. The production UI reports its actual state and does not imply unverified
   capabilities.

This is a working status document, not a certification or a claim that the
platform is production-ready.
