# Shadow313 Platform Integration Status

Last reviewed: 2026-11-14

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

For PR #115 head `7c962bd5aee6116cbf090cd64f9068b796937c77`:

- PR Checks, full pre-deploy validation, API endpoint validation, and the CI/CD workflow completed successfully.
- Python 3.11 and 3.12 unit-test jobs, SAST, secret detection, dependency scanning, Dockerfile lint, HTML validation, shell/config checks, file-integrity checks, and Python/API validation completed successfully in the observed runs.
- The CI/CD workflow's Docker build and security scan completed successfully. PyPI and TestPyPI publication jobs were skipped.
- The Vercel workflow's quality checks passed, but both production and preview deployment jobs were skipped. Do not describe this run as a deployment.
- All currently listed inline review threads on PR #115 are resolved. The PR remains open and is not merged.

Relevant runs: [PR checks](https://github.com/piyyy314/Shadow313-Nexus/actions/runs/43528831166), [pre-deploy validation](https://github.com/piyyy314/Shadow313-Nexus/actions/runs/43528831301), [CI/CD](https://github.com/piyyy314/Shadow313-Nexus/actions/runs/43528831258), [API validation](https://github.com/piyyy314/Shadow313-Nexus/actions/runs/43528831226).

For PR #116, the CI-repair and site-consistency branch remains under active validation. Its status is commit-specific; consult the live [PR checks](https://github.com/piyyy314/Shadow313-Nexus/pull/116) and [Actions runs](https://github.com/piyyy314/Shadow313-Nexus/actions) rather than copying a previous run's result into this document.

Do not merge either PR solely because an earlier head passed. Recheck the latest head SHA, required checks, review threads, and deployment status immediately before merge.

## Repository hygiene and deployment follow-up

The following historical maintenance PRs are closed and merged:

1. [PR #107 — remove committed TLS private key](https://github.com/piyyy314/Shadow313-Nexus/pull/107). The removal change is merged. Key/certificate rotation and any required Git-history cleanup are external follow-up actions and are **not verified by merge status alone**.
2. [PR #108 — Debian and Python packaging security updates](https://github.com/piyyy314/Shadow313-Nexus/pull/108). The change is merged. Confirm the actual deployed image has been rebuilt and scanned before treating runtime exposure as resolved.
3. [PR #109 — Open WebUI URL and Nginx memory limit](https://github.com/piyyy314/Shadow313-Nexus/pull/109). The change is merged. Validate the Compose stack and upload path in the target environment before asserting operational readiness.

PR #115 (ShiatoAli SOC foundation) and PR #116 (CI repairs and site consistency) remain open. This document is a handoff, not a live deployment dashboard; recheck GitHub before acting.

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
