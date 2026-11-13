# Shadow313 NEXUS repository review — 2026-11-13

## Scope and method

Reviewed the current feature branch `feat/shiatoali-soc-foundation` in
`piyyy314/Shadow313-Nexus`, including the Git tree, Docker Compose/Nginx
routing, FastAPI/OpenAPI surfaces, AI provider configuration, the Telegram
integration, SOC persistence/API, public-site allowlist, Vercel rewrites,
HTML navigation tests, CI results, and automated review comments.

This is a source/configuration review, not a production penetration test or
a live deployment validation.

## Repository and website integrity

- Git tree snapshot: 1,206 entries (633 Python files and 190 HTML files).
- Vercel rewrite destinations checked: 181; no missing destination files.
- Public static-file allowlist checked: 170 entries; no missing source files.
- The public-site build uses an explicit allowlist rather than publishing the
  repository tree.
- The OpenAPI YAML is published separately at `/docs/openapi.yaml`; its
  published copy is tested against `api/openapi.yaml`.
- Existing site tests cover shared navigation, local links, dashboard script
  syntax, public-file output, and route destinations.

## Defects fixed on this branch

1. **SOC detection and case handling**
   - Bound brute-force correlation to the rolling time window.
   - Preserved every alert when an event matches multiple detection rules.
   - Included the originating host in alert responses.
   - Updated case timestamps for note-only changes.

2. **AI/API behavior**
   - Moved synchronous provider availability checks and inference off the
     FastAPI event loop using a worker thread.
   - Added a regression test that verifies the worker-thread path.
   - Kept API-key authentication on `POST /api/chat` and aligned the request
     contract with the configured Ollama/OpenAI-compatible/gateway engine.

3. **AI gateway and Telegram integration**
   - Wired the optional OpenAI-compatible gateway into Open WebUI as well as
     the API, CLI, and Telegram bot. Open WebUI remains Ollama-only by default.
   - Replaced Telegram polling of the unavailable generic `/api/events` adapter with
     authenticated ShiatoAli alert polling.
   - Added chronological pagination and an ISO-8601 time cursor.
   - Moved synchronous SQLite/PostgreSQL operations in every SOC route to a
     worker thread so slow database calls do not block health checks or other
     API requests.
   - Preserved alert IDs at the cursor timestamp to avoid duplicate sends.
   - Preserved successful deliveries across retry batches so a later failure
     does not move the cursor backwards or resend newer alerts.
   - Added regression coverage for pagination, stale alerts, gateway-backed
     chat, and cursor retry behavior.

4. **Nginx/Open WebUI routing**
   - Routed Open WebUI's general `/api/*` requests back to Open WebUI.
   - Added explicit routing for Shadow313 FastAPI endpoints and the
     ShiatoAli/S313 API prefixes.
   - Added a test that checks every FastAPI API route has a matching Nginx
     upstream rule.

5. **API contract and dashboard**
   - Added `since` and `order` to the alerts route (not the events route) in
     both OpenAPI files.
   - Added mobile-responsive CSS to the legacy local dashboard.
   - Corrected test assertions for Python's `-c` healthcheck argument and
     the Telegram stale-alert cutoff.
   - Removed a tracked local TLS private-key file from this feature branch
     and added ignore rules/tests to prevent recommitting local TLS files.

## CI and quality status

- The initial PR validation run at `96669ef` exposed deterministic test
  failures in AI request patching, healthcheck argv indexing, Telegram alert
  cutoff, and dashboard layout. Those defects were corrected.
- A full validation run at `8ea8d3b` passed Python 3.11/3.12 tests,
  PostgreSQL integration, security scanning, Docker build (including Nginx
  config validation), and package build.
- Run `43421814142` on commit `4809dd2` passed Python 3.11/3.12 tests,
  PostgreSQL integration, changed-module Ruff/MyPy, security scanning, and
  package build. Docker image build was still running at the time of this
  report; Compose validation and `nginx -t` had already passed.
- The full-repository Ruff baseline recorded 5,496 diagnostics. This is
  existing lint debt, not a count of runtime bugs. It includes import
  ordering, long lines, legacy typing, unused imports, and security-lint
  findings.
- CI enforces Ruff and MyPy against the complete feature-branch diff for
  changed Shadow313 Python modules. Black reports seven changed modules that
  would be reformatted; that style-only step is visible but currently
  non-blocking while the existing formatting debt is assessed.
- The setuptools dependency findings were addressed by requiring
  `setuptools>=84.1.0` and upgrading setuptools before the CI audit.

## Security items requiring attention

- GitGuardian continues to flag one generic test-container password in
  historical commit `c5f625b157c01c7d5c9136feb5678741a6c4d081`. The current
  workflow no longer contains it and uses trust authentication only for its
  ephemeral PostgreSQL test service. The finding remains because the commit
  is still in PR history. No production credential was used.
- The current `master` and feature-branch trees no longer track
  `docker/nginx/ssl/shadow313.key`. Git history still contains the earlier
  commit `7703717f94f1606646ccf23d8d816e2d0d62e733` that added it; it was
  removed from the default branch by `38aad78970b67592026cbedfb137a09d89d3f15e`.
  Treat the historical key as exposed. If it was ever used outside local
  development, issue a replacement certificate/key and update deployed copies.
  Removing a file from the current tree does not erase its historical blob.
- Production SOC readiness still requires distributed rate limiting,
  retention policies, managed backups and restore drills, monitoring,
  deployment health checks, and operational access controls.

## Branch and release state

- Pull request: #115
- Base: `master`
- Feature branch is 268 commits ahead and 41 commits behind the current base
  at the latest comparison snapshot.
- Seven paths were changed on both sides of the merge base:
  `.github/workflows/shadow313-ci.yml`, `.gitignore`, `README.md`,
  `docker-compose.yml`, `docker/nginx/gen-ssl.sh`, `requirements.txt`,
  and the local TLS key deletion. The SSL script and ignore rules need an
  explicit three-way reconciliation before the PR can merge.
- GitHub reports the PR as `dirty` / not mergeable; base-branch divergence
  and overlapping infrastructure changes need reconciliation.
- The PR remains draft and unmerged.
- No production database migration or production deployment was performed.

## Next validation sequence

1. Reconcile the feature branch with current `master` and resolve the seven
   overlapping paths without rewriting shared history.
2. Decide whether to apply Black formatting to the seven reported modules.
3. Review the remaining repository-wide lint/security baseline in focused
   batches rather than suppressing findings globally.
4. Rotate any deployment that used the historically exposed local TLS key.
5. Recheck GitGuardian history handling before considering the PR merge.
