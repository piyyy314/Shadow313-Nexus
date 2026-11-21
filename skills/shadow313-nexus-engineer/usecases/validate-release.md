# Validate CI and prepare a release

## Procedure

1. Resolve the exact PR/branch/commit. Fetch current GitHub records rather than relying on old conversation summaries.
2. Inspect PR state, head/base SHAs, changed files, review comments, check suites, commit statuses, workflow runs, and job-level conclusions.
3. Classify each check distinctly: passed, failed, pending, skipped, cancelled, or externally blocked. Identify failing job names and concise log evidence.
4. Run local validation where available: formatting/lint, type checks, unit/integration tests, dependency and secret scans, build, and deployment configuration validation.
5. Confirm the build uses the intended runtime, package manager, lockfile, environment-variable names, and deployment output. Never expose secret values.
6. Verify Vercel project/root/build/output settings and domain association from live provider data when connected. Verify Cloudflare authoritative nameservers and DNS records before DNS conclusions. Treat source config as intent, not proof of live state.
7. Do not deploy, alter DNS, change production environment variables, merge, or bypass checks unless the user explicitly authorizes that exact action.
8. If the PR is ready, provide a release-readiness summary with blockers and direct links to the PR and failed workflow runs. Do not enable auto-merge or merge unless explicitly requested.

## Status rules

- `passed`: provider reports successful conclusion.
- `failed`: provider reports failure or a reproducible failing check.
- `pending`: queued or in progress.
- `skipped`: provider reports skipped.
- `externally blocked`: provider/quota/permission/third-party dependency prevents execution.
- `not run`: no execution evidence exists.

A green aggregate does not erase a failed, skipped, or externally blocked required check.
