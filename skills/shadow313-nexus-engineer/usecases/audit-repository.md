# Audit the repository

## Purpose

Establish a current, evidence-backed map of Shadow313 NEXUS and identify actionable defects without changing files.

## Procedure

1. Confirm `piyyy314/Shadow313-Nexus` or resolve the explicitly supplied repository. Record default branch, requested branch, current HEAD, and whether the source is local, connected, or remote.
2. Read repository-level agent instructions, README, contribution/security guidance, package/build manifests, deployment manifests, and CI workflows relevant to the requested scope.
3. Inventory the repository by subsystem:
   - application entrypoints and service modules
   - API routes, auth, validation, rate limits, and AI gateway adapters
   - CLI parser, command registry, handlers, help, and tests
   - HTML pages, dashboards, shared assets, navigation, and data sources
   - tests, fixtures, scripts, and dependency manifests
   - GitHub Actions, security scanners, deployment workflows
   - Vercel configuration and Cloudflare/DNS references
4. Search for duplicate or orphaned routes/handlers, TODO or placeholder paths, stale names/domains/versions, inconsistent environment-variable names, broken relative links, mismatched schemas, and dead code. Verify suspected issues at their definitions and call sites.
5. Trace each user-visible feature end to end: UI/CLI entry -> route/registry -> handler/service -> data/provider -> error path -> test/documentation.
6. For deployment concerns, distinguish checked-in configuration from live provider state. Query provider integrations only when available and authorized.
7. Rank findings by severity, likelihood, user impact, confidence, and smallest safe repair. Cite exact paths and line ranges where the host supports them.

## Output

Return:
- repository/branch/HEAD inspected
- subsystem coverage and exclusions
- findings table: severity, evidence, impact, proposed fix
- tests already present and checks run
- unknowns requiring provider or runtime access

Do not make changes during an audit-only request.
