# Shadow313 NEXUS repository map

## Known repository identity

- Repository: `piyyy314/Shadow313-Nexus`
- Default branch observed during initial authoring: `master`
- Public repository; authenticated GitHub connector reported read/push/admin permissions during initial authoring.
- The repository root contains a `skills/` directory; this skill is stored under `skills/shadow313-nexus-engineer/`.

These are orientation hints, not permanent truth. Re-check repository metadata and branch state for every task.

## Expected subsystem boundaries

| Area | Inspect |
|---|---|
| API/backend | route registration, request validation, auth, services, persistence, error handling |
| AI integrations | gateway selection, model routing, timeout/retry policy, usage/error normalization, secret references |
| CLI | parser, command registry, handler map, command help, output contract, tests |
| Web | pages, dashboards, shared components/assets, navigation, responsive/accessibility states |
| CI/security | workflow triggers, permissions, job dependencies, scanners, artifacts, required checks |
| Deployment | Vercel project/build config, runtime/output, environment variable names |
| DNS/edge | Cloudflare zone authority, DNS records, proxy/TLS settings, edge routing |

Do not assume every directory exists or that this table is an exact current architecture. Derive the live map from the current tree and source.

## Domain and hosting notes

Historical project discussions described Vercel as the static/app hosting platform and Cloudflare as the DNS provider for `shadow313.com`. The current arrangement may have changed. Verify live nameservers, records, Vercel project domains, and deployment state before recommending or performing changes.

Never treat DNS provider and application host as mutually exclusive: Cloudflare can manage authoritative DNS while Vercel serves the application.
