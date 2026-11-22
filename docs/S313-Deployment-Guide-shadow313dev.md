# Shadow313 NEXUS — Deployment and Hosting Guide

This guide reflects the current hosting decisions. It replaces earlier setup
instructions that proposed Netlify, duplicate hosting, or buying domains that
are already owned and connected.

## 1. Approved architecture

| Component | Platform | Responsibility | Current state |
|---|---|---|---|
| Source and CI | GitHub | Code, pull requests, tests, security checks | In use |
| Public website | Vercel | Static-site build, previews, production hosting | In use |
| `shadow313.com` DNS | Cloudflare | DNS zone and records | In use |
| `shadow313.dev` DNS | Vercel DNS | Existing DNS configuration | In use |
| Backend | Hetzner | Planned API and service host | Pending purchase and provisioning |

Render, Netlify, and Railway are intentionally excluded. Do not create
additional hosting projects for these providers.

## 2. Domains and DNS

The two apex domains are attached to the existing Vercel website project:

- `https://shadow313.com`
- `https://shadow313.dev`

The `www.shadow313.com` and `www.shadow313.dev` hostnames are configured as
permanent redirects to their matching apex hostnames.

DNS ownership is split by domain:

- Manage `shadow313.com` records in the Cloudflare zone.
- Manage `shadow313.dev` records in the existing Vercel DNS configuration.
- Keep Vercel website records DNS-only in Cloudflare unless a deliberate,
  tested proxy configuration is introduced.
- Use the exact target records shown by Vercel domain configuration; do not
  copy old IP addresses or DNS targets from archived instructions.
- Do not change MX, SPF, DKIM, DMARC, or other mail records as part of website
  deployment.

## 3. Vercel website deployment

The Vercel project builds the static website with:

```bash
node scripts/build-public-site.cjs
```

The configured output directory is `public-site/`. The build script publishes
the explicit allowlist in `site/public-files.json`; the repository itself is
not served as a web root.

For a change:

1. Create a focused GitHub branch and pull request.
2. Wait for required CI, security, and validation checks.
3. Inspect the Vercel preview and verify affected routes.
4. Merge only when required checks and reviews are satisfied.
5. Confirm the production deployment reaches `READY`.
6. Test the apex and `www` hostnames over HTTPS.

A successful quality-check job with a skipped deployment job is not a
production deployment.

## 4. Backend deployment — Hetzner (planned)

The backend has not yet been deployed as a hosted service. The Hetzner server
will be purchased and configured separately from the Vercel static frontend.

Before creating a public API DNS record:

1. Choose server resources based on measured API, database, worker, and storage
   requirements rather than relying on an old example size or price.
2. Add an SSH public key and restrict administrative access.
3. Apply OS updates, firewall policy, SSH hardening, and automatic security
   updates.
4. Decide whether PostgreSQL and application services run in Docker or as
   managed host services; define persistent volumes and backup retention.
5. Configure secrets outside Git and restrict service-to-service access.
6. Deploy the API and workers, then verify health, logs, TLS, and restart behavior.
7. Test database backup restoration and server recovery.
8. Configure the Vercel frontend to use the verified backend URL and API key.
9. Add the API hostname to Cloudflare only after the backend is hardened and
   listening on the intended interface.

See [Hetzner infrastructure notes](../infra/hetzner/README.md). The existing
scripts are provisioning aids, not proof of a finished production deployment.
Review them before running.

## 5. Release verification

For each production release, record:

- Git commit SHA and merged pull request.
- Required GitHub Actions conclusions.
- Vercel deployment URL and `READY` state.
- HTTPS checks for both apex domains and both `www` redirects.
- Static route and 404 behavior.
- Backend health only after a real backend is provisioned.
- Known external CI provider blocks.

Useful links:

- [GitHub repository](https://github.com/piyyy314/Shadow313-Nexus)
- [GitHub Actions](https://github.com/piyyy314/Shadow313-Nexus/actions)
- [Vercel](https://vercel.com/)
- [Cloudflare dashboard](https://dash.cloudflare.com/)
- [Hetzner Cloud Console](https://console.hetzner.cloud/)

## 6. Explicit non-goals

- No Netlify mirror or backup deployment.
- No Render service.
- No Railway backend.
- No second static hosting platform.
- No claim that the Hetzner API is online before provisioning and verification.
