# ADR 0001: Hosting and deployment boundaries

- **Status:** Accepted
- **Date:** 2026-11-22
- **Owners:** Shadow313 NEXUS maintainers

## Context

The repository contains a static public website, a Vercel API gateway, Python application packages, optional local services, and backend-oriented SOC components. A website or gateway check must not be interpreted as proof that the Python backend or optional services are deployed.

## Decision

1. GitHub is the source-control, review, and CI system.
2. Vercel hosts the public static website and its preview/production builds.
3. Cloudflare manages DNS for shadow313.com; the existing shadow313.dev DNS configuration remains with Vercel.
4. Hetzner is the planned backend host. Backend provisioning, hardening, deployment, and production validation remain separate milestones.
5. The Vercel API gateway may proxy to a separately hosted Python backend only when the backend URL and server-side credential are configured. Missing configuration must fail closed and report the backend as unavailable.
6. Render, Netlify, and Railway are not approved hosting targets unless a future ADR explicitly changes the decision.
7. GitHub Pages is a secondary delivery-artifact portal only. `.github/workflows/deliver.yml` is the sole publisher and may publish generated `dist/` artifacts only; the repository root and canonical public website must not be deployed there.

## Consequences

- Static dashboards and marketplace pages must distinguish sample data, simulations, and unverified integrations from live telemetry.
- CI quality checks, the GitHub Pages delivery-artifact deployment, and Vercel preview/production deployment are separate events and must be reported separately.
- The delivery workflow must reuse the same manifest and receipt generated for the Pages artifact; it must not regenerate a second, divergent receipt during the repository commit step.
- No workflow may claim production deployment without a successful deployment job and a matching provider deployment record.
- Backend-dependent features remain unavailable until a real backend is provisioned, secured, and verified.
- Hosting changes require an ADR update and corresponding deployment documentation.
