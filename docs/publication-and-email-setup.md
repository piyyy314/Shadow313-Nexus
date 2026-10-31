# Public website, package, and email setup

## Publication boundary

Vercel builds with `node scripts/build-site.cjs` and serves `site-dist/` only.
`site/public-files.json` is the explicit allowlist. API source remains server-side;
there is no repository-root static fallback. Existing clean page routes remain,
except routes to retired download portals/internal reports. The public build adds
an unambiguous reference/demo notice to research dashboards. Source files are
preserved in Git; this is not a security review of every historical document.

**GitHub Pages manual step still required:** its current workflow uploads the
repository root. The Agent publisher cannot change GitHub Actions workflows.
A maintainer must apply this reviewed patch, commit, and push it:

```sh
git apply --check site/github-pages-isolation.patch
git apply site/github-pages-isolation.patch
git add .github/workflows/github-pages.yml
git commit -m "fix: publish only allowlisted GitHub Pages output"
git push
```

If the workflow has changed, manually add `node scripts/build-site.cjs` before
uploading, and set the uploaded `path` to `site-dist`. Do not assume this handoff
is installed merely because Vercel is fixed. GitHub Pages also lacks Vercel
rewrites and server functions: use the custom domains for the supported site.
No GitHub Pages URL is claimed repaired by this PR.

## Email requests: intentionally fail closed until configured

The waitlist form sends an early-access **request to the operator**, not a mailing
list subscription. The contact form sends a message to that same configured inbox.
There is no subscriber database, confirmation campaign, or automated marketing.
The operator inbox is the record of accepted requests. Delivery is unverified
until a real authorized test reaches the inbox; provider acceptance is not delivery.

1. Set up Resend and verify a sending domain that you control.
2. Create a Cloudflare Turnstile widget restricted to the custom-domain hostnames
   (`shadow313.com`, `www.shadow313.com`, `shadow313.dev`, `www.shadow313.dev`).
   Add the exact preview hostname only if preview delivery testing is needed.
3. Set the following server environment variables for the intended Vercel
   environments. Enter secrets using protected environment-variable inputs;
   **never paste keys into chat, repository files, or client JavaScript**:

| Variable | Purpose |
| --- | --- |
| `RESEND_API_KEY` | Restricted sending API credential (secret) |
| `FORM_FROM_EMAIL` | Plain email address on the verified sending domain |
| `FORM_TO_EMAIL` | Operator-selected plain recipient email address |
| `TURNSTILE_SECRET_KEY` | Server-side CAPTCHA credential (secret) |
| `TURNSTILE_SITE_KEY` | Public widget site key |

No default recipient is inferred from README contact details. The operator must
choose the inbox. Missing settings disable the form and show the direct email link.
4. Redeploy after configuration. Test both forms on an authorized preview; confirm
   the actual message arrives and replies target the visitor, then test production.
5. Consider provider quotas and additional durable rate limiting before enabling
   public sending. This implementation requires Turnstile validation (single-use
   provider tokens), action/hostname checks, same-origin requests, consent,
   bounded input, a honeypot, timeouts, and fixed recipient configuration. CAPTCHA
   is not a guarantee against all abuse; monitor quotas and abuse reports.

Only the public site key is exposed by `/api/forms/config`. The server does not
return provider credentials, raw provider errors, or submission bodies in logs.
Mail is plain text. No real emails are sent by automated tests.

Sources: [Resend sending API](https://resend.com/docs/api-reference/emails/send-email),
[Turnstile server validation](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/),
[Vercel email guidance](https://vercel.com/kb/guide/sending-emails-from-an-application-on-vercel).

## Repository cleanup disposition

`python scripts/repository-inventory.py` produces the per-tracked-file inventory.
No archive, session export, or source module is automatically deleted. History
may contain real data or third-party material: inspect content/licensing and
obtain maintainer decisions before moving/removing it. Removing current files
cannot remove copies from forks, prior deployments, or Git history. Rotate any
exposed credentials separately. This change does not assert old scan counts or
CVE/version suggestions are still accurate.

## Packaging verification

Package discovery includes `shadow313*` (including SDK/platform) and
`nexus_toolkit*`. Explicit package-data rules include the built-in plugin manifest
and signature, satellite advisory data, and optional PQC JS bridge files. Python
source distributions exclude website docs/archives/internal exports; no source
module is deleted. Install a built wheel in a clean environment and test the
required optional groups; a successful build is not runtime integration proof.
