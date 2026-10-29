# Deployment, homepage and API audit — 2026-10-29

## Scope and limits

Source review of production branch `master` at `c9d9486`, including deployment workflows,
Vercel rewrites, HTML links/assets, browser-side API calls, Node/Python endpoint definitions,
and local HTTP/regression tests. Open PRs #86 and #87 were identified; their separate feature
work was not merged into this repair. This is not an external penetration test or proof that
production endpoints work. No live endpoint requests, production writes, merges or deployments
were performed. Browser checks used local Chromium with external font/CDN requests blocked;
a deployed visual check with the actual fonts is still required.

## Required manual handoff

GitHub rejected publication of `.github/workflows/deploy.yml` because the Agent publishing
token cannot edit Actions workflows. Nothing was published by that attempt. The workflow and
its matching regression-test edits are supplied in `docs/manual-vercel-workflow.patch`, not
applied to the workflow in this PR. From a checkout of this PR branch, apply them with:

```sh
git apply --check docs/manual-vercel-workflow.patch
git apply docs/manual-vercel-workflow.patch
```

Commit and push that change yourself with `[skip ci]` in the commit message. This PR also
uses `[skip ci]` to avoid the existing push/PR deployment workflow. GitHub documents that this
can leave required checks pending; do not bypass branch protection. Review and apply the
manual-only workflow first, then remove the skip marker in a subsequent commit to run checks.
The API/layout tests below were run locally, not by CI. Do not merge before this handoff.

**Until the patch is applied, GitHub Actions can still automatically deploy future pushes/PRs.**
`git.deploymentEnabled: false` controls only the separate Vercel Git integration.

## Confirmed findings addressed (workflow changes supplied as a patch)

1. **Two independent automatic Vercel deployment paths.** Git integration deploys pushes, and
   `.github/workflows/deploy.yml` separately deploys PRs and pushes to `master`. Setting only
   `git.deploymentEnabled` is insufficient. This PR disables Git-triggered deployment for
   branches carrying this configuration; the supplied patch gates both deployment jobs behind
   `workflow_dispatch` with an explicit `preview` or `production` selection. Production also
   requires `master`. Push/PR quality checks remain enabled. In the patch, the old rollback,
   which referenced a different project/team name, was removed rather than risking an
   unintended promotion. Manual preview URLs now appear in the workflow run summary.
2. **Mobile roadmap text collapses into a 40px column.** The phase label is hidden at widths
   below 900px, but the grid retains three columns (`0 40px 1fr`) for two visible children.
   Chromium reproduced 40px-wide content with overflowing words. Two columns, a shrinkable
   content track and safe word wrapping fix the cause.
3. **Signup form clips off-screen.** At 320px the form was 192px wide but its contents extended
   to x=429px. The input can now shrink and the form stacks on narrow screens. Footer copy
   also uses a more legible text color on mobile. Both homepages are valid UTF-8; no replacement
   characters or common mojibake markers were found in their source.
4. **Nested website API routes lack an explicit shared-handler rewrite.** The single function
   is `api/index.js`; this PR routes `/api/:path*` to that entry point without changing domain
   homepages. The original 165 rewrite destinations all exist; the added handler target exists
   as well. This verifies source wiring, not deployed routing behavior.
5. **Website API cannot start from a clean checkout.** It required Express without a root
   package manifest declaring that dependency. It now uses the native Node HTTP interface,
   with no added dependency.
6. **Website API fabricates successful backend work.** The previous Node handler returned clean
   webshell verdicts, negative detections, nonexistent receipts and queued scans without running
   the Python backend. These operations now explicitly return JSON HTTP 503; unknown routes
   return JSON 404 and incorrect methods return 405. Health/status remain available and disclose
   that the backend is not connected. Request bodies are no longer logged by the webhook stub.
   This intentionally changes placeholder API behavior; it does not implement the backend.
7. **SentinelOS fetches missing, blocked circuit files.** Three requests targeted
   `/shadow313/assets/circuits/*.qasm`, but no such files exist and `/shadow313/:path*` is
   deliberately blocked. It now uses the already embedded QASM examples without those requests.
8. **Public API contract implies a working hosted backend.** The advertised production server
   was removed from `api/openapi.yaml`; the local server remains. The API documentation now
   states the website/backend distinction and the HTTP 503 behavior.

## Remaining gaps / decisions

- **A real hosted backend is not connected.** `shadow313/api/server.py` and
  `shadow313/api/audit_server.py` are separate Python services, not the Node website function.
  Hosting, authentication, persistent receipt storage and any proxy routing must be designed
  before enabling real scans or receipts. Do not put server API keys in browser JavaScript.
- **AI chat is not implemented on the website backend.** SentinelOS requests `/api/chat` and
  already catches failures with an explicitly labelled local fallback. The handler now returns
  a clear 503. No provider credentials or external AI service were provisioned.
- **Waitlist storage is not connected.** The homepage already redirects valid submissions to
  `/contact` and reports that signup is unavailable. This PR does not invent a subscriber store.
- **Legacy page dependencies:** `docs/recon.html` references missing shared CSS/JS and three
  nonexistent relative tool pages. Three archived saved pages also reference missing resources.
  These are not missing Vercel rewrite destinations. They were recorded rather than rebuilding
  an unrelated legacy page or modifying archived captures.
- **Static publication boundary:** the project's default output is the repository root. Existing
  Python/environment rewrites are not a complete publication allowlist. A dedicated static output
  directory is recommended before treating all repository-only files as private. Actual public
  exposure was not probed in this audit.
- **Broad automated inventory:** the repository's existing completeness auditor reported 347
  source modules, 39 Python API routes and 176 heuristic findings (76 FAIL, 85 WARN, 15 INFO),
  including 16 endpoints without a traceable test. These are tool classifications, not confirmed
  vulnerabilities; known passing API tests show that name-based traceability can undercount.
  Suspected credential assignments were not reproduced here or treated as confirmed secrets.
- Repository-wide Ruff reports 6,542 diagnostics on both the unchanged base and this branch.
  No mass autofix was attempted. New regression-test lint passes.
- GitHub Pages publishing remains unchanged; this request concerns Vercel. Existing branches
  must incorporate the deployment configuration and workflow changes to receive these controls.

## Verification

- Four new Python regressions failed on the original configuration/layout, then passed after
  the fixes. The original website API failed to import because Express was undeclared.
- The intended full change (including the workflow patch) passed 22 focused Python tests.
  The publishable branch alone passes 21 focused tests; the extra workflow test is in the patch.
- Three native Node HTTP tests passed, exercising health/status, 21 unavailable backend paths,
  unknown routes, method validation, query strings and HEAD responses.
- Local Chromium at 320, 375, 768 and 1440px: roadmap content, signup fields/buttons and footer
  fit their viewport without internal horizontal text overflow; no page JavaScript errors.
  At 320px roadmap content is now 216px wide, rather than 40px.
- The intended full change including workflow edits passed the broader non-integration Python
  suite: **4,080 passed, 75 skipped**, with one dependency deprecation warning. The 75 skipped
  tests were not verified.
- JavaScript syntax checks and `git diff --check` passed.

## Release procedure

Apply the required workflow patch and review before merging. The configuration does not
change the currently running site by itself.
To publish deliberately, manually dispatch **Shadow313 NEXUS — Deploy to Vercel** with
`target: preview` first; use `target: production` on `master` only after verification. That
workflow continues to rely on the repository's existing Vercel secrets; their availability and
project association were not inspected. No workflow was dispatched during this work.
