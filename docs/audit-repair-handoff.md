# Audit repair handoff (2026-10-31)

## What this pull request fixes

- Full-match escaped wildcard scope validation; no unauthorized suffix-domain match.
- Version-2 Binder313 receipt envelope: full signature export, metadata/sequence
  round trip, chain-material recomputation, key-bound signature verification,
  rejection of modified fields, no signing-error downgrade, serialized binding.
  SPHINCS+ is labeled accurately rather than claiming standardized SLH-DSA.
- Shared API authentication and per-process request-size/global-rate limits;
  mobile token checks actually attached; invalid link-budget numbers rejected.
- Main API LOLBin adapter uses `analyze_event`. Missing scan/event/mobile/audit
  integrations return authenticated 503, not invented queued/success states.
- Audit server explicitly reports unsigned demo receipts/no signing public key.
  Receipt stores are capped at 1,000 rather than growing without bound.
- OpenAI-compatible URL joining and explicit `gateway` backend/key mapping.
  One AIEngine implementation; direct-file path is now a compatibility shim.
- Graph fallback, JUnit escaping, empty-algorithm classification, verbose
  simulation crash, test cwd leakage, and three former xfails now mandatory.
- Docker API/bot entrypoints, WebUI proxy port, missing dashboard upstream,
  Ollama download egress/readiness, optional Telegram/RAG profiles, named data
  volume, default seccomp, Python package/data copies in the image.
- Mistral Modelfile inherits its correct template/license; no invented machine
  status/receipt prompts; deploy script reads the actual FROM model.
- Python wheel includes SDK/platform/toolkit/runtime resources; source archive
  no longer bundles website docs/archives. This is not a PyPI release.
- Narrow static output allowlist (`site/public-files.json` → `public-site/`),
  leaving archives and source untouched. Public docs carry a reference/demo
  notice; contact cannot falsely claim a message was sent. Hosted AI remains
  explicitly unavailable rather than becoming a billable/public proxy.

## Important compatibility and security limits

Binder313 keys are **ephemeral and instance-local**. Verification uses that
instance's trusted key; a new process cannot authenticate earlier receipts without
an explicitly designed persisted-key/trust store. Do not interpret timestamp
suffix `313` as entropy, trusted time, legal attestation or an IPFS anchor. A
verified single receipt is not proof of a complete non-deleted history. Check
predecessor continuity separately. Legacy truncated exports fail closed. No
migration invents missing signatures.

The API demo receipt/chain service is not a durable signed ledger. Unknown
features are unavailable, not implemented by returning fake successful JSON.
Limits are per-process; use durable shared quotas/reverse-proxy controls before
multi-instance exposure. Audit/API health is not proof of every module working.

No archive/source deletion, credential rotation, comprehensive 5,909-diagnostic
lint refactor, Windows runtime change, live scanner operation, hosted AI send,
email send, PyPI upload, or workflow permission escalation is performed here.
The former reverted cleanup is not copied wholesale: existing pages/research,
README feature tables and model blobs are not deleted or regenerated. Packaging,
forms and publication boundaries are fixed narrowly with regression tests.

## 1. Merge the repair PR, then safely sync Windows

First back up the repository folder. In PowerShell run only commands, not `PS>`
prompts or prior output:

```powershell
git fetch origin
git status --short --branch
git stash list
```

Stop if there is local work or an unfinished merge/rebase. Preserve and review
untracked/stashed files before syncing; do not `git clean`, force-push, reset hard,
or blindly restore the earlier overlapping `shadow313/` stash.

When clean and all intended changes are merged:

```powershell
git switch master
git pull --ff-only origin master
```

A deployed preview is not automatically a merged or production release.

## 2. Test Python and package artifacts

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m pytest tests/ -q
node --test tests/vercel-api.test.cjs tests/site-clocks.test.cjs
node scripts/build-public-site.cjs
```

`full` is still a convenience subset, not all heavyweight RAG/cloud/browser/
fine-tuning dependencies. Install only extras needed for supported workflows.
Tests skipped for optional hardware/services are not proof those integrations run.

Build to a fresh artifact folder, not one containing old releases:

```powershell
python -m pip install --upgrade build twine
python -m build --outdir release-artifacts
python -m twine check release-artifacts/*
```

Install the wheel in another clean virtual environment **outside the checkout**,
then run help and required module tests. Do not publish until required tests pass.
Select an unused release version and update version sources consistently; 4.0.0
is unchanged here. No assumption that a previously uploaded filename is reusable.

## 3. Apply GitHub Actions handoff (operator permission required)

The Agent publisher cannot edit workflow files. The checked patch is
`docs/audit-workflow-handoff.patch`:

```powershell
git apply --check docs/audit-workflow-handoff.patch
git apply docs/audit-workflow-handoff.patch
git diff -- .github/workflows
```

Review it before committing. If the check fails because workflows changed, stop
and reconcile manually. It removes fail-open required checks, makes TestPyPI
errors visible, uses `public-site/` for the canonical Pages deployment and stops
the second Pages deployer. **Full lint/security gates may now fail on existing
issues; fix or review them, do not put `|| true` back to obtain green.**

```powershell
git add .github/workflows
git commit -m "ci: apply reviewed audit workflow hardening"
git push origin master
```

Do not run this while on a feature branch expecting it to update master. Add the
new audit regression tests and Node public build to required quality checks.
Vercel builds `public-site` from vercel.json; Pages clean-route rewrites/server
functions remain a separate hosting limitation. Custom domains are the supported
full site. Validate Pages artifact and URL paths before claiming its 404s fixed.

## 4. Configure TestPyPI Trusted Publishing

The actual TestPyPI job failed with **invalid-publisher**, hidden by
`continue-on-error`. Configure a TestPyPI trusted publisher for:

- GitHub owner: `piyyy314`
- Repository: `Shadow313-Nexus`
- Workflow filename: `shadow313-ci.yml`
- GitHub environment: `testpypi`

TestPyPI and PyPI are separate. For the real PyPI project configure the same
repository/workflow with environment `pypi`. Confirm ownership of the intended
package name. No keys need to be pasted into chat. The real publish job is
release/tag-triggered; TestPyPI is master-triggered. Check the actual exchange
and uploaded artifact, not only a green job or `skip-existing`.

Official guide: https://docs.pypi.org/trusted-publishers/adding-a-publisher/

**Do not publish until** tests, installed-wheel smoke checks, intentional skips,
artifact inventory, version/license metadata, and security regressions are clear.

## 5. Recover/verify local Docker without deleting data

Do not delete Windows `.ollama`, Docker volumes or WSL distributions. Windows
Ollama storage and container `ollama_data` are separate. Your earlier manifest
checks found all referenced Windows blob files; this PR does not move them.

Use `scripts/local-runtime-preflight.ps1` for read-only local diagnostics; inspect errors rather than assuming completion means healthy.

Pick one inference topology. To use the repository's **container stack**, keep
Docker Desktop running, generate/keep local keys privately and set only the
required runtime settings in a gitignored `.env`:

- `WEBUI_SECRET_KEY` (stable random secret, keep for persistent login sessions)
- `SHADOW313_API_KEY` (random local API credential)

The Telegram bot is optional (`--profile telegram`) and needs its separate bot
credential/chat ID. Do not share `.env` or paste rendered `docker compose config`
output: it can include secret values. Use quiet validation:

```powershell
docker compose config --quiet
```

Before recreating containers, back up the existing named/bind-mounted data and
inspect old mounts. The data volume is now portable/named: existing host-bound
session data is **not automatically migrated**. Do not assume a volume of the
same name changes its driver settings in place. Preserve the old data first.

Then build and start deliberately:

```powershell
docker compose build shadow313-api
docker compose up -d ollama ollama-init open-webui shadow313-api nginx
docker compose ps
docker compose logs --tail 80 ollama-init shadow313-api nginx
```

Nginx uses local HTTPS (`https://localhost`) and port 8080 proxy; this stack does
not promise direct host ports 3000/11434. Generate local TLS files with the
existing certificate helper only after reviewing it. Verify certificate/volume
permissions and Nginx binding on your Docker version. A standalone dashboard is
not part of this stack; `/dashboard/` explicitly reports unavailable rather than
pointing to nonexistent DNS. Review logs locally and redact tokens before sharing.

This environment cannot run your Docker daemon: **container health and actual
Ollama model generation remain user-side validation**.

## 6. Recreate the custom model safely (optional)

For **Windows native Ollama**, inspect the existing model before changes:

```powershell
ollama list
ollama show matarmohamad313/shadow313-nexus --modelfile
```

Save that output locally for backup. After reviewing the changed Modelfile, create
a **new local name** first; do not overwrite/push your published model blindly:

```powershell
ollama pull mistral:7b
ollama create shadow313-nexus-audit-test -f ollama/Modelfile
ollama run shadow313-nexus-audit-test
```

For container Ollama use `docker compose exec ollama ...` instead and mount/copy
the reviewed Modelfile deliberately. Neither automatically shares Windows models.
Test setup questions: the model should ask for evidence, not invent repositories,
services, receipts, or command flags. Prompt customization is not fine-tuning.
Publishing a new model and verifying upstream license terms remains your decision.

## 7. AI Gateway and email are not automatically connected

Local Ollama does not require Vercel AI Gateway. For explicitly chosen hosted
Gateway requests, use protected environment settings on the machine where the
CLI runs:

- `SHADOW313_AI_BACKEND=gateway`
- `SHADOW313_AI_ENDPOINT=https://ai-gateway.vercel.sh/v1`
- `SHADOW313_AI_MODEL=<supported provider/model ID>`
- `AI_GATEWAY_API_KEY=<enter privately, never commit>`

The CLI now joins `/v1` correctly. No real billable model call was made here.
The public site's `/api/chat` still returns honest 503; it is not a public Gateway
proxy and does not connect to your laptop localhost. Do not expose unauthenticated
Ollama just to make cloud access work. Hosted chat requires separately reviewed
authentication, budget/abuse controls, data-sharing consent and endpoint contracts.

Contact/waitlist email delivery is not configured. Choose an inbox and provider;
set credentials via protected inputs, implement spam control/consent and verify
actual inbox receipt. Until then, Contact is disabled with direct-email fallback.
Do not claim forms are working merely because a success message can be displayed.

## 8. Remaining audit items

The PR deliberately does not erase archives, rotate exposed historical tokens,
implement missing scan workers/Telegram event storage/RF hardware/QKD simulator,
introduce durable distributed quotas or a key-management service, or blindly
upgrade every optional dependency. Review transitive filelock advisories in the
actual resolved release graph; test compatibility before pinning a new constraint.
Old research docs may still list unsupported roadmap commands or certifications;
the public build labels them reference/demo content, not current evidence.

Read-only inventory of secrets, third-party licenses, historical exports and
optional integrations is not the same as remediation. Authorize any future
history rewrite/data deletion separately. Merge and verify this PR before any
production redeploy; no live production change is requested in this handoff.

A per-finding status is in `docs/audit-repair-status.csv`. Items marked operator/
partial are not silently declared resolved. The broad lint/style backlog and
missing optional hardware/cloud implementations still require review.
