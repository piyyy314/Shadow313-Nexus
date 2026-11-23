# Shadow313-Nexus Repository Relationship Audit

**Audit date:** 2026-11-22  
**Repository:** [piyyy314/Shadow313-Nexus](https://github.com/piyyy314/Shadow313-Nexus)  
**Audited master commit:** `f95c99b24613d781527f19550360987bedd362b1`

## Executive finding

Shadow313-Nexus is the canonical Shadow313 codebase. The repository contains the Python application, CLI, API, SDK, platform packages, SentinelOS dashboard assets, ShiatoAli SOC module, static website, and CI/deployment configuration.

The audit found no Git submodule file, and GitHub repository metadata reports this repository is not a fork and has no parent repository. Related project repositories exist, but the current evidence classifies them as separate projects or integration candidates—not as confirmed live dependencies or services working together.

## Repositories and actual relationship

| Repository | What it contains | Relationship to Shadow313-Nexus | Current conclusion |
|---|---|---|---|
| [Shadow313-Nexus](https://github.com/piyyy314/Shadow313-Nexus) | Canonical Python package, CLI, API, SentinelOS folder, ShiatoAli module, site and workflows | System of record | Primary repository |
| [NEXUS-OmniSec-Unified](https://github.com/piyyy314/NEXUS-OmniSec-Unified) | Separate React/Vite client and Python core; its README includes its own `core/shadow313/` tree | Potential component reuse or API integration | Not proven to be wired to this repo; avoid duplicate engines and event stores |
| [NEXUS-COMMAND-CORE](https://github.com/piyyy314/NEXUS-COMMAND-CORE) | Separate React 19 / TypeScript command-center UI; README describes Firebase and Google AI services | Potential operator UI client | Not proven to call this repo's API or share identity |
| [personal-ai-agent](https://github.com/piyyy314/personal-ai-agent) | Separate LangChain/CrewAI-style agent and analytics service | Potential bounded agent/tool integration | Not proven to use this repo as a backend |
| [Shiatoali-](https://github.com/piyyy314/Shiatoali-) | README identifies the project as Blockscout, an EVM blockchain explorer | Name collision only | Not the ShiatoAli SOC module; do not treat as a project dependency |
| SentinelOS-Shadow313 | No standalone repository with this exact name was found in the repository search performed | SentinelOS exists as `sentinelos/` in Shadow313-Nexus | In-repository subsystem, not a separate repo |

### What is actually integrated inside this repository

- **SentinelOS:** `sentinelos/` contains the dashboard HTML, CSS, JS, and a NEXUS API bridge (`sentinelos/js/nexus-api.js`). PR #140, which connected the dashboard to truthful NEXUS API status, is merged.
- **ShiatoAli SOC:** `shadow313/v4/shiatoali/` contains the embedded SOC service and router; `migrations/shiatoali/` contains migration assets. PR #115 is merged. It is not the separate `Shiatoali-` Blockscout repository.
- **Vercel gateway:** `api/index.js` is the static-site/serverless API gateway. It is not the Python backend. PR #141, which added the reviewed gateway-to-backend proxy, is merged. The README still correctly records that the hosted Python backend is not yet deployed and that Hetzner is planned.
- **AI engine:** `shadow313/core/ai_engine/` provides the local/cloud inference abstraction. PR #150 added inference-limit and cloud-endpoint destination validation and is merged.
- **Evidence and agent safety:** PR #147 hardened evidence provenance semantics; PR #149 made agent dispatch fail closed when modules/actions are unavailable. Both are merged.

## Hosting topology

| Platform | Intended role | State from repository documentation |
|---|---|---|
| GitHub | Source control, code review, CI | Active |
| Vercel | Static website and Node API gateway | Active |
| Cloudflare | DNS for `shadow313.com` | User-designated |
| Vercel DNS | Existing `shadow313.dev` DNS | Retained |
| GitHub Pages | Delivery portal for generated `dist/` artifacts only | Secondary |
| Hetzner | Python API/backend host | Planned; not yet provisioned/deployed |

No evidence in this audit supports moving the website to another provider or treating Render, Netlify, or Railway as part of the approved architecture.

## Git and CI relationship checks

- GitHub repository metadata: `fork=false`; no parent/source repository is reported.
- `.gitmodules`: not present (GitHub contents API returned 404).
- Open pull requests: none at audit time.
- PRs #115, #116, #140, #141, and #147–#151: closed and merged.
- Latest master revision: `f95c99b24613d781527f19550360987bedd362b1`.
- Latest observed Full Pre-Deploy, API Validation, CI/CD, Vercel, and Nightly Security Scan workflows all completed successfully. The pre-deploy gate included file integrity, route validation, repository completeness, Git hygiene, Python/API validation, HTML validation, config validation, shell validation, and the Python test suite.
- Snyk quota-related errors are external provider limitations. They are not counted as passing scans; other repository security controls remain enabled.

## Branch divergence requiring follow-up

There are 26 non-master branches. The following six high-impact branches were compared to current master:

| Branch | Ahead of master | Behind master | Finding |
|---|---:|---:|---|
| `fix/agent-dispatch-fail-closed-20261122` | 43 | 23 | Diverged; inspect unique agent/delivery/evidence changes |
| `fix/hosted-python-backend-proxy` | 33 | 29 | PR #141 already merged by squash; branch is historical |
| `fix/temporal-signature-verification-20261122` | 9 | 22 | Diverged; inspect signature implementation and fallback tests |
| `fix/vercel-public-site-boundary-20261122` | 7 | 23 | Diverged; compare allowlist and deploy workflow against current master |
| `feat/omni-shadow313-engineering-skill` | 21 | 92 | Diverged; inspect unique skill improvements |
| `fix/ci-audit-blockers` | 450 | 27 | PR #116 already merged; branch is not a fresh merge candidate |

These are not safe candidates for blind merging or deletion. Squash merges can make an already-merged branch appear ahead/diverged. Recover unique changes through new branches from current master, with tests, rather than merging old branch histories wholesale.

## Audit limitations and next steps

This audit verifies repository metadata, tracked tree size, selected source/configuration files, repository relationship documentation, PR state, branch comparisons, and recent GitHub workflow outcomes. It does not prove that the three candidate repositories have live service-to-service connectivity, shared identity, production traffic, or compatible event schemas. That requires inspecting their runtime configuration and performing authenticated end-to-end tests.

Recommended sequence:
1. Reconcile the six divergent branches and the remaining non-master branches, preserving backups until unique work is accounted for.
2. Verify the Hetzner backend deployment boundary before enabling remote backend-dependent features.
3. Compare NEXUS-OmniSec-Unified's event/API implementation with ShiatoAli before reusing anything.
4. Define one event schema and OpenAPI contract before connecting NEXUS-COMMAND-CORE.
5. Evaluate personal-ai-agent only through a scoped, permissioned integration contract.
