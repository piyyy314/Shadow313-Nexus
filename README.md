# Shadow313 NEXUS

**A local-first security engineering toolkit with a Python CLI, modular analysis capabilities, and a static web presence.**

[![CI](https://img.shields.io/github/actions/workflow/status/piyyy314/Shadow313-Nexus/shadow313-ci.yml?branch=master&label=CI)](https://github.com/piyyy314/Shadow313-Nexus/actions/workflows/shadow313-ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Shadow313 NEXUS is a modular toolkit for authorized security assessment,
defensive engineering, security research, and controlled lab work. This
repository contains the Python package, command-line interface, optional API
and local AI integrations, tests, deployment configuration, and public static
website.

> **Operational status:** The public website is hosted by Vercel. Cloudflare
> manages DNS for `shadow313.com`; `shadow313.dev` uses its existing Vercel
> DNS configuration. The Python backend is **not yet deployed as a hosted
> service**. Hetzner is the planned backend host and remains pending purchase,
> provisioning, hardening, and deployment validation. Website availability
> does not mean backend-dependent features are online.

## Contents

- [Project overview](#project-overview)
- [Hosting architecture](#hosting-architecture)
- [Quick start](#quick-start)
- [CLI usage](#cli-usage)
- [Optional local services](#optional-local-services)
- [Repository structure](#repository-structure)
- [Configuration](#configuration)
- [Testing](#testing)
- [Security and responsible use](#security-and-responsible-use)
- [Deployment status](#deployment-status)
- [Contributing](#contributing)
- [License](#license)

## Project overview

The codebase includes capability areas for reconnaissance, vulnerability
analysis, defensive hardening, network analysis, post-quantum cryptography,
threat intelligence, automation, reporting, and selected integrations.

Availability varies by module and optional dependency. The CLI help and
command registry are the source of truth for commands and registered handlers.
A feature description or website page is not proof that an external integration
is configured or a hosted service is running.

## Hosting architecture

| Layer | Platform | Responsibility | State |
|---|---|---|---|
| Source control and CI | GitHub | Repository, pull requests, automated checks | In use |
| Public website | Vercel | Static build, previews, production hosting | In use |
| DNS for `shadow313.com` | Cloudflare | DNS zone and record management | In use |
| DNS for `shadow313.dev` | Vercel DNS | Existing domain DNS configuration | In use |
| Backend infrastructure | Hetzner | Planned API and service host | Pending purchase and setup |

The `www` hostnames are configured to redirect to their respective apex
hostnames. Both domains are connected to the Vercel website project; this is
not a cross-domain redirect from `.com` to `.dev`.

**Render, Netlify, and Railway are not part of the intended hosting
architecture.** Do not add a second frontend host or temporary backend provider
without an explicit architecture decision.

### Static website build

The Vercel project runs:

```bash
node scripts/build-public-site.cjs
```

The build publishes the files allowlisted by `site/public-files.json` into
`public-site/`. The repository is not served as a raw web root. Do not expose
Python source, private configuration, credentials, or internal assets by
loosening the publishing allowlist without review.

### Backend boundary

The repository includes Python API code and local Docker Compose services.
The static Vercel website is not the Python backend. Backend-dependent routes
must report an explicit unavailable state until a real backend has been
deployed, configured, authenticated, and health-checked.

## Quick start

### Requirements

- Python 3.11 or newer
- Git
- A Python virtual environment (recommended)
- Optional: Docker Engine and Docker Compose plugin for local services

### Install from source

```bash
git clone https://github.com/piyyy314/Shadow313-Nexus.git
cd Shadow313-Nexus

python -m venv .venv
# Linux / macOS
source .venv/bin/activate
# Windows PowerShell:
# .venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

For the broader optional dependency set:

```bash
python -m pip install -e ".[full]"
```

The package metadata defines two console entry points: `shadow313` and
`s313-cli`. PyPI publication is not implied by the repository name. Until an
official release is published, install from a reviewed source checkout.

## CLI usage

Start with the built-in help and command registry:

```bash
shadow313 --help
shadow313 commands
shadow313 commands --all
```

Explore available module options with the CLI help:

```bash
shadow313 recon --help
shadow313 vuln --help
shadow313 defense --help
shadow313 quantum --help
shadow313 nexus --help
```

Optional modules may require additional extras, system packages, permissions,
or external credentials. Use only targets and environments for which you have
explicit authorization. Prefer passive or lab modes when evaluating unfamiliar
capabilities.

## Optional local services

### Docker Compose

The Compose configuration supports local development and integration testing.
Review `.env.example` and the Compose files before starting services:

```bash
cp .env.example .env
# Replace example values with local, non-production values.
docker compose config
docker compose up -d
docker compose ps
```

Do not commit a populated `.env` file. Keep API keys, tokens, signing material,
and database credentials in an appropriate secret store.

### Local AI

Ollama can be used as an optional local model provider. Configure the backend,
model, and endpoint with the supported `SHADOW313_AI_*` environment variables.
Cloud AI providers may transmit prompts or analysis data outside the local
machine; review provider terms and data handling before enabling them.

## Repository structure

| Path | Purpose |
|---|---|
| `shadow313/` | Primary Python package, CLI, API, core services, and modules |
| `shadow313_sdk/` | Python SDK |
| `shadow313_platform/` | Platform-level Python components |
| `nexus_toolkit/` | NEXUS toolkit components |
| `tests/` | Unit, integration, and regression tests |
| `api/` | Static-site API adapters and API contract assets |
| `site/` | Public-site allowlist and metadata |
| `index.html`, `assets/`, `about/`, `blog/`, `marketplace/`, `platform/`, `pricing/`, `tools/` | Public website source pages and assets |
| `docs/` | Technical documentation, runbooks, reports, and dashboards |
| `infra/hetzner/` | Planned Hetzner host preparation and server scripts |
| `docker/`, `Dockerfile`, `docker-compose*.yml`, `nginx.conf` | Container and local service configuration |
| `.github/workflows/` | CI, validation, security, release, and deployment workflows |
| `scripts/` | Build, validation, maintenance, and repository automation |
| `migrations/` | Database migration assets |
| `skills/` | Project engineering skills and workflow definitions |
| `cyber_lab/` | Lab materials and learning resources |

Supporting areas also include `ci/`, `ghost-watch-terminal/`, `local_bundle/`,
`ollama/`, `policies/`, `sentinelos/`, and `sigma/`. These are separate lab,
legacy, offline, or policy assets; they are not interchangeable with the main
Python package or public website. See [Repository Structure and Ownership](docs/REPOSITORY_STRUCTURE.md)
for the expanded map and organization rules.

## Configuration

Start with `.env.example` and the relevant service documentation. Common
configuration groups include:

- `SHADOW313_AI_*` — optional AI backend, model, and endpoint.
- `OPENAI_API_KEY` or `AI_GATEWAY_API_KEY` — provider credentials when that
  provider is deliberately enabled.
- Database settings — required only for optional database-backed services.
- Integration credentials — configure only integrations you intend to use.

Never place production credentials in example files, documentation, screenshots,
test fixtures, or commits.

## Testing

Install development dependencies, then run:

```bash
python -m pytest tests/ -q --tb=short --ignore=tests/integration --timeout=120
```

Useful local checks include:

```bash
python -m compileall -q shadow313 shadow313_sdk shadow313_platform nexus_toolkit
python -m ruff check .
python -m black --check .
```

Some checks require optional dependencies or system tools. GitHub Actions is
the authoritative record for a specific commit; inspect workflow runs and job
conclusions rather than relying only on the status badge.

## Security and responsible use

Shadow313 NEXUS is intended for defensive security work, authorized assessments,
research, and isolated labs.

- Obtain written authorization before scanning or testing third-party systems.
- Use lab-only modes for exploit demonstrations and controlled malware execution.
- Treat detections as analyst signals, not proof of compromise.
- Review generated commands and remediation before execution.
- Protect API credentials, signing keys, session data, and collected evidence.
- Do not expose a development API directly to the public internet.
- Review [SECURITY.md](SECURITY.md) before reporting a vulnerability.

The presence of cryptographic, AI, or audit-related code does not by itself
establish certification, legal admissibility, tamper-proof retention, or
compliance with a security framework. Validate those properties independently.

## Deployment status

The public static site and hosted backend are separate systems.

Before the Hetzner backend is considered operational, the project must complete:

1. Server selection based on API, database, worker, and storage requirements.
2. SSH-key access, firewall policy, OS updates, and host hardening.
3. Runtime and database deployment with persistent storage and backups.
4. Backend configuration, secret management, TLS, and restricted network access.
5. Health checks, logs, monitoring, restore testing, and incident procedures.
6. Vercel-to-backend integration tests using production-safe credentials.

The current scripts are documented in
[`infra/hetzner/README.md`](infra/hetzner/README.md). Review them before
running; a bootstrap script is not proof of a finished production deployment.

For release and integration decisions, see
[`docs/PLATFORM_INTEGRATION_STATUS.md`](docs/PLATFORM_INTEGRATION_STATUS.md)
and the [GitHub Actions history](https://github.com/piyyy314/Shadow313-Nexus/actions).

## Contributing

1. Open an issue for substantial changes or architectural decisions.
2. Create a focused feature or fix branch.
3. Add or update tests for behavior changes.
4. Run relevant local checks.
5. Open a pull request with scope, validation evidence, and deployment impact.

Do not bypass required checks or review by pushing directly to the production
branch.

## License

Shadow313 NEXUS is distributed under the [MIT License](LICENSE).
