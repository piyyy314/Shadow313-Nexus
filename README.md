# Shadow313 NEXUS

**Version:** 4.0.0  
**Repository:** [piyyy314/Shadow313-Nexus](https://github.com/piyyy314/Shadow313-Nexus)  
**Website:** [shadow313.dev](https://shadow313.dev)  
**License:** MIT

Shadow313 NEXUS is a Python security-intelligence toolkit. The repository contains a command-line interface (CLI), Python packages, optional API and AI integrations, tests, Docker configuration, and a static documentation/demo website.

> **Important scope and status:** The website is primarily static documentation and browser-side demonstrations. A page or UI demonstration does not prove that a backend service, scanner, AI agent, quantum computer, deployment, or external integration is running. Optional integrations require their dependencies, credentials, network access, and local configuration. Do not treat sample counters, simulated outputs, badges, or feature descriptions as operational evidence.
>
> **Release status:** The intended package distribution name is `shadow313-nexus`. PyPI publication is not confirmed by this repository state. Install from a reviewed source checkout; do not assume a similarly named registry package is this project.

## What is in this repository

| Path | Purpose |
|---|---|
| `shadow313/` | Main Python package, CLI, core services, and versioned modules |
| `shadow313_sdk/` | Python SDK package |
| `shadow313_platform/` | Platform package |
| `nexus_toolkit/` | Supporting toolkit package |
| `tests/` | Automated tests, including unit and integration coverage |
| `docs/`, `index.html`, `assets/` | Documentation and static website assets |
| `api/` | Website/API adapter and API contract |
| `docker/`, `Dockerfile`, `docker-compose.yml` | Optional container configuration |
| `scripts/` | Build, validation, and maintenance scripts |
| `.github/workflows/` | GitHub Actions automation |

The CLI entry point is `shadow313`, implemented by `shadow313.cli.main:main`. Python imports use `shadow313`.

## Requirements

- Python 3.11 or newer.
- Git for cloning the repository.
- Optional tools and services only for the features that use them (for example Docker, Ollama, or browser automation).

## Install from source

Use a fresh virtual environment and a reviewed checkout:

```bash
git clone https://github.com/piyyy314/Shadow313-Nexus.git
cd Shadow313-Nexus

python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows PowerShell:
# .\.venv\Scripts\Activate.ps1

python -m pip install --upgrade pip
python -m pip install .
```

For development and tests:

```bash
python -m pip install -e ".[dev]"
python -m pytest tests/ -q --tb=short
```

Optional dependency groups are declared in `pyproject.toml`. Install only the groups needed for the integration you intend to use. The `full` extra is a convenience subset; it does not include every heavyweight or external integration.

## CLI quick reference

Check the installed version and available commands:

```bash
shadow313 --version
shadow313 --help
shadow313 <command> --help
```

Command groups defined by the CLI include:

- `recon` — reconnaissance workflows.
- `vuln` — vulnerability and dependency analysis.
- `exploit` — advisory and explicitly scoped lab assistance.
- `network` — packet capture and network analysis.
- `defense` — defensive configuration auditing and remediation output.
- `quantum` — post-quantum cryptography audit utilities.
- `plugin` and `cicd` — plugin and CI/security tooling.
- `docs`, `learn`, and `ask` — documentation and optional AI-assisted help.
- `session`, `update`, and other versioned command groups — inspect `shadow313 --help` for the installed build.

Examples (review targets and authorization before running active operations):

```bash
shadow313 recon --target example.com --mode passive
shadow313 vuln --audit-deps requirements.txt
shadow313 quantum --scan-host example.com:443
shadow313 defense --audit
shadow313 --help
```

Use scanning and exploitation-related features only on systems you own or are explicitly authorized to assess. Some operations can generate network traffic or modify local state.

## Optional local AI and API integrations

The CLI supports configurable AI backends. The default local Ollama endpoint is `http://localhost:11434`; configure the backend, model, and endpoint using the documented environment variables and configuration file. A local default does not guarantee that every feature stays offline: integrations may call external services when enabled.

The optional Python API runs on port `8313` in the repository's Docker Compose configuration. The static website adapter is not the Python API server. Backend-dependent website routes can return an explicit unavailable response when the corresponding service is not configured or running.

Never commit API keys, tokens, private keys, or populated `.env` files. Use `.env.example` only as a template and replace example values locally.

## Docker

Review `docker-compose.yml`, `.env.example`, and the deployment documentation before starting containers:

```bash
cp .env.example .env
# Edit .env locally; do not commit it.
docker compose config --quiet
docker compose up -d
docker compose ps
```

Container health, persistent-data migration, TLS configuration, and actual model inference must be verified in the target environment. A successful image build is not proof that the complete stack is operational.

## Website and documentation

The website is a static site with HTML pages, assets, documentation, and browser demonstrations. Start with:

- [Documentation index](docs/index.html)
- [Installation guide](docs/install.html)
- [Quick start](docs/quickstart.html)
- [API reference](docs/api.html)
- [Platform integration status](docs/PLATFORM_INTEGRATION_STATUS.md)
- [Audit repair handoff](docs/audit-repair-handoff.md)

Interactive pages may use sample data or simulated behavior. Check each page's own notice and the relevant API/service status before interpreting displayed data as live.

## Validation and security status

GitHub Actions is the source of truth for automated checks on a specific commit. Review the [Actions runs](https://github.com/piyyy314/Shadow313-Nexus/actions) and the commit's check suites/statuses. A successful workflow does not imply that external providers, hosted previews, production services, or optional integrations were exercised.

External service limits (including Snyk quotas), skipped jobs, and pending provider checks must be reported separately from passed tests. Do not describe quota-blocked scans as clean scans.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance.

## Package identity

- Distribution name: `shadow313-nexus`
- CLI executable: `shadow313`
- Python import package: `shadow313`
- Current source version: `4.0.0`

These names describe this repository's package metadata; they do not establish that a release has been uploaded to PyPI.

## License

MIT. See [LICENSE](LICENSE).
