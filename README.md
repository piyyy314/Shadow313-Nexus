# Shadow313 NEXUS

Python security-research CLI with optional AI and integration modules, plus a
separate public documentation/demo website. Version: 4.0.0. Beta software;
capabilities vary by platform, installed extras, external services, and module.
Use only on systems you own or are explicitly authorized to assess.

## Install from this repository

```sh
git clone https://github.com/piyyy314/Shadow313-Nexus.git
cd Shadow313-Nexus
python -m pip install -e .
shadow313 --help
```

Install optional groups for the workflow you need, for example
`python -m pip install -e ".[recon,network,security]"`. The existing `full` extra
is a convenience subset, **not every optional module dependency**. Heavy ML,
RAG, browser, cloud, reports, and fine-tuning groups may need separate installs
or external programs. This documentation does not verify a PyPI/Docker release.

## CLI examples

These match the argument parser in `shadow313/cli/main.py`; parsing is not proof
that a module or external integration succeeds in your environment.

```sh
shadow313 cicd --help
shadow313 cicd --scan --secrets --output sarif --scan-path .
shadow313 defense --audit --profile cis-level2
shadow313 network --analyze capture.pcap --ml-anomaly --ja3
shadow313 quantum --scan-code ./src --lang python
```

Run each subcommand's `--help` for the installed version. Capture requires an
existing PCAP or supported capture tools/permissions. Defense checks may be
OS-specific; review remediation output before applying any changes.

## What is local, simulated, or external?

- **CLI:** Python modules execute on the machine where you install them. Optional
  AI providers, threat feeds, cloud APIs, SIEM exports, and IPFS integrations can
  transmit data when enabled. “Local-first” does not mean “no network traffic.”
- **Website:** static documentation and browser demonstrations with a small Node
  API. It does **not** execute the Python scanners, connect to RF hardware, enforce
  device hardening, or establish a real quantum channel.
- **Receipts:** cryptographic behavior depends on the configured implementation
  and signing dependencies. Demo IDs and hashes are not evidence of a real
  signature, independent attestation, or an IPFS anchor. Verify actual output.
- **Compliance:** implementing an algorithm or showing a badge does not confer
  FIPS validation, FedRAMP authorization, privacy certification, or audit approval.
  No such certification is asserted by this README.
- Historical dashboard counts/results and old audit reports are not current
  test, vulnerability, coverage, or production-readiness evidence.

## Repository and publication boundaries

| Location | Purpose |
| --- | --- |
| `shadow313/`, `shadow313_sdk/`, `shadow313_platform/`, `nexus_toolkit/` | CLI and related Python packages |
| `docs/`, `platform/`, `tools/`, other HTML folders | Website sources, references, historical research |
| `site/public-files.json` | Explicit public website allowlist |
| `scripts/build-site.cjs` → `site-dist/` | Static deployment output; never the repository root |
| `api/`, `server/` | Server-side website endpoint implementation; not static files |
| `tests/`, `scripts/`, `.github/`, `docker/`, `infra/` | Development, testing, deployment tooling |
| `docs-archive/`, `local_bundle/`, `notes/`, exports, audit reports | Repository-only history pending maintainer review; excluded from website output |

See [publication inventory](site/repository-inventory.csv) and
[deployment/email setup](docs/publication-and-email-setup.md). An ignored file
can still be tracked; `.gitignore` alone does not remove existing history.

```sh
node scripts/build-site.cjs
python scripts/render-site-nav.py --check
python -m pytest tests/unit/test_site_navigation.py tests/unit/test_site_theme.py tests/unit/test_publication_boundary.py
node --test tests/vercel-api.test.cjs tests/site-clocks.test.cjs tests/forms.test.cjs
```

GitHub Pages must use the isolated output too; the workflow handoff is documented
in the setup guide. Static GitHub Pages does not run the Node form API.

## Testing and security reports

Install test dependencies with `python -m pip install -e ".[dev]"` and run
`python -m pytest tests/`. Check the actual results for your commit rather than
copying historical passing-test counts or assuming a scan proves absence of
vulnerabilities. Optional integrations need dedicated runtime tests.

Report security issues privately as described in [SECURITY.md](SECURITY.md).
Do not commit credentials, real session exports, customer data, or private keys.
Repository cleanup cannot revoke credentials already exposed in Git history.

## License

[MIT](LICENSE). Review dependencies and bundled research separately for their
own license and usage constraints.
