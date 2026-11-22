# Repository Structure and Ownership

This is an orientation map of the current repository, not a promise that every
optional integration is enabled or every deployment target is live.

## Top-level layout

```text
Shadow313-Nexus/
├── .github/                 # GitHub Actions, issue templates, automation
├── ci/                      # CI templates and reusable validation assets
├── api/                     # Static-site API adapters and API contracts
├── assets/                  # Shared public-site assets
├── about/                   # Public about pages
├── blog/                    # Public technical articles
├── cyber_lab/               # Lab exercises and learning materials
├── docs/                    # Product docs, technical reports, dashboards
├── infra/
│   └── hetzner/             # Planned server setup and host automation
├── logs/                    # Local workstation diagnostics (not committed)
├── marketplace/             # Public marketplace pages
├── migrations/              # Database migration assets
├── nexus_toolkit/           # NEXUS toolkit package
├── ollama/                  # Local model and Ollama helpers
├── platform/                # Public platform pages
├── policies/                # Container/security policy definitions
├── pricing/                 # Public pricing pages
├── scripts/                 # Build, validation, maintenance automation
├── sentinelos/              # SentinelOS assets and components
├── shadow313/               # Primary Python application package
├── shadow313_platform/      # Platform Python package
├── shadow313_sdk/           # SDK Python package
├── sigma/                   # Sigma detection rules
├── site/                    # Static publishing allowlist and metadata
├── skills/                  # Project engineering skills
├── tests/                   # Automated tests
├── tools/                   # Supporting utilities and tool pages
├── Dockerfile               # Application container build
├── docker-compose.yml        # Local multi-service development stack
├── index.html               # Public website entry page
├── pyproject.toml            # Python package, extras, CLI entry points
├── vercel.json               # Vercel routes, headers, and static build
└── README.md                 # Project entry point
```

## Ownership boundaries

| Area | Canonical owner | Rules |
|---|---|---|
| Python runtime | `shadow313/` | Keep importable application code inside the package |
| SDK | `shadow313_sdk/` | Public Python client interfaces |
| Platform extensions | `shadow313_platform/` | Platform-level package functionality |
| Website | `index.html`, public page folders, `assets/` | Static content only; no secrets or private source |
| Published file selection | `site/public-files.json` | Explicit allowlist; review every addition |
| Vercel routing/build | `vercel.json`, `scripts/build-public-site.cjs` | Keep routes and published output aligned |
| CI and security | `.github/workflows/` | Keep validation reproducible and branch-aware |
| Infrastructure | `infra/` and `docker/` | Separate local development from production provisioning |
| Tests | `tests/` | Mirror package boundaries where practical |
| Documentation | `docs/` | Describe verified behavior and operational state |

## Organization rules

1. New Python application code belongs under the appropriate package, not in
   the repository root.
2. New automated tests belong under `tests/` and should follow package or
   subsystem boundaries.
3. Build, validation, and maintenance scripts belong under `scripts/`.
4. Host-specific provisioning belongs under `infra/<provider>/`; do not mix
   provider instructions with application code.
5. Public pages and assets must be added to the static-site allowlist only after
   review for secrets, private source, and unsafe paths.
6. Keep root-level configuration only when a tool requires that conventional
   location (for example `pyproject.toml`, `vercel.json`, Docker files, and
   GitHub metadata).
7. Treat historical scripts and compatibility entry points as legacy until
   their callers and CI references have been checked. Do not bulk-move them
   without updating references and testing the resulting paths.
8. Generated archives, local logs, credentials, virtual environments, caches,
   and build output must not be committed as source.

## Hosting boundaries

- **Vercel:** public static website and deployment previews.
- **Cloudflare:** DNS management for `shadow313.com`.
- **GitHub:** source control and CI/CD.
- **Hetzner:** planned backend host; not yet provisioned.
- **Render, Netlify, and Railway:** not part of the approved deployment topology.

The `infra/hetzner/` scripts need focused review before production use. The
current scripts include VPN-focused provisioning and a broader bootstrap path;
neither should be assumed to be a complete, validated application deployment
pipeline.


## Supporting and compatibility areas

These directories are retained because they contain separate components or
historical/operational material. They are not candidates for blind deletion:

| Path | Role | Maintenance guidance |
|---|---|---|
| `ci/` | CI templates and reusable validation assets | Promote active templates into workflows only after review |
| `ghost-watch-terminal/` | Separate Ghost Watch terminal component | Keep isolated from the primary CLI package until integration is tested |
| `local_bundle/` | Offline copy of selected website pages | Regenerate from canonical pages; avoid hand-editing duplicate content |
| `ollama/` | Local model files and helper scripts | Keep model/runtime setup separate from hosted infrastructure |
| `policies/` | Container and policy-as-code rules | Validate policy changes with the matching policy engine |
| `sentinelos/` | SentinelOS assets and supporting components | Treat as a distinct subsystem |
| `sigma/` | Sigma detection content | Validate rules with a Sigma-compatible tool |
| `dist/` | Distribution manifest and receipt artifacts | Do not treat as the Python build output directory without checking its manifest |
| `logs/` | Local workstation diagnostics | Keep machine-specific runtime reports local and ignored; do not commit them |

Several PowerShell maintenance scripts remain at the repository root for
backward compatibility with existing local workflows. New scripts belong in
`scripts/`. Move old entry points only after searching for callers and updating
documentation, workflows, and local automation.
