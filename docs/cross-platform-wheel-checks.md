# Installed-wheel checks: Linux, Windows, macOS

Once activated, the workflow builds and hashes one pure-Python `py3-none-any`
wheel, then tests it unchanged across Ubuntu 24.04, Windows Server 2022, and
macOS 15 on Python 3.11 and 3.12. This is
not a standalone `.exe`/macOS app build or a claim of full platform support.

## Activate the workflow (maintainer step)

The connected publisher cannot change `.github/workflows` files. The reviewed
workflow is supplied as `ci/cross-platform-wheel.yml.template`; it **does not run
until installed**. After this PR merges, stop simultaneous WSL/Windows builds,
pull a clean master, then in your Ubuntu checkout:

```bash
git status --short --branch
git pull --ff-only origin master
git switch -c ci/activate-wheel-checks
cp ci/cross-platform-wheel.yml.template .github/workflows/cross-platform-wheel.yml
git diff --no-index -- /dev/null .github/workflows/cross-platform-wheel.yml
```

The last command returns 1 to indicate a diff; that is expected. Review it, then:

```bash
git add .github/workflows/cross-platform-wheel.yml
git commit -m "ci: activate installed-wheel compatibility matrix"
git push -u origin ci/activate-wheel-checks
```

Open a PR into master. No new secrets are required: read-only `GITHUB_TOKEN` and
GitHub Actions artifact access suffice. No deployment, external scanning, or
package publication occurs. Pip downloads public dependencies. Wait for all
matrix jobs and **Installed wheel gate** to succeed before merging. Then make
that gate a required status check via your repository rules if desired; this
configuration is not changed by these files. Workflow activation must be done
by an account/credential authorized to modify workflows.

## What it tests

- Build wheel/sdist once, check metadata with Twine, create SHA-256 manifest.
- Each job validates the exact artifact set and hashes before installation.
- Each invocation creates a unique temporary virtual environment, removes
  inherited Python paths, installs the wheel (not editable source), and runs
  copied smoke tests outside the repository. Temporary environments are removed.
- Core: all four import roots resolve within that environment; distribution
  identity/version, resources, console entrypoint, CLI parsers, SQLite cleanup,
  receipt roundtrip/tampering and explicitly labeled HMAC mode are checked.
- API: same checks plus dashboard dependencies, auth rejection, disabled scan
  behavior, and oversized-body rejection using in-process FastAPI TestClient.
- Linux PQC: install the real `pqc` extra; require SPHINCS+ signing and reject
  tampered signatures/payloads. A fallback does **not** pass this profile.
- No `continue-on-error`; the aggregate gate fails on failed/skipped/cancelled jobs.

These are smoke tests, **not** the full repository pytest suite. Existing Linux
full-suite workflows remain unchanged. Core HMAC checks are not PQC certification.
A green core/API Windows or macOS job does not validate native `pyspx`, packet
capture, browsers, GPUs, Ollama, cloud credentials, hardware, or every CLI module.
Native signing on Windows/macOS is not claimed; Windows MSVC currently fails on
PySPX's variable-length C arrays. WSL is the separate Linux route, not native
Windows support. Hosted runner OS/architecture is printed in test output; only
the actual runner architecture is covered, not every Intel/ARM Mac/Windows/Linux.
Dependencies are presently resolved from version ranges, not a release lockfile.

The existing `build-release.yml` standalone-binary workflow is independent: its
`full`/PySPX install can fail on Windows and its macOS x64 filename does not
establish runner architecture. Do not treat its outputs as verified installers
or trigger a release tag based solely on this wheel gate.

## Run a profile locally

From a clean reviewed checkout in Ubuntu with build/twine installed in your
chosen development/tooling environment:

```bash
artifact_dir="$(mktemp -d /tmp/shadow313-matrix-artifacts.XXXXXX)"
python -m build --outdir "$artifact_dir"
python -m twine check "$artifact_dir"/*
python scripts/check-wheel.py "$artifact_dir" --write-manifest
python scripts/check-wheel.py "$artifact_dir" --profile core
python scripts/check-wheel.py "$artifact_dir" --profile api
python scripts/check-wheel.py "$artifact_dir" --profile pqc
```

Stop at any failed command. `pqc` is for a working native-signing environment.
Repeat runs use different environments automatically. No old environments,
models, databases, stashes, source files, or Docker volumes are deleted.
