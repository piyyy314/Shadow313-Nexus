# Python distribution name: shadow313-nexus

This changes only the distribution identity/install name. The version remains
4.0.0; this is not a new feature release or an upload. The command is still
`shadow313`; imports and local configuration directories retain `shadow313`.

A package name being absent from `pip index versions` is not proof that PyPI
will accept it. Check name ownership/availability in your PyPI account and set up
Trusted Publishing for **shadow313-nexus**, not the unrelated shadow313 project.
TestPyPI and PyPI require separate publisher configuration. Existing artifacts
named `shadow313-4.0.0...` were built before this rename and must not be uploaded
as the new project. Do not manually rename a wheel or share an upload token.

## After this PR merges

Stop tests/builds in both Windows and WSL, preserve local work, and pull master
only from a clean checkout:

```bash
git status --short --branch
git pull --ff-only origin master
```

## Migration safety: do not coinstall the two distributions

`shadow313` and `shadow313-nexus` own the same import files and CLI script.
Installing one over the other leaves two distribution records; uninstalling the
old one afterward can remove files used by the new one. Use a **fresh environment**.
Do not uninstall either from your working environment just to test a wheel.
If intentionally migrating an existing environment, first verify the old
installation belongs to this project, back it up, remove that verified old
installation **before** installing the new wheel, and retest. Never assume a
registry package named `shadow313` is this project's code.

## Fresh artifact and wheel-check directories on every run

In Ubuntu, from the reviewed repository checkout, use an isolated build tool
venv and unique output directories. These commands neither overwrite old
artifacts nor clear your working environment:

```bash
build_env="$(mktemp -d /tmp/shadow313-build.XXXXXX)"
python3 -m venv "$build_env"
"$build_env/bin/python" -m pip install --upgrade build twine
artifact_dir="$(mktemp -d /tmp/shadow313-artifacts.XXXXXX)"
"$build_env/bin/python" -m build --outdir "$artifact_dir"
"$build_env/bin/python" -m twine check "$artifact_dir"/*
```

Expected normalized filenames are `shadow313_nexus-4.0.0-py3-none-any.whl` and
`shadow313_nexus-4.0.0.tar.gz`. Metadata must say `Name: shadow313-nexus` and the
entrypoint must remain `shadow313 = shadow313.cli.main:main`. Never rename an old
wheel. Do not commit release outputs.

Create another **unique** disposable environment on every wheel check. Keep all
checks pointed to this exact variable and install the exact built artifact:

```bash
check_env="$(mktemp -d /tmp/shadow313-wheel-check.XXXXXX)"
python3 -m venv "$check_env"
"$check_env/bin/python" -m pip install \
  "$artifact_dir/shadow313_nexus-4.0.0-py3-none-any.whl"
cd /tmp
"$check_env/bin/python" -m pip check
"$check_env/bin/python" -c \
  'from importlib.metadata import version; import shadow313; print(version("shadow313-nexus")); print(shadow313.__file__)'
"$check_env/bin/shadow313" --help
```

A repeat run cannot reuse an installed same-version wheel because `mktemp`
creates new paths. Inspect the printed import path; it must point inside
`check_env`, not the repository or your development environment.

Then verify required resources and supported optional features again. No new
security claims follow from a rename. The previously skipped features remain
unverified. For a new project name, version 4.0.0 on the **old name's** TestPyPI
project does not occupy 4.0.0 on this new name; still check both indexes first.
No upload occurs in these instructions. Configure the exact trusted publisher,
verify TestPyPI acceptance/install, and authorize a real PyPI release separately.

Historical research/archives can retain old release text; active generated CI
install snippets, runtime missing-dependency hints, README and homepage examples
use reviewed-source installs until registry ownership/publication is confirmed.
Generated CI templates instead install the scanner from a full, reviewed Git
commit pin (48bedb1); they must not install the consumer repository with `pip
install .`. Review and update that pin deliberately, not a moving branch.
Only switch public instructions to the verified distribution after publishing.
Docker image names, Ollama model names, API service names and Python imports
are independent identities and are not renamed by this change.
