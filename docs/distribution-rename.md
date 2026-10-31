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

In the intended Ubuntu environment, rebuild into a **fresh empty directory**:

```bash
source ~/.venvs/shadow313/bin/activate
python -m pip install --upgrade build twine
python -m build --outdir release-artifacts-nexus
python -m twine check release-artifacts-nexus/*
```

Expected distribution filenames use the normalized underscore form:
`shadow313_nexus-4.0.0-py3-none-any.whl` and `shadow313_nexus-4.0.0.tar.gz`.
Metadata inside must say `Name: shadow313-nexus`. CLI entrypoint must still be
`shadow313 = shadow313.cli.main:main`. Do not commit generated release folders.
Use a new artifact directory for each subsequent release build.

Create a fresh wheel-check venv outside the checkout rather than mixing the old
and new distributions (both install the same import/command paths):

```bash
python3 -m venv ~/.venvs/shadow313-nexus-wheel-check
~/.venvs/shadow313-nexus-wheel-check/bin/python -m pip install \
  ./release-artifacts-nexus/shadow313_nexus-4.0.0-py3-none-any.whl
cd /tmp
~/.venvs/shadow313-nexus-wheel-check/bin/python -c \
  'from importlib.metadata import version; import shadow313; print(version("shadow313-nexus")); print(shadow313.__file__)'
~/.venvs/shadow313-nexus-wheel-check/bin/shadow313 --help
```

Then verify required resources and supported optional features again. No new
security claims follow from a rename. The previously skipped features remain
unverified. For a new project name, version 4.0.0 on the **old name's** TestPyPI
project does not occupy 4.0.0 on this new name; still check both indexes first.
No upload occurs in these instructions. Configure the exact trusted publisher,
verify TestPyPI acceptance/install, and authorize a real PyPI release separately.

Historical research/archives can retain old release text; active generated CI
install snippets, runtime missing-dependency hints, README and homepage examples
use the new name. Docker image names, Ollama model names, API service names and
Python imports are independent identities and are not renamed by this change.
