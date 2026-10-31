"""Distribution rename must not rename the CLI or Python import packages."""

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_distribution_name_and_entrypoint_are_distinct():
    config = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert config["project"]["name"] == "shadow313-nexus"
    assert config["project"]["scripts"] == {"shadow313": "shadow313.cli.main:main"}
    assert config["project"]["version"] == "4.0.0"
    assert (ROOT / "shadow313/__init__.py").is_file()


def test_public_install_examples_use_reviewed_source_until_publication():
    for name in [
        "README.md",
        "index.html",
        "shadow313/modules/cicd/cicd.py",
        "shadow313/modules/cicd/cicd_module.py",
        "shadow313/v2/dashboard/app.py",
        "shadow313/v4/mobile_api/mobile_api.py",
    ]:
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "pip install shadow313" not in text, name
        assert 'pip install "shadow313' not in text, name
        assert (
            "pip install ." in text
            or ".[dashboard]" in text
            or "pip install git+https://github.com/piyyy314/Shadow313-Nexus.git@" in text
        )
    homepage = (ROOT / "index.html").read_text(encoding="utf-8")
    assert ">pip install .</span>" in homepage
    assert "writeText('pip install .')" in homepage
    assert "inside that checkout in a fresh environment" in homepage


def test_wheel_check_guide_uses_unique_disposable_environments():
    text = (ROOT / "docs/distribution-rename.md").read_text(encoding="utf-8")
    assert 'check_env="$(mktemp -d /tmp/shadow313-wheel-check.XXXXXX)"' in text
    assert 'python3 -m venv "$check_env"' in text
    assert '"$check_env/bin/python" -m pip install' in text
    assert '"$artifact_dir/shadow313_nexus-4.0.0-py3-none-any.whl"' in text
    assert "python3 -m venv ~/.venvs/shadow313-nexus-wheel-check" not in text
    assert "uninstalling the" in text
    assert "**before** installing the new wheel" in text


def test_generated_ci_installs_scanner_from_pinned_source_not_consumer_checkout():
    import re

    import yaml

    from shadow313.modules.cicd import cicd, cicd_module

    for module in (cicd, cicd_module):
        for template in (module.GITHUB_ACTIONS_WORKFLOW, module.GITLAB_CI_TEMPLATE):
            yaml.safe_load(template)
            installs = [line.strip() for line in template.splitlines() if "pip install" in line]
            assert installs
            for line in installs:
                assert re.search(
                    r"pip install git\+https://github.com/piyyy314/Shadow313-Nexus\.git@[0-9a-f]{40}$",
                    line,
                )
