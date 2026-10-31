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


def test_active_install_examples_use_new_name():
    for name in [
        "README.md",
        "index.html",
        "shadow313/modules/cicd/cicd.py",
        "shadow313/modules/cicd/cicd_module.py",
        "shadow313/v2/dashboard/app.py",
        "shadow313/v4/mobile_api/mobile_api.py",
    ]:
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "pip install shadow313\n" not in text, name
        assert "pip install shadow313[" not in text, name
        assert 'pip install "shadow313[' not in text, name
        assert "pip install shadow313-nexus" in text or 'pip install "shadow313-nexus' in text
    homepage = (ROOT / "index.html").read_text(encoding="utf-8")
    assert ">pip install shadow313-nexus</span>" in homepage
    assert "writeText('pip install shadow313-nexus')" in homepage
