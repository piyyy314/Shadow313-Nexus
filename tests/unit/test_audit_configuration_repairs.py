"""Structural acceptance checks; these do not claim a running Docker engine."""

import json
import subprocess
import tomllib
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_compose_effective_commands_and_egress():
    c = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    s = c["services"]
    for name in ("shadow313-api", "telegram-bot"):
        assert s[name]["entrypoint"] == []
        assert s[name]["command"][0] == "python"
    assert "telegram" in s["telegram-bot"]["profiles"]
    assert not any(
        "TELEGRAM_" in value and ":?" in value for value in s["telegram-bot"]["environment"]
    )
    assert any(not c["networks"][n].get("internal") for n in s["ollama"]["networks"])
    assert s["ollama"]["healthcheck"]["test"] == ["CMD", "ollama", "list"]
    assert "driver_opts" not in c["volumes"]["shadow313_data"]
    assert all("seccomp:unconfined" not in v.get("security_opt", []) for v in s.values())


def test_nginx_matches_compose_service_ports():
    text = (ROOT / "nginx.conf").read_text()
    assert "server open-webui:8080;" in text
    assert "server open-webui:3000;" not in text
    assert "server shadow313-dashboard:" not in text
    assert "dashboard service is not configured" in text


def test_model_uses_base_template_and_truthful_prompt():
    text = (ROOT / "ollama/Modelfile").read_text()
    assert text.startswith("FROM mistral:7b")
    assert "\nTEMPLATE " not in text
    assert "<|start_header_id|>" not in text
    assert "\nLICENSE " not in text
    assert "not training, tool execution" in text
    assert "Do not invent" in text
    script = (ROOT / "ollama/deploy_shadow313_model.sh").read_text()
    assert 'BASE_MODEL="llama' not in script
    assert "ollama/Modelfile" in script


def test_package_rules_include_related_packages_and_data():
    c = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["setuptools"]
    assert "nexus_toolkit*" in c["packages"]["find"]["include"]
    assert "plugin.json" in c["package-data"]["shadow313.plugins.custom_ai_threat_analyzer"]
    assert "recursive-include docs" not in (ROOT / "MANIFEST.in").read_text()


def test_public_output_is_exact_explicit_allowlist():
    subprocess.run(["node", "scripts/build-public-site.cjs"], cwd=ROOT, check=True)
    out = ROOT / "public-site"
    expected = set(json.loads((ROOT / "site/public-files.json").read_text())) | {".nojekyll"}
    actual = {p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()}
    assert actual == expected
    for excluded in (
        "README.md",
        "requirements.txt",
        "docs-archive",
        "local_bundle",
        "shadow313",
        "notes",
        "api",
        "server",
        "docs/session-exports",
    ):
        assert not (out / excluded).exists()
    config = json.loads((ROOT / "vercel.json").read_text())
    assert config["outputDirectory"] == "public-site"
    for route in config["rewrites"]:
        if not route["destination"].startswith("/api/"):
            assert route["destination"].lstrip("/") in expected


def test_contact_cannot_claim_delivery():
    text = (ROOT / "docs/contact.html").read_text()
    assert '<button type="submit" disabled' in text
    assert "Online form delivery is not configured" in text
    assert "Message sent!" not in text
