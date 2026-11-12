"""Regression tests for local TLS certificate generation and Compose wiring."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_compose_initializes_tls_volume_for_unprivileged_nginx():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]
    initializer = services["nginx-cert-init"]
    nginx = services["nginx"]
    command = initializer["command"][0]

    assert "nginx_ssl:/certs" in initializer["volumes"]
    assert "nginx_ssl:/etc/nginx/ssl:ro" in nginx["volumes"]
    assert "chown 101:101" in command
    assert "chmod 640 /certs/shadow313.key" in command
    assert nginx["user"] == "nginx"
    assert nginx["depends_on"]["nginx-cert-init"]["condition"] == "service_completed_successfully"
    assert "nginx_ssl" in compose["volumes"]


def test_manual_tls_generator_does_not_make_private_key_world_readable():
    script = (ROOT / "docker/nginx/gen-ssl.sh").read_text(encoding="utf-8")

    assert 'chmod 600 "$KEY"' in script
    assert 'chmod 644 "$CERT"' in script
    assert 'chmod 644 "$KEY"' not in script

def test_compose_passes_ai_provider_configuration_to_all_runtimes():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    for service_name in ("shadow313-cli", "shadow313-api", "telegram-bot"):
        environment = compose["services"][service_name]["environment"]
        assert any(value.startswith("SHADOW313_AI_BACKEND=") for value in environment)
        assert any(value.startswith("SHADOW313_AI_ENDPOINT=") for value in environment)
        assert any(value.startswith("SHADOW313_AI_MODEL=") for value in environment)
        assert any(value.startswith("AI_GATEWAY_API_KEY=") for value in environment)
        assert any(value.startswith("OPENAI_API_KEY=") for value in environment)


def test_ollama_initializer_skips_cloud_backends_and_uses_configured_models():
    script = (ROOT / "docker/ollama/init.sh").read_text(encoding="utf-8")

    assert 'if [ "${SHADOW313_AI_BACKEND:-ollama}" != "ollama" ]' in script
    assert "OLLAMA_DEFAULT_MODEL" in script
    assert "SHADOW313_AI_MODEL" in script
    assert "OLLAMA_EXTRA_MODELS" in script
    assert 'ollama pull matarmohamad313/shadow313-nexus' not in script

