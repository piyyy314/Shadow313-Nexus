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
    assert services["ollama-init"]["depends_on"]["ollama"]["condition"] == "service_started"
    assert services["open-webui"]["depends_on"]["ollama"]["condition"] == "service_healthy"
    for service_name in ("shadow313-cli", "shadow313-api", "telegram-bot"):
        assert services[service_name]["depends_on"]["ollama-init"]["condition"] == "service_completed_successfully"
    assert services["telegram-bot"]["depends_on"]["shadow313-api"]["condition"] == "service_healthy"
    assert set(services["shadow313-cli"]["networks"]) == {
        "shadow313_internal",
        "shadow313_external",
    }


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

    backend_check = script.index('if [ "${SHADOW313_AI_BACKEND:-ollama}" != "ollama" ]')
    ollama_wait = script.index("until ollama list")
    assert backend_check < ollama_wait
    assert "OLLAMA_DEFAULT_MODEL" in script
    assert "SHADOW313_AI_MODEL" in script
    assert "OLLAMA_EXTRA_MODELS" in script
    assert 'ollama pull matarmohamad313/shadow313-nexus' not in script

def test_api_healthcheck_uses_runtime_python_not_missing_curl():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    healthcheck = compose["services"]["shadow313-api"]["healthcheck"]

    assert healthcheck["test"][0:2] == ["CMD", "python"]
    assert "urllib.request.urlopen" in healthcheck["test"][2]
    assert "curl" not in healthcheck["test"]

