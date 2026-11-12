"""Infrastructure contract tests for local Docker/Nginx routing."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_nginx_routes_soc_and_versioned_api_to_fastapi():
    config = (ROOT / "nginx.conf").read_text(encoding="utf-8")
    assert "location /api/shiatoali/ {" in config
    assert "proxy_pass         http://shadow313_api;" in config
    assert "location /api/s313/ {" in config
    assert "proxy_pass         http://shadow313_api/api/;" in config


def test_local_tls_generator_writes_to_compose_mounted_directory():
    script = (ROOT / "docker/nginx/gen-ssl.sh").read_text(encoding="utf-8")
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")

    assert 'SSL_DIR="$(dirname "$0")/ssl"' in script
    assert 'mkdir -p "$SSL_DIR"' in script
    assert "./docker/nginx/ssl:/etc/nginx/ssl:ro" in compose
    assert "docker/nginx/ssl/*.key" in ignore
    assert "docker/nginx/ssl/*.crt" in ignore


def test_compose_passes_gateway_endpoint_to_ai_services():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert compose.count("AI_GATEWAY_ENDPOINT=") >= 2
