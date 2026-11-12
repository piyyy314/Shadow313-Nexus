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

    assert "nginx-cert-init:" in compose
    assert "nginx_ssl:/certs" in compose
    assert "nginx_ssl:/etc/nginx/ssl:ro" in compose
    assert "chown 101:101" in compose
    assert "chmod 640 /certs/shadow313.key" in compose
    assert "service_completed_successfully" in compose
    assert "nginx_ssl:" in compose
    assert "docker/nginx/ssl/*.key" in ignore
    assert "docker/nginx/ssl/*.crt" in ignore


def test_compose_passes_gateway_endpoint_to_ai_services():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert compose.count("AI_GATEWAY_ENDPOINT=") >= 2
