"""Infrastructure contract tests for local Docker/Nginx routing."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_nginx_routes_general_soc_and_versioned_api_to_fastapi():
    config = (ROOT / "nginx.conf").read_text(encoding="utf-8")
    assert "location /api/ {" in config
    assert "proxy_pass         http://shadow313_api;" in config
    assert "location /api/shiatoali/ {" in config
    assert "location /api/s313/ {" in config
    assert "proxy_pass         http://shadow313_api/api/;" in config


def test_compose_manages_nginx_tls_volume_and_permissions():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    assert "nginx-cert-init:" in compose
    initializer = compose.split("nginx-cert-init:", 1)[1].split("  nginx:", 1)[0]
    assert initializer.index("if [ ! -s") < initializer.index("apk add --no-cache openssl")
    assert "nginx_ssl:/certs" in compose
    assert "nginx_ssl:/etc/nginx/ssl:ro" in compose
    assert "chown 101:101" in compose
    assert "chmod 640 /certs/shadow313.key" in compose
    assert "service_completed_successfully" in compose
    assert "nginx_ssl:" in compose


def test_compose_passes_gateway_endpoint_to_ai_services():
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert compose.count("AI_GATEWAY_ENDPOINT=") >= 2



def test_static_site_publishes_shiatoali_console():
    public_files = json.loads(
        (ROOT / "site/public-files.json").read_text(encoding="utf-8")
    )
    assert "docs/shiatoali-console.html" in public_files
    build_script = (ROOT / "scripts/build-public-site.cjs").read_text(encoding="utf-8")
    assert "relative !== 'docs/shiatoali-console.html'" in build_script
