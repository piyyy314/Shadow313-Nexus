"""Infrastructure contract tests for local Docker/Nginx routing."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_nginx_preserves_open_webui_api_and_routes_shadow313_endpoints():
    config = (ROOT / "nginx.conf").read_text(encoding="utf-8")
    webui_api = config.split("location /api/ {", 1)[1].split("}", 1)[0]

    assert "proxy_pass         http://openwebui;" in webui_api
    assert "location ^~ /api/shiatoali/ {" in config
    assert "location /api/s313/ {" in config
    assert "proxy_pass         http://shadow313_api/api/;" in config
    assert "location ~ ^/api/(?:status|modules|chat|detect|" in config
    assert "proxy_pass         http://shadow313_api;" in config
    assert "location /api/ {\n            limit_req zone=ui" in config


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


def test_every_fastapi_api_route_has_an_explicit_nginx_upstream():
    from shadow313.api.server import create_app

    config = (ROOT / "nginx.conf").read_text(encoding="utf-8")
    match = re.search(r"location ~ (\^/api/[^ ]+) \{", config)
    assert match is not None
    shadow_api_pattern = re.compile(match.group(1))
    app = create_app(api_key="nginx-route-test-key")

    for route in app.routes:
        path = getattr(route, "path", "")
        if not path.startswith("/api/"):
            continue
        if path.startswith("/api/shiatoali/"):
            assert "location ^~ /api/shiatoali/ {" in config
            continue
        sample_path = path.replace("{bind_id}", "sample-bind-id")
        assert shadow_api_pattern.fullmatch(sample_path), path


def test_local_tls_private_key_is_not_tracked_in_source_tree():
    assert not (ROOT / "docker/nginx/ssl/shadow313.key").exists()
    ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "docker/nginx/ssl/*.key" in ignore
    assert "docker/nginx/ssl/*.crt" in ignore
