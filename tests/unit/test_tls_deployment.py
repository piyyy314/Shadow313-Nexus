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
