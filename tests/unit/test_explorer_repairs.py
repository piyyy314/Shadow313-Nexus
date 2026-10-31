"""Regression checks for deployment wiring and API configuration."""
import json
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from shadow313.api.server import create_app

ROOT = Path(__file__).resolve().parents[2]


def test_ollama_healthcheck_and_bot_port():
    config = yaml.safe_load((ROOT / 'docker-compose.yml').read_text())
    services = config['services']
    assert services['ollama']['healthcheck']['test'] == ['CMD', 'ollama', 'list']
    bot = services['telegram-bot']
    assert 'SHADOW313_API_URL=http://shadow313-api:8313' in bot['environment']
    assert 'shadow313_internal' in bot['networks']
    assert any(
        not config['networks'][network].get('internal', False)
        for network in bot['networks']
    ), 'Telegram requires an internet-routable network for outbound HTTPS'
    assert 'healthcheck' not in bot


def test_no_duplicate_compose_keys():
    def check(node):
        if isinstance(node, yaml.MappingNode):
            keys = [key.value for key, _ in node.value]
            assert len(keys) == len(set(keys)), keys
            for _, value in node.value:
                check(value)
        elif isinstance(node, yaml.SequenceNode):
            for value in node.value:
                check(value)
    check(yaml.compose((ROOT / 'docker-compose.yml').read_text()))


def test_coverage_alias_destinations_exist():
    routes = {r['source']: r['destination'] for r in json.loads((ROOT / 'vercel.json').read_text())['rewrites']}
    for route in ['/coverage_matrix', '/attck-coverage-graph']:
        assert (ROOT / routes[route].lstrip('/')).is_file()


def test_production_api_requires_key(monkeypatch):
    monkeypatch.setenv('SHADOW313_ENV', 'production')
    with pytest.raises(RuntimeError, match='SHADOW313_API_KEY'):
        create_app()


def test_api_reads_key_from_environment(monkeypatch):
    monkeypatch.setenv('SHADOW313_API_KEY', 'test-only-key')
    client = TestClient(create_app())
    assert client.get('/api/modules').status_code == 401
    assert client.get('/api/modules', headers={'X-API-Key': 'test-only-key'}).status_code == 200


def test_production_origin_preflight():
    client = TestClient(create_app(api_key='test-only-key'))
    response = client.options('/api/modules', headers={
        'Origin': 'https://shadow313.com', 'Access-Control-Request-Method': 'GET',
        'Access-Control-Request-Headers': 'X-API-Key',
    })
    assert response.status_code == 200
    assert response.headers['access-control-allow-origin'] == 'https://shadow313.com'


def test_explicit_key_overrides_environment(monkeypatch):
    monkeypatch.setenv('SHADOW313_API_KEY', 'environment-test-key')
    client = TestClient(create_app(api_key='explicit-test-key'))
    assert client.get('/api/modules', headers={'X-API-Key': 'environment-test-key'}).status_code == 401
    assert client.get('/api/modules', headers={'X-API-Key': 'explicit-test-key'}).status_code == 200
