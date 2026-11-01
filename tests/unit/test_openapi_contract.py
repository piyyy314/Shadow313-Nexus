"""The checked-in OpenAPI contract matches the Python API routes."""
import json
import subprocess
from pathlib import Path

import yaml

from shadow313.api.server import create_app

ROOT = Path(__file__).resolve().parents[2]


def test_openapi_paths_match_api_routes():
    with open("api/openapi.yaml", encoding="utf-8") as contract_file:
        contract = yaml.safe_load(contract_file)

    app = create_app(api_key="test-key")
    internal_routes = {"/api/docs", "/api/redoc", "/api/openapi.json"}
    implementation_paths = set(app.openapi()["paths"]) - internal_routes
    contract_paths = set(contract["paths"])

    assert implementation_paths == contract_paths


def test_unavailable_integrations_document_200_without_503():
    with open("api/openapi.yaml", encoding="utf-8") as contract_file:
        contract = yaml.safe_load(contract_file)

    paths = (
        "/api/scan/recon",
        "/api/scan/vuln",
        "/api/mobile/scan",
        "/api/mobile/status",
        "/api/mobile/alerts",
        "/api/mobile/findings",
        "/api/mobile/sessions",
        "/api/events",
    )
    for path in paths:
        operations = contract["paths"][path]
        for operation in operations.values():
            assert "200" in operation["responses"]
            assert "503" not in operation["responses"]


def test_static_api_adapter_returns_200_with_unavailable_status():
    cases = [
        ("POST", "/api/scan/recon"),
        ("POST", "/api/scan/vuln"),
        ("POST", "/api/mobile/scan"),
        ("GET", "/api/mobile/status"),
        ("GET", "/api/mobile/alerts"),
        ("GET", "/api/mobile/findings"),
        ("GET", "/api/mobile/sessions"),
        ("GET", "/api/events"),
    ]
    script = """
const handler = require('./api/index.js');
const cases = JSON.parse(process.argv[1]);
const results = cases.map(([method, url]) => {
  const res = {
    headers: {},
    setHeader(name, value) { this.headers[name] = value; },
    end(body) { this.body = body; },
  };
  handler({ method, url }, res);
  return { statusCode: res.statusCode, body: JSON.parse(res.body) };
});
console.log(JSON.stringify(results));
"""
    result = subprocess.run(
        ["node", "-e", script, json.dumps(cases)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    responses = json.loads(result.stdout)
    assert len(responses) == len(cases)
    assert all(response["statusCode"] == 200 for response in responses)
    assert all(response["body"]["status"] == "unavailable" for response in responses)
